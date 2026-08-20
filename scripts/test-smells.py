#!/usr/bin/env python3
"""Report Go tests that may not be testing what their name says.

This is a candidate generator, not a gate. It finds shapes, and a shape is not
a defect: roughly a third of what it reports is a false positive, usually a
test that asserts through a helper or through `errors.Is` rather than a literal
`t.Error`. Nothing here should be acted on without reading the production code
the test exercises.

It exists because the tree has 5,180 test functions across 226,000 lines, which
is more than anyone reads looking for the handful that cannot fail. The
categories are ordered by how much a hit costs when it is real:

  no-assertion       nothing in the body can fail the test. Sometimes correct
                     -- a test whose point is "this does not panic" asserts by
                     completing -- and sometimes decoration.
  refusal-unchecked  the name promises a refusal and no refusal assertion was
                     found. When real this is the worst kind here: a test named
                     `...Rejects...` that passes against code which accepts.
  stale-skip         a `t.Skip` whose message says the fixture went stale. The
                     test has silently stopped running.
  duplicate-body     bodies identical once string and number literals are
                     blanked, which is the table test somebody did not write.
  merge              small sibling tests sharing a prefix. Weakest signal; most
                     of these should be left alone.

Measured precision, from the 1.0.3 sweep, so the next reader budgets rather
than guesses: `refusal-unchecked` was 0 for 27 in internal/handler before the
rule was widened, `duplicate-body` was worth acting on about a third of the
time and produced 9 real merges there, and `merge` produced none -- every
cluster either spanned unrelated behaviours or had already been covered by a
duplicate-body merge.

    scripts/test-smells.py                    human-readable summary
    scripts/test-smells.py --json out.json    per-directory worklist
    scripts/test-smells.py --dir internal/jwt limit to one directory
"""

import argparse
import collections
import hashlib
import json
import os
import re
import sys

FUNC_RE = re.compile(r"^func (Test|Fuzz|Benchmark|Example)([A-Za-z0-9_]*)\(")

# Anything that can fail a test, including the helper vocabulary this repo uses.
# Missing one of these is what produces a false `no-assertion`, so the set is
# deliberately generous: a false negative here costs nothing, a false positive
# costs somebody a read.
ASSERT_RE = re.compile(
    r"\bt\.(Error|Errorf|Fatal|Fatalf)\b|\brequire\.|\bassert\.|"
    r"\berrors\.(Is|As)\b|\bmust[A-Z]\w*\(|\brequire[A-Z]\w*\(|\bexpect[A-Z]\w*\(|"
    r"\bwant[A-Z]\w*\(|\bassert[A-Z]\w*\("
)

REFUSAL_NAME_RE = re.compile(
    r"Refus|Reject|Denie|Denies|Invalid|Forbid|Unauthoriz|FailsClosed|NotAllowed", re.IGNORECASE
)

# A refusal can be checked many ways, and the first version of this rule listed
# only the 4xx constants. That produced 27 candidates in internal/handler and
# 27 false positives: those handlers refuse with 500 on a storage failure, 413
# on an oversize body, and a 302 whose fragment carries the error, and several
# assert through a helper or by checking that a repository was never consulted.
# Nothing was wrong with the tests. The rule was wrong about what a refusal
# looks like, so it now accepts any status assertion at all and any helper call,
# and only fires when the body contains no visible check of an outcome.
REFUSAL_CHECK_RE = re.compile(
    r"err\s*[!=]=\s*nil|errors\.(Is|As)|"
    r"http\.Status[A-Za-z]+|\brec\.Code\b|\bresp\.StatusCode\b|\bw\.Code\b|"
    r"\bwantErr\b|\bwantStatus\b|\bwantCode\b|"
    r"\bmust[A-Z]|\brequire[A-Z]|\bwant[A-Z]|\bassert[A-Z]|\bexpect[A-Z]|"
    r"\bguardCall\b|\bLocation\b|\bBody\.String\(\)"
)

# A skip message admitting the premise moved, as opposed to one guarding a
# resource that is genuinely absent on this machine.
STALE_SKIP_RE = re.compile(
    r"has gained|is now|no longer|not yet|never|already|claims nil|"
    r"not large enough|not configured|not enabled|not available",
    re.IGNORECASE,
)

SKIP_RE = re.compile(r"^\s*(t\.Skipf?\([^\n]*)", re.MULTILINE)
PREFIX_RE = re.compile(r"(Test[A-Z][a-z0-9]*(?:_[A-Za-z0-9]+)?)")

SKIP_DIRS = {"vendor", ".git", "node_modules", "sdk", "web", "site"}

# A body shorter than this normalises to too little to be a meaningful match.
MIN_DUPLICATE_CHARS = 120
MIN_MERGE_CLUSTER = 6
MAX_MERGE_LOC = 60


def repo_root():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(here)


def collect(root, only_dir):
    """Return every top-level test function with its body text."""
    funcs = []
    base = os.path.join(root, only_dir) if only_dir else root
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if not name.endswith("_test.go"):
                continue
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()
            current = None
            for index, line in enumerate(lines):
                match = FUNC_RE.match(line)
                if match:
                    if current:
                        current["end"] = index
                        funcs.append(current)
                    current = {
                        "kind": match.group(1),
                        "name": match.group(1) + match.group(2),
                        "path": os.path.relpath(path, root),
                        "start": index,
                        "lines": [],
                    }
                elif line.startswith("func ") and current:
                    current["end"] = index
                    funcs.append(current)
                    current = None
                if current is not None:
                    current["lines"].append(line)
            if current:
                current["end"] = len(lines)
                funcs.append(current)
    for func in funcs:
        func["text"] = "".join(func.pop("lines"))
        func["loc"] = func["end"] - func["start"]
    return funcs


def normalise(text):
    """Blank the parts a duplicate is allowed to differ in."""
    out = []
    for line in text.split("\n")[1:]:  # the signature differs by definition
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        line = re.sub(r'"[^"]*"', '""', line)
        line = re.sub(r"\b\d+\b", "0", line)
        out.append(line)
    return "\n".join(out)


def find(tests):
    """Return candidates grouped by directory."""
    items = collections.defaultdict(list)

    def add(func, category, detail):
        items[os.path.dirname(func["path"])].append(
            {
                "cat": category,
                "file": func["path"],
                "line": func["start"] + 1,
                "name": func["name"],
                "loc": func["loc"],
                "detail": detail,
            }
        )

    for func in tests:
        if not ASSERT_RE.search(func["text"]):
            add(func, "no-assertion", "nothing in the body can fail the test")

        if REFUSAL_NAME_RE.search(func["name"]) and not REFUSAL_CHECK_RE.search(func["text"]):
            add(
                func,
                "refusal-unchecked",
                "the name promises a refusal; no refusal assertion found",
            )

        for match in SKIP_RE.finditer(func["text"]):
            call = match.group(1).strip()[:160]
            category = "stale-skip" if STALE_SKIP_RE.search(call) else "skip"
            add(func, category, call)

    by_hash = collections.defaultdict(list)
    for func in tests:
        body = normalise(func["text"])
        if len(body) >= MIN_DUPLICATE_CHARS:
            by_hash[hashlib.sha256(body.encode()).hexdigest()].append(func)
    for group in by_hash.values():
        if len(group) < 2:
            continue
        peers = ", ".join(f"{f['path']}:{f['start'] + 1}" for f in group)
        detail = f"identical modulo literals to {len(group) - 1} other(s): {peers}"
        for func in group:
            add(func, "duplicate-body", detail)

    clusters = collections.defaultdict(list)
    for func in tests:
        if func["loc"] > MAX_MERGE_LOC:
            continue
        match = PREFIX_RE.match(func["name"])
        clusters[(func["path"], match.group(1) if match else func["name"])].append(func)
    for (path, prefix), group in clusters.items():
        if len(group) < MIN_MERGE_CLUSTER:
            continue
        members = ", ".join(f"{f['name']}:{f['start'] + 1}" for f in group)
        items[os.path.dirname(path)].append(
            {
                "cat": "merge",
                "file": path,
                "line": min(f["start"] for f in group) + 1,
                "name": f"{prefix}* x{len(group)}",
                "loc": sum(f["loc"] for f in group),
                "detail": f"small sibling tests sharing a prefix: {members}",
            }
        )

    return items


# Ordered by how much a real hit costs, which is also the order to work them in.
CATEGORY_ORDER = [
    "refusal-unchecked",
    "no-assertion",
    "stale-skip",
    "skip",
    "duplicate-body",
    "merge",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", metavar="PATH", help="write the per-directory worklist here")
    parser.add_argument("--dir", metavar="DIR", help="limit the scan to one directory")
    parser.add_argument(
        "--cat", metavar="NAME", action="append", help="only this category (repeatable)"
    )
    args = parser.parse_args()

    root = repo_root()
    tests = [f for f in collect(root, args.dir) if f["kind"] == "Test"]
    if not tests:
        print("no test functions found; the scan is broken or --dir names nothing", file=sys.stderr)
        return 1

    items = find(tests)
    if args.cat:
        wanted = set(args.cat)
        items = {
            directory: [i for i in found if i["cat"] in wanted]
            for directory, found in items.items()
        }
        items = {d: f for d, f in items.items() if f}

    total = sum(len(f) for f in items.values())
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(dict(sorted(items.items())), handle, indent=1)
        print(f"{total} candidates across {len(items)} directories -> {args.json}")

    print(f"\n{len(tests)} test functions scanned, {total} candidates\n")
    for directory, found in sorted(items.items(), key=lambda kv: -len(kv[1])):
        counts = collections.Counter(i["cat"] for i in found)
        summary = " ".join(
            f"{cat}={counts[cat]}" for cat in CATEGORY_ORDER if counts[cat]
        )
        print(f"{len(found):4d}  {directory or '.':40s} {summary}")

    print("\nThese are candidates, not findings. Verify each against the production")
    print("code before acting; about a third are false positives.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
