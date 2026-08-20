#!/usr/bin/env python3
"""Report production Go matching defect classes vault42 has already shipped.

Like scripts/test-smells.py this is a candidate generator, not a gate, and most
hits are benign. What earns each rule its place is that the class below has
been a real bug in this tree, and three of them have been a real bug twice, in
unrelated files. That is the argument for a standing scan rather than a
one-time review: the classes recur because the mistake is easy to make and the
result looks correct.

Nothing here replaces golangci-lint, which already runs a wide rule set on this
repo. These are the patterns no linter flags because each one is legitimate
almost everywhere it appears.

    scripts/prod-scan.py                  every rule
    scripts/prod-scan.py --rule fold      one rule
    scripts/prod-scan.py --list           the rules and why each exists
"""

import argparse
import collections
import os
import re
import sys

SKIP_DIRS = {"vendor", ".git", "node_modules", "sdk", "web", "site", "tmp"}

# Each rule carries the history that earns it a place. A rule whose story is
# "this could theoretically happen" belongs in a linter, not here.
RULES = [
    {
        "id": "fold",
        "pattern": re.compile(r"strings\.(ToLower|ToUpper|EqualFold)\("),
        "summary": "case folding used where something else will normalise differently",
        "why": (
            "Folding is neither length- nor class-preserving, and the code that acts "
            "on the string may normalise it another way. internal/outbound compared "
            "strings.ToLower(u.Hostname()) while net/http dials the UTS-46 form, "
            "which was an allowlist bypass. internal/jwt folded claim names while "
            "encoding/json matches tags case-insensitively and takes the LAST match, "
            "which let a duplicate claim replace the checked one. For each hit ask "
            "who else reads this string: if the answer is the runtime, the network "
            "stack, a database collation or encoding/json, assume they fold "
            "differently."
        ),
    },
    {
        "id": "float-to-int",
        "pattern": re.compile(r"\b(int|int64|uint64|uint)\(\s*[a-zA-Z_][\w.]*\s*\)"),
        "summary": "a numeric conversion that may be out of range",
        "why": (
            "int64(float64) out of range is implementation-defined in Go and yields "
            "MinInt64 on amd64, which reads as a valid instant in the distant past. "
            "Three call sites had it: oauth2 auth_time, jwt/types.go and "
            "jwt/claims.go. Any JSON number that reaches a time conversion needs an "
            "explicit range refusal before the cast."
        ),
    },
    {
        "id": "host-substring",
        "pattern": re.compile(
            r"strings\.(Contains|HasPrefix|HasSuffix)\([^,]*(?i:host|url|origin|referer|domain)"
        ),
        "summary": "a substring test standing in for an origin check",
        "why": (
            "HasSuffix(host, base) accepts notexample.com for base example.com. The "
            "form that does not is host == base or a HasSuffix against a leading "
            "dot. A hit is fine if the dot is there; the point is to look."
        ),
    },
    {
        "id": "background-context",
        "pattern": re.compile(r"context\.(Background|TODO)\(\)"),
        "summary": "a fresh context where the caller's should have been carried",
        "why": (
            "A new context in a request path drops cancellation and the deadline, so "
            "the work outlives the request that asked for it. This was live in the "
            "Redis TLS dialer. Legitimate at process start and in background "
            "sweepers, which is most of the hits."
        ),
    },
    {
        "id": "secret-compare",
        "pattern": re.compile(
            r"(?i:secret|token|password|passwd|signature|hmac|\bmac\b|digest|nonce)"
            r"[\w.]*\s*==\s*(?!nil\b|\"\"|0\b)[a-zA-Z_\"]"
        ),
        "summary": "a secret compared with == rather than in constant time",
        "why": (
            "== returns as soon as two bytes differ, so the comparison time leaks "
            "the length of the matching prefix, while subtle.ConstantTimeCompare "
            "does not. Comparisons against the empty string and nil are excluded "
            "because an emptiness check leaks nothing."
        ),
    },
    {
        "id": "marker",
        "pattern": re.compile(r"//\s*(TODO|FIXME|XXX|HACK)\b"),
        "summary": "an unresolved marker in shipped code",
        "why": (
            "A marker that survived to a release is either work nobody tracked or a "
            "known defect nobody filed. Either way it belongs somewhere a person "
            "looks, not in a comment."
        ),
    },
]

def repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def scan(root, wanted):
    hits = collections.defaultdict(list)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if not name.endswith(".go") or name.endswith("_test.go"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            with open(path, encoding="utf-8", errors="replace") as handle:
                for number, line in enumerate(handle, 1):
                    stripped = line.strip()
                    for rule in RULES:
                        if rule["id"] not in wanted:
                            continue
                        # A comment is not code, except to the rule about comments.
                        if stripped.startswith("//") and rule["id"] != "marker":
                            continue
                        if rule["pattern"].search(line):
                            hits[rule["id"]].append((rel, number, stripped[:120]))
    return hits


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rule", action="append", metavar="ID", help="only this rule (repeatable)")
    parser.add_argument("--list", action="store_true", help="describe the rules and exit")
    parser.add_argument("--limit", type=int, default=18, help="hits shown per rule (0 for all)")
    args = parser.parse_args()

    if args.list:
        for rule in RULES:
            print(f"\n{rule['id']}: {rule['summary']}\n")
            for line in rule["why"].split(". "):
                if line.strip():
                    print(f"    {line.strip().rstrip('.')}.")
        return 0

    known = {r["id"] for r in RULES}
    wanted = set(args.rule) if args.rule else known
    unknown = wanted - known
    if unknown:
        print(f"unknown rule(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        print(f"known: {', '.join(sorted(known))}", file=sys.stderr)
        return 2

    hits = scan(repo_root(), wanted)
    for rule in RULES:
        if rule["id"] not in wanted:
            continue
        found = hits.get(rule["id"], [])
        print(f"\n### {rule['id']}: {len(found)} -- {rule['summary']}")
        print(f"    {rule['why']}")
        shown = found if args.limit == 0 else found[: args.limit]
        for rel, number, text in shown:
            print(f"    {rel}:{number}  {text}")
        if len(found) > len(shown):
            print(f"    ... and {len(found) - len(shown)} more (--limit 0 for all)")

    print("\nCandidates, not findings. Most hits are legitimate. Prove a divergence")
    print("with a runnable program before calling anything here a defect.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
