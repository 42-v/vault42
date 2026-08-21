#!/usr/bin/env python3
"""Anchor the compliance register's code citations after code moves.

The register cites code two ways and they no longer work the same.

`evidence` entries are anchors: `path#<something on the cited line>`, resolved
and uniqueness-checked by TestComplianceRegister_EvidenceAnchorsResolveToExactly
OneLine. An anchor cannot drift, because it names its line rather than counting
to it. This script is what converts a `path:line` entry into one: write the line
number if that is what you have, run --apply, and the citation becomes an anchor
for the statement that was on it.

Prose citations -- the sentences in `notes`, in the accepted-risk bodies and in
the retired-risk paragraphs -- still carry `path:line`, because an anchor reads
as a quotation of the code mid-sentence and the notes are also the text the
relevance gate matches identifiers against. For those this does the original
job: read what the cited line said at a git ref, find where that text went, and
re-anchor when the match is unique.

That lookup used to be wrong on its second run. It compared the ref's text at
the number currently in the register, so once a citation had been re-anchored to
the working tree the ref's text at the NEW number was some unrelated line, and
the tool reported nonsense with a straight face. A prose field is now remapped
only when it is byte-identical to the same field at the ref: an edited field may
already carry the author's own fix, and guessing on top of that is what produced
the drift in the first place.

    scripts/register-reanchor.py --check          report, change nothing
    scripts/register-reanchor.py --apply          rewrite the register
    scripts/register-reanchor.py --apply --ref X  compare prose against ref X
"""

import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTER = os.path.join(REPO_ROOT, "docs", "compliance-register.json")
REGISTER_REL = "docs/compliance-register.json"

# The shape the register's prose gates match, minus .github/workflows, which
# uses anchors.
CITATION = re.compile(
    r"\b((?:internal|cmd|tests|scripts|migrations|charts|web|packages|docs)"
    r"/[A-Za-z0-9_./-]+\.(?:go|py|sh|yaml|yml|sql|ts|vue|json|md)):(\d+)"
)

# An evidence entry that still counts lines. Anything carrying a '#' is already
# an anchor, and a bare path cites the whole file.
NUMBERED_EVIDENCE = re.compile(r"^([^#]+):(\d+)$")

# Prose fields that carry citations. Kept explicit rather than walking every
# string, so a new field is a deliberate addition here and not a silent one.
RISK_FIELDS = ("rationale", "compensating_control", "residual_risk",
               "cost_of_closing", "revisit_when")

WORKFLOW_PREFIX = ".github/workflows/"

# An anchor is the cited line's own text, so most are short. A few statements
# are not, and a hundred-column anchor in a JSON document is unreadable, so a
# long one is cut back to the shortest unique prefix that still carries enough
# of the statement to be recognizable.
MAX_ANCHOR = 96
MIN_PREFIX = 20

# Resolved once so the ruff rule about partial executable paths has an answer
# rather than a suppression, and so a PATH change mid-run cannot swap the binary.
GIT = shutil.which("git") or "/usr/bin/git"


def git_show(ref, path):
    """The file's contents at a ref, or None when it did not exist there.

    ref and path both come from this repository's own register and its own
    argv, never from a request, which is why the subprocess call is safe -- but
    they are still passed as a list rather than through a shell, so a path
    containing a shell metacharacter is an argument and not a command.
    """
    proc = subprocess.run(  # noqa: S603 -- argv list, no shell, inputs are repo-local
        [GIT, "show", f"{ref}:{path}"],
        capture_output=True, text=True, cwd=REPO_ROOT, check=False)
    return proc.stdout if proc.returncode == 0 else None


def git_lines(ref, path):
    raw = git_show(ref, path)
    return raw.split("\n") if raw is not None else None


def working_lines(path, cache):
    if path not in cache:
        full = os.path.join(REPO_ROOT, path)
        if os.path.exists(full):
            with open(full, encoding="utf-8") as fh:
                cache[path] = fh.read().split("\n")
        else:
            cache[path] = None
    return cache[path]


# --- the Go declaration index, mirrored from register_anchors_test.go ---------

FUNC_DECL = re.compile(
    r"^func\s+(?:\(\s*\w+\s+\*?(?P<recv>\w+)[^)]*\)\s*)?(?P<name>\w+)")
SIMPLE_DECL = re.compile(r"^(?:type|var|const)\s+(?P<name>\w+)")


def go_decl_spans(lines):
    """Map a Go file's top-level declarations to their 1-based line spans.

    Grouped `var (` / `const (` blocks are deliberately not indexed. The gate
    indexes those per spec, through go/ast, and reproducing that here by regex
    would let this script emit an `in:` anchor the gate resolves differently --
    which is a worse failure than declining to scope one citation.
    """
    spans = collections.defaultdict(list)
    for i, line in enumerate(lines):
        m = FUNC_DECL.match(line)
        if m:
            name = m.group("name")
            if m.group("recv"):
                name = f"({m.group('recv')}).{name}"
        else:
            m = SIMPLE_DECL.match(line)
            if not m or line.rstrip().endswith("("):
                continue
            name = m.group("name")

        start = i
        while start > 0 and lines[start - 1].startswith("//"):
            start -= 1

        end = i
        if line.rstrip().endswith("{"):
            for j in range(i + 1, len(lines)):
                if lines[j] == "}":
                    end = j
                    break
        spans[name].append((start + 1, end + 1))
    return spans


# --- anchor selection --------------------------------------------------------


def _contains_count(needle, lines):
    return sum(1 for line in lines if needle in line)


def _prefix_count(needle, lines):
    return sum(1 for line in lines if line.startswith(needle))


def _shorten(text, lines, count):
    """The shortest boundary prefix of text that still matches one line.

    '@' is a boundary as well as a space so that a pinned image or action cuts
    in front of its digest: `FROM gcr.io/distroless/static-debian12:nonroot` is
    the evidence, and the sha256 after it is a value Dependabot rewrites.
    """
    if len(text) <= MAX_ANCHOR:
        return text
    for cut, ch in enumerate(text):
        if ch in " @" and cut >= MIN_PREFIX and count(text[:cut], lines) == 1:
            return text[:cut]
    return text


def anchor_for(path, line, lines):
    """Return (anchor, reason). Exactly one of the two is None."""
    if line < 1 or line > len(lines):
        return None, f"the file has {len(lines)} lines"
    raw = lines[line - 1]
    text = raw.strip()
    if not text:
        return None, "the cited line is blank"
    if text.startswith(("^", "in:")):
        return None, "the cited line starts with an anchor keyword"

    if _contains_count(text, lines) == 1:
        return _shorten(text, lines, _contains_count), None
    if _prefix_count(raw, lines) == 1:
        return "^" + _shorten(raw, lines, _prefix_count), None

    if path.endswith(".go"):
        for name, spans in go_decl_spans(lines).items():
            if len(spans) != 1:
                continue
            start, end = spans[0]
            if not start <= line <= end:
                continue
            scoped = lines[start - 1:end]
            if _contains_count(text, scoped) == 1:
                return f"in:{name}:{_shorten(text, scoped, _contains_count)}", None

    return None, (f"{_contains_count(text, lines)} lines carry this text and no single "
                  f"declaration holds one of them")


# --- the two jobs ------------------------------------------------------------


class Anchorer:
    """Converts `path:line` evidence entries into anchors."""

    def __init__(self):
        self.work = {}
        self.converted = []
        self.manual = []

    def convert(self, entry):
        if entry.startswith(WORKFLOW_PREFIX):
            return entry
        m = NUMBERED_EVIDENCE.match(entry)
        if not m:
            return entry
        path, line = m.group(1), int(m.group(2))

        lines = working_lines(path, self.work)
        if lines is None:
            self.manual.append((entry, "the file does not exist"))
            return entry

        # Line 1 is `package x`, an H1 or an apiVersion. None of those is
        # evidence of anything in particular, and the register already has a
        # form for "this whole file": the bare path.
        if line == 1:
            self.converted.append((entry, path))
            return path

        anchor, reason = anchor_for(path, line, lines)
        if anchor is None:
            self.manual.append((entry, reason))
            return entry
        self.converted.append((entry, f"{path}#{anchor}"))
        return f"{path}#{anchor}"


class ProseReanchorer:
    """Re-anchors `path:line` citations inside the register's prose."""

    def __init__(self, ref):
        self.ref = ref
        self.work = {}
        self.old = {}
        self.moved = []
        self.ambiguous = []
        self.gone = []
        self.edited = []

    def remap(self, path, line):
        """Return the new line number for a citation, or None to leave it."""
        cur = working_lines(path, self.work)
        if cur is None:
            self.gone.append((path, line, "the file does not exist"))
            return None

        if path not in self.old:
            self.old[path] = git_lines(self.ref, path)
        was = self.old[path]
        if was is None or line > len(was):
            return None

        text = was[line - 1]
        if line <= len(cur) and cur[line - 1] == text:
            return None  # still correct

        # An empty or near-empty line carries no identity and cannot be searched
        # for. Report it rather than matching the first blank line in the file.
        if len(text.strip()) < 4:
            self.ambiguous.append((path, line, text.strip(),
                                   "the line's text is too short to search for"))
            return None

        hits = [i + 1 for i, line_text in enumerate(cur) if line_text == text]

        # gofmt re-aligns a struct literal's values when a longer field name
        # joins it, so a citation into one can be invalidated by a change that
        # did not touch its line at all: "CacheBackend: x" became
        # "CacheBackend:       x" and matched nothing. Fall back to comparing
        # with runs of whitespace collapsed, which survives realignment and
        # still will not match a different statement.
        if not hits:
            want = " ".join(text.split())
            hits = [i + 1 for i, line_text in enumerate(cur)
                    if " ".join(line_text.split()) == want]

        if len(hits) == 1:
            self.moved.append((path, line, hits[0], text.strip()[:70]))
            return hits[0]
        self.ambiguous.append((path, line, text.strip()[:70],
                               f"{len(hits)} matches in the working tree"))
        return None

    def rewrite(self, where, body, baseline):
        """Rewrite every citation in one prose field.

        A field that has changed since the ref is left alone: its baseline is
        gone, so the line numbers in it may already be the author's own fix and
        remapping them against the ref would move a correct citation onto
        whatever text used to live at that number.
        """
        if baseline is None or baseline != body:
            if CITATION.search(body):
                self.edited.append(where)
            return body

        def sub(m):
            new = self.remap(m.group(1), int(m.group(2)))
            return f"{m.group(1)}:{new}" if new else m.group(0)

        return CITATION.sub(sub, body)


def prose_fields(reg):
    """Every citation-bearing prose field, keyed so two registers can be paired."""
    fields = {}
    for row in reg.get("requirements", []):
        key = ("requirement", row.get("standard", ""), row.get("requirement_id", ""), "notes")
        fields[key] = row.get("notes") or ""
    for risk_id, risk in reg.get("accepted_risks", {}).items():
        for field in RISK_FIELDS:
            fields[("accepted_risk", risk_id, field)] = risk.get(field) or ""
    for risk_id, prose in reg.get("retired_risks", {}).items():
        fields[("retired_risk", risk_id)] = prose or ""
    return fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--ref", default="HEAD",
                        help="git ref the prose citations were written against (default HEAD)")
    args = parser.parse_args()

    with open(REGISTER, encoding="utf-8") as fh:
        reg = json.load(fh, object_pairs_hook=collections.OrderedDict)

    ref_raw = git_show(args.ref, REGISTER_REL)
    baseline = prose_fields(json.loads(ref_raw)) if ref_raw else {}

    anchorer = Anchorer()
    prose = ProseReanchorer(args.ref)

    for row in reg["requirements"]:
        row["evidence"] = [anchorer.convert(e) for e in (row.get("evidence") or [])]
        key = ("requirement", row.get("standard", ""), row.get("requirement_id", ""), "notes")
        if row.get("notes"):
            row["notes"] = prose.rewrite(f"{key[1]} {key[2]} notes", row["notes"],
                                         baseline.get(key))
    for risk_id, risk in reg["accepted_risks"].items():
        for field in RISK_FIELDS:
            if risk.get(field):
                risk[field] = prose.rewrite(f"{risk_id} {field}", risk[field],
                                            baseline.get(("accepted_risk", risk_id, field)))
    for risk_id, body in list(reg["retired_risks"].items()):
        reg["retired_risks"][risk_id] = prose.rewrite(
            f"{risk_id} (retired)", body, baseline.get(("retired_risk", risk_id)))

    for was, now in anchorer.converted:
        print(f"anchor  {was} -> {now}")
    for path, was, now, text in prose.moved:
        print(f"moved   {path}:{was} -> :{now}  {text}")
    for entry, why in anchorer.manual:
        print(f"MANUAL  {entry}  {why}", file=sys.stderr)
    for path, line, text, why in prose.ambiguous:
        print(f"MANUAL  {path}:{line}  {why}  was {text!r}", file=sys.stderr)
    for path, line, why in prose.gone:
        print(f"MANUAL  {path}:{line}  {why}", file=sys.stderr)
    for where in prose.edited:
        print(f"skipped {where}: edited since {args.ref}, so it has no baseline to remap from",
              file=sys.stderr)

    changed = len(anchorer.converted) + len(prose.moved)
    if args.apply and changed:
        with open(REGISTER, "w", encoding="utf-8") as fh:
            json.dump(reg, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"\nrewrote {len(anchorer.converted)} evidence anchor(s) and "
              f"{len(prose.moved)} prose citation(s) in {REGISTER_REL}")
    elif args.check:
        print(f"\n{len(anchorer.converted)} evidence entr(ies) would be anchored, "
              f"{len(prose.moved)} prose citation(s) would move, "
              f"{len(anchorer.manual) + len(prose.ambiguous) + len(prose.gone)} need a person")

    # A citation needing a person is not a failure of this tool; it is the case
    # it deliberately refuses to guess at. The register's own gates decide
    # whether the result is acceptable, and they run in CI.
    return 0


if __name__ == "__main__":
    sys.exit(main())
