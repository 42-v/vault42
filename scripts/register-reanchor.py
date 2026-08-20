#!/usr/bin/env python3
"""Re-anchor the compliance register's file:line citations after code moves.

The register cites code two ways: an `evidence` list and sentences in prose.
Both carry `path:line`, and a line number is invalidated by any edit above it.
Three gates catch the citations that land somewhere dead -- a blank line, a
closing brace, an anchor that no longer resolves -- and none of them catches the
common case, where the citation lands on a real line that is simply not the one
anybody meant.

Fixing that by hand needs the reader to know what the line USED to say, which
git already knows. This does that lookup: for every citation, read the line at
the given ref, and if the working tree no longer has that text at that number,
find where the text went. A unique match is re-anchored; anything else is
reported, because guessing is what produced the drift.

Workflow citations are excluded: those are anchors now (path#anchor) and cannot
drift by construction.

    scripts/register-reanchor.py --check          report, change nothing
    scripts/register-reanchor.py --apply          rewrite the register
    scripts/register-reanchor.py --apply --ref X  compare against ref X
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

# The same shape the register's own gates match, minus .github/workflows, which
# uses anchors.
CITATION = re.compile(
    r"\b((?:internal|cmd|tests|scripts|migrations|charts|web|packages|docs)"
    r"/[A-Za-z0-9_./-]+\.(?:go|py|sh|yaml|yml|sql|ts|vue|json|md)):(\d+)"
)

# Prose fields that carry citations. Kept explicit rather than walking every
# string, so a new field is a deliberate addition here and not a silent one.
RISK_FIELDS = ("rationale", "compensating_control", "residual_risk",
               "cost_of_closing", "revisit_when")


# Resolved once so the ruff rule about partial executable paths has an answer
# rather than a suppression, and so a PATH change mid-run cannot swap the binary.
GIT = shutil.which("git") or "/usr/bin/git"


def git_lines(ref, path):
    """The file's lines at a ref, or None when it did not exist there.

    ref and path both come from this repository's own register and its own
    argv, never from a request, which is why the subprocess call is safe -- but
    they are still passed as a list rather than through a shell, so a path
    containing a shell metacharacter is an argument and not a command.
    """
    proc = subprocess.run(  # noqa: S603 -- argv list, no shell, inputs are repo-local
        [GIT, "show", f"{ref}:{path}"],
        capture_output=True, text=True, cwd=REPO_ROOT, check=False)
    return proc.stdout.split("\n") if proc.returncode == 0 else None


def working_lines(path, cache):
    if path not in cache:
        full = os.path.join(REPO_ROOT, path)
        if os.path.exists(full):
            with open(full) as fh:
                cache[path] = fh.read().split("\n")
        else:
            cache[path] = None
    return cache[path]


class Reanchorer:
    def __init__(self, ref):
        self.ref = ref
        self.work = {}
        self.old = {}
        self.moved = []
        self.ambiguous = []
        self.gone = []

    def remap(self, path, line):
        """Return the new line number for a citation, or None to leave it."""
        cur = working_lines(path, self.work)
        if cur is None:
            self.gone.append((path, line, "file does not exist"))
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
                                   "line text is too short to search for"))
            return None

        hits = [i + 1 for i, line_text in enumerate(cur) if line_text == text]
        if len(hits) == 1:
            self.moved.append((path, line, hits[0], text.strip()[:70]))
            return hits[0]
        self.ambiguous.append((path, line, text.strip()[:70],
                               f"{len(hits)} matches in the working tree"))
        return None

    def rewrite(self, blob):
        """Rewrite every citation in one string."""
        def sub(m):
            new = self.remap(m.group(1), int(m.group(2)))
            return f"{m.group(1)}:{new}" if new else m.group(0)
        return CITATION.sub(sub, blob)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--ref", default="HEAD",
                        help="git ref the citations were written against (default HEAD)")
    args = parser.parse_args()

    with open(REGISTER) as fh:
        reg = json.load(fh, object_pairs_hook=collections.OrderedDict)

    r = Reanchorer(args.ref)

    for row in reg["requirements"]:
        row["evidence"] = [r.rewrite(e) for e in (row.get("evidence") or [])]
        if row.get("notes"):
            row["notes"] = r.rewrite(row["notes"])
    for risk in reg["accepted_risks"].values():
        for field in RISK_FIELDS:
            if risk.get(field):
                risk[field] = r.rewrite(risk[field])
    for key, prose in list(reg["retired_risks"].items()):
        reg["retired_risks"][key] = r.rewrite(prose)

    for path, was, now, text in r.moved:
        print(f"moved   {path}:{was} -> :{now}  {text}")
    for path, line, text, why in r.ambiguous:
        print(f"MANUAL  {path}:{line}  {why}  was {text!r}", file=sys.stderr)
    for path, line, why in r.gone:
        print(f"MANUAL  {path}:{line}  {why}", file=sys.stderr)

    if args.apply and r.moved:
        with open(REGISTER, "w") as fh:
            json.dump(reg, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"\nrewrote {len(r.moved)} citation(s) in docs/compliance-register.json")
    elif args.check:
        print(f"\n{len(r.moved)} citation(s) would move, "
              f"{len(r.ambiguous) + len(r.gone)} need a person")

    # A citation needing a person is not a failure of this tool; it is the case
    # it deliberately refuses to guess at. The register's own gates decide
    # whether the result is acceptable, and they run in CI.
    return 0


if __name__ == "__main__":
    sys.exit(main())
