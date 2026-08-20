#!/usr/bin/env python3
"""Hold gosec's test-file findings to a frozen set rather than to a count.

`gosec -tests ./...` reports 124 HIGH findings, every one of them in a _test.go
file and every one of them test-shaped: fake DSNs in fixtures, integer
conversions in table-driven cases, InsecureSkipVerify in an end-to-end client
that talks to a container it just started. Production code is scanned separately
and is at zero.

They were held by a per-rule count. That has a hole, and it is the hole that
matters for this particular rule set: G101 is "hardcoded credentials", the
allowance is 76, and swapping one fixture DSN for a real leaked one leaves the
count at 76. The gate cannot tell which 76.

So the baseline freezes the finding, not the tally: the rule, the file, and the
text of the flagged line. A new finding fails even when it replaces one that
went away, and a finding that moves down its file is unaffected, because the
key is the source line rather than its number. This is the same shape as
.coverage-exclusions.json, which freezes the text of every excluded statement
for the same reason.

Every rule in the set also owes a sentence saying why its findings are accepted
in test code, checked here rather than left in a comment.

    scripts/gosec-baseline.py --generate report.json   rewrite the baseline
    scripts/gosec-baseline.py --check report.json      compare, exit 1 on drift
"""

import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(REPO_ROOT, ".gosec-tests-baseline.json")
BLOCKING = ("HIGH", "CRITICAL")

# One sentence per rule, and the reason a finding of that rule is tolerable in a
# test and would not be in production. A rule that appears in the entries and
# not here fails the check: an allowance nobody can explain is a suppression.
RULE_REASONS = {
    "G101": (
        "Hardcoded credentials. Every one is a fixture: a fake DSN, a literal "
        "test password, or a constant that exists so a redaction path has "
        "something to redact. None is a credential for anything that exists."
    ),
    "G115": (
        "Integer overflow on conversion. All in table-driven tests and encoding "
        "helpers where the input is a literal the test wrote itself, so the "
        "range is known at the call site and there is nothing to validate."
    ),
    "G122": (
        "Filesystem operation inside a filepath.WalkDir callback. The trees "
        "walked are the repository's own source and testdata directories, read "
        "by tests that scan the tree; there is no attacker between the walk and "
        "the read."
    ),
    "G402": (
        "InsecureSkipVerify. Two end-to-end tests, each talking to a container "
        "the same test just started, over a certificate that container "
        "generated. Verifying it would test the fixture, not the product."
    ),
    "G702": (
        "Command injection via taint analysis. Test harnesses building an "
        "argv from constants and t.TempDir(); nothing on the path comes from "
        "outside the test binary."
    ),
    "G703": (
        "Path traversal via taint analysis. Migration tests reading the "
        "repository's own migrations directory and writing under t.TempDir()."
    ),
}


def rel(path):
    return os.path.relpath(path, REPO_ROOT).replace(os.sep, "/")


def flagged_line(issue):
    """The source line gosec pointed at, normalized.

    `code` carries the flagged line plus a line either side, each prefixed with
    its number. Keeping only the flagged line means an edit above or below it
    does not invalidate the entry, and dropping the number means the entry
    survives the file growing.
    """
    snippet = issue.get("code", "")
    reported = issue.get("line", "")

    # A range means the finding spans several lines and no single one is the
    # flagged line. Key on the whole normalized snippet: less stable under an
    # edit nearby, and the alternative is keying on whichever line happens to
    # come first, which for two of these is a bare `{`.
    if "-" in reported:
        return " ".join(snippet.split())

    for raw in snippet.split("\n"):
        number, _, text = raw.partition(": ")
        if number.strip() == reported:
            normalized = " ".join(text.split())
            # A line that carries no identity is not a fingerprint. Two G101
            # findings resolved to `{` this way, which would match any brace in
            # the file under that rule.
            if len(normalized) > 3:
                return normalized
            break

    return " ".join(snippet.split())


def key(issue):
    return (issue["rule_id"], rel(issue["file"]), flagged_line(issue))


def load_report(path):
    with open(path) as fh:
        report = json.load(fh)
    issues = report.get("Issues")
    if issues is None:
        sys.exit("gosec report has no Issues key; the scan did not complete")
    return [i for i in issues if i.get("severity") in BLOCKING]


def entries_from(issues):
    """One entry per distinct flagged line, carrying how many findings it holds.

    A single line can hold more than one: `[]byte{mt | 25, byte(n >> 8), byte(n)}`
    is two G115 conversions at one position. Collapsing those to one entry would
    let a third conversion appear on the line without failing anything, so the
    count travels with the entry.
    """
    counts = {}
    for issue in issues:
        counts[key(issue)] = counts.get(key(issue), 0) + 1
    return [{"rule": k[0], "file": k[1], "line_text": k[2], "count": n}
            for k, n in sorted(counts.items())]


def check(path):
    issues = load_report(path)
    if not issues:
        # gosec writing an empty report is the failure this whole gate exists to
        # notice; a genuinely clean tree is a change to celebrate and to record,
        # not to pass silently.
        print("gosec reported no HIGH or CRITICAL findings at all. If that is "
              "real, regenerate the baseline; if it is not, the scan failed.",
              file=sys.stderr)
        return 1

    with open(BASELINE) as fh:
        baseline = json.load(fh)
    frozen = {(e["rule"], e["file"], e["line_text"]): e["count"] for e in baseline["entries"]}
    current = {(e["rule"], e["file"], e["line_text"]): e["count"] for e in entries_from(issues)}

    rc = 0

    # Production code is gated at zero by the scan that runs without -tests. A
    # HIGH finding outside a _test.go file arriving here means that gate did not
    # see it, so it is never frozen and never tolerated regardless of the
    # baseline.
    leaked = [i for i in issues if not rel(i["file"]).endswith("_test.go")]
    for issue in leaked:
        print(f"::error file={rel(issue['file'])},line={issue['line']}::"
              f"{issue['rule_id']} {issue['details']} in non-test code", file=sys.stderr)
    if leaked:
        print(f"{len(leaked)} HIGH/CRITICAL finding(s) in non-test code. The baseline "
              f"covers test files only.", file=sys.stderr)
        rc = 1

    missing_reason = sorted({rule for rule, _, _ in frozen} - set(RULE_REASONS))
    if missing_reason:
        print(f"::error::gosec rules with frozen findings and no stated reason: "
              f"{', '.join(missing_reason)}", file=sys.stderr)
        rc = 1

    new = sorted(k for k in current if k not in frozen)
    for rule, file, text in new:
        print(f"::error::gosec {rule} finding not in the baseline: {file}: {text}",
              file=sys.stderr)

    grew = sorted(k for k in current if k in frozen and current[k] > frozen[k])
    for k in grew:
        rule, file, text = k
        print(f"::error::gosec {rule} at {file} now fires {current[k]} times, was "
              f"{frozen[k]}: {text}", file=sys.stderr)
    if grew:
        rc = 1
    if new:
        print(f"{len(new)} gosec finding(s) are not in .gosec-tests-baseline.json. A "
              f"count-based allowance would have accepted these as long as the total held; "
              f"the baseline freezes the flagged line so a replacement is still a new "
              f"finding. If they are correct and belong in test code, regenerate with "
              f"scripts/gosec-baseline.py --generate.", file=sys.stderr)
        rc = 1

    gone = sorted(k for k in frozen if k not in current)
    for rule, file, text in gone:
        print(f"gosec {rule} no longer fires at {file}: {text} -- regenerate to drop it")

    print(f"gosec: {sum(current.values())} HIGH/CRITICAL findings over "
          f"{len(current)} lines, {sum(frozen.values())} frozen over {len(frozen)}, "
          f"{len(new)} new, {len(gone)} gone")
    return rc


def generate(path):
    issues = load_report(path)
    entries = entries_from(issues)
    rules = sorted({e["rule"] for e in entries})
    unknown = [r for r in rules if r not in RULE_REASONS]
    if unknown:
        sys.exit(f"no stated reason for rule(s) {', '.join(unknown)}; add one to "
                 f"RULE_REASONS in {rel(__file__)} before freezing findings under it")

    doc = {
        "_comment": [
            "HIGH and CRITICAL gosec findings in _test.go files, frozen by rule, file",
            "and the text of the flagged line. Production code is scanned separately",
            "and must stay at zero; it is at zero.",
            "",
            "This is not a suppression list. A finding that is not here fails CI, and",
            "that includes a finding of an already-listed rule in an already-listed",
            "file: the previous version of this file held per-rule counts, so a real",
            "credential replacing a fixture one kept the G101 total at 76 and passed.",
            "",
            "Keyed on the source line rather than the line number, so the entry",
            "survives the file growing above it. Regenerate with",
            "scripts/gosec-baseline.py --generate <report.json>.",
        ],
        "rules": {r: RULE_REASONS[r] for r in rules},
        "entries": entries,
        "lines": len(entries),
        "total": sum(e["count"] for e in entries),
    }
    with open(BASELINE, "w") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    print(f"wrote {rel(BASELINE)}: {len(entries)} entries across {len(rules)} rules")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="gosec JSON report")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--generate", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    return generate(args.report) if args.generate else check(args.report)


if __name__ == "__main__":
    sys.exit(main())
