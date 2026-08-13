#!/usr/bin/env python3
"""Report exactly which statements a coverage profile leaves uncovered.

`go tool cover -func` rounds to one decimal and reports per-function totals, which
is the wrong shape for closing a coverage gap: it cannot tell you that a function
at 92% is missing one three-statement error branch at line 148, and it cannot be
diffed between two runs to prove a wave landed the blocks it was assigned.

This reads the raw profile instead. Under `-coverpkg` the same block appears once
per test binary, so blocks are OR-folded by key before anything is counted -- the
same fold `cov_total` in scripts/lib/coverage-env.sh applies, so the totals here
always agree with docs/test-coverage.md.

Usage:
    scripts/cov-gaps.py PROFILE                 # summary + per-file gap table
    scripts/cov-gaps.py PROFILE --file PATH     # every uncovered block in one file
    scripts/cov-gaps.py PROFILE --target 99.69  # covered-count needed to land a figure
    scripts/cov-gaps.py PROFILE --diff OTHER    # blocks OTHER covers that PROFILE does not
    scripts/cov-gaps.py PROFILE --json          # machine-readable, for tooling
    scripts/cov-gaps.py PROFILE --exclude FILE  # coverage of REACHABLE statements
    scripts/cov-gaps.py PROFILE --verify-exclusions     # the release gate

The exclusion set (.coverage-exclusions.json) is how 1.0.0 can claim "100.00% of
reachable statements" without the claim being unfalsifiable. Each entry names one
statement, freezes its source line verbatim, and carries the argument for why it
is not reachable. --verify-exclusions is what stops the set rotting or growing:
it fails when an excluded line has moved, changed text, or become covered, when
an entry is still unconfirmed, when the set has grown past its ratchet, when the
profile it is measured against is not the canonical one, and when covered +
excluded does not equal total.

The profile is not optional. Every one of those checks except the frozen-text
comparison needs a measurement, so a run without one would confirm that N strings
still sit at N line numbers and nothing else, then exit 0 wearing the name of a
release gate.
"""

import argparse
import json
import os
import sys
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_EXCLUSIONS = os.path.join(REPO_ROOT, ".coverage-exclusions.json")
BUCKETS = ("B", "C")
ENTRY_FIELDS = ("package", "file", "line", "occurrence", "source", "bucket",
                "justification", "confirmed")

# ---------------------------------------------------------------------------
# Ratchets. Measured from the canonical scripts/coverage.sh run, not chosen.
#
# The exclusion set constrains the denominator, so every check that reads it is
# only as good as the profile it is handed. load() accepts any file that starts
# with a mode: header, the identity check divides the profile's own numbers by
# each other, and release-check.sh --coverage-only takes a path from the caller.
# Nothing in that chain notices a profile from a narrower run: a `go test
# -coverprofile` over a handful of packages satisfies covered + excluded == total
# trivially and reports "100.00% of reachable" over a quarter of the tree.
#
# These three constants are what make the gate falsifiable. They live here rather
# than in .coverage-exclusions.json so that growing the set is a two-file diff,
# and the second file is the one a reviewer already opens.
#
# BASELINE_TOTAL_STATEMENTS is a floor, in the same spirit as GOLANGCI_MAX_ISSUES
# in scripts/release-check.sh: a profile smaller than the canonical run is either
# a subset run or a tree that lost code, and both need a human. When code is
# genuinely deleted, re-measure and lower it in the same review as the deletion.
# BASELINE_PACKAGES catches the shape the floor cannot: a package dropped from
# the run while enough statements remain to clear the count.
BASELINE_TOTAL_STATEMENTS = 10345

# BASELINE_MAX_ENTRIES is a ratchet: the exclusion set may only shrink, so a new
# entry has to be paid for by covering a statement somewhere else or by an
# argument made here.
#
# Raised from 38 to 46 for 1.0.0. The arithmetic, so the next reader can check it
# rather than take it on trust:
#
#   38  the frozen baseline, entirely non-cmd, because cmd/ sat outside the
#       coverage measurement when it was set: 2615 non-test lines, including
#       cmd/recover, the offline erasure-recovery tool, which had no tests at all
#   +6  cmd/ entries, now that cmd/ is measured. None could have been counted in
#       38, because nothing was counting that tree
#   +2  the companion statements of two webauthn blocks that were ALREADY
#       excluded. Each holds a WriteError and a return, only the WriteError was
#       named, and the verifier rejects a block naming some of its statements.
#       These are not new exclusions; they are the rest of two old ones
#   =46
#
# Four entries were deleted in the same pass, as their statements became covered:
# two webauthn session-marshal arms reached by the new MFA audit tests, and two
# kms arms reached by the keystore work. So the non-cmd set reads 38 -> 40 while
# four genuine exclusions left it.
#
# The next person to raise this owes the same arithmetic: what entered the
# measurement, what is a new exclusion rather than a fuller statement of an old
# one, and what left the set entirely.
BASELINE_MAX_ENTRIES = 46
BASELINE_PACKAGES = (
    "internal/adminapi",
    "internal/audit",
    "internal/cache",
    "internal/cli",
    "internal/config",
    "internal/crypto",
    "internal/email",
    "internal/frontend",
    "internal/handler",
    "internal/honeypot",
    "internal/httputil",
    "internal/jwt",
    "internal/keystore",
    "internal/kms",
    "internal/metrics",
    "internal/middleware",
    "internal/migrate",
    "internal/model",
    "internal/oauth2",
    "internal/rbac",
    "internal/redis",
    "internal/repository/postgres",
    "internal/sanitize",
    "internal/seed",
    "internal/server",
    "internal/service",
    "internal/useragent",
)


def load(path):
    """Fold a coverage profile into {block_key: (statements, covered)}.

    A block key is "file.go:startLine.startCol,endLine.endCol". The same key
    appearing in several test binaries is one block: covered by any is covered.
    """
    blocks = {}
    with open(path) as fh:
        header = fh.readline()
        if not header.startswith("mode:"):
            sys.exit(f"{path}: not a coverage profile (no mode: header)")
        for line in fh:
            parts = line.split()
            if len(parts) < 3:
                continue
            key, stmts, count = parts[0], int(parts[1]), int(parts[2])
            prev = blocks.get(key)
            blocks[key] = (stmts, (prev[1] if prev else False) or count > 0)
    if not blocks:
        sys.exit(f"{path}: profile is empty")
    return blocks


def split_key(key):
    """"pkg/path/file.go:12.34,56.78" -> ("pkg/path/file.go", 12, 56)."""
    path, _, span = key.rpartition(":")
    start, _, end = span.partition(",")
    return path, int(start.split(".")[0]), int(end.split(".")[0])


def totals(blocks):
    total = sum(s for s, _ in blocks.values())
    covered = sum(s for s, c in blocks.values() if c)
    return total, covered


def pct(covered, total):
    return 100.0 * covered / total if total else 0.0


def reachable_targets(total, want):
    """The covered-counts that bracket `want`, and whether `want` is reachable.

    One statement moves the total by 100/total points, so most two-decimal figures
    are not reachable at a given statement count. Promising an unreachable number
    is how a release ends up quietly shipping a different one.
    """
    need = None
    for covered in range(total + 1):
        if round(pct(covered, total), 2) == round(want, 2):
            need = covered
            break
    lo = int(total * want / 100.0)
    return need, lo


def plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def repo_path(path):
    """Repo-relative name for a path inside the tree, absolute for one outside."""
    rel = os.path.relpath(os.path.abspath(path), REPO_ROOT)
    return os.path.abspath(path) if rel.startswith("..") else rel


def load_exclusions(path):
    """Parse and schema-check the exclusion document.

    Problems are returned rather than raised so the verifier can print all of
    them at once. A gate that reports one error per run turns a five-minute fix
    into five CI round-trips.
    """
    problems = []
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        return None, [f"{path}: no exclusion file"]
    except json.JSONDecodeError as exc:
        return None, [f"{path}: not valid JSON: {exc}"]

    if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
        return None, [f"{path}: expected an object with an 'entries' list"]

    seen = {}
    for i, e in enumerate(doc["entries"]):
        where = f"entry #{i + 1}"
        if not isinstance(e, dict):
            problems.append(f"{where}: not an object")
            continue
        missing = [f for f in ENTRY_FIELDS if f not in e]
        if missing:
            problems.append(f"{where}: missing {', '.join(missing)}")
            continue
        where = f"{e['file']}:{e['line']}"
        if e["bucket"] not in BUCKETS:
            problems.append(f"{where}: bucket {e['bucket']!r} is not one of {BUCKETS}")
        if not isinstance(e["line"], int) or e["line"] < 1:
            problems.append(f"{where}: line must be a positive integer")
        if not isinstance(e["occurrence"], int) or e["occurrence"] < 1:
            problems.append(f"{where}: occurrence must be a positive integer")
        if not isinstance(e["confirmed"], bool):
            problems.append(f"{where}: confirmed must be true or false")
        if len(str(e["justification"]).split()) < 6:
            problems.append(f"{where}: justification is too thin for a reviewer to check")
        if os.path.isabs(e["file"]) or ".." in e["file"].split("/"):
            problems.append(f"{where}: file must be a repo-relative path")
        if e["package"] != os.path.dirname(e["file"]):
            problems.append(f"{where}: package {e['package']!r} is not the file's directory")
        # Two keys, because an entry is addressed two ways and either collision
        # means two entries claim one statement: by line, and by the frozen text
        # plus which occurrence of it this is.
        keys = ((e["file"], e["line"]), (e["file"], e["source"], e["occurrence"]))
        dup = next((seen[k] for k in keys if k in seen), None)
        if dup is not None:
            problems.append(f"{where}: duplicate of entry #{dup + 1}")
        for k in keys:
            seen[k] = i
    return doc, problems


def check_sources(entries):
    """Confirm every entry still names the exact statement it froze.

    An entry identifies a statement by its frozen text and by which of the
    identical lines carrying that text it is; the line number is advisory, which
    is what .coverage-exclusions.json promises and what --relocate rewrites. So
    the match is "the occurrence-th line holding this text is the line named",
    not "this text appears at this line".

    The difference is the whole check. Eight entries freeze text that appears
    more than once in its file, and internal/handler/webauthn.go:77 and :190
    freeze a bare `return` that appears 37 times there. Comparing text at the
    named line alone accepts any of those 37 landing on line 77 after a refactor
    removed the block the entry was written for, and reports 40/40 matching.

    Requiring the occurrence to line up costs something in return: churn among
    the identical lines above an entry fails the gate even when the entry itself
    is untouched. That is the intended price of freezing text as unspecific as a
    bare return, and the fix is a re-review, which is what an exclusion is for.

    Returns (problems, moved), where `moved` maps an entry's index to the line
    its statement now sits on. Finding the statement elsewhere is a different
    failure from not finding it at all: the first is a refactor that moved it,
    the second is a statement that no longer exists.
    """
    problems, moved, cache = [], {}, {}
    for i, e in enumerate(entries):
        if e["file"] not in cache:
            try:
                with open(os.path.join(REPO_ROOT, e["file"])) as fh:
                    cache[e["file"]] = fh.read().split("\n")
            except OSError as exc:
                cache[e["file"]] = None
                problems.append(f"{e['file']}: cannot read ({exc.strerror})")
        src = cache[e["file"]]
        if src is None:
            continue
        hits = [n for n, line in enumerate(src, 1) if line == e["source"]]
        if len(hits) < e["occurrence"]:
            problems.append(f"{e['file']}:{e['line']}: the excluded statement is gone "
                            f"({len(hits)} lines match its frozen text, wanted #{e['occurrence']}). "
                            f"Delete the entry, or re-justify it against the new code.")
            continue
        at = hits[e["occurrence"] - 1]
        if at == e["line"]:
            continue
        moved[i] = at
        problems.append(f"{e['file']}:{e['line']}: occurrence #{e['occurrence']} of the frozen "
                        f"text is on line {at}, not {e['line']}. The statement moved, or a line "
                        f"identical to it appeared above; either way the entry no longer names "
                        f"what it was reviewed against. Re-review it and rerun with --relocate.")
    return problems, moved


def index_profile(blocks, module):
    """{repo-relative file: [(start, end, statements, covered, key)]}."""
    prefix = module.rstrip("/") + "/" if module else ""
    by_file = defaultdict(list)
    for key, (stmts, covered) in blocks.items():
        path, start, end = split_key(key)
        if prefix and path.startswith(prefix):
            path = path[len(prefix):]
        by_file[path].append((start, end, stmts, covered, key))
    return by_file


def resolve_exclusions(blocks, doc):
    """Map every entry onto the profile block that contains it.

    A block is excluded only when the file names *every* statement in it. A
    two-statement block with one entry means the set is half-written, and
    catching that here says so, instead of surfacing later as an off-by-one in
    the covered + excluded == total assertion.
    """
    by_file = index_profile(blocks, doc.get("module", ""))
    problems = []
    per_block = defaultdict(list)
    for e in doc["entries"]:
        hits = [b for b in by_file.get(e["file"], []) if b[0] <= e["line"] <= b[1]]
        if not hits:
            problems.append(f"{e['file']}:{e['line']}: no instrumented statement here in the profile; "
                            f"the source moved, or its package was not measured")
            continue
        if any(b[3] for b in hits):
            problems.append(f"{e['file']}:{e['line']}: now COVERED, delete the exclusion")
            continue
        per_block[min(hits, key=lambda b: b[1] - b[0])[4]].append(e)

    excluded = {}
    for key, es in per_block.items():
        stmts = blocks[key][0]
        if len(es) != stmts:
            path, start, end = split_key(key)
            problems.append(f"{path}:{start}-{end}: block holds {stmts} statements but the "
                            f"exclusion file names {len(es)} of them")
            continue
        excluded[key] = stmts
    return excluded, problems


def check_canonical(blocks, total, module):
    """Confirm the profile is the canonical run, not a slice of it.

    Everything the gate asserts is relative to the profile it is given, so a
    profile that measures less of the tree makes every assertion easier. This is
    the only check that compares the measurement against something outside it.

    The statement floor names the figure it measured in both directions, so
    moving the ratchet is a one-line edit against a measured number rather than
    an argued one.
    """
    problems, notes = [], []
    if total < BASELINE_TOTAL_STATEMENTS:
        problems.append(f"profile holds {total} statements, the canonical run holds "
                        f"{BASELINE_TOTAL_STATEMENTS}. Almost always this is a subset run: "
                        f"`go test -coverprofile` over some packages rather than "
                        f"scripts/coverage.sh, whose -coverpkg=./internal/... instruments all "
                        f"of internal/ whichever suites run. Measure the canonical profile, or "
                        f"if code was deleted, lower BASELINE_TOTAL_STATEMENTS to {total} in "
                        f"the same review as the deletion.")
    elif total > BASELINE_TOTAL_STATEMENTS:
        notes.append(f"profile holds {total} statements, {total - BASELINE_TOTAL_STATEMENTS} "
                     f"over the floor; raise BASELINE_TOTAL_STATEMENTS to {total}")

    measured = {os.path.dirname(f) for f in index_profile(blocks, module)}
    missing = [p for p in BASELINE_PACKAGES if p not in measured]
    if missing:
        problems.append(f"{plural(len(missing), 'canonical package')} contribute no statement "
                        f"to this profile, so nothing in them was measured: "
                        + ", ".join(missing))
    return problems, notes


def verify_exclusions(args):
    """The release gate. Returns a process exit code."""
    path = args.exclude or DEFAULT_EXCLUSIONS
    shown = repo_path(path)
    doc, problems = load_exclusions(path)
    if doc is None:
        for p in problems:
            print(f"FAIL  {p}")
        return 1

    entries = doc["entries"]
    src_problems, moved = check_sources(entries)

    # --relocate is a rewrite tool, never a verdict: it exits nonzero whatever it
    # finds, including when it finds nothing. Returning 0 on an empty run would
    # make `--verify-exclusions --relocate` a green gate that measured nothing,
    # which is the bypass this mode would otherwise hand to a CI author.
    if args.relocate:
        if not moved:
            print(f"{shown}: nothing to relocate. Rerun without --relocate to verify the set.")
            return 1
        for i, line in moved.items():
            entries[i]["line"] = line
        with open(path, "w") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"{shown}: relocated {plural(len(moved), 'line number')}. Review the diff, then rerun to verify.")
        return 1

    problems += src_problems
    buckets = defaultdict(int)
    for e in entries:
        buckets[e["bucket"]] += 1
    unconfirmed = [e for e in entries if not e["confirmed"]]

    notes = []
    # The set may only ever shrink. .coverage-exclusions.json says so in prose;
    # this is what makes it true. Same shape as GOLANGCI_MAX_ISSUES in
    # scripts/release-check.sh: over the ratchet fails, under it prints the
    # number to lower the ratchet to.
    if len(entries) > BASELINE_MAX_ENTRIES:
        problems.append(f"the set holds {len(entries)} entries, the ratchet is "
                        f"{BASELINE_MAX_ENTRIES}. The set may only shrink: cover the statement, "
                        f"delete the branch, or argue the case in review and raise "
                        f"BASELINE_MAX_ENTRIES in scripts/cov-gaps.py alongside it.")
    elif len(entries) < BASELINE_MAX_ENTRIES:
        notes.append(f"the set holds {len(entries)} entries, "
                     f"{BASELINE_MAX_ENTRIES - len(entries)} under the ratchet; "
                     f"lower BASELINE_MAX_ENTRIES to {len(entries)}")
    if unconfirmed:
        problems.append(f"{len(unconfirmed)} of {len(entries)} entries are confirmed=false. "
                        f"Check each against the profile and set confirmed=true, or delete it: "
                        + ", ".join(f"{e['file']}:{e['line']}" for e in unconfirmed))

    print(f"exclusions  {shown}")
    print(f"entries     {len(entries)} "
          f"({', '.join(f'{n} {b}' for b, n in sorted(buckets.items()))})")
    print(f"source      {len(entries) - len(src_problems)}/{len(entries)} match their frozen text")

    if args.profile is None:
        # Without a measurement the only check that ran was the one above. Every
        # other assertion the gate exists to make -- that no excluded statement
        # has become covered, that the packages were measured at all, that
        # covered + excluded == total -- needs a profile, so this is a failure
        # and not a reduced mode.
        problems.append("no coverage profile. The frozen-text comparison is the only check that "
                        "runs without one, and on its own it proves that "
                        f"{plural(len(entries), 'string')} still sit at "
                        f"{plural(len(entries), 'line number')}. Pass the profile "
                        "scripts/coverage.sh writes.")
    else:
        blocks = load(args.profile)
        total, covered = totals(blocks)
        canon_problems, canon_notes = check_canonical(blocks, total, doc.get("module", ""))
        problems += canon_problems
        notes += canon_notes
        excluded, prof_problems = resolve_exclusions(blocks, doc)
        problems += prof_problems
        n_excluded = sum(excluded.values())

        print(f"profile     {args.profile}")
        print(f"total       {total}")
        print(f"covered     {covered}")
        print(f"excluded    {n_excluded}")
        print(f"reachable   {total - n_excluded}")
        if total - n_excluded:
            print(f"coverage    {pct(covered, total - n_excluded):.2f}% of reachable "
                  f"({pct(covered, total):.2f}% of total)")
        if covered + n_excluded != total:
            gap = total - covered - n_excluded
            problems.append(f"covered + excluded = {covered + n_excluded}, total = {total}: "
                            f"{plural(gap, 'statement')} neither covered nor excluded")

    for n in notes:
        print(f"NOTE  {n}")

    if problems:
        print(f"\n{len(problems)} problem{'' if len(problems) == 1 else 's'}")
        for p in problems:
            print(f"FAIL  {p}")
        return 1
    print("\nOK")
    return 0


def report(blocks, args, excluded_n=0, full_total=None):
    total, covered = totals(blocks)
    if full_total is None:
        full_total = total
    uncovered_by_file = defaultdict(list)
    for key, (stmts, is_cov) in blocks.items():
        if is_cov:
            continue
        path, start, end = split_key(key)
        uncovered_by_file[path].append({"start": start, "end": end, "statements": stmts})

    if args.json:
        # total_statements is always the full instrumented count, so a consumer can
        # assert covered + excluded == total without knowing whether an exclusion
        # file was applied. reachable_statements is what the coverage figure is a
        # percentage of.
        print(json.dumps({
            "total_statements": full_total,
            "covered_statements": covered,
            "excluded_statements": excluded_n,
            "reachable_statements": full_total - excluded_n,
            "uncovered_statements": total - covered,
            "coverage": round(pct(covered, total), 2),
            "files": {
                f: sorted(v, key=lambda b: b["start"])
                for f, v in sorted(uncovered_by_file.items())
            },
        }, indent=2))
        return

    print(f"total      {total} statements")
    print(f"covered    {covered}")
    print(f"uncovered  {total - covered}")
    print(f"coverage   {pct(covered, total):.2f}%")

    if args.target is not None:
        need, lo = reachable_targets(total, args.target)
        print()
        if need is None:
            print(f"target {args.target:.2f}% is NOT reachable at {total} statements.")
            print(f"  {lo} covered -> {pct(lo, total):.2f}%")
            print(f"  {lo + 1} covered -> {pct(lo + 1, total):.2f}%")
            print("  pick a figure that lands on a whole statement.")
        else:
            print(f"target {args.target:.2f}% needs {need} covered "
                  f"(+{need - covered} from here, {total - need} may stay uncovered)")

    if args.file:
        hits = {f: v for f, v in uncovered_by_file.items() if args.file in f}
        if not hits:
            print(f"\nno uncovered blocks matching {args.file!r}")
            return
        for f, spans in sorted(hits.items()):
            print(f"\n{f}")
            for b in sorted(spans, key=lambda b: b["start"]):
                span = str(b["start"]) if b["start"] == b["end"] else f"{b['start']}-{b['end']}"
                print(f"  lines {span:>12}   {b['statements']} stmt")
        return

    print(f"\nuncovered blocks by file ({len(uncovered_by_file)} files)")
    print(f"{'statements':>10}  {'blocks':>6}  file")
    rows = sorted(
        ((sum(b["statements"] for b in v), len(v), f) for f, v in uncovered_by_file.items()),
        reverse=True,
    )
    for stmts, count, f in rows:
        print(f"{stmts:>10}  {count:>6}  {f}")


def diff(base, other):
    """Blocks `other` covers that `base` does not, and any regression the other way."""
    gained = sorted(
        (k for k, (_, c) in other.items() if c and k in base and not base[k][1]),
        key=lambda k: split_key(k),
    )
    lost = sorted(
        (k for k, (_, c) in base.items() if c and k in other and not other[k][1]),
        key=lambda k: split_key(k),
    )
    new_blocks = set(other) - set(base)
    gone_blocks = set(base) - set(other)

    gained_stmts = sum(other[k][0] for k in gained)
    lost_stmts = sum(base[k][0] for k in lost)

    print(f"newly covered  {len(gained)} blocks / {gained_stmts} statements")
    for k in gained:
        f, s, e = split_key(k)
        print(f"  + {f}:{s}-{e}  {other[k][0]} stmt")
    if lost:
        print(f"\nREGRESSED      {len(lost)} blocks / {lost_stmts} statements")
        for k in lost:
            f, s, e = split_key(k)
            print(f"  - {f}:{s}-{e}  {base[k][0]} stmt")
    if new_blocks or gone_blocks:
        print(f"\nblock set changed: {len(new_blocks)} new, {len(gone_blocks)} removed")
        print("  the source moved between runs, so the two totals are not comparable.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("profile", nargs="?",
                    help="coverage profile from scripts/coverage.sh; only --relocate, "
                         "which never reports a pass, runs without one")
    ap.add_argument("--file", help="show every uncovered block in files matching this substring")
    ap.add_argument("--target", type=float, help="covered-count needed to land this coverage figure")
    ap.add_argument("--diff", metavar="OTHER", help="blocks OTHER covers that PROFILE does not")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--exclude", metavar="FILE", nargs="?", const=DEFAULT_EXCLUSIONS,
                    help=f"exclusion set to subtract from the denominator "
                         f"(default {os.path.relpath(DEFAULT_EXCLUSIONS, REPO_ROOT)})")
    ap.add_argument("--verify-exclusions", action="store_true",
                    help="check the exclusion set against the source, against the ratchets "
                         "and against PROFILE; nonzero exit on any drift")
    ap.add_argument("--relocate", action="store_true",
                    help="with --verify-exclusions: rewrite only the line numbers of entries "
                         "whose frozen text moved, then exit nonzero so the diff gets reviewed")
    args = ap.parse_args()

    if args.verify_exclusions:
        sys.exit(verify_exclusions(args))
    if args.relocate:
        sys.exit("--relocate is only meaningful with --verify-exclusions")
    if not args.profile:
        sys.exit("a coverage profile is required (scripts/coverage.sh writes one)")

    blocks = load(args.profile)
    if args.diff:
        diff(blocks, load(args.diff))
        return

    full_total, _ = totals(blocks)
    excluded_n = 0

    # --json always accounts for exclusions, even without --exclude: a consumer
    # checking covered + excluded == total cannot do so from a figure that silently
    # omits the exclusion set.
    #
    # A set that will not load or will not resolve is fatal in both modes. Passing
    # excluded=0 through instead hands every consumer a reachable figure equal to
    # raw total coverage, which is a plausible-looking number for a broken
    # exclusion set: it happens to trip release-check.sh's identity assertion, and
    # it does not trip anything in scripts/readme-gen.sh, which publishes it.
    exclusion_path = args.exclude or (DEFAULT_EXCLUSIONS if args.json else None)
    if exclusion_path:
        doc, problems = load_exclusions(exclusion_path)
        if doc is None:
            sys.exit("\n".join(problems))
        excluded, problems = resolve_exclusions(blocks, doc)
        if problems:
            print(f"{len(problems)} exclusions did not resolve against this profile; "
                  f"any reachable figure computed from it would be a guess:", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            sys.exit(1)
        excluded_n = sum(excluded.values())
        if args.exclude:
            print(f"excluded   {excluded_n} statements of {full_total} "
                  f"({repo_path(exclusion_path)}), reachable {full_total - excluded_n}")
            blocks = {k: v for k, v in blocks.items() if k not in excluded}

    report(blocks, args, excluded_n=excluded_n, full_total=full_total)


if __name__ == "__main__":
    main()
