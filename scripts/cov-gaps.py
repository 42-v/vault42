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
    scripts/cov-gaps.py --verify-exclusions [PROFILE]   # the release gate

The exclusion set (.coverage-exclusions.json) is how 1.0.0 can claim "100.00% of
reachable statements" without the claim being unfalsifiable. Each entry names one
statement, freezes its source line verbatim, and carries the argument for why it
is not reachable. --verify-exclusions is what stops the set rotting or growing:
it fails when an excluded line has moved, changed text, or become covered, when
an entry is still unconfirmed and a real profile is available to confirm it, and
when covered + excluded does not equal total.
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
        key = (e["file"], e["line"])
        if key in seen:
            problems.append(f"{where}: duplicate of entry #{seen[key] + 1}")
        seen[key] = i
    return doc, problems


def check_sources(entries):
    """Confirm every entry still names the exact line it froze.

    Returns (problems, moved), where `moved` maps an entry's index to the line
    its frozen text now sits on. Finding the text elsewhere is a different
    failure from not finding it at all: the first is a refactor that moved a
    statement, the second is a statement that no longer exists.
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
        at = e["line"] - 1
        if 0 <= at < len(src) and src[at] == e["source"]:
            continue
        hits = [n for n, line in enumerate(src, 1) if line == e["source"]]
        if len(hits) >= e["occurrence"]:
            moved[i] = hits[e["occurrence"] - 1]
            problems.append(f"{e['file']}:{e['line']}: statement moved to line {moved[i]}, "
                            f"re-review it and rerun with --relocate")
        else:
            problems.append(f"{e['file']}:{e['line']}: the excluded statement is gone "
                            f"({len(hits)} lines match its frozen text, wanted #{e['occurrence']}). "
                            f"Delete the entry, or re-justify it against the new code.")
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

    if args.relocate:
        if not moved:
            print(f"{shown}: nothing to relocate")
            return 1 if problems or src_problems else 0
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

    print(f"exclusions  {shown}")
    print(f"entries     {len(entries)} "
          f"({', '.join(f'{n} {b}' for b, n in sorted(buckets.items()))})")
    print(f"source      {len(entries) - len(src_problems)}/{len(entries)} match their frozen text")

    if args.profile:
        blocks = load(args.profile)
        total, covered = totals(blocks)
        excluded, prof_problems = resolve_exclusions(blocks, doc)
        problems += prof_problems
        n_excluded = sum(excluded.values())

        if unconfirmed:
            problems.append(f"{len(unconfirmed)} of {len(entries)} entries are still "
                            f"confirmed=false while a real profile is available. Check each "
                            f"against this profile and set confirmed=true, or delete it: "
                            + ", ".join(f"{e['file']}:{e['line']}" for e in unconfirmed))

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
    elif unconfirmed:
        print(f"UNCONFIRMED {len(unconfirmed)} of {len(entries)} entries were inferred, not measured. Run "
              f"scripts/coverage.sh on a host with a container runtime and rerun with its profile.")

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
                    help="coverage profile; optional only with --verify-exclusions")
    ap.add_argument("--file", help="show every uncovered block in files matching this substring")
    ap.add_argument("--target", type=float, help="covered-count needed to land this coverage figure")
    ap.add_argument("--diff", metavar="OTHER", help="blocks OTHER covers that PROFILE does not")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--exclude", metavar="FILE", nargs="?", const=DEFAULT_EXCLUSIONS,
                    help=f"exclusion set to subtract from the denominator "
                         f"(default {os.path.relpath(DEFAULT_EXCLUSIONS, REPO_ROOT)})")
    ap.add_argument("--verify-exclusions", action="store_true",
                    help="check the exclusion set against the source and, with a profile, "
                         "against the measurement; nonzero exit on any drift")
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
    # omits the exclusion set. An unreadable or unresolvable set is reported as zero
    # rather than guessed, so the caller's arithmetic fails loudly instead of passing
    # on a number nobody computed.
    exclusion_path = args.exclude or (DEFAULT_EXCLUSIONS if args.json else None)
    if exclusion_path:
        doc, problems = load_exclusions(exclusion_path)
        if doc is None:
            if args.exclude:
                sys.exit("\n".join(problems))
        else:
            excluded, problems = resolve_exclusions(blocks, doc)
            if problems:
                if args.exclude:
                    print(f"{len(problems)} exclusions did not resolve against this profile; "
                          f"the reachable figure below would be a guess:", file=sys.stderr)
                    for p in problems:
                        print(f"  {p}", file=sys.stderr)
                    sys.exit(1)
            else:
                excluded_n = sum(excluded.values())
                if args.exclude:
                    print(f"excluded   {excluded_n} statements of {full_total} "
                          f"({repo_path(exclusion_path)}), reachable {full_total - excluded_n}")
                    blocks = {k: v for k, v in blocks.items() if k not in excluded}

    report(blocks, args, excluded_n=excluded_n, full_total=full_total)


if __name__ == "__main__":
    main()
