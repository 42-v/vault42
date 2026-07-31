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
"""

import argparse
import json
import sys
from collections import defaultdict


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


def report(blocks, args):
    total, covered = totals(blocks)
    uncovered_by_file = defaultdict(list)
    for key, (stmts, is_cov) in blocks.items():
        if is_cov:
            continue
        path, start, end = split_key(key)
        uncovered_by_file[path].append({"start": start, "end": end, "statements": stmts})

    if args.json:
        print(json.dumps({
            "total_statements": total,
            "covered_statements": covered,
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
    ap.add_argument("profile")
    ap.add_argument("--file", help="show every uncovered block in files matching this substring")
    ap.add_argument("--target", type=float, help="covered-count needed to land this coverage figure")
    ap.add_argument("--diff", metavar="OTHER", help="blocks OTHER covers that PROFILE does not")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    blocks = load(args.profile)
    if args.diff:
        diff(blocks, load(args.diff))
        return
    report(blocks, args)


if __name__ == "__main__":
    main()
