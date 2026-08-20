#!/usr/bin/env python3
"""Merge the cobertura reports coverlet writes and gate on the total.

One report is produced per test project, and the two overlap: both reference the
same shared source only through their own assembly, but a line covered by either
run is covered. Taking the maximum hit count per (file, line) across reports is
the merge; summing the per-report percentages would double-count the denominator
and report a number lower than the truth.

The gate refuses a vacuous pass. A run that collected nothing at all produces
either no report or a report with no lines, and both of those would otherwise
divide by zero into a cheerful 100%. Two other gates in this repository turned
out to be incapable of failing, so this one states what it measured.
"""

from __future__ import annotations

import argparse
import collections
import glob
import os
import sys
import xml.etree.ElementTree as ET

# Every source file the two published packages ship. Named rather than
# discovered so that a project excluded from the run by a build change shows up
# as a missing file instead of a smaller, still-green denominator.
EXPECTED_FILES = {
    "Internal/LimitedReadStream.cs",
    "Internal/Pkce.cs",
    "Internal/TokenResponse.cs",
    "Internal/TokenStore.cs",
    "VaultAuthCallback.razor",
    "VaultAuthService.cs",
    "VaultAuthenticationExtensions.cs",
    "VaultAuthenticationHandler.cs",
    "VaultAuthenticationOptions.cs",
    "VaultAuthenticationStateProvider.cs",
    "VaultAuthorizationMessageHandler.cs",
    "VaultBlazorExtensions.cs",
    "VaultBlazorOptions.cs",
    "VaultClaimTypes.cs",
    "VaultClaimsPrincipalExtensions.cs",
    "VaultDefaults.cs",
    "VaultFingerprintValidator.cs",
    "VaultJwksManager.cs",
}


def merge(results_dir: str) -> dict[str, dict[int, int]]:
    pattern = os.path.join(results_dir, "**", "coverage.cobertura.xml")
    reports = sorted(glob.glob(pattern, recursive=True))
    if not reports:
        sys.exit(f"ERROR: no cobertura report under {results_dir}; the run collected nothing.")

    lines: dict[str, dict[int, int]] = collections.defaultdict(dict)
    for report in reports:
        # ruff S314: the reports are written by coverlet into a directory this
        # script created moments earlier. There is no untrusted input here, and
        # pulling in defusedxml would add a dependency to read our own output.
        root = ET.parse(report).getroot()  # noqa: S314
        for cls in root.iter("class"):
            filename = cls.get("filename")
            if filename is None:
                continue
            for line in cls.iter("line"):
                number = int(line.get("number", "0"))
                hits = int(line.get("hits", "0"))
                lines[filename][number] = max(lines[filename].get(number, 0), hits)
    print(f"merged {len(reports)} cobertura report(s)")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results_dir")
    parser.add_argument("--floor", type=float, default=100.0)
    args = parser.parse_args()

    lines = merge(args.results_dir)

    # A file with no lines at all is not "fully covered", it is absent from the
    # measurement. Files with no executable lines (constants only) never appear
    # in a cobertura report, so absence is only an error for files that carry
    # statements -- which is why the expected set is checked as a subset.
    measured = set(lines)
    missing = {f for f in EXPECTED_FILES if f not in measured}
    # VaultClaimTypes.cs and VaultDefaults.cs are const-only and emit no
    # sequence points, so they are legitimately absent.
    missing -= {"VaultClaimTypes.cs", "VaultDefaults.cs"}
    if missing:
        return fail(
            "these shipped source files are absent from the coverage report, so the "
            "number below describes a smaller tree than the one that is published:\n  "
            + "\n  ".join(sorted(missing))
        )

    total = covered = 0
    rows = []
    for filename, hits in lines.items():
        file_total = len(hits)
        file_covered = sum(1 for h in hits.values() if h > 0)
        total += file_total
        covered += file_covered
        ratio = file_covered / file_total if file_total else 1.0
        rows.append((ratio, filename, file_covered, file_total))

    if total == 0:
        return fail("the merged report contains no lines at all; nothing was measured.")

    rows.sort()
    for ratio, filename, file_covered, file_total in rows:
        print(f"{ratio * 100:7.2f}%  {file_covered:4d}/{file_total:4d}  {filename}")

    percent = 100.0 * covered / total
    print(f"\nTOTAL {covered}/{total} = {percent:.2f}% (floor {args.floor:.2f}%)")

    if percent + 1e-9 < args.floor:
        uncovered = {
            filename: sorted(n for n, h in hits.items() if h == 0)
            for filename, hits in lines.items()
            if any(h == 0 for h in hits.values())
        }
        detail = "\n".join(f"  {f}: {ns}" for f, ns in sorted(uncovered.items()))
        return fail(
            f"coverage {percent:.2f}% is below the floor {args.floor:.2f}%."
            f"\nUncovered lines:\n{detail}"
        )

    return 0


def fail(message: str) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
