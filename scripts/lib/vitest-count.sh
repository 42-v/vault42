#!/bin/bash
# The one place vitest output is counted.
#
# There were two, and they disagreed. Both read `\d+(?= passed)` out of the
# combined log of the two frontend suites, and vitest prints that token twice
# per suite -- once for "Test Files  33 passed" and once for "Tests  749
# passed" -- so both summed four numbers where two were wanted. The published
# Vue figure was the number of tests PLUS the number of test files.
#
# Fixing one copy made it worse rather than better. readme-gen.sh takes
# VUE_TESTS from the caller when it is set, and scripts/precommit.sh sets it
# from 04-vue-tests.sh, so the corrected counter sat in an arm the documented
# regeneration path never reaches: the next precommit run would have rewritten
# a corrected 1260 back to 1315.
#
# So it lives here, sourced by both.

# vitest_counts <logfile>
#
# Prints "PASSED FAILED SUMMARIES" for a log holding one or more vitest runs.
#
# SUMMARIES is the number of "Tests ..." lines matched, and it is the return
# value that matters most: summing the wrong set of lines produces a plausible
# number rather than an error, which is exactly how the wrong figure survived.
# A caller that knows how many suites it ran can check it.
vitest_counts() {
  local log=$1 passed failed summaries
  passed=$({ grep -oP '^\s*Tests\s+\K\d+(?= passed)' "$log" || true; } | awk '{s+=$1}END{print s+0}')
  # `\d+(?= failed)` unanchored matches "Test Files  1 failed" as well, so a
  # single failing test in one suite reported two.
  failed=$({ grep -oP '^\s*Tests\s+\K\d+(?= failed)' "$log" || true; } | awk '{s+=$1}END{print s+0}')
  summaries=$({ grep -cP '^\s*Tests\s+\d+' "$log" || true; })
  printf '%d %d %d\n' "$passed" "$failed" "$summaries"
}
