#!/bin/bash
# Run the .NET SDK test suites under coverage and gate on the result.
#
# The two packages under packages/dotnet are published to nuget.org, and until
# 1.0.1 their tests ran in exactly one place: the release workflow, after the tag
# was already pushed. Nothing built them on a pull request. Two dependabot bumps
# to the test SDK merged green without either project being compiled, and the
# suite that did exist covered 53% of the shipped lines -- including 0% of
# VaultAuthService, which is the entire OAuth2 client.
#
# The floor is 100.00 because the set is small, self-contained and has no
# platform-specific branches. There is no exclusions file, and the intent is not
# to add one: when a line cannot be reached, delete it. That is how
# VaultErrorResponse and the List<object> arm of the array-claim reader went. If
# a genuinely unreachable line ever does appear, lowering DOTNET_COVERAGE_FLOOR
# is a one-line diff that a reviewer sees, which is the point.
#
# Usage: scripts/dotnet-coverage.sh [--floor N] [--json PATH]
#
# --json writes {covered, total, percent} for scripts/readme-gen.sh, so the C#
# badge quotes the number this gate measured rather than re-deriving one that
# could disagree with it.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
solution="$root/packages/dotnet/Vault42.sln"
results="${DOTNET_COVERAGE_RESULTS:-$root/tmp/dotnet-coverage}"
floor="${DOTNET_COVERAGE_FLOOR:-100.00}"
json_out=""

while [ $# -gt 0 ]; do
  case "$1" in
    --floor)
      [ $# -ge 2 ] || { echo "--floor needs a value" >&2; exit 2; }
      floor="$2"
      shift 2
      ;;
    --json)
      [ $# -ge 2 ] || { echo "--json needs a path" >&2; exit 2; }
      json_out="$2"
      shift 2
      ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v dotnet >/dev/null 2>&1 || {
  echo "ERROR: dotnet is not on PATH; refusing to report a coverage number for a suite that did not run." >&2
  exit 1
}

# Belt and braces around an rm -rf whose target comes from the environment.
case "$results" in
  ""|"/"|"$HOME") echo "refusing to clear DOTNET_COVERAGE_RESULTS=$results" >&2; exit 2 ;;
esac
rm -rf "${results:?}"
mkdir -p "$results"

# The test count goes to the badge generator too, and it comes from the same run
# that produced the profile so the two can never describe different suites.
dotnet test "$solution" -c Release --nologo \
  --collect:"XPlat Code Coverage" \
  --results-directory "$results" | tee "$results/test-output.txt"

if [ -n "$json_out" ]; then
  python3 "$root/scripts/dotnet-coverage.py" "$results" --floor "$floor" --json "$json_out"
else
  python3 "$root/scripts/dotnet-coverage.py" "$results" --floor "$floor"
fi
