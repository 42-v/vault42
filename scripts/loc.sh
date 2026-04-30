#!/bin/bash
# Code stats: Go files, lines, test files, test count.
set -eo pipefail
GO_FILES=$(find . -name '*.go' -not -path './vendor/*' | grep -cv '_test\.go$')
GO_LINES=$(find . -name '*.go' -not -path './vendor/*' -not -name '*_test.go' -exec cat {} + | wc -l)
TEST_FILES=$(find . -name '*_test.go' -not -path './vendor/*' | wc -l)
# CI sets TEST_COUNT to skip re-running tests just for a number.
if [ -z "${TEST_COUNT:-}" ]; then
  TEST_COUNT=$(go test -count=1 -v ./... 2>&1 | grep -c '^--- PASS' || true)
fi
echo "${GO_FILES} files, ${GO_LINES} lines, ${TEST_FILES} test files, ${TEST_COUNT} tests"
