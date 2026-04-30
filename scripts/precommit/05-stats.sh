#!/bin/bash
# Step 5: Code stats
# Outputs: GO_FILES GO_LINES TEST_FILES VUE_FILES VUE_LINES LOCALE_COUNT
set -eo pipefail
cd "$(dirname "$0")/../.."

GO_FILES=$(find . -name '*.go' -not -path './vendor/*' -not -path './tests/browser/*' | grep -cv '_test\.go$')
GO_LINES=$(find . -name '*.go' -not -path './vendor/*' -not -path './tests/browser/*' -not -name '*_test.go' -exec cat {} + | wc -l | tr -d ' ')
TEST_FILES=$(find . -name '*_test.go' -not -path './vendor/*' | wc -l | tr -d ' ')
VUE_FILES=$(find web/src packages/vue/src -name '*.vue' -o -name '*.ts' 2>/dev/null | grep -cv '_test\.\|\.test\.\|__tests__' || true)
VUE_LINES=$(find web/src packages/vue/src \( -name '*.vue' -o -name '*.ts' \) -not -path '*__tests__*' -not -name '*.test.*' -exec cat {} + 2>/dev/null | wc -l | tr -d ' ')
LOCALE_COUNT=$(ls web/src/locales/*.json 2>/dev/null | wc -l | tr -d ' ')

printf "%s %s %s %s %s %s\n" "$GO_FILES" "$GO_LINES" "$TEST_FILES" "$VUE_FILES" "$VUE_LINES" "$LOCALE_COUNT"
