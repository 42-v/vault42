#!/bin/bash
# Step 1: Build + vet (gate — fail fast)
set -eo pipefail
cd "$(dirname "$0")/../.."

go build ./... 2>&1
go vet ./... 2>&1
