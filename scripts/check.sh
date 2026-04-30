#!/bin/bash
# Full build + vet check. Exit code 0 = clean.
set -e
go build ./... 2>&1
go vet ./... 2>&1
echo "OK"
