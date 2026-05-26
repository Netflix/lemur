#!/usr/bin/env bash
set -euo pipefail

# The user that clones the repository (root) is different from the user performing git commands
git config --global --add safe.directory /go/src/github.com/DataDog/lemur

# Campaigner refreshes mutable-latest-prod (rebuilds master HEAD against the
# latest base image). Required for the once a month rebuild policy.
echo "lemur:mutable-latest-prod"
echo "lemur:mutable-latest-prod-fips"
