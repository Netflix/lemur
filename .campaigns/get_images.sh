#!/usr/bin/env bash
set -euo pipefail

# The user that clones the repository (root) is different from the user performing git commands
git config --global --add safe.directory /go/src/github.com/DataDog/lemur

# Campaigner should always re-build images for the latest release
LATEST_RELEASE_TAG=$(git describe --tags $(git rev-list --tags --max-count=1))
echo "lemur:${LATEST_RELEASE_TAG}"
echo "lemur:${LATEST_RELEASE_TAG}-fips"
echo "lemur:latest"
