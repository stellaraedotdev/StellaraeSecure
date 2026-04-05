#!/usr/bin/env bash
set -euo pipefail

TAG="${1:-}"

if [[ -z "$TAG" ]]; then
  echo "Tag is required. Example: v0.2.0"
  exit 1
fi

if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid tag format: $TAG"
  echo "Expected semantic version tag: vMAJOR.MINOR.PATCH"
  exit 1
fi

if [[ ! -f CHANGELOG.md ]]; then
  echo "CHANGELOG.md is missing"
  exit 1
fi

if ! grep -q "^## \[$TAG\]" CHANGELOG.md; then
  echo "CHANGELOG.md does not contain an entry for $TAG"
  echo "Add a section header like: ## [$TAG] - YYYY-MM-DD"
  exit 1
fi

echo "Tag and changelog validation passed for $TAG"
