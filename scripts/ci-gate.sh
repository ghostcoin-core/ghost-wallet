#!/usr/bin/env bash
# Merge gate: clean install, typecheck, lint and unit tests.
# Exits non-zero as soon as any step fails.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> npm ci"
npm ci --no-audit --no-fund

echo "==> typecheck"
npx tsc --noEmit

echo "==> lint"
npx eslint . --max-warnings 0

echo "==> unit tests"
npx jest --ci --passWithNoTests=false

echo "==> gate passed"
