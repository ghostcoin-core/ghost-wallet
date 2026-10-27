#!/usr/bin/env bash
# Merge gate: clean install, typecheck, lint, unit tests and the Rust core tests.
# Exits non-zero as soon as any step fails.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> pnpm install"
pnpm install --frozen-lockfile

echo "==> typecheck"
pnpm exec tsc --noEmit

echo "==> lint"
pnpm exec eslint . --max-warnings 0

echo "==> unit tests"
pnpm exec jest --ci --passWithNoTests=false

echo "==> rust core tests"
cargo test --manifest-path core/Cargo.toml --locked

echo "==> gate passed"
