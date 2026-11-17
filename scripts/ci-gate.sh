#!/usr/bin/env bash
# Merge gate: clean install, typecheck, lint, unit tests, the Rust core tests,
# the Seal tests and the card applet's tests.
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

echo "==> seal tests"
cargo test --manifest-path seal/Cargo.toml --locked

echo "==> card applet (needs JDK 17 and Ant)"
card-applet/build.sh
card-applet/test.sh

echo "==> gate passed"
