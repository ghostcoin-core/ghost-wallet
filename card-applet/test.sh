#!/usr/bin/env bash
# Runs the applet's tests on jcardsim (see test/ghostcard/CardTests.java).
# The applet is compiled from src/ with one class swapped: Nvm, its single
# path to persistent memory, is replaced by test/tear/ghostcard/Nvm.java,
# which can cut the power at any write.
#
#   ./test.sh                 every test
#   ./test.sh <name part>...  only the tests whose names contain one of these
set -euo pipefail
cd "$(dirname "$0")"
./build.sh fetch
cache="${CARD_APPLET_CACHE:-$HOME/.cache/card-applet}"
cp="$cache/jcardsim-3.0.5.11.jar:$cache/bcprov-jdk18on-1.87.jar"
out=build/test
rm -rf "$out"
mkdir -p "$out"
sources=$(find src -name '*.java' ! -name Nvm.java; find test host -name '*.java' ! -name CapHash.java)
# shellcheck disable=SC2086
javac -nowarn -Xlint:-options -d "$out" -cp "$cp" $sources
java -cp "$out:$cp" ghostcard.CardTests test/vectors.txt "$@"
