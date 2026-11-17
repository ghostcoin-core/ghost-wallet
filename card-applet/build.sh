#!/usr/bin/env bash
# Builds the Ghost card applet's CAP file and prints its code hash.
#
# Needs JDK 17 (JAVA_HOME) and Apache Ant on PATH. The Java Card tools are
# fetched once, at pinned versions with checked hashes, into
# $CARD_APPLET_CACHE (default ~/.cache/card-applet).
#
#   ./build.sh          build build/ghostcard.cap and print its hash
#   ./build.sh fetch    only fetch the tools
set -euo pipefail
cd "$(dirname "$0")"
here=$(pwd)
cache="${CARD_APPLET_CACHE:-$HOME/.cache/card-applet}"
mkdir -p "$cache"

SDK_REPO=https://github.com/martinpaljak/oracle_javacard_sdks
SDK_COMMIT=700ec80afdda210a0e62fb6a151a9cddc1acd244
MAVEN=https://repo1.maven.org/maven2

fetch() { # url file sha256
  local url="$1" file="$cache/$2" sum="$3"
  if [ ! -f "$file" ] || ! echo "$sum  $file" | sha256sum -c --status; then
    curl -sSfL -o "$file.part" "$url"
    echo "$sum  $file.part" | sha256sum -c --status || { echo "hash mismatch: $url" >&2; rm -f "$file.part"; exit 1; }
    mv "$file.part" "$file"
  fi
}

fetch https://github.com/martinpaljak/ant-javacard/releases/download/v26.05.15/ant-javacard.jar \
  ant-javacard.jar 14f5e25c07b184e4ec02ee148892c2ea7ad5d7e9db8b91109524df8f7d000589
fetch "$MAVEN/com/klinec/jcardsim/3.0.5.11/jcardsim-3.0.5.11.jar" \
  jcardsim-3.0.5.11.jar f6c3b6b8140401a47cf39d7b9dbfc052e381474c6c3b22018051024be1fca97c
fetch "$MAVEN/org/bouncycastle/bcprov-jdk18on/1.87/bcprov-jdk18on-1.87.jar" \
  bcprov-jdk18on-1.87.jar 12d2d3dd82a9ec15e92ec7c7943ee64f6097c6dc12c07e984f1693b77565b9aa

if [ "$(git -C "$cache/sdks" rev-parse HEAD 2>/dev/null)" != "$SDK_COMMIT" ]; then
  rm -rf "$cache/sdks"
  git clone -q --filter=blob:none --no-checkout "$SDK_REPO" "$cache/sdks"
  git -C "$cache/sdks" sparse-checkout set jc305u4_kit jc310r20210706_kit
  git -C "$cache/sdks" checkout -q "$SDK_COMMIT"
fi

if [ "${1:-}" = fetch ]; then
  exit 0
fi

python3 gen/generate.py --check
rm -rf build
ant -q -Dtools="$cache" cap
mkdir -p build/host
javac -d build/host -cp "$cache/ant-javacard.jar" host/CapHash.java
java -cp "build/host:$cache/ant-javacard.jar" CapHash build/ghostcard.cap
