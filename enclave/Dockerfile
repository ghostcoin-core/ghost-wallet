# The Seal's enclave image, one per region. Build from the repository root:
#
#   docker build --platform linux/arm64 --build-arg SEAL_REGION=<region> \
#     -f enclave/Dockerfile -t ghost-seal-enclave:<region> .
#
# then `nitro-cli build-enclave` turns the image into the EIF. Each region of
# enclave/deploy/regions.json gets its own image and its own PCRs:
# enclave/scripts/compute-pcrs.sh builds and measures them all. Everything
# that goes into the image is pinned: the toolchain image by digest, the
# crates by seal/Cargo.lock (--locked), and the build settings in
# enclave/build.env (toolchain, a fixed target, SOURCE_DATE_EPOCH, a static
# link, --remap-path-prefix). The release profile in seal/Cargo.toml is set
# for deterministic output.

# Rust 1.99.1 on Debian trixie (slim), the multi-platform index, pinned by digest.
FROM docker.io/library/rust:1.99.1-slim-trixie@sha256:7eab7ce19273ce785e0ca7578bdf7bc1fcbae621775a8197379a04c9f6e03cd5 AS build

WORKDIR /seal-build
COPY enclave/build.env /seal-build/enclave/build.env
COPY seal/Cargo.toml seal/Cargo.lock /seal-build/seal/
COPY seal/src /seal-build/seal/src
# The wallet core the seal crate depends on (`../core`).
COPY core/Cargo.toml core/Cargo.lock /seal-build/core/
COPY core/src /seal-build/core/src

# The enclave program, for one region. SEAL_REGION is compiled into
# seal_enclave as its own region (the host can never change it): it must be
# one of the region list compiled into the program (RELEASE_REGIONS in
# seal/src/journal_anchor.rs), or the build stops.
FROM build AS enclave-build
ARG SEAL_REGION
RUN set -eu; \
    . /seal-build/enclave/build.env; \
    case "${SEAL_REGION:-}" in \
      "" | -* | *[!a-z0-9-]*) echo "enclave/Dockerfile: --build-arg SEAL_REGION=<region> is required (a-z, 0-9 and -)" >&2; exit 1 ;; \
    esac; \
    grep -q "^pub const RELEASE_REGIONS: .*\"$SEAL_REGION\"" /seal-build/seal/src/journal_anchor.rs \
      || { echo "enclave/Dockerfile: SEAL_REGION=$SEAL_REGION is not on the compiled region list" >&2; exit 1; }; \
    export SEAL_REGION; \
    test "$(rustc --version | cut -d' ' -f2)" = "$SEAL_TOOLCHAIN"; \
    export SOURCE_DATE_EPOCH="$SEAL_SOURCE_DATE_EPOCH"; \
    export CARGO_TARGET_DIR=/seal-build/target; \
    export RUSTFLAGS="-C target-feature=$SEAL_TARGET_FEATURES -C link-arg=-Wl,--build-id=none --remap-path-prefix=/seal-build=$SEAL_BUILD_ROOT --remap-path-prefix=$CARGO_HOME=$SEAL_CARGO_ROOT"; \
    cargo build --release --locked --features nitro --bin seal_enclave --target "$SEAL_TARGET" --manifest-path /seal-build/seal/Cargo.toml; \
    install -m 0755 "/seal-build/target/$SEAL_TARGET/release/seal_enclave" /seal_enclave; \
    touch -d "@$SEAL_SOURCE_DATE_EPOCH" /seal_enclave; \
    echo "seal_enclave for $SEAL_REGION"; \
    sha256sum /seal_enclave

# The host's proxy is not in the enclave image and not measured, and is the
# same for every region (no SEAL_REGION). It looks up host names (a Ghost
# node), so it is built for musl, whose resolver works in a static program
# on any host; rustup checks the target's hash against the toolchain's
# release manifest.
FROM build AS proxy-build
# Crates in seal_proxy's tree (ring, through rustls) compile C for the musl
# target, so cc-rs needs a musl C compiler: Debian trixie's musl-gcc wrapper
# (musl-tools) around the image's gcc. The three packages come from a fixed
# snapshot of the Debian archive and are checked against their SHA-256 before
# dpkg installs them. Only this stage has them: the build stage and the
# measured enclave stages are unchanged.
ADD https://snapshot.debian.org/archive/debian/20260510T204219Z/pool/main/m/musl/musl_1.2.5-3.1~deb13u1_arm64.deb /seal-musl/musl.deb
ADD https://snapshot.debian.org/archive/debian/20260510T204219Z/pool/main/m/musl/musl-dev_1.2.5-3.1~deb13u1_arm64.deb /seal-musl/musl-dev.deb
ADD https://snapshot.debian.org/archive/debian/20260510T204219Z/pool/main/m/musl/musl-tools_1.2.5-3.1~deb13u1_arm64.deb /seal-musl/musl-tools.deb
RUN set -eu; \
    echo "46cf1fcaa2d49d1573ef0ceabdb36e04a359a9a37d8e4304024f9018682e3f35  /seal-musl/musl.deb" | sha256sum -c -; \
    echo "384ea029e3694baac696d3993d93246f9a4b3741c493697e1ceb7256d8820748  /seal-musl/musl-dev.deb" | sha256sum -c -; \
    echo "3d3a33291ee2bb651dae1940671fb302d0a1b90a0ad9bc2a1ae8e81151d811c7  /seal-musl/musl-tools.deb" | sha256sum -c -; \
    dpkg -i /seal-musl/musl.deb /seal-musl/musl-dev.deb /seal-musl/musl-tools.deb; \
    rm -rf /seal-musl; \
    command -v musl-gcc
RUN set -eu; \
    . /seal-build/enclave/build.env; \
    rustup target add "$SEAL_PROXY_TARGET"; \
    export CC_aarch64_unknown_linux_musl=musl-gcc; \
    export AR_aarch64_unknown_linux_musl=ar; \
    export SOURCE_DATE_EPOCH="$SEAL_SOURCE_DATE_EPOCH"; \
    export CARGO_TARGET_DIR=/seal-build/target; \
    export RUSTFLAGS="--remap-path-prefix=/seal-build=$SEAL_BUILD_ROOT --remap-path-prefix=$CARGO_HOME=$SEAL_CARGO_ROOT"; \
    cargo build --release --locked --features nitro --bin seal_proxy --target "$SEAL_PROXY_TARGET" --manifest-path /seal-build/seal/Cargo.toml; \
    install -m 0755 "/seal-build/target/$SEAL_PROXY_TARGET/release/seal_proxy" /seal_proxy; \
    sha256sum /seal_proxy

# The parent proxy for the host, exported with
#   docker build --platform linux/arm64 -f enclave/Dockerfile --target proxy -o enclave/out .
FROM scratch AS proxy
COPY --from=proxy-build /seal_proxy /seal_proxy

# The enclave image (the default, last stage): the static program and
# nothing else. nitro-cli adds the enclave kernel and init around it; PCR2
# measures this layer.
FROM scratch AS enclave
COPY --from=enclave-build /seal_enclave /seal_enclave
ENTRYPOINT ["/seal_enclave"]
