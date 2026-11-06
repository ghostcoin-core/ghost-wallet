# The Seal's enclave image. Build from the repository root:
#
#   docker build --platform linux/arm64 -f enclave/Dockerfile -t ghost-seal-enclave .
#
# then `nitro-cli build-enclave` turns the image into the EIF (see
# enclave/scripts/compute-pcrs.sh). Everything that goes into the image is
# pinned: the toolchain image by digest, the crates by seal/Cargo.lock
# (--locked), and the build settings in enclave/build.env (toolchain, a fixed
# target, SOURCE_DATE_EPOCH, a static link, --remap-path-prefix). The release
# profile in seal/Cargo.toml is set for deterministic output.

# Rust 1.99.1 on Debian trixie (slim), the multi-platform index, pinned by digest.
FROM docker.io/library/rust:1.99.1-slim-trixie@sha256:7eab7ce19273ce785e0ca7578bdf7bc1fcbae621775a8197379a04c9f6e03cd5 AS build

WORKDIR /seal-build
COPY enclave/build.env /seal-build/enclave/build.env
COPY seal/Cargo.toml seal/Cargo.lock /seal-build/seal/
COPY seal/src /seal-build/seal/src
# The wallet core the seal crate depends on (`../core`).
COPY core/Cargo.toml core/Cargo.lock /seal-build/core/
COPY core/src /seal-build/core/src

RUN set -eu; \
    . /seal-build/enclave/build.env; \
    test "$(rustc --version | cut -d' ' -f2)" = "$SEAL_TOOLCHAIN"; \
    export SOURCE_DATE_EPOCH="$SEAL_SOURCE_DATE_EPOCH"; \
    export CARGO_TARGET_DIR=/seal-build/target; \
    export RUSTFLAGS="-C target-feature=$SEAL_TARGET_FEATURES -C link-arg=-Wl,--build-id=none --remap-path-prefix=/seal-build=$SEAL_BUILD_ROOT --remap-path-prefix=$CARGO_HOME=$SEAL_CARGO_ROOT"; \
    cargo build --release --locked --features nitro --bin seal_enclave --target "$SEAL_TARGET" --manifest-path /seal-build/seal/Cargo.toml; \
    install -m 0755 "/seal-build/target/$SEAL_TARGET/release/seal_enclave" /seal_enclave; \
    touch -d "@$SEAL_SOURCE_DATE_EPOCH" /seal_enclave; \
    sha256sum /seal_enclave

# The host's proxy is not in the enclave image and not measured. It looks up
# host names (a Ghost node), so it is built for musl, whose resolver works in a
# static program on any host; rustup checks the target's hash against the
# toolchain's release manifest.
RUN set -eu; \
    . /seal-build/enclave/build.env; \
    rustup target add "$SEAL_PROXY_TARGET"; \
    export SOURCE_DATE_EPOCH="$SEAL_SOURCE_DATE_EPOCH"; \
    export CARGO_TARGET_DIR=/seal-build/target; \
    export RUSTFLAGS="--remap-path-prefix=/seal-build=$SEAL_BUILD_ROOT --remap-path-prefix=$CARGO_HOME=$SEAL_CARGO_ROOT"; \
    cargo build --release --locked --features nitro --bin seal_proxy --target "$SEAL_PROXY_TARGET" --manifest-path /seal-build/seal/Cargo.toml; \
    install -m 0755 "/seal-build/target/$SEAL_PROXY_TARGET/release/seal_proxy" /seal_proxy; \
    sha256sum /seal_proxy

# The parent proxy for the host, exported with
#   docker build --platform linux/arm64 -f enclave/Dockerfile --target proxy -o enclave/out .
FROM scratch AS proxy
COPY --from=build /seal_proxy /seal_proxy

# The enclave image (the default, last stage): the static program and
# nothing else. nitro-cli adds the enclave kernel and init around it; PCR2
# measures this layer.
FROM scratch AS enclave
COPY --from=build /seal_enclave /seal_enclave
ENTRYPOINT ["/seal_enclave"]
