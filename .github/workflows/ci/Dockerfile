ARG RUST_VERSION=1.93

FROM docker.io/rust:${RUST_VERSION}

ENV DEBCONF_NONINTERACTIVE_SEEN=true \
    DEBIAN_FRONTEND=noninteractive \
    DEBIAN_PRIORITY=critical

RUN set -eux; \
    curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash

ENV XWIN_CACHE_DIR=/usr/local/share/xwin
RUN set -eux; \
    cargo binstall -y cargo-xwin \
    && mkdir -p ${XWIN_CACHE_DIR} \
    && cargo xwin cache xwin

RUN set -eux; \
    cargo binstall -y cargo-zigbuild cargo-hack

RUN set -eux; \
    apt-get update \
    && apt-get install -y --no-install-recommends \
           file patchelf \
           build-essential \
           libwebkit2gtk-4.1-dev \
           libgtk-3-dev \
           librsvg2-dev \
           libxdo-dev \
           libssl-dev \
    && apt-get install -y --no-install-recommends \
           llvm lld clang \
           libappindicator3-dev \
    && apt-get install -y --no-install-recommends \
           protobuf-compiler libprotobuf-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ARG ZIG_VERSION=0.13.0
RUN set -eux; \
    wget -qO- "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" | tar -xJ -C /opt/ \
    && ln -sf /opt/zig-linux-x86_64-${ZIG_VERSION}/zig /usr/local/bin/zig

COPY --chmod=0755 ./rustup.sh /rustup.sh
RUN set -eux; \
    /rustup.sh

ARG NODE_VERSION=22
ARG PNPM_VERSION=10
RUN set -eux; \
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && npm install -g pnpm@${PNPM_VERSION}

ENV PNPM_HOME="/usr/local/share/pnpm" \
    PATH="$PNPM_HOME:$PATH"
