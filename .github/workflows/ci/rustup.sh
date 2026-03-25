#!/usr/bin/env bash

set -euxo pipefail

TARGETS=(
    "aarch64-unknown-linux-musl"
    "x86_64-unknown-linux-musl"
    "riscv64gc-unknown-linux-musl"
    "armv7-unknown-linux-musleabihf"
    "armv7-unknown-linux-musleabi"
    "arm-unknown-linux-musleabihf"
    "arm-unknown-linux-musleabi"
    "loongarch64-unknown-linux-musl"
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
    "x86_64-pc-windows-msvc"
    "aarch64-pc-windows-msvc"
    "i686-pc-windows-msvc"
    "x86_64-unknown-freebsd"
)

for target in "${TARGETS[@]}"; do
    rustup target add "$target"
done

rustup component add rustfmt
rustup component add clippy
