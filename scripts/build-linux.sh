#!/bin/bash
# Build for Linux targets only
# Requires: cross-compilation toolchain (e.g., brew install filosottile/musl-cross/musl-cross)

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${PROJECT_ROOT}/dist/linux"
LIB_NAME="entlib_native"

mkdir -p "${OUTPUT_DIR}"
cd "${PROJECT_ROOT}"

echo "Building for Linux x86_64..."
rustup target add x86_64-unknown-linux-gnu 2>/dev/null || true

if cargo build --release --target x86_64-unknown-linux-gnu; then
    cp "target/x86_64-unknown-linux-gnu/release/lib${LIB_NAME}.so" "${OUTPUT_DIR}/lib${LIB_NAME}_x86_64.so"
    echo "Built: lib${LIB_NAME}_x86_64.so"
fi

echo "Building for Linux aarch64..."
rustup target add aarch64-unknown-linux-gnu 2>/dev/null || true

if cargo build --release --target aarch64-unknown-linux-gnu; then
    cp "target/aarch64-unknown-linux-gnu/release/lib${LIB_NAME}.so" "${OUTPUT_DIR}/lib${LIB_NAME}_aarch64.so"
    echo "Built: lib${LIB_NAME}_aarch64.so"
fi

echo ""
echo "Linux builds complete. Output: ${OUTPUT_DIR}"
ls -la "${OUTPUT_DIR}/"
