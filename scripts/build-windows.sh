#!/bin/bash
# Build for Windows targets
# Requires: MinGW (brew install mingw-w64 on macOS)

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${PROJECT_ROOT}/dist/windows"
LIB_NAME="entlib_native"

mkdir -p "${OUTPUT_DIR}"
cd "${PROJECT_ROOT}"

echo "Building for Windows x86_64..."
rustup target add x86_64-pc-windows-gnu 2>/dev/null || true

if cargo build --release --target x86_64-pc-windows-gnu; then
    cp "target/x86_64-pc-windows-gnu/release/${LIB_NAME}.dll" "${OUTPUT_DIR}/${LIB_NAME}_x86_64.dll"
    echo "Built: ${LIB_NAME}_x86_64.dll"
fi

echo "Building for Windows i686 (32-bit)..."
rustup target add i686-pc-windows-gnu 2>/dev/null || true

if cargo build --release --target i686-pc-windows-gnu; then
    cp "target/i686-pc-windows-gnu/release/${LIB_NAME}.dll" "${OUTPUT_DIR}/${LIB_NAME}_i686.dll"
    echo "Built: ${LIB_NAME}_i686.dll"
fi

echo ""
echo "Windows builds complete. Output: ${OUTPUT_DIR}"
ls -la "${OUTPUT_DIR}/"
