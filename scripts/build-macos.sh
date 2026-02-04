#!/bin/bash
# Build for macOS targets (Intel and Apple Silicon)
# Can create universal binary

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${PROJECT_ROOT}/dist/macos"
LIB_NAME="entlib_native"

mkdir -p "${OUTPUT_DIR}"
cd "${PROJECT_ROOT}"

echo "Building for macOS x86_64 (Intel)..."
rustup target add x86_64-apple-darwin 2>/dev/null || true

if cargo build --release --target x86_64-apple-darwin; then
    cp "target/x86_64-apple-darwin/release/lib${LIB_NAME}.dylib" "${OUTPUT_DIR}/lib${LIB_NAME}_x86_64.dylib"
    echo "Built: lib${LIB_NAME}_x86_64.dylib"
fi

echo "Building for macOS aarch64 (Apple Silicon)..."
rustup target add aarch64-apple-darwin 2>/dev/null || true

if cargo build --release --target aarch64-apple-darwin; then
    cp "target/aarch64-apple-darwin/release/lib${LIB_NAME}.dylib" "${OUTPUT_DIR}/lib${LIB_NAME}_aarch64.dylib"
    echo "Built: lib${LIB_NAME}_aarch64.dylib"
fi

# Create universal binary if both architectures built successfully
if [ -f "${OUTPUT_DIR}/lib${LIB_NAME}_x86_64.dylib" ] && [ -f "${OUTPUT_DIR}/lib${LIB_NAME}_aarch64.dylib" ]; then
    echo "Creating universal binary..."
    lipo -create \
        "${OUTPUT_DIR}/lib${LIB_NAME}_x86_64.dylib" \
        "${OUTPUT_DIR}/lib${LIB_NAME}_aarch64.dylib" \
        -output "${OUTPUT_DIR}/lib${LIB_NAME}_universal.dylib"
    echo "Built: lib${LIB_NAME}_universal.dylib"
fi

echo ""
echo "macOS builds complete. Output: ${OUTPUT_DIR}"
ls -la "${OUTPUT_DIR}/"
