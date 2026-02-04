#!/bin/bash
# Cross-compilation build script for entlib-native
# Outputs: .so (Linux), .dll (Windows), .dylib (macOS)

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${PROJECT_ROOT}/dist"
LIB_NAME="entlib_native"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[BUILD]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Detect current OS
OS="$(uname -s)"
ARCH="$(uname -m)"

print_status "Detected OS: ${OS}, Architecture: ${ARCH}"
print_status "Output directory: ${OUTPUT_DIR}"

# Function to build for a specific target
build_target() {
    local target=$1
    local output_ext=$2
    local output_prefix=$3

    print_status "Building for ${target}..."

    if rustup target list --installed | grep -q "${target}"; then
        if cargo build --release --target "${target}" 2>/dev/null; then
            local src_file="${PROJECT_ROOT}/target/${target}/release/${output_prefix}${LIB_NAME}${output_ext}"
            if [ -f "${src_file}" ]; then
                cp "${src_file}" "${OUTPUT_DIR}/"
                print_status "Successfully built: ${output_prefix}${LIB_NAME}${output_ext}"
                return 0
            fi
        fi
    fi

    print_warning "Skipped ${target} (target not installed or build failed)"
    return 1
}

# Install targets if not present
install_target_if_missing() {
    local target=$1
    if ! rustup target list --installed | grep -q "${target}"; then
        print_status "Installing target: ${target}"
        rustup target add "${target}" 2>/dev/null || print_warning "Could not install ${target}"
    fi
}

# Main build process
cd "${PROJECT_ROOT}"

echo ""
echo "========================================"
echo "  entlib-native Cross-Compilation"
echo "========================================"
echo ""

# Always build for current platform first
print_status "Building for current platform..."
cargo build --release
echo ""

# Copy native build
case "${OS}" in
    "Darwin")
        if [ -f "target/release/lib${LIB_NAME}.dylib" ]; then
            cp "target/release/lib${LIB_NAME}.dylib" "${OUTPUT_DIR}/"
            print_status "Native build: lib${LIB_NAME}.dylib"
        fi
        ;;
    "Linux")
        if [ -f "target/release/lib${LIB_NAME}.so" ]; then
            cp "target/release/lib${LIB_NAME}.so" "${OUTPUT_DIR}/"
            print_status "Native build: lib${LIB_NAME}.so"
        fi
        ;;
    "MINGW"*|"MSYS"*|"CYGWIN"*)
        if [ -f "target/release/${LIB_NAME}.dll" ]; then
            cp "target/release/${LIB_NAME}.dll" "${OUTPUT_DIR}/"
            print_status "Native build: ${LIB_NAME}.dll"
        fi
        ;;
esac

echo ""
print_status "Cross-compilation targets..."
echo ""

# macOS targets
if [ "${OS}" = "Darwin" ]; then
    # On macOS, we can build for both Intel and Apple Silicon
    install_target_if_missing "x86_64-apple-darwin"
    install_target_if_missing "aarch64-apple-darwin"

    build_target "x86_64-apple-darwin" ".dylib" "lib" || true
    build_target "aarch64-apple-darwin" ".dylib" "lib" || true
fi

# Linux targets (requires cross-compilation toolchain)
install_target_if_missing "x86_64-unknown-linux-gnu"
install_target_if_missing "aarch64-unknown-linux-gnu"

build_target "x86_64-unknown-linux-gnu" ".so" "lib" || true
build_target "aarch64-unknown-linux-gnu" ".so" "lib" || true

# Windows targets (requires MinGW)
install_target_if_missing "x86_64-pc-windows-gnu"

build_target "x86_64-pc-windows-gnu" ".dll" "" || true

echo ""
echo "========================================"
print_status "Build complete!"
echo "========================================"
echo ""
print_status "Output files in: ${OUTPUT_DIR}"
ls -la "${OUTPUT_DIR}/"
