#!/bin/bash
# Docker-based cross-compilation for Linux (.so) and Windows (.dll)
# Requires: Docker
# Note: Uses /tmp for Docker volume mount compatibility on macOS

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${PROJECT_ROOT}/dist"
LIB_NAME="entlib_native"
TEMP_BUILD_DIR="/tmp/entlib-native-build"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[BUILD]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    if [ -d "${TEMP_BUILD_DIR}" ]; then
        rm -rf "${TEMP_BUILD_DIR}"
    fi
}

# Check Docker
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker Desktop."
    exit 1
fi

cd "${PROJECT_ROOT}"

# Prepare temp directory for Docker build
prepare_build_dir() {
    print_status "Preparing build directory..."
    rm -rf "${TEMP_BUILD_DIR}"
    mkdir -p "${TEMP_BUILD_DIR}"

    # Copy source files (exclude target and dist)
    rsync -a --exclude='target' --exclude='dist' --exclude='.git' "${PROJECT_ROOT}/" "${TEMP_BUILD_DIR}/"
    mkdir -p "${TEMP_BUILD_DIR}/dist/linux"
    mkdir -p "${TEMP_BUILD_DIR}/dist/windows"
}

# =============================================================================
# Linux Build (x86_64 and aarch64)
# =============================================================================
build_linux() {
    local arch=$1
    local target=""
    local output_suffix=""
    local cross_compiler=""

    case "${arch}" in
        "x86_64")
            target="x86_64-unknown-linux-gnu"
            output_suffix="x86_64"
            cross_compiler=""
            ;;
        "aarch64")
            target="aarch64-unknown-linux-gnu"
            output_suffix="aarch64"
            cross_compiler="gcc-aarch64-linux-gnu"
            ;;
        *)
            print_error "Unknown architecture: ${arch}"
            return 1
            ;;
    esac

    print_status "Building Linux ${arch} (.so)..."

    local install_cmd=""
    if [ -n "${cross_compiler}" ]; then
        install_cmd="apt-get update && apt-get install -y ${cross_compiler} && "
    fi

    docker run --rm \
        -v "${TEMP_BUILD_DIR}:/workspace" \
        -w /workspace \
        rust:latest \
        bash -c "
            ${install_cmd}
            rustup target add ${target} && \
            cargo build --release --target ${target} && \
            cp target/${target}/release/lib${LIB_NAME}.so /workspace/dist/linux/lib${LIB_NAME}_${output_suffix}.so
        "

    # Copy result back to project
    mkdir -p "${OUTPUT_DIR}/linux"
    if [ -f "${TEMP_BUILD_DIR}/dist/linux/lib${LIB_NAME}_${output_suffix}.so" ]; then
        cp "${TEMP_BUILD_DIR}/dist/linux/lib${LIB_NAME}_${output_suffix}.so" "${OUTPUT_DIR}/linux/"
        print_status "Built: lib${LIB_NAME}_${output_suffix}.so"
    else
        print_error "Failed to build Linux ${arch}"
        return 1
    fi
}

# =============================================================================
# Windows Build (x86_64)
# =============================================================================
build_windows() {
    print_status "Building Windows x86_64 (.dll)..."

    docker run --rm \
        -v "${TEMP_BUILD_DIR}:/workspace" \
        -w /workspace \
        rust:latest \
        bash -c "
            apt-get update && apt-get install -y gcc-mingw-w64-x86-64 && \
            rustup target add x86_64-pc-windows-gnu && \
            cargo build --release --target x86_64-pc-windows-gnu && \
            cp target/x86_64-pc-windows-gnu/release/${LIB_NAME}.dll /workspace/dist/windows/${LIB_NAME}_x86_64.dll
        "

    # Copy result back to project
    mkdir -p "${OUTPUT_DIR}/windows"
    if [ -f "${TEMP_BUILD_DIR}/dist/windows/${LIB_NAME}_x86_64.dll" ]; then
        cp "${TEMP_BUILD_DIR}/dist/windows/${LIB_NAME}_x86_64.dll" "${OUTPUT_DIR}/windows/"
        print_status "Built: ${LIB_NAME}_x86_64.dll"
    else
        print_error "Failed to build Windows x86_64"
        return 1
    fi
}

# =============================================================================
# Main
# =============================================================================
echo ""
echo "========================================"
echo "  Docker Cross-Compilation"
echo "========================================"
echo ""

# Prepare build directory
prepare_build_dir

# Set trap for cleanup
trap cleanup EXIT

case "${1:-all}" in
    "linux")
        build_linux "x86_64"
        build_linux "aarch64"
        ;;
    "linux-x86_64")
        build_linux "x86_64"
        ;;
    "linux-aarch64")
        build_linux "aarch64"
        ;;
    "windows")
        build_windows
        ;;
    "all")
        build_linux "x86_64"
        build_linux "aarch64"
        build_windows
        ;;
    *)
        echo "Usage: $0 [linux|linux-x86_64|linux-aarch64|windows|all]"
        exit 1
        ;;
esac

echo ""
echo "========================================"
print_status "Build complete!"
echo "========================================"
echo ""
print_status "Output files:"
ls -la "${OUTPUT_DIR}/"*/
