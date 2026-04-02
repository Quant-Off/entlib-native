#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="/workspace"
CRATE_DIR="${WORKSPACE_ROOT}/core/constant-time"
SAW_DIR="${CRATE_DIR}/saw"

echo "=== entlib-native-constant-time SAW Formal Verification ==="
echo ""

if [ ! -f "${WORKSPACE_ROOT}/Cargo.toml" ]; then
    echo "ERROR: ${WORKSPACE_ROOT}/Cargo.toml not found."
    exit 1
fi

# Phase 0: Build LLVM bitcode
echo "Building LLVM bitcode (saw_verify + audit_mode)..."
cd "${WORKSPACE_ROOT}"
RUSTFLAGS="--emit=llvm-bc" cargo build --release \
    --features "entlib-native-constant-time/saw_verify" \
    --features "audit_mode" \
    -p entlib-native-constant-time 2>&1

BC_FILE=$(find target/release/deps -name 'entlib_native_constant_time-*.bc' -type f | head -1)

if [ -z "${BC_FILE}" ]; then
    echo "ERROR: LLVM bitcode not found in target/release/deps/"
    exit 1
fi

echo "Bitcode: ${BC_FILE}"
echo ""

# Phase 1 + 2: SAW verification
export ENTLIB_CT_BC="${WORKSPACE_ROOT}/${BC_FILE}"
cd "${SAW_DIR}"
saw verify.saw
