#!/usr/bin/env bash
# test_h6_avx512.sh -- Build and run Firedancer H6 differential tests
#
# This script builds Firedancer from source and runs our H6 test suite
# which checks for divergences between the AVX512 and reference Ed25519
# implementations.
#
# Requirements:
#   - Linux x86_64 with AVX512F support (or SDE emulator)
#   - GCC 11+ or Clang 14+
#   - make, git
#
# Usage:
#   chmod +x test_h6_avx512.sh
#   ./test_h6_avx512.sh [--clone] [--fuzz-iters N] [--sde]
#
# Options:
#   --clone        Clone firedancer repo fresh (default: use ./firedancer/)
#   --fuzz-iters N Number of fuzzer iterations (default: 10000000)
#   --sde          Use Intel SDE for AVX512 emulation on non-AVX512 CPUs
#   --ref-only     Only build/run reference (non-AVX512) for baseline comparison

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FD_DIR="${SCRIPT_DIR}/../firedancer"
FUZZ_ITERS=10000000
USE_SDE=0
DO_CLONE=0
REF_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clone)      DO_CLONE=1; shift ;;
    --fuzz-iters) FUZZ_ITERS="$2"; shift 2 ;;
    --sde)        USE_SDE=1; shift ;;
    --ref-only)   REF_ONLY=1; shift ;;
    *)            echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ======================================================================
# Step 0: Check environment
# ======================================================================

echo "=== Firedancer H6 Test Suite ==="
echo "Date: $(date)"
echo "Host: $(hostname)"
echo ""

# Check AVX512 support
if grep -q avx512f /proc/cpuinfo 2>/dev/null; then
  echo "[OK] CPU supports AVX512F"
  HAS_AVX512=1
else
  echo "[WARN] CPU does NOT support AVX512F"
  HAS_AVX512=0
  if [[ $USE_SDE -eq 0 && $REF_ONLY -eq 0 ]]; then
    echo "       Use --sde for Intel SDE emulation, or --ref-only for reference-only testing"
    echo "       Falling back to reference-only mode"
    REF_ONLY=1
  fi
fi

# Check for Intel SDE
SDE_CMD=""
if [[ $USE_SDE -eq 1 ]]; then
  if command -v sde64 &>/dev/null; then
    SDE_CMD="sde64 -- "
    echo "[OK] Intel SDE found: $(which sde64)"
  elif [[ -x /opt/intel/sde/sde64 ]]; then
    SDE_CMD="/opt/intel/sde/sde64 -- "
    echo "[OK] Intel SDE found: /opt/intel/sde/sde64"
  else
    echo "[ERROR] Intel SDE not found. Install from: https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html"
    exit 1
  fi
fi

# ======================================================================
# Step 1: Get Firedancer source
# ======================================================================

if [[ $DO_CLONE -eq 1 ]] || [[ ! -d "$FD_DIR" ]]; then
  echo ""
  echo "=== Cloning Firedancer ==="
  git clone --depth 1 https://github.com/firedancer-io/firedancer.git "$FD_DIR"
fi

if [[ ! -f "$FD_DIR/Makefile" ]]; then
  echo "[ERROR] Firedancer source not found at $FD_DIR"
  exit 1
fi
echo "[OK] Firedancer source at: $FD_DIR"

# ======================================================================
# Step 2: Copy test files into the source tree
# ======================================================================

echo ""
echo "=== Copying test files ==="

TEST_SRC_DIR="$FD_DIR/src/ballet/ed25519"
cp "$SCRIPT_DIR/test_h6_vectors.c"      "$TEST_SRC_DIR/"
cp "$SCRIPT_DIR/test_h6_inline_diff.c"  "$TEST_SRC_DIR/"
cp "$SCRIPT_DIR/test_h6_fuzz.c"         "$TEST_SRC_DIR/"

# Add our tests to the build system
if ! grep -q "test_h6_vectors" "$TEST_SRC_DIR/Local.mk"; then
  cat >> "$TEST_SRC_DIR/Local.mk" << 'LOCALMK'

# H6 differential tests
$(call make-unit-test,test_h6_vectors,test_h6_vectors,fd_ballet fd_util)
$(call make-unit-test,test_h6_inline_diff,test_h6_inline_diff,fd_ballet fd_util)
$(call make-unit-test,test_h6_fuzz,test_h6_fuzz,fd_ballet fd_util)
LOCALMK
  echo "[OK] Added H6 tests to Local.mk"
fi

# ======================================================================
# Step 3: Build
# ======================================================================

echo ""
echo "=== Building Firedancer ==="
cd "$FD_DIR"

NPROC=$(nproc 2>/dev/null || echo 4)
echo "Building with -j${NPROC}..."

# Build the main library and test binaries
make -j"$NPROC" 2>&1 | tail -20

# Find the build directory
BUILD_DIR=$(ls -d build/native/*/bin 2>/dev/null | head -1 || true)
if [[ -z "$BUILD_DIR" ]]; then
  # Try common paths
  for d in build/native/gcc/bin build/native/clang/bin build/linux/gcc/bin; do
    if [[ -d "$FD_DIR/$d" ]]; then
      BUILD_DIR="$d"
      break
    fi
  done
fi

if [[ -z "$BUILD_DIR" ]]; then
  echo "[ERROR] Could not find build output directory"
  echo "Contents of build/:"
  ls -R build/ 2>/dev/null | head -30
  exit 1
fi

echo "[OK] Build directory: $BUILD_DIR"

# Verify our test binaries exist
for bin in test_h6_vectors test_h6_inline_diff test_h6_fuzz; do
  if [[ ! -x "$FD_DIR/$BUILD_DIR/$bin" ]]; then
    echo "[WARN] Binary not found: $bin (may need different build path)"
  else
    echo "[OK] Built: $bin"
  fi
done

# ======================================================================
# Step 4: Run tests
# ======================================================================

RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo ""
echo "=== Running Test 1: Static test vectors ==="
echo "Output: $RESULTS_DIR/vectors_${TIMESTAMP}.txt"
${SDE_CMD}${FD_DIR}/${BUILD_DIR}/test_h6_vectors 2>&1 | tee "$RESULTS_DIR/vectors_${TIMESTAMP}.txt"
echo ""

echo "=== Running Test 2: Inline differential test ==="
echo "Output: $RESULTS_DIR/inline_diff_${TIMESTAMP}.txt"
${SDE_CMD}${FD_DIR}/${BUILD_DIR}/test_h6_inline_diff 2>&1 | tee "$RESULTS_DIR/inline_diff_${TIMESTAMP}.txt"
echo ""

echo "=== Running Test 3: Fuzzer (${FUZZ_ITERS} iterations) ==="
echo "Output: $RESULTS_DIR/fuzz_${TIMESTAMP}.txt"
${SDE_CMD}${FD_DIR}/${BUILD_DIR}/test_h6_fuzz "$FUZZ_ITERS" 42 2>&1 | tee "$RESULTS_DIR/fuzz_${TIMESTAMP}.txt"
echo ""

# ======================================================================
# Step 5: Also run Firedancer's own test suite
# ======================================================================

echo "=== Running Firedancer's built-in Ed25519 tests ==="
for test_bin in test_ed25519 test_ed25519_signature_malleability; do
  if [[ -x "$FD_DIR/$BUILD_DIR/$test_bin" ]]; then
    echo "--- $test_bin ---"
    ${SDE_CMD}${FD_DIR}/${BUILD_DIR}/$test_bin 2>&1 | tail -5
  fi
done

if [[ $HAS_AVX512 -eq 1 ]] && [[ -x "$FD_DIR/$BUILD_DIR/test_r43x6" ]]; then
  echo "--- test_r43x6 ---"
  ${FD_DIR}/${BUILD_DIR}/test_r43x6 2>&1 | tail -5
fi

# ======================================================================
# Step 6: Summary
# ======================================================================

echo ""
echo "=========================================="
echo "=== H6 TEST SUITE COMPLETE ==="
echo "=========================================="
echo "Results saved to: $RESULTS_DIR/"
echo ""
echo "Next steps:"
echo "  1. Review results for any FAIL or DIVERGENCE lines"
echo "  2. If running ref-only, re-run on AVX512 machine and compare outputs"
echo "  3. For longer fuzzing: ./test_h6_fuzz 100000000 <random_seed>"
echo "  4. For Firedancer's own diff fuzzer (vs dalek):"
echo "     make -j CC=clang EXTRAS=fuzz BUILDDIR=clang-fuzz"
echo "     build/clang-fuzz/fuzz-test/fuzz_ed25519_sigverify_diff corpus/ -timeout=3"
echo ""
