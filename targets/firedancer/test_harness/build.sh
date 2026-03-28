#!/bin/bash
# build.sh -- Build the Ed25519 test harness against Firedancer
#
# Usage:
#   ./build.sh                              # auto-detect
#   ./build.sh /path/to/firedancer          # specify root
#   BUILDDIR=/path/to/build ./build.sh      # specify build dir

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIREDANCER="${1:-${SCRIPT_DIR}/../firedancer}"
FD_SRC="${FIREDANCER}/src"

echo "=== Firedancer Ed25519 Test Harness Builder ==="
echo "Firedancer root: ${FIREDANCER}"
echo "Source root:     ${FD_SRC}"

# Check that the source exists
if [ ! -f "${FD_SRC}/ballet/ed25519/fd_ed25519_user.c" ]; then
    echo "ERROR: Cannot find Firedancer source at ${FD_SRC}"
    echo "       Specify the path: ./build.sh /path/to/firedancer"
    exit 1
fi

# Try to find the build directory
if [ -z "${BUILDDIR:-}" ]; then
    for candidate in \
        "${FIREDANCER}/build/native/gcc" \
        "${FIREDANCER}/build/linux/gcc/x86_64" \
        "${FIREDANCER}/build"/*; do
        if [ -d "${candidate}/lib" ] && [ -f "${candidate}/lib/libfd_ballet.a" ]; then
            BUILDDIR="${candidate}"
            break
        fi
    done
fi

CC="${CC:-gcc}"

# Feature flags -- reference (non-AVX512) build
FD_FLAGS="-DFD_HAS_HOSTED=1 -DFD_HAS_ATOMIC=1 -DFD_HAS_THREADS=1"
FD_FLAGS="${FD_FLAGS} -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1"
FD_FLAGS="${FD_FLAGS} -DFD_HAS_X86=1 -DFD_HAS_SSE=0 -DFD_HAS_AVX=0 -DFD_HAS_AVX512=0"

# Include paths
INCLUDES="-I${FD_SRC}/ballet/ed25519 -I${FD_SRC}/ballet/sha512"
INCLUDES="${INCLUDES} -I${FD_SRC}/ballet -I${FD_SRC}/util -I${FD_SRC}"
INCLUDES="${INCLUDES} -I${FD_SRC}/util/bits -I${FD_SRC}/util/sanitize"
INCLUDES="${INCLUDES} -I${FD_SRC}/util/rng -I${FD_SRC}/util/spad"
INCLUDES="${INCLUDES} -I${FD_SRC}/util/alloc -I${FD_SRC}/util/wksp"
INCLUDES="${INCLUDES} -I${FD_SRC}/util/tpool -I${FD_SRC}/util/scratch"
INCLUDES="${INCLUDES} -I${FD_SRC}/util/shmem -I${FD_SRC}/util/tile"
INCLUDES="${INCLUDES} -I${FD_SRC}/util/log -I${FD_SRC}/util/env"
INCLUDES="${INCLUDES} -I${FD_SRC}/util/cstr -I${FD_SRC}/util/io"
INCLUDES="${INCLUDES} -I${FD_SRC}/util/checkpt -I${FD_SRC}/util/sandbox"
INCLUDES="${INCLUDES} -I${FD_SRC}/ballet/bigint"

if [ -n "${BUILDDIR:-}" ] && [ -f "${BUILDDIR}/lib/libfd_ballet.a" ]; then
    echo "Build dir:       ${BUILDDIR}"
    echo ""
    echo "Building with pre-built Firedancer libraries..."
    set -x
    ${CC} -std=c17 -O2 -Wall -Wextra \
        ${FD_FLAGS} ${INCLUDES} \
        -o "${SCRIPT_DIR}/ed25519_test" \
        "${SCRIPT_DIR}/ed25519_test.c" \
        "${BUILDDIR}/lib/libfd_ballet.a" \
        "${BUILDDIR}/lib/libfd_util.a" \
        -lpthread -lm
    set +x
else
    echo "No pre-built libraries found. Building from source..."
    echo ""

    FD_SRCS="${FD_SRC}/ballet/ed25519/fd_ed25519_user.c"
    FD_SRCS="${FD_SRCS} ${FD_SRC}/ballet/ed25519/fd_curve25519.c"
    FD_SRCS="${FD_SRCS} ${FD_SRC}/ballet/ed25519/fd_f25519.c"
    FD_SRCS="${FD_SRCS} ${FD_SRC}/ballet/ed25519/fd_curve25519_scalar.c"
    FD_SRCS="${FD_SRCS} ${FD_SRC}/ballet/ed25519/fd_curve25519_tables.c"
    FD_SRCS="${FD_SRCS} ${FD_SRC}/ballet/sha512/fd_sha512.c"

    echo "NOTE: Building from source requires that the Firedancer util"
    echo "      library is available. You may need to build Firedancer"
    echo "      first with 'make -j' in the Firedancer root directory."
    echo ""

    set -x
    ${CC} -std=c17 -O2 -Wall -Wextra \
        ${FD_FLAGS} ${INCLUDES} \
        -o "${SCRIPT_DIR}/ed25519_test" \
        "${SCRIPT_DIR}/ed25519_test.c" \
        ${FD_SRCS} \
        -lpthread -lm
    set +x
fi

echo ""
echo "=== Build successful: ${SCRIPT_DIR}/ed25519_test ==="
echo ""
echo "Usage:"
echo "  ./ed25519_test --vectors                          # run built-in tests"
echo "  ./ed25519_test <pubkey> <sig> <msg>               # single verify"
echo "  echo '<pubkey> <sig> <msg> ACCEPT' | ./ed25519_test --stdin  # from pipe"
