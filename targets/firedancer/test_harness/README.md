# Firedancer Ed25519 Verification Test Harness

Standalone test harness to exercise `fd_ed25519_verify()` from the
Firedancer Solana validator implementation with arbitrary inputs.

## Architecture

Firedancer's Ed25519 implementation:

- **Verify function**: `src/ballet/ed25519/fd_ed25519_user.c`
- **Curve operations**: `src/ballet/ed25519/fd_curve25519.c` (dispatches to `ref/` or `avx512/`)
- **Field arithmetic**: `src/ballet/ed25519/fd_f25519.c` -> `ref/fd_f25519.h` (uses fiat-crypto)
- **Scalar ops**: `src/ballet/ed25519/fd_curve25519_scalar.c`
- **SHA-512**: `src/ballet/sha512/fd_sha512.c`
- **Precomputed tables**: `src/ballet/ed25519/table/fd_curve25519_table_ref.c`

### Verification logic summary

`fd_ed25519_verify()` performs these checks in order:

1. **Scalar validation**: `S < L` (group order), via `fd_curve25519_scalar_validate()`
2. **Point decompression**: decompress both `A` (pubkey) and `R` (sig first half)
   - Uses `fd_ed25519_point_frombytes_2x()` (concurrent decompression)
   - Accepts non-canonical y-coordinates (y >= p is reduced mod p)
3. **Small-order check**: rejects both small-order `A` and small-order `R`
   - Uses `fd_ed25519_affine_is_small_order()` -- checks if the affine point
     has X=0, Y=0, or Y equals known order-8 point y-coordinates
4. **Hash computation**: `k = SHA-512(R || A || msg)` reduced mod L
5. **Equation check**: `[S]B == R + [k]A'` (non-cofactored, single equation)
   - Uses `fd_ed25519_double_scalar_mul_base()` to compute `[k](-A') + [S]B`
   - Compares result against `R` using `fd_ed25519_point_eq_z1()` (extended coordinates)
   - Does NOT compress and compare bytes (no implicit canonicality check on R)

### Key behavioral observations

- **Non-cofactored verification**: uses `[S]B = R + [k]A`, not `[8][S]B = [8]R + [8][k]A`
- **Small-order rejection**: explicitly rejects small-order R and small-order A
- **Non-canonical R accepted**: the commented-out canonicality check in the source
  suggests this is deliberately deferred until Agave switches to dalek 4.x
- **Point comparison in extended coords**: avoids the field inversion of recompression

## Build Requirements

- Linux x86-64 (Firedancer targets Linux)
- GCC or Clang with C17 support
- Firedancer source tree (already present at `../firedancer/`)
- Firedancer must be built first: `cd ../firedancer && make -j`

## Building

### Option 1: Using the build script

```bash
chmod +x build.sh
./build.sh                        # auto-detect Firedancer
./build.sh /path/to/firedancer    # specify path
```

### Option 2: Using make

```bash
make                              # auto-detect
make FIREDANCER=/path/to/firedancer
```

### Option 3: Direct compilation (after building Firedancer)

```bash
FD=../firedancer
BUILD=${FD}/build/native/gcc    # adjust to your build dir

gcc -std=c17 -O2 \
    -DFD_HAS_HOSTED=1 -DFD_HAS_ATOMIC=1 -DFD_HAS_THREADS=1 \
    -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 \
    -DFD_HAS_X86=1 \
    -I${FD}/src/ballet/ed25519 -I${FD}/src/ballet/sha512 \
    -I${FD}/src/ballet -I${FD}/src/util -I${FD}/src \
    -o ed25519_test ed25519_test.c \
    ${BUILD}/lib/libfd_ballet.a \
    ${BUILD}/lib/libfd_util.a \
    -lpthread -lm
```

## Usage

### Run built-in test vectors

```bash
./ed25519_test --vectors
```

### Verify a single signature

```bash
./ed25519_test <pubkey_hex> <sig_hex> <msg_hex>
```

Example with RFC 8032 test vector 1 (empty message):

```bash
./ed25519_test \
  d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b0b8d183f8e8 \
  e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b \
  ""
```

### Read test vectors from stdin

```bash
./ed25519_test --stdin < test_vectors.txt
```

Format per line: `pubkey_hex sig_hex msg_hex [ACCEPT|REJECT]`

Lines starting with `#` are comments. Empty msg = empty hex string or omit.

### Exit codes

- `0` = signature accepted (ACCEPT)
- `1` = signature rejected (REJECT) or test failure
- `2` = usage error

## Test Vector Categories

| Category | What it tests |
|----------|--------------|
| Baseline (RFC 8032) | Known-good signatures that must accept |
| H1: Cofactor | Cofactored vs non-cofactored equation behavior |
| H2: Non-canonical R | R point with y >= p (non-canonical encoding) |
| H3: Small-order | All 8 small-order points as A and as R |
| H4: S boundary | S = L-1, L, L+1, 0, 2^255, 2^256-1 |
| H5: Decompression | Invalid point encodings (not on curve) |
| H6: Wrong message | Valid sig verified against wrong message |
| H7: Mixed order | Points with both torsion and prime-order components |

## File listing

- `ed25519_test.c` -- main test harness source
- `test_vectors.txt` -- stdin-format test vectors
- `Makefile` -- GNU Make build file
- `build.sh` -- convenience build script
- `README.md` -- this file
