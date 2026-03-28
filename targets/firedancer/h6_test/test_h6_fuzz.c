/* test_h6_fuzz.c -- Continuous random differential fuzzer for Ed25519
 *
 * This program generates random Ed25519 inputs and verifies them with
 * Firedancer's implementation (whichever backend is compiled).
 * It checks:
 *   1. Verify result consistency (sign -> verify must ACCEPT)
 *   2. Field arithmetic round-trip consistency
 *   3. Point operations idempotency
 *   4. Random signature rejection (no false accepts)
 *
 * On an AVX512 machine, this tests the AVX512 code path.
 * Run output can be compared against the same fuzzer compiled with
 * FD_HAS_AVX512=0 to find divergences.
 *
 * For true differential fuzzing (both in one binary), use Firedancer's
 * own fuzz_ed25519_sigverify_diff.c which compares against ed25519-dalek.
 *
 * Build:
 *   cd firedancer && make -j
 *   # Linked against fd_ballet + fd_util
 *
 * Usage:
 *   ./test_h6_fuzz [iterations] [seed]
 *   Default: 10000000 iterations, seed=42
 */

#include "../../util/fd_util.h"
#include "fd_ed25519.h"
#include "fd_curve25519.h"
#include "fd_f25519.h"
#include "../sha512/fd_sha512.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* ======================================================================
   Random byte generation using fd_rng
   ====================================================================== */

static void
rng_bytes(fd_rng_t *rng, uchar *buf, ulong n) {
  for (ulong i = 0; i < n; i += 8) {
    ulong r = fd_rng_ulong(rng);
    ulong rem = (n - i < 8) ? (n - i) : 8;
    memcpy(buf + i, &r, rem);
  }
}

/* ======================================================================
   Test 1: Sign-then-verify consistency
   ====================================================================== */

static ulong
fuzz_sign_verify(fd_rng_t *rng, fd_sha512_t *sha, ulong iters) {
  ulong fail = 0;

  for (ulong i = 0; i < iters; i++) {
    uchar prv[32], pub[32], sig[64];
    uchar msg[128];
    ulong msg_sz = fd_rng_ulong(rng) % 128;

    rng_bytes(rng, prv, 32);
    rng_bytes(rng, msg, msg_sz);

    fd_ed25519_public_from_private(pub, prv, sha);
    fd_ed25519_sign(sig, msg, msg_sz, pub, prv, sha);

    int result = fd_ed25519_verify(msg, msg_sz, sig, pub, sha);
    if (result != FD_ED25519_SUCCESS) {
      printf("[DIVERGENCE] sign-verify failed at iter %lu\n", i);
      printf("  prv: "); for(int j=0;j<32;j++) printf("%02x",prv[j]); printf("\n");
      printf("  pub: "); for(int j=0;j<32;j++) printf("%02x",pub[j]); printf("\n");
      printf("  sig: "); for(int j=0;j<64;j++) printf("%02x",sig[j]); printf("\n");
      printf("  msg(%lu): ", msg_sz); for(ulong j=0;j<msg_sz;j++) printf("%02x",msg[j]); printf("\n");
      printf("  result: %d (%s)\n", result, fd_ed25519_strerror(result));
      fail++;
    }

    if (i > 0 && i % 1000000 == 0) {
      printf("  sign-verify: %lu/%lu iterations, %lu failures\n", i, iters, fail);
    }
  }
  return fail;
}

/* ======================================================================
   Test 2: Random signature rejection (no false accepts)
   ====================================================================== */

static ulong
fuzz_random_reject(fd_rng_t *rng, fd_sha512_t *sha, ulong iters) {
  ulong fail = 0;
  ulong accept_count = 0;

  for (ulong i = 0; i < iters; i++) {
    uchar pub[32], sig[64];
    uchar msg[64];
    ulong msg_sz = fd_rng_ulong(rng) % 64;

    rng_bytes(rng, pub, 32);
    rng_bytes(rng, sig, 64);
    rng_bytes(rng, msg, msg_sz);

    int result = fd_ed25519_verify(msg, msg_sz, sig, pub, sha);
    if (result == FD_ED25519_SUCCESS) {
      /* Random bytes accepting is astronomically unlikely (2^-128 or worse).
         If this happens, it's either a bug or we hit the lottery. */
      printf("[SUSPICIOUS] random sig ACCEPTED at iter %lu\n", i);
      printf("  pub: "); for(int j=0;j<32;j++) printf("%02x",pub[j]); printf("\n");
      printf("  sig: "); for(int j=0;j<64;j++) printf("%02x",sig[j]); printf("\n");
      accept_count++;
    }

    if (i > 0 && i % 1000000 == 0) {
      printf("  random-reject: %lu/%lu iterations, %lu suspicious accepts\n", i, iters, accept_count);
    }
  }
  return fail;
}

/* ======================================================================
   Test 3: Field arithmetic consistency
   ====================================================================== */

static ulong
fuzz_field_ops(fd_rng_t *rng, ulong iters) {
  ulong fail = 0;

  for (ulong i = 0; i < iters; i++) {
    uchar a_bytes[32], b_bytes[32];
    rng_bytes(rng, a_bytes, 32);
    rng_bytes(rng, b_bytes, 32);
    a_bytes[31] &= 0x7f; /* Clear high bit for valid field element */
    b_bytes[31] &= 0x7f;

    fd_f25519_t a[1], b[1], r[1];
    fd_f25519_frombytes(a, a_bytes);
    fd_f25519_frombytes(b, b_bytes);

    /* Test: tobytes(mul(a,b)) should be canonical */
    fd_f25519_mul(r, a, b);
    uchar out1[32], out2[32];
    fd_f25519_tobytes(out1, r);
    fd_f25519_t check[1];
    fd_f25519_frombytes(check, out1);
    fd_f25519_tobytes(out2, check);
    if (memcmp(out1, out2, 32) != 0) {
      printf("[FAIL] field mul non-canonical at iter %lu\n", i);
      fail++;
    }

    /* Test: tobytes(sqr(a)) should be canonical */
    fd_f25519_sqr(r, a);
    fd_f25519_tobytes(out1, r);
    fd_f25519_frombytes(check, out1);
    fd_f25519_tobytes(out2, check);
    if (memcmp(out1, out2, 32) != 0) {
      printf("[FAIL] field sqr non-canonical at iter %lu\n", i);
      fail++;
    }

    /* Test: a * 1 == a */
    fd_f25519_mul(r, a, fd_f25519_one);
    uchar out_a[32], out_r[32];
    fd_f25519_tobytes(out_a, a);
    fd_f25519_tobytes(out_r, r);
    if (memcmp(out_a, out_r, 32) != 0) {
      printf("[FAIL] a*1 != a at iter %lu\n", i);
      fail++;
    }

    /* Test: a + 0 == a */
    fd_f25519_add(r, a, fd_f25519_zero);
    fd_f25519_tobytes(out_r, r);
    if (memcmp(out_a, out_r, 32) != 0) {
      printf("[FAIL] a+0 != a at iter %lu\n", i);
      fail++;
    }

    /* Test: a - a == 0 */
    fd_f25519_sub(r, a, a);
    if (!fd_f25519_is_zero(r)) {
      printf("[FAIL] a-a != 0 at iter %lu\n", i);
      fail++;
    }

    /* Test: a * a == sqr(a) */
    fd_f25519_t mul_aa[1], sqr_a[1];
    fd_f25519_mul(mul_aa, a, a);
    fd_f25519_sqr(sqr_a, a);
    uchar out_mul[32], out_sqr[32];
    fd_f25519_tobytes(out_mul, mul_aa);
    fd_f25519_tobytes(out_sqr, sqr_a);
    if (memcmp(out_mul, out_sqr, 32) != 0) {
      printf("[FAIL] a*a != sqr(a) at iter %lu\n", i);
      printf("  a:      "); for(int j=0;j<32;j++) printf("%02x",a_bytes[j]); printf("\n");
      printf("  a*a:    "); for(int j=0;j<32;j++) printf("%02x",out_mul[j]); printf("\n");
      printf("  sqr(a): "); for(int j=0;j<32;j++) printf("%02x",out_sqr[j]); printf("\n");
      fail++;
    }

    if (i > 0 && i % 1000000 == 0) {
      printf("  field-ops: %lu/%lu iterations, %lu failures\n", i, iters, fail);
    }
  }
  return fail;
}

/* ======================================================================
   Test 4: Point decompression round-trip
   ====================================================================== */

static ulong
fuzz_point_roundtrip(fd_rng_t *rng, ulong iters) {
  ulong fail = 0;
  ulong on_curve = 0;

  for (ulong i = 0; i < iters; i++) {
    uchar bytes[32];
    rng_bytes(rng, bytes, 32);
    bytes[31] &= 0x7f; /* Clear sign bit initially */

    /* Try with sign bit 0 */
    fd_ed25519_point_t pt[1];
    if (fd_ed25519_point_frombytes(pt, bytes)) {
      on_curve++;
      uchar out[32];
      fd_ed25519_point_tobytes(out, pt);

      /* Decompress again */
      fd_ed25519_point_t pt2[1];
      if (!fd_ed25519_point_frombytes(pt2, out)) {
        printf("[FAIL] round-trip decompress failed at iter %lu\n", i);
        fail++;
        continue;
      }

      uchar out2[32];
      fd_ed25519_point_tobytes(out2, pt2);
      if (memcmp(out, out2, 32) != 0) {
        printf("[FAIL] point tobytes not idempotent at iter %lu\n", i);
        fail++;
      }
    }

    /* Try with sign bit 1 */
    bytes[31] |= 0x80;
    if (fd_ed25519_point_frombytes(pt, bytes)) {
      on_curve++;
      uchar out[32];
      fd_ed25519_point_tobytes(out, pt);

      fd_ed25519_point_t pt2[1];
      if (!fd_ed25519_point_frombytes(pt2, out)) {
        printf("[FAIL] round-trip decompress (sign=1) failed at iter %lu\n", i);
        fail++;
        continue;
      }

      uchar out2[32];
      fd_ed25519_point_tobytes(out2, pt2);
      if (memcmp(out, out2, 32) != 0) {
        printf("[FAIL] point tobytes (sign=1) not idempotent at iter %lu\n", i);
        fail++;
      }
    }

    if (i > 0 && i % 1000000 == 0) {
      printf("  point-roundtrip: %lu/%lu iterations, %lu on-curve, %lu failures\n",
             i, iters, on_curve, fail);
    }
  }
  printf("  point-roundtrip: %lu on-curve out of %lu attempts\n", on_curve, iters * 2);
  return fail;
}

/* ======================================================================
   Test 5: pow22523 and sqrt_ratio consistency
   ====================================================================== */

static ulong
fuzz_sqrt_ratio(fd_rng_t *rng, ulong iters) {
  ulong fail = 0;

  for (ulong i = 0; i < iters; i++) {
    uchar u_bytes[32], v_bytes[32];
    rng_bytes(rng, u_bytes, 32);
    rng_bytes(rng, v_bytes, 32);
    u_bytes[31] &= 0x7f;
    v_bytes[31] &= 0x7f;

    fd_f25519_t u[1], v[1], r[1];
    fd_f25519_frombytes(u, u_bytes);
    fd_f25519_frombytes(v, v_bytes);

    /* Skip if v == 0 */
    if (fd_f25519_is_zero(v)) continue;

    int was_square = fd_f25519_sqrt_ratio(r, u, v);

    if (was_square) {
      /* Verify: v * r^2 == u */
      fd_f25519_t r2[1], vr2[1];
      fd_f25519_sqr(r2, r);
      fd_f25519_mul(vr2, v, r2);

      uchar out_u[32], out_vr2[32];
      fd_f25519_tobytes(out_u, u);
      fd_f25519_tobytes(out_vr2, vr2);

      if (memcmp(out_u, out_vr2, 32) != 0) {
        printf("[FAIL] sqrt_ratio: v*r^2 != u at iter %lu\n", i);
        printf("  u:     "); for(int j=0;j<32;j++) printf("%02x",out_u[j]); printf("\n");
        printf("  v*r^2: "); for(int j=0;j<32;j++) printf("%02x",out_vr2[j]); printf("\n");
        fail++;
      }
    }

    if (i > 0 && i % 1000000 == 0) {
      printf("  sqrt-ratio: %lu/%lu iterations, %lu failures\n", i, iters, fail);
    }
  }
  return fail;
}

/* ======================================================================
   Main
   ====================================================================== */

int main(int argc, char **argv) {
  fd_boot(&argc, &argv);

  ulong iters = 10000000UL;
  uint  seed  = 42;

  if (argc > 1) iters = strtoul(argv[1], NULL, 10);
  if (argc > 2) seed  = (uint)strtoul(argv[2], NULL, 10);

  printf("=== Firedancer H6 Fuzzer ===\n");
  printf("Implementation: %s\n",
#if FD_HAS_AVX512
    "AVX512"
#else
    "Reference"
#endif
  );
  printf("Iterations: %lu, Seed: %u\n\n", iters, seed);

  fd_rng_t _rng[1];
  fd_rng_t *rng = fd_rng_join(fd_rng_new(_rng, seed, 0UL));

  fd_sha512_t _sha[1];
  fd_sha512_t *sha = fd_sha512_join(fd_sha512_new(_sha));

  ulong total_fail = 0;

  printf("--- Test 1: Sign-then-verify (%lu iterations) ---\n", iters / 10);
  total_fail += fuzz_sign_verify(rng, sha, iters / 10);

  printf("\n--- Test 2: Random signature rejection (%lu iterations) ---\n", iters);
  total_fail += fuzz_random_reject(rng, sha, iters);

  printf("\n--- Test 3: Field arithmetic consistency (%lu iterations) ---\n", iters);
  total_fail += fuzz_field_ops(rng, iters);

  printf("\n--- Test 4: Point decompression round-trip (%lu iterations) ---\n", iters / 10);
  total_fail += fuzz_point_roundtrip(rng, iters / 10);

  printf("\n--- Test 5: sqrt_ratio consistency (%lu iterations) ---\n", iters / 10);
  total_fail += fuzz_sqrt_ratio(rng, iters / 10);

  printf("\n=== FINAL: %lu total failures ===\n", total_fail);

  fd_sha512_delete(fd_sha512_leave(sha));
  fd_rng_delete(fd_rng_leave(rng));
  fd_halt();
  return total_fail > 0 ? 1 : 0;
}
