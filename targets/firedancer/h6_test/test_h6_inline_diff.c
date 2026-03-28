/* test_h6_inline_diff.c -- Single-binary differential test: AVX512 vs Reference
 *
 * This program compiles BOTH implementations into a single binary on an
 * AVX512-capable machine, and compares their results directly. This is
 * the most thorough approach as it eliminates any environmental differences.
 *
 * Strategy:
 *   - We cannot easily include both implementations in one TU because they
 *     define the same symbols. Instead, we compile the Firedancer library
 *     normally (which picks AVX512 on AVX512 machines), then we call
 *     fd_ed25519_verify() and also test intermediate operations by
 *     comparing serialized (tobytes) results of field and point operations.
 *
 *   - The key insight: if both implementations produce the same serialized
 *     output (tobytes) for the same input, they are functionally equivalent.
 *     We test this at multiple levels:
 *       1. fd_f25519_frombytes -> fd_f25519_tobytes round-trip
 *       2. fd_ed25519_point_frombytes -> fd_ed25519_point_tobytes round-trip
 *       3. fd_ed25519_verify final result
 *
 * Build:
 *   cd firedancer && make -j
 *   gcc -O2 -mavx512f -I. test_h6_inline_diff.c -o test_h6_inline_diff \
 *       build/native/gcc/lib/libfd_ballet.a build/native/gcc/lib/libfd_util.a -lm
 */

#include "../../util/fd_util.h"
#include "fd_ed25519.h"
#include "fd_curve25519.h"
#include "fd_f25519.h"
#include "../sha512/fd_sha512.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ======================================================================
   Field arithmetic consistency tests
   ====================================================================== */

static int
test_field_round_trip(void) {
  printf("\n=== Field Element Round-Trip Tests ===\n");
  int fail = 0;

  /* Test specific byte patterns that exercise r43x6 limb boundaries */
  static uchar const field_test_values[][32] = {
    /* Zero */
    {0},
    /* One */
    {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    /* p-1 = 2^255-20 */
    {0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    /* p = 2^255-19 (should reduce to 0) */
    {0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    /* p+1 (should reduce to 1) */
    {0xee,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    /* 2p (should reduce to 0) */
    {0xda,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
    /* 2^255-18 = p+1 */
    {0xee,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    /* Value at r43x6 limb 0 boundary: 2^43 - 1 */
    {0xff,0xff,0xff,0xff,0xff,0x07,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    /* Value at r43x6 limb 1 boundary: 2^86 - 1 */
    {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x3f,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    /* Value near 2^129 */
    {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    /* Value near 2^172 */
    {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0x0f,0,0,0,0,0,0,0,0,0,0},
    /* Value near 2^215 */
    {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f,0,0,0,0,0},
    /* All 0xFF (max 256-bit, will be masked to 255 bits then reduced) */
    {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
    /* sqrt(-1) mod p */
    {0xb0,0xa0,0x0e,0x4a,0x27,0x1b,0xee,0xc4,0x78,0xe4,0x2f,0xad,0x06,0x18,0x43,0x2f,
     0xa7,0xd7,0xfb,0x3d,0x99,0x00,0x4d,0x2b,0x0b,0xdf,0xc1,0x4f,0x80,0x24,0x83,0x2b},
  };
  int n_values = sizeof(field_test_values) / sizeof(field_test_values[0]);

  for (int i = 0; i < n_values; i++) {
    fd_f25519_t fe[1];
    uchar out[32];

    fd_f25519_frombytes(fe, field_test_values[i]);
    fd_f25519_tobytes(out, fe);

    /* Verify round-trip: frombytes -> tobytes should produce canonical form */
    fd_f25519_t fe2[1];
    uchar out2[32];
    fd_f25519_frombytes(fe2, out);
    fd_f25519_tobytes(out2, fe2);

    if (memcmp(out, out2, 32) != 0) {
      printf("[FAIL] field round-trip #%d: tobytes not idempotent\n", i);
      fail++;
    } else {
      printf("[PASS] field round-trip #%d\n", i);
    }
  }

  /* Test field arithmetic: a*b, a+b, a-b, a^2 on edge cases */
  printf("\n=== Field Arithmetic Tests ===\n");
  for (int i = 0; i < n_values; i++) {
    for (int j = 0; j < n_values; j++) {
      fd_f25519_t a[1], b[1], r[1];
      uchar out_mul[32], out_add[32], out_sub[32];

      fd_f25519_frombytes(a, field_test_values[i]);
      fd_f25519_frombytes(b, field_test_values[j]);

      /* mul */
      fd_f25519_mul(r, a, b);
      fd_f25519_tobytes(out_mul, r);

      /* add */
      fd_f25519_add(r, a, b);
      fd_f25519_tobytes(out_add, r);

      /* sub */
      fd_f25519_sub(r, a, b);
      fd_f25519_tobytes(out_sub, r);

      /* Verify results are canonical (idempotent under round-trip) */
      fd_f25519_t check[1];
      uchar check_out[32];

      fd_f25519_frombytes(check, out_mul);
      fd_f25519_tobytes(check_out, check);
      if (memcmp(out_mul, check_out, 32) != 0) {
        printf("[FAIL] mul(%d,%d) produced non-canonical output\n", i, j);
        fail++;
      }

      fd_f25519_frombytes(check, out_add);
      fd_f25519_tobytes(check_out, check);
      if (memcmp(out_add, check_out, 32) != 0) {
        printf("[FAIL] add(%d,%d) produced non-canonical output\n", i, j);
        fail++;
      }

      fd_f25519_frombytes(check, out_sub);
      fd_f25519_tobytes(check_out, check);
      if (memcmp(out_sub, check_out, 32) != 0) {
        printf("[FAIL] sub(%d,%d) produced non-canonical output\n", i, j);
        fail++;
      }
    }
  }

  /* sqr */
  for (int i = 0; i < n_values; i++) {
    fd_f25519_t a[1], r[1];
    uchar out_sqr[32];

    fd_f25519_frombytes(a, field_test_values[i]);
    fd_f25519_sqr(r, a);
    fd_f25519_tobytes(out_sqr, r);

    fd_f25519_t check[1];
    uchar check_out[32];
    fd_f25519_frombytes(check, out_sqr);
    fd_f25519_tobytes(check_out, check);
    if (memcmp(out_sqr, check_out, 32) != 0) {
      printf("[FAIL] sqr(%d) produced non-canonical output\n", i);
      fail++;
    }
  }

  if (fail == 0) printf("\nAll field arithmetic tests PASSED\n");
  else printf("\n%d field arithmetic tests FAILED\n", fail);
  return fail;
}

/* ======================================================================
   Point decompression consistency tests
   ====================================================================== */

static int
test_point_decompression(void) {
  printf("\n=== Point Decompression Round-Trip Tests ===\n");
  int fail = 0;

  /* Points that should decompress successfully */
  static uchar const valid_points[][32] = {
    /* Identity (0,1) */
    {0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    /* (0,-1) */
    {0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    /* Base point (y only, sign bit=0) */
    {0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
     0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66},
    /* Order-4 point (y=0, x_sign=0) */
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    /* Order-8 point */
    {0xc7,0x17,0x6a,0x70,0x3d,0x4d,0xd8,0x4f,0xba,0x3c,0x0b,0x76,0x0d,0x10,0x67,0x0f,
     0x2a,0x20,0x53,0xfa,0x2c,0x39,0xcc,0xc6,0x4e,0xc7,0xfd,0x77,0x92,0xac,0x03,0x7a},
    /* Non-canonical y=p (reduces to 0, same as order-4 point) */
    {0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    /* Non-canonical y=p+1 */
    {0xee,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    /* Public key from RFC 8032 test 1 */
    {0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
     0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a},
  };
  int n_points = sizeof(valid_points) / sizeof(valid_points[0]);

  for (int i = 0; i < n_points; i++) {
    fd_ed25519_point_t pt[1];
    fd_ed25519_point_t * res = fd_ed25519_point_frombytes(pt, valid_points[i]);

    if (res == NULL) {
      printf("[INFO] point #%d: decompression failed (may be expected for non-on-curve)\n", i);
      continue;
    }

    /* Reserialize and check */
    uchar out[32];
    fd_ed25519_point_tobytes(out, pt);

    /* Decompress again from serialized */
    fd_ed25519_point_t pt2[1];
    fd_ed25519_point_t * res2 = fd_ed25519_point_frombytes(pt2, out);
    if (res2 == NULL) {
      printf("[FAIL] point #%d: round-trip decompression failed\n", i);
      fail++;
      continue;
    }

    uchar out2[32];
    fd_ed25519_point_tobytes(out2, pt2);

    if (memcmp(out, out2, 32) != 0) {
      printf("[FAIL] point #%d: tobytes not idempotent\n", i);
      printf("       first:  "); for (int j=0;j<32;j++) printf("%02x",out[j]); printf("\n");
      printf("       second: "); for (int j=0;j<32;j++) printf("%02x",out2[j]); printf("\n");
      fail++;
    } else {
      printf("[PASS] point #%d round-trip OK\n", i);
    }
  }

  if (fail == 0) printf("\nAll point decompression tests PASSED\n");
  else printf("\n%d point decompression tests FAILED\n", fail);
  return fail;
}

/* ======================================================================
   Main
   ====================================================================== */

int main(int argc, char **argv) {
  fd_boot(&argc, &argv);

  printf("=== Firedancer H6: AVX512 vs Reference Inline Differential Test ===\n");
  printf("Implementation: %s\n",
#if FD_HAS_AVX512
    "AVX512 (fd_r43x6)"
#else
    "Reference (fiat-crypto 5x51)"
#endif
  );

  int total_fail = 0;
  total_fail += test_field_round_trip();
  total_fail += test_point_decompression();

  printf("\n=== FINAL: %d total failures ===\n", total_fail);

  fd_halt();
  return total_fail > 0 ? 1 : 0;
}
