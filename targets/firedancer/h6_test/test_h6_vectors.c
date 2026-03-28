/* test_h6_vectors.c -- Differential test: AVX512 vs Reference Ed25519 in Firedancer
 *
 * This program is compiled TWICE against the Firedancer codebase:
 *   1) With FD_HAS_AVX512=0 (reference implementation)
 *   2) With FD_HAS_AVX512=1 (AVX512 implementation)
 * Both binaries are run on the SAME test vectors and results compared.
 *
 * Alternatively, on an AVX512 machine we can link both implementations
 * into a single binary by using the approach in test_h6_inline_diff.c.
 *
 * Build (see test_h6_avx512.sh for automated build):
 *   cd firedancer
 *   make -j test_h6_vectors EXTRAS="h6"
 */

#include "../../util/fd_util.h"
#include "fd_ed25519.h"
#include "fd_curve25519.h"
#include "../sha512/fd_sha512.h"
#include "../hex/fd_hex.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ======================================================================
   Test vector structure
   ====================================================================== */

typedef struct {
  char const * id;
  char const * pubkey_hex;     /* 64 hex chars = 32 bytes */
  char const * sig_hex;        /* 128 hex chars = 64 bytes */
  char const * msg_hex;        /* variable length, empty string = empty msg */
  int          expected;       /* 1=ACCEPT, 0=REJECT, -1=unknown */
} test_vector_t;

/* ======================================================================
   ALL test vectors from H1-H5 plus edge-case field values
   ====================================================================== */

static test_vector_t const test_vectors[] = {

  /* --- Baseline valid signatures (RFC 8032) --- */
  { "baseline_valid_1",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "", 1 },
  { "baseline_valid_2",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    "72", 1 },
  { "baseline_valid_3",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    "af82", 1 },

  /* --- Baseline rejects --- */
  { "baseline_wrong_msg",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "deadbeef", 0 },
  { "baseline_wrong_pubkey",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "", 0 },

  /* --- H3: Small-order pubkeys (all 8 torsion points) --- */
  { "H3_pubkey_identity",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H3_pubkey_order2",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H3_pubkey_order4a",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H3_pubkey_order4b",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H3_pubkey_order8a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H3_pubkey_order8b",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H3_pubkey_order8c",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H3_pubkey_order8d",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },

  /* --- H3: Small-order R in signature --- */
  { "H3_R_identity",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H3_R_order2",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H3_R_order4",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H3_R_order8",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },

  /* --- H4: Scalar S boundary values --- */
  { "H4_S_zero",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901550000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H4_S_one",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901550100000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H4_S_eq_L_minus_1",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
    "", 0 },
  { "H4_S_eq_L",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
    "", 0 },
  { "H4_S_eq_L_plus_1",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
    "", 0 },
  { "H4_S_max_255bit",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "", 0 },
  { "H4_S_all_ff",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "", 0 },

  /* --- H2: Non-canonical R y-coordinate (p+0 through p+18) --- */
  { "H2_R_y_p_plus_0",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H2_R_y_p_plus_1",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H2_R_y_p_plus_2",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H2_R_y_p_plus_3",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H2_R_y_p_plus_9",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H2_R_y_p_plus_18",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },

  /* --- H2: Non-canonical pubkey y-coordinate --- */
  { "H2_pubkey_y_eq_p",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "", -1 },
  { "H2_pubkey_y_p_plus_1",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },
  { "H2_pubkey_y_p_plus_3",
    "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "", 0 },

  /* --- Invalid point encodings --- */
  { "pubkey_not_on_curve",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "", 0 },
  { "R_not_on_curve",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "", 0 },

  /* --- H6-specific: Field edge-case values for R y-coordinate ---
   * These specifically target the r43x6 representation boundaries.
   * Values near 2^43, 2^86, 2^129, 2^172, 2^215 limb boundaries
   * might behave differently in carry propagation.
   */

  /* y = 2^43 - 1 = 0x000007ffffffffff (limb 0 all ones) */
  { "H6_R_y_limb0_max",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "ffffffffff070000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },

  /* y = 2^86 - 1 (limbs 0,1 all ones) */
  { "H6_R_y_limb01_max",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "ffffffffffff3f00000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },

  /* y = 2^129 - 1 (limbs 0,1,2 all ones) */
  { "H6_R_y_limb012_max",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "ffffffffffffffffffffffffffffffff01000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },

  /* y = 2^172 - 1 (limbs 0-3 all ones) */
  { "H6_R_y_limb0123_max",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "ffffffffffffffffffffffffffffffffffffffffffff0f0000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },

  /* y = 2^215 - 1 (limbs 0-4 all ones) */
  { "H6_R_y_limb01234_max",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffff7f00000000"
    "0000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },

  /* y = 2^254 - 1 (maximum 255-bit value with high bit clear) */
  { "H6_R_y_max_254bit",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"
    "0000000000000000000000000000000000000000000000000000000000000000",
    "", 0 },

  { NULL, NULL, NULL, NULL, 0 } /* sentinel */
};

/* ======================================================================
   Hex decode helper
   ====================================================================== */

static int hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static ulong hex_decode(uchar *out, char const *hex, ulong max_out) {
  if (!hex) return 0;
  ulong len = strlen(hex);
  if (len % 2 != 0) return 0;
  ulong n = len / 2;
  if (n > max_out) n = max_out;
  for (ulong i = 0; i < n; i++) {
    int hi = hex_val(hex[2*i]);
    int lo = hex_val(hex[2*i+1]);
    if (hi < 0 || lo < 0) return 0;
    out[i] = (uchar)((hi << 4) | lo);
  }
  return n;
}

/* ======================================================================
   Main
   ====================================================================== */

int main(int argc, char **argv) {
  fd_boot(&argc, &argv);

  fd_sha512_t _sha[1];
  fd_sha512_t *sha = fd_sha512_join(fd_sha512_new(_sha));

  int pass = 0;
  int fail = 0;
  int skip = 0;

  printf("=== Firedancer H6 Test: Ed25519 Verify with %s implementation ===\n",
#if FD_HAS_AVX512
         "AVX512"
#else
         "REFERENCE"
#endif
  );
  printf("Vector count: ");
  int count = 0;
  for (test_vector_t const *v = test_vectors; v->id; v++) count++;
  printf("%d\n\n", count);

  for (test_vector_t const *v = test_vectors; v->id; v++) {
    uchar pubkey[32];
    uchar sig[64];
    uchar msg[1024];

    hex_decode(pubkey, v->pubkey_hex, 32);
    hex_decode(sig, v->sig_hex, 64);
    ulong msg_sz = hex_decode(msg, v->msg_hex, sizeof(msg));

    int result = fd_ed25519_verify(msg, msg_sz, sig, pubkey, sha);
    int accepted = (result == FD_ED25519_SUCCESS) ? 1 : 0;
    char const *result_str = accepted ? "ACCEPT" : "REJECT";

    /* Also test point decompression separately */
    fd_ed25519_point_t R_pt[1], A_pt[1];
    int R_decomp = (fd_ed25519_point_frombytes(R_pt, sig) != NULL) ? 1 : 0;
    int A_decomp = (fd_ed25519_point_frombytes(A_pt, pubkey) != NULL) ? 1 : 0;

    /* Serialize decompressed points back to check round-trip */
    uchar R_reser[32] = {0};
    uchar A_reser[32] = {0};
    if (R_decomp) fd_ed25519_point_tobytes(R_reser, R_pt);
    if (A_decomp) fd_ed25519_point_tobytes(A_reser, A_pt);

    if (v->expected == -1) {
      printf("[SKIP] %-40s => %s (R_decomp=%d A_decomp=%d) (no expected)\n",
             v->id, result_str, R_decomp, A_decomp);
      skip++;
    } else if (accepted == v->expected) {
      printf("[PASS] %-40s => %s (R_decomp=%d A_decomp=%d)\n",
             v->id, result_str, R_decomp, A_decomp);
      pass++;
    } else {
      printf("[FAIL] %-40s => %s (expected %s) (R_decomp=%d A_decomp=%d)\n",
             v->id, result_str, v->expected ? "ACCEPT" : "REJECT", R_decomp, A_decomp);
      fail++;
    }

    /* Print round-trip info for debugging */
    printf("       R_reser: ");
    for (int i = 0; i < 32; i++) printf("%02x", R_reser[i]);
    printf("\n       A_reser: ");
    for (int i = 0; i < 32; i++) printf("%02x", A_reser[i]);
    printf("\n");
  }

  printf("\n=== Summary: %d passed, %d failed, %d skipped (of %d total) ===\n",
         pass, fail, skip, pass + fail + skip);

  fd_sha512_delete(fd_sha512_leave(sha));
  fd_halt();
  return fail > 0 ? 1 : 0;
}
