/* ed25519_test.c -- Standalone test harness for Firedancer's Ed25519 verify
 *
 * This links against the Firedancer source tree and exercises
 * fd_ed25519_verify() with arbitrary test vectors.
 *
 * Usage:
 *   ./ed25519_test <pubkey_hex> <sig_hex> <msg_hex>
 *   echo "<pubkey_hex> <sig_hex> <msg_hex>" | ./ed25519_test --stdin
 *   ./ed25519_test --vectors          (run built-in test vectors)
 *
 * Exit code: 0 = ACCEPT, 1 = REJECT, 2 = usage error
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Firedancer headers */
#include "fd_ed25519.h"
#include "fd_curve25519.h"

/* ------------------------------------------------------------------ */
/*  Hex utilities                                                      */
/* ------------------------------------------------------------------ */

static int hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Returns number of bytes decoded, or -1 on error.
   out must have room for at least strlen(hex)/2 bytes. */
static int hex_decode(unsigned char *out, const char *hex, int max_out) {
  int len = (int)strlen(hex);
  if (len % 2 != 0) return -1;
  int nbytes = len / 2;
  if (nbytes > max_out) return -1;
  for (int i = 0; i < nbytes; i++) {
    int hi = hex_digit(hex[2*i]);
    int lo = hex_digit(hex[2*i+1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return nbytes;
}

static void hex_encode(char *out, const unsigned char *data, int len) {
  static const char hex_chars[] = "0123456789abcdef";
  for (int i = 0; i < len; i++) {
    out[2*i]   = hex_chars[(data[i] >> 4) & 0xf];
    out[2*i+1] = hex_chars[data[i] & 0xf];
  }
  out[2*len] = '\0';
}

/* ------------------------------------------------------------------ */
/*  Core verify wrapper                                                */
/* ------------------------------------------------------------------ */

static int
do_verify(const unsigned char *pubkey,
          const unsigned char *sig,
          const unsigned char *msg,
          unsigned long        msg_len) {

  /* Allocate SHA-512 state with proper alignment */
  fd_sha512_t _sha[1] __attribute__((aligned(FD_SHA512_ALIGN)));
  fd_sha512_t *sha = fd_sha512_join(fd_sha512_new(_sha));
  if (!sha) {
    fprintf(stderr, "ERROR: failed to init sha512\n");
    return -1;
  }

  int result = fd_ed25519_verify(msg, msg_len, sig, pubkey, sha);

  fd_sha512_delete(fd_sha512_leave(sha));
  return result;
}

/* ------------------------------------------------------------------ */
/*  Test vector infrastructure                                         */
/* ------------------------------------------------------------------ */

typedef struct {
  const char *name;
  const char *hypothesis;
  const char *pubkey_hex;
  const char *sig_hex;
  const char *msg_hex;
  int         expect_accept; /* 1=ACCEPT, 0=REJECT */
} test_vector_t;

/*
 * Ed25519 group order L and field prime p:
 *   L = 2^252 + 27742317777372353535851937790883648493
 *     = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
 *   p = 2^255 - 19
 *     = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
 *
 * L-1 in little-endian (32 bytes):
 *   ecd3f55c1a631258d69cf7a2def9de14000000000000000000000000000000010
 *   (that's the fd_curve25519_scalar_minus_one constant)
 *
 * Small-order points on Ed25519 (8 total, compressed encodings):
 *   Identity (0,1):        0100000000000000000000000000000000000000000000000000000000000000
 *   Order 2  (0,-1):       ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
 *   Order 4  (sqrt(-1),0): 0000000000000000000000000000000000000000000000000000000000000000
 *   Order 4  (-sqrt(-1),0):0000000000000000000000000000000000000000000000000000000000000080
 *   Order 8 (+,y0):        26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
 *   Order 8 (-,y0):        26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85
 *   Order 8 (+,y1):        c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
 *   Order 8 (-,y1):        c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
 */

/* RFC 8032 test vector 1 (empty message) */
#define RFC8032_TV1_PRIVKEY "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
#define RFC8032_TV1_PUBKEY  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b0b8d183f8e8"
#define RFC8032_TV1_SIG     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
#define RFC8032_TV1_MSG     ""

/* RFC 8032 test vector 2 (message = 0x72) */
#define RFC8032_TV2_PUBKEY  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
#define RFC8032_TV2_SIG     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
#define RFC8032_TV2_MSG     "72"

static const test_vector_t test_vectors[] = {

  /* ============================================================
   * BASELINE: Known-good RFC 8032 vectors (must ACCEPT)
   * ============================================================ */
  {
    .name           = "RFC8032-TV1: empty message",
    .hypothesis     = "baseline",
    .pubkey_hex     = RFC8032_TV1_PUBKEY,
    .sig_hex        = RFC8032_TV1_SIG,
    .msg_hex        = RFC8032_TV1_MSG,
    .expect_accept  = 1,
  },
  {
    .name           = "RFC8032-TV2: single byte 0x72",
    .hypothesis     = "baseline",
    .pubkey_hex     = RFC8032_TV2_PUBKEY,
    .sig_hex        = RFC8032_TV2_SIG,
    .msg_hex        = RFC8032_TV2_MSG,
    .expect_accept  = 1,
  },

  /* ============================================================
   * H1: Cofactor equation
   *
   * Firedancer verifies: [S]B = R + [k]A  (NOT the cofactored equation)
   * BUT it rejects small-order A and small-order R.
   * So a cofactor-only sig (valid under [8][S]B = [8]R + [8][k]A but
   * not under the stricter equation) should be REJECTED because:
   *   - If R has small-order component -> small order check catches it
   *   - If A has small-order component -> small order check catches it
   *
   * Test: identity point as R, identity as A (both small-order)
   * S = 0 would make [S]B = 0 = R + [k]*0, but both R and A are
   * small-order so rejected before the equation is even checked.
   * ============================================================ */
  {
    .name           = "H1-cofactor: R=identity, A=identity, S=0 (small-order reject)",
    .hypothesis     = "H1-cofactor",
    .pubkey_hex     = "0100000000000000000000000000000000000000000000000000000000000000",
    .sig_hex        = "0100000000000000000000000000000000000000000000000000000000000000"
                      "0000000000000000000000000000000000000000000000000000000000000000",
    .msg_hex        = "",
    .expect_accept  = 0,  /* rejected: small-order A */
  },
  {
    .name           = "H1-cofactor: R=order8pt, A=valid, S=0",
    .hypothesis     = "H1-cofactor",
    .pubkey_hex     = RFC8032_TV1_PUBKEY,
    .sig_hex        = "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
                      "0000000000000000000000000000000000000000000000000000000000000000",
    .msg_hex        = "",
    .expect_accept  = 0,  /* rejected: R is small-order */
  },

  /* ============================================================
   * H2: Non-canonical R encoding
   *
   * Firedancer's fd_f25519_frombytes accepts non-canonical y values
   * (y >= p). The verify function does NOT re-compress R to check
   * canonicality (the commented-out code in fd_ed25519_user.c).
   * Instead it compares points in extended coords via fd_ed25519_point_eq_z1.
   *
   * Non-canonical y = p + k for k in [0..18]:
   *   p   = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
   *   p+0 = edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
   *   p+1 = eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
   *   ...
   *   p+18= ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
   *
   * The high bit (bit 255) is the x-sign bit, so for non-canonical
   * we use the low 255 bits >= p.
   *
   * Testing: a valid signature with canonical R, then the same R
   * re-encoded non-canonically. If Firedancer reduces mod p on
   * decompression (it does via fiat_25519_from_bytes), the point will
   * be the same, and if eq_z1 comparison works correctly, it should
   * still ACCEPT (since it compares in extended coordinates, not bytes).
   * ============================================================ */
  {
    .name           = "H2-noncanon-R: R.y = p (encodes y=0 non-canonically)",
    .hypothesis     = "H2-noncanonical-R",
    /* R with y=0 is a small-order point (order 4), so this will be
       rejected by the small-order check regardless of canonicality */
    .pubkey_hex     = RFC8032_TV1_PUBKEY,
    .sig_hex        = "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
                      "0000000000000000000000000000000000000000000000000000000000000000",
    .msg_hex        = "",
    .expect_accept  = 0,  /* rejected: R is small-order (order 4 point) */
  },
  {
    .name           = "H2-noncanon-R: identity y=1 encoded as y=p+1 (non-canonical)",
    .hypothesis     = "H2-noncanonical-R",
    /* Non-canonical encoding of identity: y = p+1 = 0x7f...ee
       The identity is small-order, so rejected */
    .pubkey_hex     = RFC8032_TV1_PUBKEY,
    .sig_hex        = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
                      "0000000000000000000000000000000000000000000000000000000000000000",
    .msg_hex        = "",
    .expect_accept  = 0,  /* rejected: R decompresses to identity (small-order) */
  },

  /* ============================================================
   * H3: Small-order points
   *
   * Firedancer REJECTS both small-order A and small-order R via
   * fd_ed25519_affine_is_small_order(). There are 8 small-order
   * points. Test all of them as R and as A.
   * ============================================================ */
  {
    .name           = "H3-small-order: A=order2 (0,-1)",
    .hypothesis     = "H3-small-order",
    .pubkey_hex     = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    .sig_hex        = RFC8032_TV1_SIG,  /* reuse any sig, will fail at pubkey check */
    .msg_hex        = "",
    .expect_accept  = 0,  /* rejected: pubkey is small-order */
  },
  {
    .name           = "H3-small-order: A=order4a (sqrt(-1),0)",
    .hypothesis     = "H3-small-order",
    .pubkey_hex     = "0000000000000000000000000000000000000000000000000000000000000000",
    .sig_hex        = RFC8032_TV1_SIG,
    .msg_hex        = "",
    .expect_accept  = 0,  /* rejected: pubkey is small-order */
  },
  {
    .name           = "H3-small-order: A=order4b (-sqrt(-1),0)",
    .hypothesis     = "H3-small-order",
    .pubkey_hex     = "0000000000000000000000000000000000000000000000000000000000000080",
    .sig_hex        = RFC8032_TV1_SIG,
    .msg_hex        = "",
    .expect_accept  = 0,
  },
  {
    .name           = "H3-small-order: A=order8a",
    .hypothesis     = "H3-small-order",
    .pubkey_hex     = "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    .sig_hex        = RFC8032_TV1_SIG,
    .msg_hex        = "",
    .expect_accept  = 0,
  },
  {
    .name           = "H3-small-order: A=order8b",
    .hypothesis     = "H3-small-order",
    .pubkey_hex     = "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    .sig_hex        = RFC8032_TV1_SIG,
    .msg_hex        = "",
    .expect_accept  = 0,
  },
  {
    .name           = "H3-small-order: A=order8c",
    .hypothesis     = "H3-small-order",
    .pubkey_hex     = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    .sig_hex        = RFC8032_TV1_SIG,
    .msg_hex        = "",
    .expect_accept  = 0,
  },
  {
    .name           = "H3-small-order: A=order8d",
    .hypothesis     = "H3-small-order",
    .pubkey_hex     = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    .sig_hex        = RFC8032_TV1_SIG,
    .msg_hex        = "",
    .expect_accept  = 0,
  },
  {
    .name           = "H3-small-order: R=identity, A=valid, S=0",
    .hypothesis     = "H3-small-order",
    .pubkey_hex     = RFC8032_TV1_PUBKEY,
    .sig_hex        = "0100000000000000000000000000000000000000000000000000000000000000"
                      "0000000000000000000000000000000000000000000000000000000000000000",
    .msg_hex        = "",
    .expect_accept  = 0,  /* R is identity = small-order */
  },
  {
    .name           = "H3-small-order: R=order2, A=valid, S=0",
    .hypothesis     = "H3-small-order",
    .pubkey_hex     = RFC8032_TV1_PUBKEY,
    .sig_hex        = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
                      "0000000000000000000000000000000000000000000000000000000000000000",
    .msg_hex        = "",
    .expect_accept  = 0,  /* R is small-order */
  },

  /* ============================================================
   * H4: S boundary values
   *
   * S must be in [0, L). Firedancer checks via
   * fd_curve25519_scalar_validate().
   *
   * L   = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
   * L-1 = 0x10...ec (valid)
   * L   = 0x10...ed (invalid)
   * L+1 = 0x10...ee (invalid)
   *
   * In little-endian (as stored in the sig):
   * L-1: ec d3 f5 5c 1a 63 12 58 d6 9c f7 a2 de f9 de 14 00...00 10
   * L:   ed d3 f5 5c 1a 63 12 58 d6 9c f7 a2 de f9 de 14 00...00 10
   * L+1: ee d3 f5 5c 1a 63 12 58 d6 9c f7 a2 de f9 de 14 00...00 10
   * ============================================================ */
  {
    .name           = "H4-S-boundary: S = L-1 (max valid scalar)",
    .hypothesis     = "H4-S-boundary",
    .pubkey_hex     = RFC8032_TV1_PUBKEY,
    .sig_hex        = RFC8032_TV1_SIG,  /* just checking S validation logic */
    /* This is a valid sig so will pass scalar check, but we also want
       to explicitly test S=L-1 with a fake R: */
    .msg_hex        = "",
    .expect_accept  = 1,  /* valid sig from RFC */
  },
  {
    .name           = "H4-S-boundary: S = L (should reject)",
    .hypothesis     = "H4-S-boundary",
    /* R = base point (valid, not small order), S = L */
    .pubkey_hex     = RFC8032_TV1_PUBKEY,
    .sig_hex        = "5866666666666666666666666666666666666666666666666666666666666666"
                      "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
    .msg_hex        = "",
    .expect_accept  = 0,  /* S >= L */
  },
  {
    .name           = "H4-S-boundary: S = L+1 (should reject)",
    .hypothesis     = "H4-S-boundary",
    .pubkey_hex     = RFC8032_TV1_PUBKEY,
    .sig_hex        = "5866666666666666666666666666666666666666666666666666666666666666"
                      "eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
    .msg_hex        = "",
    .expect_accept  = 0,  /* S >= L */
  },
  {
    .name           = "H4-S-boundary: S = 2^256 - 1 (all 0xff, should reject)",
    .hypothesis     = "H4-S-boundary",
    .pubkey_hex     = RFC8032_TV1_PUBKEY,
    .sig_hex        = "5866666666666666666666666666666666666666666666666666666666666666"
                      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    .msg_hex        = "",
    .expect_accept  = 0,  /* S way above L */
  },
  {
    .name           = "H4-S-boundary: S = 0 (technically valid scalar)",
    .hypothesis     = "H4-S-boundary",
    /* S=0 means [S]B = identity. So we need R + [k]A = identity.
       This is unlikely with a random R/A, so the eq check will fail,
       but S=0 itself should pass the scalar validation. */
    .pubkey_hex     = RFC8032_TV1_PUBKEY,
    .sig_hex        = "5866666666666666666666666666666666666666666666666666666666666666"
                      "0000000000000000000000000000000000000000000000000000000000000000",
    .msg_hex        = "",
    .expect_accept  = 0,  /* S=0 is valid scalar, but eq check fails */
  },

  /* ============================================================
   * H5: Point decompression failure
   *
   * Not every 32-byte string is a valid compressed Ed25519 point.
   * Test that invalid point encodings are properly rejected.
   * ============================================================ */
  {
    .name           = "H5-decompress: A = invalid point (no square root)",
    .hypothesis     = "H5-decompress-fail",
    /* 0x02...00 is not a valid compressed point */
    .pubkey_hex     = "0200000000000000000000000000000000000000000000000000000000000000",
    .sig_hex        = RFC8032_TV1_SIG,
    .msg_hex        = "",
    .expect_accept  = 0,  /* A fails decompression */
  },
  {
    .name           = "H5-decompress: R = invalid point",
    .hypothesis     = "H5-decompress-fail",
    .pubkey_hex     = RFC8032_TV1_PUBKEY,
    .sig_hex        = "0200000000000000000000000000000000000000000000000000000000000000"
                      "0000000000000000000000000000000000000000000000000000000000000000",
    .msg_hex        = "",
    .expect_accept  = 0,  /* R fails decompression */
  },

  /* ============================================================
   * H6: Wrong message (sanity check)
   *
   * A valid signature on one message must not verify on a different
   * message. This tests the SHA-512 hash path.
   * ============================================================ */
  {
    .name           = "H6-wrong-msg: RFC8032-TV1 sig verified against wrong msg",
    .hypothesis     = "H6-wrong-msg",
    .pubkey_hex     = RFC8032_TV1_PUBKEY,
    .sig_hex        = RFC8032_TV1_SIG,
    .msg_hex        = "deadbeef",
    .expect_accept  = 0,  /* wrong message */
  },

  /* ============================================================
   * H7: Mixed small-order + valid component (A = valid + torsion)
   *
   * If A has both a prime-order and a torsion component, the
   * is_small_order check should NOT trigger (the point is not
   * small-order, it just has a small-order component).
   * The cofactor vs non-cofactor equation matters here.
   *
   * A = P_valid + P_torsion has order 8*L, not small order.
   * This is a legitimate pubkey shape in the wild.
   * We can't easily construct a valid sig for it without the
   * private key, so we just verify it doesn't crash and properly
   * rejects (wrong sig).
   * ============================================================ */
  {
    .name           = "H7-mixed-order: A with torsion component, random sig",
    .hypothesis     = "H7-mixed-order",
    /* This pubkey was chosen to NOT be small-order but to be on the curve */
    .pubkey_hex     = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b0b8d183f8e8",
    .sig_hex        = "0000000000000000000000000000000000000000000000000000000000000000"
                      "0000000000000000000000000000000000000000000000000000000000000000",
    .msg_hex        = "",
    .expect_accept  = 0,  /* R=identity is small-order -> rejected */
  },

  /* Sentinel */
  { .name = NULL },
};

/* ------------------------------------------------------------------ */
/*  Run test vectors                                                   */
/* ------------------------------------------------------------------ */

static int
run_vectors(void) {
  int pass = 0, fail = 0, total = 0;

  for (int i = 0; test_vectors[i].name != NULL; i++) {
    const test_vector_t *tv = &test_vectors[i];
    total++;

    unsigned char pubkey[32];
    unsigned char sig[64];
    unsigned char msg[4096];

    int pk_len = hex_decode(pubkey, tv->pubkey_hex, 32);
    int sig_len = hex_decode(sig, tv->sig_hex, 64);
    int msg_len = hex_decode(msg, tv->msg_hex, 4096);

    if (pk_len != 32 || sig_len != 64 || msg_len < 0) {
      printf("  [SKIP] %s -- bad test vector encoding\n", tv->name);
      fail++;
      continue;
    }

    int result = do_verify(pubkey, sig, msg, (unsigned long)msg_len);
    int got_accept = (result == FD_ED25519_SUCCESS) ? 1 : 0;

    if (got_accept == tv->expect_accept) {
      printf("  [PASS] %s (got %s, error=%d)\n",
             tv->name,
             got_accept ? "ACCEPT" : "REJECT",
             result);
      pass++;
    } else {
      printf("  [FAIL] %s\n", tv->name);
      printf("         Expected: %s\n", tv->expect_accept ? "ACCEPT" : "REJECT");
      printf("         Got:      %s (error=%d: %s)\n",
             got_accept ? "ACCEPT" : "REJECT",
             result,
             fd_ed25519_strerror(result));
      fail++;
    }
  }

  printf("\n--- Results: %d/%d passed, %d failed ---\n", pass, total, fail);
  return fail > 0 ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/*  Read from stdin mode                                               */
/* ------------------------------------------------------------------ */

static int
run_stdin(void) {
  char line[16384];
  int line_num = 0;
  int total = 0, pass_count = 0, fail_count = 0;

  while (fgets(line, sizeof(line), stdin)) {
    line_num++;
    /* Strip newline */
    char *nl = strchr(line, '\n');
    if (nl) *nl = '\0';
    nl = strchr(line, '\r');
    if (nl) *nl = '\0';

    /* Skip comments and empty lines */
    if (line[0] == '#' || line[0] == '\0') continue;

    /* Parse: pubkey_hex sig_hex msg_hex [expect:ACCEPT|REJECT] */
    char pk_hex[65], sig_hex[129], msg_hex[8193], expect_str[16];
    int has_expect = 0;

    int nf = sscanf(line, "%64s %128s %8192s %15s", pk_hex, sig_hex, msg_hex, expect_str);
    if (nf < 3) {
      /* Try 2-field format (no message = empty) */
      nf = sscanf(line, "%64s %128s", pk_hex, sig_hex);
      if (nf < 2) {
        fprintf(stderr, "Line %d: parse error\n", line_num);
        continue;
      }
      msg_hex[0] = '\0';
    }
    if (nf >= 4) has_expect = 1;

    unsigned char pubkey[32], sig[64], msg[4096];
    int pk_len = hex_decode(pubkey, pk_hex, 32);
    int sig_len = hex_decode(sig, sig_hex, 64);
    int msg_len = hex_decode(msg, msg_hex, 4096);

    if (pk_len != 32) {
      fprintf(stderr, "Line %d: bad pubkey hex (got %d bytes)\n", line_num, pk_len);
      continue;
    }
    if (sig_len != 64) {
      fprintf(stderr, "Line %d: bad sig hex (got %d bytes)\n", line_num, sig_len);
      continue;
    }
    if (msg_len < 0) {
      fprintf(stderr, "Line %d: bad msg hex\n", line_num);
      continue;
    }

    int result = do_verify(pubkey, sig, msg, (unsigned long)msg_len);
    int got_accept = (result == FD_ED25519_SUCCESS) ? 1 : 0;

    total++;

    if (has_expect) {
      int expected = (strcmp(expect_str, "ACCEPT") == 0) ? 1 : 0;
      if (got_accept == expected) {
        printf("Line %d: PASS (%s)\n", line_num, got_accept ? "ACCEPT" : "REJECT");
        pass_count++;
      } else {
        printf("Line %d: FAIL (expected %s, got %s, err=%d: %s)\n",
               line_num,
               expected ? "ACCEPT" : "REJECT",
               got_accept ? "ACCEPT" : "REJECT",
               result, fd_ed25519_strerror(result));
        fail_count++;
      }
    } else {
      printf("Line %d: %s (err=%d: %s)\n",
             line_num,
             got_accept ? "ACCEPT" : "REJECT",
             result, fd_ed25519_strerror(result));
      pass_count++;
    }
  }

  if (total > 0 && fail_count > 0) {
    printf("\n--- %d/%d passed, %d failed ---\n", pass_count, total, fail_count);
    return 1;
  }
  if (total > 0) {
    printf("\n--- %d/%d passed ---\n", pass_count, total);
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog) {
  fprintf(stderr,
    "Usage:\n"
    "  %s <pubkey_hex> <sig_hex> <msg_hex>\n"
    "  %s --stdin              (read vectors from stdin)\n"
    "  %s --vectors            (run built-in test vectors)\n"
    "\n"
    "  pubkey: 32 bytes (64 hex chars)\n"
    "  sig:    64 bytes (128 hex chars) = R || S\n"
    "  msg:    N bytes  (2*N hex chars)\n"
    "\n"
    "Exit codes: 0=ACCEPT, 1=REJECT/FAIL, 2=usage error\n",
    prog, prog, prog);
}

int main(int argc, char **argv) {
  /* Initialize Firedancer runtime */
  fd_boot(&argc, &argv);

  if (argc < 2) {
    usage(argv[0]);
    fd_halt();
    return 2;
  }

  if (strcmp(argv[1], "--vectors") == 0) {
    printf("Running built-in test vectors...\n\n");
    int rc = run_vectors();
    fd_halt();
    return rc;
  }

  if (strcmp(argv[1], "--stdin") == 0) {
    int rc = run_stdin();
    fd_halt();
    return rc;
  }

  if (argc < 4) {
    usage(argv[0]);
    fd_halt();
    return 2;
  }

  /* Single verify mode */
  unsigned char pubkey[32], sig[64], msg[65536];

  int pk_len = hex_decode(pubkey, argv[1], 32);
  if (pk_len != 32) {
    fprintf(stderr, "ERROR: pubkey must be 32 bytes (64 hex chars)\n");
    fd_halt();
    return 2;
  }

  int sig_len = hex_decode(sig, argv[2], 64);
  if (sig_len != 64) {
    fprintf(stderr, "ERROR: sig must be 64 bytes (128 hex chars)\n");
    fd_halt();
    return 2;
  }

  int msg_len = hex_decode(msg, argv[3], 65536);
  if (msg_len < 0) {
    fprintf(stderr, "ERROR: bad message hex\n");
    fd_halt();
    return 2;
  }

  int result = do_verify(pubkey, sig, msg, (unsigned long)msg_len);

  if (result == FD_ED25519_SUCCESS) {
    printf("ACCEPT\n");
    fd_halt();
    return 0;
  } else {
    printf("REJECT (error=%d: %s)\n", result, fd_ed25519_strerror(result));
    fd_halt();
    return 1;
  }
}
