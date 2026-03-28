/* test_h6_valid.c -- Differential test of valid Ed25519 signatures
 *
 * Reads valid_vectors.json and verifies each signature through Firedancer's
 * Ed25519 implementation.  When compiled against both the reference (ref)
 * and AVX512 backends, any divergence in the verify result indicates a bug
 * in the field arithmetic.
 *
 * All vectors in valid_vectors.json are VALID signatures that pass
 * ed25519-dalek verify.  They are specifically crafted to have pubkey and
 * R-point coordinates near field arithmetic boundaries:
 *   - y near 0 or p
 *   - y near r43x6 limb boundaries (2^43, 2^86, 2^129, 2^172, 2^215)
 *   - S near 0 or L
 *
 * Build (inside Firedancer source tree):
 *
 *   # Reference backend:
 *   gcc -O2 -DFD_HAS_AVX512=0 -I../.. \
 *       test_h6_valid.c \
 *       ../../ballet/ed25519/ref/fd_ed25519_ref.c \
 *       ../../ballet/ed25519/fd_curve25519.c \
 *       ../../ballet/sha512/fd_sha512.c \
 *       -o test_h6_valid_ref
 *
 *   # AVX512 backend:
 *   gcc -O2 -DFD_HAS_AVX512=1 -mavx512f -mavx512ifma -I../.. \
 *       test_h6_valid.c \
 *       ../../ballet/ed25519/avx512/fd_ed25519_avx512.c \
 *       ../../ballet/ed25519/fd_curve25519.c \
 *       ../../ballet/sha512/fd_sha512.c \
 *       -o test_h6_valid_avx512
 *
 *   # Compare results:
 *   ./test_h6_valid_ref  > results_ref.txt
 *   ./test_h6_valid_avx512 > results_avx512.txt
 *   diff results_ref.txt results_avx512.txt
 *
 * Or use the inline-diff approach (single binary, needs AVX512 CPU):
 *   See test_h6_inline_diff.c for that pattern.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Firedancer headers -- adjust paths as needed */
#include "fd_ed25519.h"

/* ======================================================================
   Hex utilities
   ====================================================================== */

static int
hex_nibble( char c ) {
  if( c >= '0' && c <= '9' ) return c - '0';
  if( c >= 'a' && c <= 'f' ) return c - 'a' + 10;
  if( c >= 'A' && c <= 'F' ) return c - 'A' + 10;
  return -1;
}

static int
hex_decode( unsigned char * out, int out_max, char const * hex, int hex_len ) {
  if( hex_len % 2 != 0 ) return -1;
  int n = hex_len / 2;
  if( n > out_max ) return -1;
  for( int i = 0; i < n; i++ ) {
    int hi = hex_nibble( hex[2*i] );
    int lo = hex_nibble( hex[2*i+1] );
    if( hi < 0 || lo < 0 ) return -1;
    out[i] = (unsigned char)( (hi << 4) | lo );
  }
  return n;
}

/* ======================================================================
   Minimal JSON parser (just enough for our format)
   ====================================================================== */

#define MAX_VECTORS   20000
#define MAX_ID_LEN    128
#define MAX_MSG_LEN   4096  /* hex-encoded message, so 2048 bytes max */
#define MAX_CAT_LEN   64

typedef struct {
  char id[MAX_ID_LEN];
  char category[MAX_CAT_LEN];
  unsigned char pubkey[32];
  unsigned char sig[64];
  unsigned char msg[MAX_MSG_LEN / 2];
  int  msg_len;
  int  expected;  /* 1=accept, 0=reject */
} vector_t;

static vector_t vectors[MAX_VECTORS];
static int      n_vectors = 0;

/* Simple: find "key": "value" patterns line-by-line */
static char const *
json_find_str( char const * line, char const * key ) {
  char search[256];
  snprintf( search, sizeof(search), "\"%s\"", key );
  char const * p = strstr( line, search );
  if( !p ) return NULL;
  p += strlen(search);
  while( *p && (*p == ' ' || *p == ':' || *p == '\t') ) p++;
  if( *p == '"' ) return p + 1;  /* Return pointer past opening quote */
  return NULL;
}

static int
json_extract_str( char const * line, char const * key, char * out, int out_max ) {
  char const * start = json_find_str( line, key );
  if( !start ) return 0;
  int i = 0;
  while( start[i] && start[i] != '"' && i < out_max - 1 ) {
    out[i] = start[i];
    i++;
  }
  out[i] = '\0';
  return 1;
}

static int
json_extract_int( char const * line, char const * key, int * out ) {
  char search[256];
  snprintf( search, sizeof(search), "\"%s\"", key );
  char const * p = strstr( line, search );
  if( !p ) return 0;
  p += strlen(search);
  while( *p && (*p == ' ' || *p == ':' || *p == '\t') ) p++;
  if( !isdigit(*p) && *p != '-' ) return 0;
  *out = atoi( p );
  return 1;
}

static int
load_vectors( char const * path ) {
  FILE * f = fopen( path, "r" );
  if( !f ) {
    fprintf( stderr, "ERROR: Cannot open %s\n", path );
    return -1;
  }

  char line[8192];
  int  in_vector  = 0;
  int  idx        = 0;

  char id_buf[MAX_ID_LEN]   = {0};
  char cat_buf[MAX_CAT_LEN] = {0};
  char pk_hex[65]            = {0};
  char sig_hex[129]          = {0};
  char msg_hex[MAX_MSG_LEN+1] = {0};
  int  expected              = -1;
  int  have_id=0, have_pk=0, have_sig=0, have_msg=0, have_exp=0, have_cat=0;

  while( fgets( line, sizeof(line), f ) ) {
    /* Detect start of a vector object */
    if( strstr( line, "{" ) && !strstr( line, "\"description\"" ) &&
        !strstr( line, "\"count\"" ) && !strstr( line, "\"vectors\"" ) ) {
      in_vector = 1;
      have_id = have_pk = have_sig = have_msg = have_exp = have_cat = 0;
      id_buf[0] = pk_hex[0] = sig_hex[0] = msg_hex[0] = cat_buf[0] = 0;
      expected = -1;
    }

    if( in_vector ) {
      if( !have_id  ) have_id  = json_extract_str( line, "id", id_buf, sizeof(id_buf) );
      if( !have_cat ) have_cat = json_extract_str( line, "category", cat_buf, sizeof(cat_buf) );
      if( !have_pk  ) have_pk  = json_extract_str( line, "pubkey_hex", pk_hex, sizeof(pk_hex) );
      if( !have_sig ) have_sig = json_extract_str( line, "sig_hex", sig_hex, sizeof(sig_hex) );
      if( !have_msg ) have_msg = json_extract_str( line, "msg_hex", msg_hex, sizeof(msg_hex) );
      if( !have_exp ) have_exp = json_extract_int( line, "expected", &expected );
    }

    /* Detect end of a vector object */
    if( in_vector && strstr( line, "}" ) ) {
      if( have_pk && have_sig ) {
        vector_t * v = &vectors[idx];
        strncpy( v->id, have_id ? id_buf : "unknown", MAX_ID_LEN - 1 );
        strncpy( v->category, have_cat ? cat_buf : "unknown", MAX_CAT_LEN - 1 );
        v->expected = have_exp ? expected : -1;

        if( hex_decode( v->pubkey, 32, pk_hex, (int)strlen(pk_hex) ) != 32 ) {
          fprintf( stderr, "WARN: bad pubkey hex for %s, skipping\n", v->id );
        } else if( hex_decode( v->sig, 64, sig_hex, (int)strlen(sig_hex) ) != 64 ) {
          fprintf( stderr, "WARN: bad sig hex for %s, skipping\n", v->id );
        } else {
          int mlen = (int)strlen(msg_hex);
          if( mlen > 0 ) {
            v->msg_len = hex_decode( v->msg, sizeof(v->msg), msg_hex, mlen );
            if( v->msg_len < 0 ) {
              fprintf( stderr, "WARN: bad msg hex for %s, skipping\n", v->id );
              goto next;
            }
          } else {
            v->msg_len = 0;
          }
          idx++;
          if( idx >= MAX_VECTORS ) {
            fprintf( stderr, "WARN: max vectors reached (%d)\n", MAX_VECTORS );
            break;
          }
        }
      }
next:
      in_vector = 0;
    }
  }

  fclose( f );
  n_vectors = idx;
  return idx;
}

/* ======================================================================
   Main: verify each vector and report results
   ====================================================================== */

int
main( int argc, char ** argv ) {
  char const * json_path = "valid_vectors.json";
  if( argc > 1 ) json_path = argv[1];

  int n = load_vectors( json_path );
  if( n < 0 ) return 1;
  fprintf( stderr, "Loaded %d vectors from %s\n", n, json_path );

  int pass = 0, fail = 0, mismatch = 0;

  for( int i = 0; i < n_vectors; i++ ) {
    vector_t * v = &vectors[i];

    /* Call Firedancer's fd_ed25519_verify */
    int result = fd_ed25519_verify( v->msg, (unsigned long)v->msg_len,
                                    v->sig, v->pubkey, NULL );
    /* fd_ed25519_verify returns FD_ED25519_SUCCESS (0) on success */
    int accepted = (result == FD_ED25519_SUCCESS) ? 1 : 0;

    /* Output in a diff-friendly format */
    printf( "%-30s  cat=%-16s  expected=%d  got=%d  %s\n",
            v->id, v->category, v->expected, accepted,
            (v->expected == accepted) ? "OK" : "MISMATCH" );

    if( v->expected >= 0 && v->expected != accepted ) {
      mismatch++;
      fprintf( stderr, "MISMATCH: %s expected=%d got=%d\n",
               v->id, v->expected, accepted );
    }

    if( accepted ) pass++;
    else          fail++;
  }

  fprintf( stderr, "\n=== Summary ===\n" );
  fprintf( stderr, "Total:     %d\n", n_vectors );
  fprintf( stderr, "Accepted:  %d\n", pass );
  fprintf( stderr, "Rejected:  %d\n", fail );
  fprintf( stderr, "Mismatch:  %d\n", mismatch );

  if( mismatch > 0 ) {
    fprintf( stderr, "\n*** %d MISMATCHES FOUND -- possible ref/AVX512 divergence ***\n", mismatch );
    return 2;
  }

  /* For differential testing:
   * Run this binary built with ref, capture stdout.
   * Run this binary built with AVX512, capture stdout.
   * diff the two outputs. Any difference = bug. */
  fprintf( stderr, "\nAll vectors matched expectations.\n" );
  fprintf( stderr, "For differential test: compare stdout from ref vs AVX512 builds.\n" );

  return 0;
}
