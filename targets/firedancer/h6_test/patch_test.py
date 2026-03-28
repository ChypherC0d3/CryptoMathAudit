#!/usr/bin/env python3
import sys

text = open('/tmp/test_h6_valid.c').read()

text = text.replace(
    '#include "fd_ed25519.h"',
    '#include "fd_ed25519.h"\n#include "fd_sha512.h"'
)

old = 'int pass = 0, fail = 0, mismatch = 0;'
new = r'''int pass = 0, fail = 0, mismatch = 0;

  /* Create sha512 scratch space for fd_ed25519_verify */
  unsigned char _sha_mem[FD_SHA512_FOOTPRINT] __attribute__((aligned(FD_SHA512_ALIGN)));
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha_mem ) );
  if( !sha ) { fprintf( stderr, "ERROR: fd_sha512 init failed\n" ); return 1; }'''
text = text.replace(old, new)

text = text.replace('v->sig, v->pubkey, NULL );', 'v->sig, v->pubkey, sha );')

open('/tmp/test_h6_valid_patched.c', 'w').write(text)
print('Patched OK')
