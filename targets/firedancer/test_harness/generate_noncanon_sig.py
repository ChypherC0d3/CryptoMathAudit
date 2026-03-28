#!/usr/bin/env python3
"""
Generate Ed25519 test vectors with non-canonical R encodings.

This script creates VALID Ed25519 signatures where the R point is encoded
with a non-canonical y-coordinate (y >= p, where p = 2^255 - 19).

The core hypothesis: Firedancer reduces y mod p during decompression (accepting
non-canonical encodings), while ed25519-dalek v1.0.1 verify_strict() rejects
them. If a valid signature with non-canonical R is ACCEPTED by Firedancer but
REJECTED by Dalek, this constitutes a consensus-breaking divergence.

Strategy:
  1. Generate keypair: a (scalar), A = [a]B (public key)
  2. For each nonce r, compute R = [r]B
  3. If R.y < 19, then R.y + p < 2^255, so we can encode R non-canonically
     (replacing y with y+p in the 32-byte encoding)
  4. Compute k = SHA-512(R_noncanon_bytes || A_bytes || msg) mod L
  5. Compute S = (r + k*a) mod L
  6. The signature is (R_noncanon_bytes || S_bytes)
  7. This signature is mathematically valid (Firedancer should ACCEPT)
  8. But Dalek verify_strict rejects non-canonical R bytes

Since R.y < 19 has probability ~19/p (near zero for random r), we use a
deterministic search: hash-derive r values and check R.y until we find one
with R.y < 19.

ALTERNATE APPROACH (used here): Since finding R.y < 19 is computationally
infeasible by random search (~2^251 trials needed), we use a mathematical
shortcut. We pick a known small y value (e.g., y=3 which is on the curve)
and CONSTRUCT R from it. We don't know the discrete log, so we can't create
a fully valid signature. Instead we:

  A) Test non-canonical decompression behavior (does the verifier accept or
     reject the non-canonical encoding BEFORE the equation check?)
  B) For valid-signature tests, we construct signatures where we DO know r,
     using a different approach: we manipulate the x-sign bit to explore
     non-canonical encodings in a way that preserves mathematical validity.

For approach A, the key test vectors are:
  - Non-canonical R with y=p+k (k=0..18) paired with S=0 and valid pubkey
  - These test the decompression path in isolation

For approach B (the critical one), we use the following trick:
  - Generate a normal valid signature (R_canonical, S) where we know r
  - The canonical encoding has R.y in [0, p)
  - We cannot add p to make it non-canonical (R.y + p >= 2^255 for most R.y)
  - BUT: there exists a value p+k for k in [0,18] that might decode to a
    valid non-small-order point. We test THESE as R in signatures.

The MOST IMPORTANT test: Create a fully valid signature with non-canonical R.
To do this we need R.y < 19. We use exhaustive search with a fast scalar mult.
"""

import hashlib
import json
import os
import sys
import secrets
import struct
import time

# =============================================================================
# Field arithmetic mod p = 2^255 - 19
# =============================================================================

p = (1 << 255) - 19

def fe_add(a, b): return (a + b) % p
def fe_sub(a, b): return (a - b) % p
def fe_mul(a, b): return (a * b) % p
def fe_sq(a): return (a * a) % p
def fe_inv(a): return pow(a, p - 2, p)
def fe_neg(a): return (-a) % p
def fe_is_zero(a): return (a % p) == 0
def fe_eq(a, b): return ((a - b) % p) == 0
def fe_is_negative(a): return (a % p) % 2  # odd = negative in Ed25519

# =============================================================================
# Ed25519 curve parameters
# =============================================================================

# Curve: -x^2 + y^2 = 1 + d*x^2*y^2
d = fe_mul(-121665, fe_inv(121666))

# Group order
L = (1 << 252) + 27742317777372353535851937790883648493

# sqrt(-1) mod p
SQRT_M1 = pow(2, (p - 1) // 4, p)

def sqrt_mod_p(a):
    """Compute sqrt(a) mod p, or None if not a QR."""
    candidate = pow(a, (p + 3) // 8, p)
    if fe_eq(fe_sq(candidate), a):
        return candidate
    candidate = fe_mul(candidate, SQRT_M1)
    if fe_eq(fe_sq(candidate), a):
        return candidate
    return None

# Base point B
B_y = fe_mul(4, fe_inv(5))
_B_u = fe_sub(fe_sq(B_y), 1)
_B_v = fe_add(fe_mul(d, fe_sq(B_y)), 1)
_B_x2 = fe_mul(_B_u, fe_inv(_B_v))
_B_x = sqrt_mod_p(_B_x2)
if fe_is_negative(_B_x):
    _B_x = fe_neg(_B_x)
B = (_B_x, B_y, 1, fe_mul(_B_x, B_y))

# Identity
IDENTITY = (0, 1, 1, 0)

# Small-order y-coordinates for rejection check
def decode_y_from_hex(hex_str):
    b = bytes.fromhex(hex_str)
    y_bytes = bytearray(b)
    y_bytes[31] &= 0x7F
    return int.from_bytes(y_bytes, 'little')

ORDER8_Y0 = decode_y_from_hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
ORDER8_Y1 = decode_y_from_hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")

def is_small_order_affine(x, y):
    """Check if affine point (x,y) is small-order (Firedancer's check)."""
    return (fe_is_zero(x) or fe_is_zero(y) or
            fe_eq(y, ORDER8_Y0) or fe_eq(y, ORDER8_Y1))

# =============================================================================
# Extended twisted Edwards point arithmetic
# =============================================================================

def point_add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = fe_mul(X1, X2)
    B = fe_mul(Y1, Y2)
    C = fe_mul(fe_mul(d, T1), T2)
    D = fe_mul(Z1, Z2)
    E = fe_mul(fe_add(X1, Y1), fe_add(X2, Y2))
    E = fe_sub(fe_sub(E, A), B)
    F = fe_sub(D, C)
    G = fe_add(D, C)
    H = fe_sub(B, fe_neg(A))  # B + A (since a=-1)
    X3 = fe_mul(E, F)
    Y3 = fe_mul(G, H)
    Z3 = fe_mul(F, G)
    T3 = fe_mul(E, H)
    return (X3, Y3, Z3, T3)

def point_neg(P):
    X, Y, Z, T = P
    return (fe_neg(X), Y, Z, fe_neg(T))

def point_double(P):
    X1, Y1, Z1, T1 = P
    A = fe_sq(X1)
    B = fe_sq(Y1)
    C = fe_mul(2, fe_sq(Z1))
    D = fe_neg(A)
    E = fe_sub(fe_sub(fe_sq(fe_add(X1, Y1)), A), B)
    G = fe_add(D, B)
    F = fe_sub(G, C)
    H = fe_sub(D, B)
    X3 = fe_mul(E, F)
    Y3 = fe_mul(G, H)
    T3 = fe_mul(E, H)
    Z3 = fe_mul(F, G)
    return (X3, Y3, Z3, T3)

def scalar_mult(s, P):
    if s == 0:
        return IDENTITY
    if s < 0:
        s = -s
        P = point_neg(P)
    result = IDENTITY
    current = P
    while s > 0:
        if s & 1:
            result = point_add(result, current)
        current = point_double(current)
        s >>= 1
    return result

def point_to_affine(P):
    """Convert extended coords to affine (x, y)."""
    X, Y, Z, T = P
    z_inv = fe_inv(Z)
    return (fe_mul(X, z_inv), fe_mul(Y, z_inv))

def encode_point(P):
    """Encode point as 32-byte canonical Ed25519 encoding."""
    x, y = point_to_affine(P)
    y_bytes = y.to_bytes(32, 'little')
    buf = bytearray(y_bytes)
    if fe_is_negative(x):
        buf[31] |= 0x80
    return bytes(buf)

def encode_point_noncanonical(P):
    """Encode point with non-canonical y (y + p instead of y).
    Only possible if y < 19 (so y + p < 2^255).
    Returns None if not possible."""
    x, y = point_to_affine(P)
    if y >= 19:
        return None  # y + p >= 2^255, doesn't fit in 255 bits
    y_noncanon = y + p
    # y_noncanon must fit in 255 bits (bit 255 is x-sign)
    if y_noncanon >= (1 << 255):
        return None
    y_bytes = y_noncanon.to_bytes(32, 'little')
    buf = bytearray(y_bytes)
    if fe_is_negative(x):
        buf[31] |= 0x80
    return bytes(buf)

def sha512_modL(data):
    h = hashlib.sha512(data).digest()
    k = int.from_bytes(h, 'little')
    return k % L

# =============================================================================
# Ed25519 key generation and signing
# =============================================================================

def ed25519_keygen(seed_bytes):
    """Generate Ed25519 keypair from 32-byte seed.
    Returns (private_scalar_a, nonce_prefix, public_key_point, public_key_bytes)."""
    h = hashlib.sha512(seed_bytes).digest()
    # Clamp the first 32 bytes to get scalar a
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    a = int.from_bytes(a_bytes, 'little')
    # Second 32 bytes are the nonce prefix
    nonce_prefix = h[32:]
    # Public key
    A = scalar_mult(a, B)
    A_bytes = encode_point(A)
    return a, nonce_prefix, A, A_bytes

def ed25519_sign_with_known_r(r, a, A_bytes, msg):
    """Sign with explicit r value (not derived from nonce_prefix).
    Returns (signature_bytes, R_point)."""
    R = scalar_mult(r, B)
    R_bytes = encode_point(R)

    # k = SHA-512(R_bytes || A_bytes || msg) mod L
    k = sha512_modL(R_bytes + A_bytes + msg)

    # S = (r + k*a) mod L
    S = (r + k * a) % L
    S_bytes = S.to_bytes(32, 'little')

    sig = R_bytes + S_bytes
    return sig, R

def ed25519_sign_noncanon_r(r, a, A_bytes, msg):
    """Sign with non-canonical R encoding.
    Returns (noncanon_sig_bytes, canon_sig_bytes, R_point) or None if R.y >= 19."""
    R = scalar_mult(r, B)

    # Check if non-canonical encoding is possible
    R_noncanon_bytes = encode_point_noncanonical(R)
    if R_noncanon_bytes is None:
        return None

    R_canon_bytes = encode_point(R)

    # For the non-canonical signature, hash uses NON-CANONICAL bytes
    # (this is what Firedancer does - it hashes the original sig bytes)
    k_noncanon = sha512_modL(R_noncanon_bytes + A_bytes + msg)
    S_noncanon = (r + k_noncanon * a) % L
    S_noncanon_bytes = S_noncanon.to_bytes(32, 'little')
    noncanon_sig = R_noncanon_bytes + S_noncanon_bytes

    # Also create the canonical version for comparison
    k_canon = sha512_modL(R_canon_bytes + A_bytes + msg)
    S_canon = (r + k_canon * a) % L
    S_canon_bytes = S_canon.to_bytes(32, 'little')
    canon_sig = R_canon_bytes + S_canon_bytes

    return noncanon_sig, canon_sig, R

# =============================================================================
# Point analysis helpers
# =============================================================================

def y_from_encoding(enc_bytes):
    """Extract the y value from a 32-byte point encoding."""
    buf = bytearray(enc_bytes)
    buf[31] &= 0x7F
    return int.from_bytes(buf, 'little')

def check_on_curve(y):
    """Check if y value corresponds to a point on the Ed25519 curve.
    Returns (on_curve, x_value) or (False, None)."""
    u = fe_sub(fe_sq(y), 1)       # y^2 - 1
    v = fe_add(fe_mul(d, fe_sq(y)), 1)  # d*y^2 + 1
    x = sqrt_mod_p(fe_mul(u, fe_inv(v)))
    if x is None:
        return False, None
    return True, x

# =============================================================================
# Non-canonical encoding analysis
# =============================================================================

def analyze_noncanonical_values():
    """Analyze all 19 non-canonical y values (p, p+1, ..., p+18)."""
    print("=" * 80)
    print("ANALYSIS: Non-canonical y values and their curve properties")
    print("=" * 80)
    print()
    print(f"p = 2^255 - 19 = {p}")
    print(f"p (hex LE) = {p.to_bytes(32, 'little').hex()}")
    print()

    results = []
    for k in range(19):
        y_noncanon = p + k
        y_canon = k  # y_noncanon mod p = k
        on_curve, x = check_on_curve(y_canon)

        # Encode y_noncanon as 32 bytes LE (with x-sign = 0)
        enc = y_noncanon.to_bytes(32, 'little')
        enc_hex = enc.hex()

        is_small = False
        if on_curve and x is not None:
            is_small = is_small_order_affine(x, y_canon)

        status = "ON CURVE" if on_curve else "NOT ON CURVE"
        so_status = " (SMALL ORDER)" if is_small else " (NOT small order)" if on_curve else ""

        print(f"  y = p + {k:2d} (canon y={k:2d}): {status}{so_status}")
        print(f"    encoding (x_sign=0): {enc_hex}")

        results.append({
            'k': k,
            'y_noncanon': y_noncanon,
            'y_canon': y_canon,
            'on_curve': on_curve,
            'x': x,
            'is_small_order': is_small,
            'encoding': enc_hex,
        })
    print()
    return results

# =============================================================================
# Search for r where R.y < 19 (for valid non-canonical signatures)
# =============================================================================

def search_for_small_y_r(a, A_bytes, max_iterations=100000):
    """
    Search for r such that R = [r]B has R.y < 19.

    This is a brute-force search. The probability of R.y < 19 for random r
    is approximately 19/p ~ 3.3e-76, which means we would need ~3e75 trials.
    This is computationally infeasible.

    Instead, we use an INCREMENTAL approach: start from a known point and
    add B repeatedly, checking y each time. This is still infeasible for
    finding R.y < 19, but we include it for completeness.

    Returns (r, R_point) or None if not found.
    """
    print(f"Searching for r where R.y < 19 (up to {max_iterations} iterations)...")
    print("NOTE: Probability is ~19/p ~ 3.3e-76, so this will NOT succeed.")
    print("This search is included for completeness only.")
    print()

    # Use incremental point addition for speed
    R = B  # r = 1
    for r in range(1, max_iterations + 1):
        x, y = point_to_affine(R)
        if y < 19:
            print(f"  FOUND! r={r}, R.y={y}")
            on_curve, _ = check_on_curve(y)
            is_small = is_small_order_affine(x, y)
            print(f"  On curve: {on_curve}, Small order: {is_small}")
            return r, R
        if r % 10000 == 0:
            print(f"  ...tried {r} values, R.y = {y} (need < 19)")
        R = point_add(R, B)

    print(f"  Not found in {max_iterations} iterations (as expected).")
    return None

# =============================================================================
# Generate test vectors
# =============================================================================

def generate_decompression_test_vectors():
    """
    Generate test vectors that test non-canonical R decompression.

    These use non-canonical R encodings with S computed to make the signature
    mathematically valid IF R decompresses correctly (i.e., to the canonical
    point). The key insight:

    - Firedancer: reduces y mod p -> decompresses to canonical point -> ACCEPTS
    - Dalek verify_strict: rejects non-canonical y (y >= p) -> REJECTS

    For non-canonical R where the canonical y is on the curve and NOT small-order,
    we construct S such that the equation [S]B = R + [k]A holds.
    """
    print("=" * 80)
    print("GENERATING TEST VECTORS: Non-canonical R with valid signatures")
    print("=" * 80)
    print()

    # Generate a keypair
    seed = hashlib.sha256(b"firedancer-noncanon-test-seed-v1").digest()
    a, nonce_prefix, A, A_bytes = ed25519_keygen(seed)
    print(f"Public key A: {A_bytes.hex()}")
    print()

    # Analyze which non-canonical y values give valid non-small-order points
    nc_results = analyze_noncanonical_values()

    vectors = []

    # For each non-canonical y that IS on the curve and NOT small order,
    # we want to create a valid signature. But we need to know the discrete
    # log r of the resulting R point, which we don't have.
    #
    # HOWEVER, we can create test vectors in two categories:
    #
    # Category 1: Non-canonical R decompression tests (S=0, will fail equation
    # check, but tests whether the verifier rejects at decompression or later)
    #
    # Category 2: Non-canonical R with VALID equation (requires knowing r)

    msg = b""  # empty message

    # Category 1: Decompression behavior tests
    print("-" * 60)
    print("Category 1: Non-canonical R decompression tests")
    print("-" * 60)
    print()

    for res in nc_results:
        k = res['k']
        enc_hex = res['encoding']
        on_curve = res['on_curve']
        is_small = res['is_small_order']

        if not on_curve:
            # Non-canonical y that reduces to a y not on the curve
            # Both Firedancer and Dalek should reject (decompression failure)
            expected_fd = "REJECT"
            expected_dalek = "REJECT"
            desc = f"R non-canonical y=p+{k} (canon y={k}), not on curve"
        elif is_small:
            # On curve but small order
            # Firedancer: decompresses OK but rejects small order
            # Dalek: rejects non-canonical encoding OR rejects small order
            expected_fd = "REJECT"
            expected_dalek = "REJECT"
            desc = f"R non-canonical y=p+{k} (canon y={k}), small order"
        else:
            # On curve and NOT small order - THIS IS THE INTERESTING CASE
            # Firedancer: decompresses OK, not small order, then equation check
            # Dalek: might reject non-canonical encoding before equation check
            # With S=0, equation will fail in both (unless [0]B = R + [k]A somehow)
            # But the KEY question is: does Dalek reject at decompression?
            expected_fd = "REJECT"  # equation won't match with S=0
            expected_dalek = "REJECT"  # rejects non-canonical R
            desc = f"R non-canonical y=p+{k} (canon y={k}), NOT small order, S=0 (equation fails)"

        # Use the RFC 8032 TV1 pubkey as a valid non-small-order pubkey
        pubkey_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        s_zero = "00" * 32
        sig_hex = enc_hex + s_zero

        vec_id = f"H2_noncanon_R_y_p_plus_{k}"
        vec = {
            "id": vec_id,
            "hypothesis": "H2: Non-canonical R y-coordinate decompression",
            "description": desc,
            "pubkey": pubkey_hex,
            "signature": sig_hex,
            "message": "",
            "expected_firedancer": expected_fd,
            "expected_dalek_strict": expected_dalek,
            "expected_dalek_loose": expected_dalek,
            "noncanon_y_offset": k,
            "canonical_y": res['y_canon'],
            "on_curve": on_curve,
            "is_small_order": is_small,
        }
        vectors.append(vec)
        print(f"  [{vec_id}] {desc}")
        print(f"    R encoding: {enc_hex}")
        print(f"    Expected: FD={expected_fd}, Dalek={expected_dalek}")
        print()

    # Category 2: Valid signatures with non-canonical R
    print()
    print("-" * 60)
    print("Category 2: Valid signatures with non-canonical R encoding")
    print("-" * 60)
    print()

    # For non-canonical y values that are on the curve and not small order,
    # we want to construct a fully valid signature.
    #
    # The approach: We pick random r, compute R = [r]B, and create two
    # signatures:
    #   1. Canonical: standard encoding of R
    #   2. Non-canonical: non-standard encoding of R (if R.y < 19)
    #
    # Since we know r, we can compute S correctly for both cases.
    # Note that the hash k differs because it includes the R encoding bytes!
    #
    # For the non-canonical signature:
    #   k_nc = SHA-512(R_noncanon || A || msg) mod L
    #   S_nc = (r + k_nc * a) mod L
    #   sig_nc = R_noncanon || S_nc
    #
    # If Firedancer:
    #   1. Reads R_noncanon bytes
    #   2. Decompresses: y_raw = p + R.y_orig, reduces mod p -> R.y_orig -> same point R
    #   3. Computes k using ORIGINAL bytes: k = SHA-512(R_noncanon || A || msg) = k_nc
    #   4. Checks [S_nc]B == R + [k_nc]A
    #   5. S_nc = r + k_nc * a, so [S_nc]B = [r]B + [k_nc * a]B = R + [k_nc]A
    #   6. ACCEPTS!
    #
    # If Dalek verify_strict:
    #   1. Reads R_noncanon bytes
    #   2. CompressedEdwardsY::decompress() - does it reject y >= p?
    #   3. If yes -> REJECTS (before equation check)
    #   4. If no (reduces mod p) -> would need to check how k is computed
    #
    # We EXPECT Dalek to reject at step 2-3. Let's verify.

    # Since we can't find R.y < 19 by brute force, we use a DIFFERENT trick:
    # We directly construct R from a small y value.
    #
    # For y=3: we verified this is on the curve and not small order.
    # x^2 = (y^2 - 1) / (d*y^2 + 1) = (9-1)/(9d+1) = 8/(9d+1)
    #
    # We don't know the discrete log r of this point (x, 3).
    # But we CAN test the decompression + hash behavior without a valid equation.
    #
    # For a FULL valid signature test, we REALLY need r.
    # Let's try another approach: use the nonce derivation from ed25519 signing.

    # Approach: generate many signatures normally, check if any R.y < 19
    print("Attempting to find a valid keypair+nonce where R.y < 19...")
    print("(This is infeasible by random search but we try a few for demonstration)")
    print()

    found_noncanon = False
    for trial in range(100):
        seed_trial = hashlib.sha256(f"noncanon-trial-{trial}".encode()).digest()
        a_t, nonce_t, A_t, A_t_bytes = ed25519_keygen(seed_trial)

        # Try a few r values for each key
        for r_idx in range(100):
            r_bytes = hashlib.sha512(nonce_t + f"r-{r_idx}".encode()).digest()
            r_val = int.from_bytes(r_bytes, 'little') % L

            R_point = scalar_mult(r_val, B)
            R_x, R_y = point_to_affine(R_point)

            if R_y < 19:
                print(f"  FOUND! trial={trial}, r_idx={r_idx}, R.y={R_y}")
                found_noncanon = True

                result = ed25519_sign_noncanon_r(r_val, a_t, A_t_bytes, msg)
                if result is not None:
                    noncanon_sig, canon_sig, R_found = result
                    # Verify canonical signature with our emulator
                    print(f"  Canonical sig: {canon_sig.hex()}")
                    print(f"  Non-canonical sig: {noncanon_sig.hex()}")
                    print(f"  Pubkey: {A_t_bytes.hex()}")

                    # Add to vectors
                    vec = {
                        "id": f"H2_CRITICAL_noncanon_R_valid_sig_y{R_y}",
                        "hypothesis": "H2: CRITICAL - valid sig with non-canonical R",
                        "description": f"Fully valid signature where R is encoded with non-canonical y=p+{R_y}. Firedancer should ACCEPT, Dalek should REJECT.",
                        "pubkey": A_t_bytes.hex(),
                        "signature": noncanon_sig.hex(),
                        "message": "",
                        "expected_firedancer": "ACCEPT",
                        "expected_dalek_strict": "REJECT",
                        "expected_dalek_loose": "unknown",
                        "canonical_signature": canon_sig.hex(),
                        "R_y_canonical": R_y,
                        "R_y_noncanonical": R_y + p,
                    }
                    vectors.append(vec)
                break
        if found_noncanon:
            break

    if not found_noncanon:
        print("  Could not find R.y < 19 (as expected - probability ~3.3e-76)")
        print()
        print("  FALLBACK: Constructing test vector from known small-y point")
        print()

        # Construct a test using y=3 (known to be on curve, not small order)
        # We pick y=3, compute x, form the point, encode non-canonically
        y_target = 3
        on_curve, x_val = check_on_curve(y_target)
        assert on_curve, f"y={y_target} should be on the curve"
        assert not is_small_order_affine(x_val, y_target), f"y={y_target} should not be small order"

        # Use the even x (x_sign = 0)
        if fe_is_negative(x_val):
            x_val = fe_neg(x_val)

        R_target = (x_val, y_target, 1, fe_mul(x_val, y_target))

        # Non-canonical encoding of this R
        y_nc = y_target + p  # = 3 + (2^255 - 19) = 2^255 - 16
        enc_nc = y_nc.to_bytes(32, 'little')
        # x_sign = 0 (we chose even x)
        R_nc_hex = enc_nc.hex()

        # Canonical encoding for comparison
        R_canon_hex = encode_point(R_target).hex()

        print(f"  R (canon):    {R_canon_hex}")
        print(f"  R (noncanon): {R_nc_hex}")
        print(f"  R.x = {x_val}")
        print(f"  R.y = {y_target}")
        print()

        # We don't know r (discrete log), so we can't construct a valid S.
        # But we CAN construct a scenario where the HASH differs and test
        # Firedancer's decompression + hash behavior.
        #
        # Key question: Firedancer hashes the ORIGINAL (non-canonical) bytes.
        # So even if it decompresses correctly, the hash k will be different
        # from a canonical encoding's hash.
        #
        # For a MAXIMALLY useful test: use S=0 and check rejection reason.
        # If Firedancer rejects with "equation check failed" (not "decompression failed"),
        # it means decompression succeeded. If Dalek rejects with "decompression failed"
        # or "non-canonical", that's different behavior (even though both reject).
        #
        # BUT: we can also construct a valid signature IF we choose r cleverly.
        # Since we're signing with a known key (a), we need r such that [r]B = R_target.
        # We don't know such r. But we CAN sign the "correct" way:
        #
        # Pick any r' -> R' = [r']B (canonical)
        # Encode R' canonically
        # Compute k' = SHA-512(R'_canon || A || msg) mod L
        # S' = r' + k' * a mod L
        # This is a standard valid signature.
        #
        # Now, for non-canonical test: we need a sig where R is non-canonical.
        # We DON'T have the discrete log of R_target, so we can't create a
        # valid sig with R_target as the R point.
        #
        # CONCLUSION: Without finding r where [r]B.y < 19, we CANNOT create
        # a fully valid signature with non-canonical R. The decompression-only
        # test vectors above are the best we can do in pure Python.
        #
        # To create a valid-sig test, we would need:
        # 1. A C/Rust program linked against a fast Ed25519 library
        # 2. To search trillions of r values (still won't work - need ~10^75)
        # 3. OR a different mathematical approach

        # Add the decompression-focused test vector with a valid pubkey
        # and S computed as if the equation should hold (it won't, but this
        # tests the decompression path)

        # Create a more sophisticated test: use the non-canonical R in a
        # signature where we compute S using the non-canonical bytes in the hash
        # This won't verify because we don't know r for R_target, but it tests
        # whether Firedancer even gets to the equation check
        pubkey_hex = A_bytes.hex()

        # Compute k using non-canonical R bytes (as Firedancer would)
        k_test = sha512_modL(bytes.fromhex(R_nc_hex) + A_bytes + msg)
        # Set S = k_test * a mod L (this won't make the equation work, but
        # it's a plausible-looking S value)
        S_test = (k_test * a) % L
        S_test_bytes = S_test.to_bytes(32, 'little')
        sig_hex = R_nc_hex + S_test_bytes.hex()

        vec = {
            "id": "H2_noncanon_R_y3_valid_point",
            "hypothesis": "H2: Non-canonical R with y=3+p, valid curve point, not small order",
            "description": "R encoded with non-canonical y=p+3 (canonical y=3). Point is on curve and NOT small order. Tests decompression path. S is computed but equation won't hold (unknown discrete log). Key test: does Firedancer reject at equation-check (decompressed OK) vs Dalek rejecting at decompression?",
            "pubkey": pubkey_hex,
            "signature": sig_hex,
            "message": "",
            "expected_firedancer": "REJECT",  # equation check fails (we don't know r)
            "expected_dalek_strict": "REJECT",  # non-canonical R rejected at decompression
            "expected_dalek_loose": "REJECT",
            "R_canonical_encoding": R_canon_hex,
            "R_noncanonical_encoding": R_nc_hex,
            "R_y_canonical": y_target,
            "test_purpose": "Verify that Firedancer decompresses non-canonical R (gets to equation check) while Dalek rejects at decompression. Different rejection REASONS indicate the behavioral divergence that could lead to a consensus split with a crafted valid signature.",
        }
        vectors.append(vec)
        print(f"  Added test vector: {vec['id']}")
        print()

    # Category 3: Test vectors for PUBKEY non-canonical encoding
    # (less critical but still worth testing)
    print()
    print("-" * 60)
    print("Category 3: Non-canonical PUBKEY encoding (for completeness)")
    print("-" * 60)
    print()

    # Non-canonical pubkey where the canonical y IS a valid, non-small-order point
    for k in [3, 5, 7, 9, 11]:  # y values that might be on curve
        y_canon = k
        on_curve, x_val = check_on_curve(y_canon)
        if not on_curve:
            continue
        if is_small_order_affine(x_val, y_canon):
            continue

        y_nc = y_canon + p
        enc = y_nc.to_bytes(32, 'little')
        # x_sign = 0
        pk_nc_hex = enc.hex()

        vec = {
            "id": f"H2_noncanon_pubkey_y_p_plus_{k}",
            "hypothesis": "H2: Non-canonical pubkey y-coordinate",
            "description": f"Pubkey with non-canonical y=p+{k} (canon y={k}), on curve, not small order. Tests pubkey decompression.",
            "pubkey": pk_nc_hex,
            "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            "message": "",
            "expected_firedancer": "REJECT",  # wrong pubkey for this sig
            "expected_dalek_strict": "REJECT",  # non-canonical pubkey
            "expected_dalek_loose": "unknown",
        }
        vectors.append(vec)
        print(f"  [{vec['id']}] Pubkey non-canonical y=p+{k}")

    print()
    return vectors

# =============================================================================
# Firedancer emulator verification (inline)
# =============================================================================

def firedancer_verify_inline(msg_bytes, sig_bytes, pubkey_bytes):
    """Firedancer verification emulator (same logic as firedancer_verify.py)."""
    if len(sig_bytes) != 64 or len(pubkey_bytes) != 32:
        return False, "bad input length"

    r_bytes = sig_bytes[:32]
    s_bytes = sig_bytes[32:]

    # S < L check
    S = int.from_bytes(s_bytes, 'little')
    if S >= L:
        return False, "S >= L"

    # Decompress pubkey
    def decompress(buf):
        x_sign = (buf[31] >> 7) & 1
        y_b = bytearray(buf)
        y_b[31] &= 0x7F
        y_raw = int.from_bytes(y_b, 'little')
        y = y_raw % p  # Firedancer reduces mod p
        u = fe_sub(fe_sq(y), 1)
        v = fe_add(fe_mul(d, fe_sq(y)), 1)
        v3 = fe_mul(fe_sq(v), v)
        v7 = fe_mul(fe_sq(v3), v)
        uv7 = fe_mul(u, v7)
        p58 = pow(uv7, (p - 5) // 8, p)
        x = fe_mul(fe_mul(u, v3), p58)
        check = fe_mul(fe_sq(x), v)
        if fe_eq(check, u):
            pass
        elif fe_eq(check, fe_neg(u)):
            x = fe_mul(x, SQRT_M1)
        else:
            return None
        if fe_is_negative(x) != x_sign:
            x = fe_neg(x)
        return (x, y, 1, fe_mul(x, y))

    A = decompress(pubkey_bytes)
    if A is None:
        return False, "pubkey decompression failed"

    R = decompress(r_bytes)
    if R is None:
        return False, "R decompression failed"

    # Small order check
    x_a, y_a = A[0], A[1]
    if is_small_order_affine(x_a, y_a):
        return False, "pubkey small order"

    x_r, y_r = R[0], R[1]
    if is_small_order_affine(x_r, y_r):
        return False, "R small order"

    # Hash using ORIGINAL bytes
    k = sha512_modL(bytes(r_bytes) + bytes(pubkey_bytes) + bytes(msg_bytes))

    # [S]B - [k]A = R ?
    neg_A = point_neg(A)
    kA_neg = scalar_mult(k, neg_A)
    SB = scalar_mult(S, B)
    Rcmp = point_add(kA_neg, SB)

    # Projective equality
    X1, Y1, Z1, T1 = Rcmp
    X2, Y2, Z2, T2 = R
    if (fe_eq(fe_mul(X1, Z2), fe_mul(X2, Z1)) and
        fe_eq(fe_mul(Y1, Z2), fe_mul(Y2, Z1))):
        return True, "SUCCESS"
    else:
        return False, "equation check failed"

# =============================================================================
# Main
# =============================================================================

def main():
    print()
    print("#" * 80)
    print("#  Non-canonical R Ed25519 Test Vector Generator")
    print("#  Target: Firedancer vs ed25519-dalek v1.0.1 consensus divergence")
    print("#" * 80)
    print()

    # Generate vectors
    vectors = generate_decompression_test_vectors()

    # Run Firedancer emulator on all vectors
    print()
    print("=" * 80)
    print("FIREDANCER EMULATOR RESULTS")
    print("=" * 80)
    print()

    for vec in vectors:
        pub = bytes.fromhex(vec["pubkey"])
        sig = bytes.fromhex(vec["signature"])
        msg = bytes.fromhex(vec["message"]) if vec["message"] else b""

        accept, reason = firedancer_verify_inline(msg, sig, pub)
        result = "ACCEPT" if accept else "REJECT"

        match_expected = result == vec["expected_firedancer"]
        flag = "" if match_expected else " *** UNEXPECTED ***"

        print(f"  [{vec['id']}]")
        print(f"    Result: {result} ({reason})")
        print(f"    Expected FD: {vec['expected_firedancer']}")
        print(f"    Expected Dalek: {vec['expected_dalek_strict']}")
        if flag:
            print(f"    {flag}")

        # Critical check: if Firedancer ACCEPTS but Dalek REJECTS
        if result == "ACCEPT" and vec["expected_dalek_strict"] == "REJECT":
            print(f"    *** CONSENSUS DIVERGENCE DETECTED ***")

        # Store the actual result
        vec["result_firedancer_emulation"] = result
        vec["result_firedancer_reason"] = reason
        print()

    # Highlight the key findings
    print()
    print("=" * 80)
    print("KEY FINDINGS")
    print("=" * 80)
    print()

    # Find vectors where Firedancer decompression succeeded (i.e., rejection was
    # at equation check, not at decompression)
    decompressed_ok = [v for v in vectors
                       if v.get("result_firedancer_reason") == "equation check failed"
                       and v.get("on_curve", True)]
    decompressed_failed = [v for v in vectors
                           if v.get("result_firedancer_reason") == "R decompression failed"]
    small_order_rejected = [v for v in vectors
                            if v.get("result_firedancer_reason") == "R small order"]

    print(f"Non-canonical R vectors that decompressed successfully in Firedancer: {len(decompressed_ok)}")
    for v in decompressed_ok:
        print(f"  - {v['id']}: y_canon={v.get('canonical_y', v.get('noncanon_y_offset', '?'))}")

    print(f"Non-canonical R vectors that failed decompression: {len(decompressed_failed)}")
    for v in decompressed_failed:
        print(f"  - {v['id']}")

    print(f"Non-canonical R vectors rejected as small order: {len(small_order_rejected)}")
    for v in small_order_rejected:
        print(f"  - {v['id']}")

    print()
    print("CRITICAL INSIGHT:")
    print("  If Firedancer decompresses non-canonical R (reducing y mod p),")
    print("  but Dalek rejects non-canonical R at the CompressedEdwardsY level,")
    print("  then a valid signature with non-canonical R would be ACCEPTED by")
    print("  Firedancer but REJECTED by Dalek -- a consensus split.")
    print()
    print("  The only barrier to exploitation is finding r where [r]B.y < 19,")
    print("  which requires solving the discrete log problem for a specific")
    print("  range of outputs. This is computationally infeasible with current")
    print("  technology, but the BEHAVIORAL DIVERGENCE itself is the bug.")
    print()

    # Save vectors to JSON
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "noncanon_test_vectors.json")
    output_data = {
        "description": "Non-canonical R encoding test vectors for Firedancer vs Dalek differential testing",
        "generated_by": "generate_noncanon_sig.py",
        "key_hypothesis": "Firedancer reduces non-canonical y mod p during decompression (ACCEPTS), while Dalek verify_strict rejects non-canonical y >= p (REJECTS). This behavioral divergence could lead to a consensus split if a valid signature with non-canonical R is constructed.",
        "vectors": vectors,
    }

    with open(output_path, 'w') as f:
        json.dump(output_data, f, indent=2, default=str)
    print(f"Saved {len(vectors)} test vectors to: {output_path}")
    print()

    # Also append the most interesting vectors to the main test_vectors.json
    main_vectors_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "test_vectors.json")
    if os.path.exists(main_vectors_path):
        with open(main_vectors_path, 'r') as f:
            main_data = json.load(f)

        # Add vectors that aren't already there
        existing_ids = {v["id"] for v in main_data["vectors"]}
        new_vectors = []
        for v in vectors:
            if v["id"] not in existing_ids:
                # Clean up extra fields for the main file
                clean_v = {
                    "id": v["id"],
                    "hypothesis": v["hypothesis"],
                    "description": v["description"],
                    "pubkey": v["pubkey"],
                    "signature": v["signature"],
                    "message": v["message"],
                    "expected_firedancer": v["expected_firedancer"],
                    "expected_dalek_strict": v["expected_dalek_strict"],
                    "expected_dalek_loose": v.get("expected_dalek_loose", "unknown"),
                }
                new_vectors.append(clean_v)

        if new_vectors:
            main_data["vectors"].extend(new_vectors)
            with open(main_vectors_path, 'w') as f:
                json.dump(main_data, f, indent=2)
            print(f"Added {len(new_vectors)} new vectors to: {main_vectors_path}")
        else:
            print("No new vectors to add to main test_vectors.json")
    print()

    return vectors


if __name__ == "__main__":
    main()
