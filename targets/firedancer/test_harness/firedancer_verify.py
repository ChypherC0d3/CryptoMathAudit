#!/usr/bin/env python3
"""
Firedancer Ed25519 verification logic replicated in pure Python.

Replicates the EXACT behavior of fd_ed25519_verify() from
firedancer/src/ballet/ed25519/fd_ed25519_user.c (lines 135-230).

Key behavioral differences from standard Ed25519:
  - Non-canonical y (y >= p) is ACCEPTED (reduced mod p silently)
  - Small-order R and A are REJECTED
  - S >= L is REJECTED
  - Cofactorless equation: [S]B = R + [k]A (no cofactor)
  - Point comparison in projective coords (not byte comparison)
  - Hash uses ORIGINAL signature bytes (possibly non-canonical)

Dependencies: hashlib (stdlib) only.
"""

import hashlib
import json
import os
import sys

# =============================================================================
# Field arithmetic mod p = 2^255 - 19
# =============================================================================

p = (1 << 255) - 19

def fe_add(a, b):
    return (a + b) % p

def fe_sub(a, b):
    return (a - b) % p

def fe_mul(a, b):
    return (a * b) % p

def fe_sq(a):
    return (a * a) % p

def fe_pow(a, e):
    return pow(a, e, p)

def fe_inv(a):
    """Modular inverse using Fermat's little theorem: a^(p-2) mod p"""
    return pow(a, p - 2, p)

def fe_neg(a):
    return (-a) % p

def fe_is_zero(a):
    return (a % p) == 0

def fe_eq(a, b):
    return ((a - b) % p) == 0

def fe_is_negative(a):
    """Returns 1 if a is odd (bit 0 set), 0 if even. This is the Ed25519 sign convention."""
    return (a % p) % 2

# =============================================================================
# Ed25519 curve parameters
# =============================================================================

# Curve: -x^2 + y^2 = 1 + d*x^2*y^2  (twisted Edwards)
# d = -121665/121666 mod p
d = fe_mul(-121665, fe_inv(121666))

# Base point B
B_y = fe_mul(4, fe_inv(5))  # y = 4/5
# Compute x from y: x^2 = (y^2 - 1) / (d * y^2 + 1)
_B_u = fe_sub(fe_sq(B_y), 1)
_B_v = fe_add(fe_mul(d, fe_sq(B_y)), 1)
_B_v_inv = fe_inv(_B_v)
_B_x2 = fe_mul(_B_u, _B_v_inv)

def sqrt_mod_p(a):
    """Compute sqrt(a) mod p. Returns the non-negative root or None if no root."""
    # p = 5 mod 8, use Atkin's algorithm
    # candidate = a^((p+3)/8) mod p
    candidate = fe_pow(a, (p + 3) // 8)
    if fe_eq(fe_sq(candidate), a):
        return candidate
    # Try candidate * sqrt(-1)
    sqrt_m1 = fe_pow(2, (p - 1) // 4)
    candidate = fe_mul(candidate, sqrt_m1)
    if fe_eq(fe_sq(candidate), a):
        return candidate
    return None

# sqrt(-1) mod p
SQRT_M1 = fe_pow(2, (p - 1) // 4)

_B_x = sqrt_mod_p(_B_x2)
if fe_is_negative(_B_x):
    _B_x = fe_neg(_B_x)

# Base point in extended coordinates (X, Y, Z, T) where x=X/Z, y=Y/Z, T=X*Y/Z
B = (_B_x, B_y, 1, fe_mul(_B_x, B_y))

# Group order
L = (1 << 252) + 27742317777372353535851937790883648493

# Identity point
IDENTITY = (0, 1, 1, 0)

# =============================================================================
# Small-order point y-coordinates for rejection
# =============================================================================

# The 8 small-order points on Ed25519 (order dividing 8):
# P0: (0, 1)       order 1 (identity)     X==0
# P1: (0, -1)      order 2                X==0
# P2: (sqrt(-1),0) order 4                Y==0
# -P2:(-sqrt(-1),0) order 4               Y==0
# P3: (*, y3)      order 8                Y matches order8_y0
# -P3:(*, y3)      order 8                Y matches order8_y0
# P4: (*, y4)      order 8                Y matches order8_y1
# -P4:(*, y4)      order 8                Y matches order8_y1

# Firedancer checks: X==0 OR Y==0 OR Y==order8_y0 OR Y==order8_y1
# order8_y0 and order8_y1 are the y-coordinates of the order-8 points.

# From the Firedancer table comments:
# P3 encoding: 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
# P4 encoding: c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a

# Decode y-coordinates from the known encodings
def decode_y_from_encoding(hex_str):
    """Decode just the y coordinate from a 32-byte point encoding."""
    b = bytes.fromhex(hex_str)
    # Clear the x-sign bit (bit 255)
    y_bytes = bytearray(b)
    y_bytes[31] &= 0x7F
    return int.from_bytes(y_bytes, 'little')

ORDER8_Y0 = decode_y_from_encoding("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
ORDER8_Y1 = decode_y_from_encoding("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")

def is_small_order(point):
    """
    Replicates fd_ed25519_affine_is_small_order.
    Assumes point is affine (Z==1).
    Checks: X==0 OR Y==0 OR Y==order8_y0 OR Y==order8_y1
    """
    x, y, z, t = point
    # For affine points, z==1, so x and y are the actual coords
    return (fe_is_zero(x) or fe_is_zero(y)
            or fe_eq(y, ORDER8_Y0) or fe_eq(y, ORDER8_Y1))

# =============================================================================
# Extended twisted Edwards point arithmetic
# =============================================================================

def point_add(P, Q):
    """Add two points in extended twisted Edwards coordinates.
    P = (X1, Y1, Z1, T1), Q = (X2, Y2, Z2, T2)
    Using the unified addition formula for -x^2 + y^2 = 1 + d*x^2*y^2
    """
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q

    A = fe_mul(X1, X2)
    B = fe_mul(Y1, Y2)
    C = fe_mul(fe_mul(d, T1), T2)
    D = fe_mul(Z1, Z2)

    # For twisted Edwards -x^2 + y^2 = 1 + d*x^2*y^2 (a = -1):
    E = fe_mul(fe_add(X1, Y1), fe_add(X2, Y2))
    E = fe_sub(fe_sub(E, A), B)  # E = (X1+Y1)(X2+Y2) - A - B
    F = fe_sub(D, C)
    G = fe_add(D, C)
    H = fe_sub(B, fe_neg(A))  # H = B - a*A = B + A (since a = -1)

    X3 = fe_mul(E, F)
    Y3 = fe_mul(G, H)
    Z3 = fe_mul(F, G)
    T3 = fe_mul(E, H)

    return (X3, Y3, Z3, T3)

def point_neg(P):
    """Negate a point: -(X, Y, Z, T) = (-X, Y, Z, -T)"""
    X, Y, Z, T = P
    return (fe_neg(X), Y, Z, fe_neg(T))

def point_double(P):
    """Double a point in extended coordinates.
    For twisted Edwards with a = -1.
    """
    X1, Y1, Z1, T1 = P

    A = fe_sq(X1)
    B = fe_sq(Y1)
    C = fe_mul(2, fe_sq(Z1))
    D = fe_neg(A)  # a * A = -A since a = -1
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
    """Compute [s]P using double-and-add."""
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

def point_eq(P, Q):
    """
    Replicates fd_ed25519_point_eq_z1.
    Compares two points in projective/extended coordinates.
    Assumes Q has Z==1 (affine/decompressed point).

    Check: P.X * Q.Z == Q.X * P.Z AND P.Y * Q.Z == Q.Y * P.Z
    Since Q.Z == 1: P.X == Q.X * P.Z AND P.Y == Q.Y * P.Z
    """
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q

    # General projective equality: X1*Z2 == X2*Z1 AND Y1*Z2 == Y2*Z1
    lhs_x = fe_mul(X1, Z2)
    rhs_x = fe_mul(X2, Z1)
    lhs_y = fe_mul(Y1, Z2)
    rhs_y = fe_mul(Y2, Z1)

    return fe_eq(lhs_x, rhs_x) and fe_eq(lhs_y, rhs_y)

# =============================================================================
# Point decompression (fd_ed25519_point_frombytes equivalent)
# =============================================================================

def sqrt_ratio_m1(u, v):
    """
    Compute sqrt(u/v) mod p, following Ed25519 decompression.
    Returns (success, root).

    Uses the method: candidate = u * v^3 * (u * v^7)^((p-5)/8)
    Then check candidate^2 * v == u or candidate^2 * v == -u.
    """
    v3 = fe_mul(fe_sq(v), v)         # v^3
    v7 = fe_mul(fe_sq(v3), v)        # v^7
    uv7 = fe_mul(u, v7)              # u * v^7
    p58 = fe_pow(uv7, (p - 5) // 8)  # (u*v^7)^((p-5)/8)
    r = fe_mul(fe_mul(u, v3), p58)   # u * v^3 * (u*v^7)^((p-5)/8)

    check = fe_mul(fe_sq(r), v)
    if fe_eq(check, u):
        return (True, r)
    if fe_eq(check, fe_neg(u)):
        r = fe_mul(r, SQRT_M1)
        return (True, r)
    return (False, 0)

def point_decompress(buf_bytes):
    """
    Decompress a 32-byte Ed25519 point encoding.
    Replicates fd_ed25519_point_frombytes behavior:
    1. Read 32 bytes little-endian
    2. Extract x-sign bit from bit 255
    3. Mask bit 255 to get y (255 bits)
    4. Reduce y mod p (ACCEPTS non-canonical y >= p)
    5. Compute x from curve equation
    6. Return (x, y, 1, x*y) or None if not on curve

    Returns: (x, y, 1, t) tuple or None if decompression fails.
    """
    if len(buf_bytes) != 32:
        return None

    # Extract x sign bit (bit 255 = MSB of byte 31)
    x_sign = (buf_bytes[31] >> 7) & 1

    # Read y as little-endian 256-bit integer, mask bit 255
    y_bytes = bytearray(buf_bytes)
    y_bytes[31] &= 0x7F
    y = int.from_bytes(y_bytes, 'little')

    # CRITICAL: Reduce y mod p (Firedancer accepts non-canonical y >= p)
    y = y % p

    # Compute u = y^2 - 1
    u = fe_sub(fe_sq(y), 1)
    # Compute v = d*y^2 + 1
    v = fe_add(fe_mul(d, fe_sq(y)), 1)

    # Compute x = sqrt(u/v)
    success, x = sqrt_ratio_m1(u, v)
    if not success:
        return None  # Not on curve

    # Negate x if sign doesn't match
    if fe_is_negative(x) != x_sign:
        x = fe_neg(x)

    # Special case: x == 0 but x_sign == 1 is technically invalid in RFC 8032
    # but Firedancer accepts it (the point still decompresses)
    # Actually, if x==0 and x_sign==1, decompression should fail per RFC.
    # But Firedancer's frombytes does NOT check this explicitly.
    # The sqrt_ratio returns x=0, and -0 == 0, so negate has no effect.
    # We'll accept it (matching Firedancer).

    t = fe_mul(x, y)
    return (x, y, 1, t)

# =============================================================================
# Scalar validation: S < L
# =============================================================================

def scalar_validate(s_bytes):
    """
    Replicates fd_curve25519_scalar_validate.
    Checks if 256-bit scalar (little-endian bytes) is in [0, L).
    Returns True if valid (s < L), False otherwise.
    """
    s = int.from_bytes(s_bytes, 'little')
    return s < L

def scalar_from_bytes(s_bytes):
    """Read a scalar from 32 little-endian bytes."""
    return int.from_bytes(s_bytes, 'little')

# =============================================================================
# SHA-512 hash to scalar
# =============================================================================

def sha512_modL(data):
    """Compute SHA-512(data) and reduce the 512-bit result mod L."""
    h = hashlib.sha512(data).digest()
    # Interpret as 512-bit little-endian integer
    k = int.from_bytes(h, 'little')
    return k % L

# =============================================================================
# fd_ed25519_verify -- Main verification function
# =============================================================================

def firedancer_verify(msg_bytes, sig_bytes, pubkey_bytes):
    """
    Replicate fd_ed25519_verify exactly.

    Args:
        msg_bytes: message bytes
        sig_bytes: 64-byte signature (R || S)
        pubkey_bytes: 32-byte public key

    Returns:
        (accept, reason) where accept is True/False and reason is a string.
    """
    if len(sig_bytes) != 64:
        return (False, "ERR_SIG: signature not 64 bytes")
    if len(pubkey_bytes) != 32:
        return (False, "ERR_PUBKEY: pubkey not 32 bytes")

    r_bytes = sig_bytes[:32]
    s_bytes = sig_bytes[32:]

    # Step 1: Check scalar S < L
    if not scalar_validate(s_bytes):
        return (False, "ERR_SIG: S >= L")

    S = scalar_from_bytes(s_bytes)

    # Step 2: Decompress pubkey A and signature point R
    A = point_decompress(pubkey_bytes)
    if A is None:
        return (False, "ERR_PUBKEY: decompression failed")

    R = point_decompress(r_bytes)
    if R is None:
        return (False, "ERR_SIG: R decompression failed")

    # Step 3: Check small-order
    if is_small_order(A):
        return (False, "ERR_PUBKEY: small order")

    if is_small_order(R):
        return (False, "ERR_SIG: R small order")

    # Step 4: Compute k = SHA-512(R_bytes || A_bytes || msg) mod L
    # CRITICAL: Uses the ORIGINAL bytes, not re-encoded canonical bytes
    hash_input = bytes(r_bytes) + bytes(pubkey_bytes) + bytes(msg_bytes)
    k = sha512_modL(hash_input)

    # Step 5: Compute Rcmp = [S]B - [k]A  (equivalently, [S]B + [-k]A)
    # Firedancer does: negate A, then compute [k](-A) + [S]B
    neg_A = point_neg(A)
    # [k](-A) + [S]B = [S]B - [k]A
    kA_neg = scalar_mult(k, neg_A)
    SB = scalar_mult(S, B)
    Rcmp = point_add(kA_neg, SB)

    # Step 6: Compare Rcmp with R using projective equality
    if point_eq(Rcmp, R):
        return (True, "SUCCESS")
    else:
        return (False, "ERR_MSG: equation check failed")

# =============================================================================
# Test harness
# =============================================================================

def run_tests(json_path):
    """Load test vectors and run Firedancer-equivalent verification."""
    with open(json_path, 'r') as f:
        data = json.load(f)

    vectors = data.get("vectors", [])

    print("=" * 80)
    print("Firedancer Ed25519 Verification - Test Results")
    print("=" * 80)
    print()

    discrepancies = []
    results_summary = []

    for vec in vectors:
        vec_id = vec["id"]
        desc = vec["description"]
        pubkey_hex = vec["pubkey"]
        sig_hex = vec["signature"]
        msg_hex = vec["message"]
        expected_fd = vec.get("expected_firedancer", "unknown")
        expected_dalek_strict = vec.get("expected_dalek_strict", "unknown")
        expected_dalek_loose = vec.get("expected_dalek_loose", "unknown")

        pubkey_bytes = bytes.fromhex(pubkey_hex)
        sig_bytes = bytes.fromhex(sig_hex)
        msg_bytes = bytes.fromhex(msg_hex) if msg_hex else b""

        accept, reason = firedancer_verify(msg_bytes, sig_bytes, pubkey_bytes)
        result = "ACCEPT" if accept else "REJECT"

        # Check for discrepancies
        fd_match = True
        dalek_strict_match = True
        if expected_fd != "unknown" and expected_fd != result:
            fd_match = False
        if expected_dalek_strict != "unknown" and expected_dalek_strict != result:
            dalek_strict_match = False

        # Discrepancy between our Firedancer emulation and Dalek strict
        disc_with_dalek = (result != expected_dalek_strict and expected_dalek_strict != "unknown")
        disc_with_fd_expected = (not fd_match)

        flag = ""
        if disc_with_fd_expected:
            flag = " *** MISMATCH vs expected_firedancer ***"
            discrepancies.append((vec_id, result, expected_fd, expected_dalek_strict, reason))
        elif disc_with_dalek:
            flag = " [differs from dalek_strict]"

        print(f"[{vec_id}]")
        print(f"  Description: {desc}")
        print(f"  Our result (Firedancer emulation): {result}")
        print(f"    Reason: {reason}")
        print(f"  expected_firedancer:    {expected_fd}")
        print(f"  expected_dalek_strict:  {expected_dalek_strict}")
        print(f"  expected_dalek_loose:   {expected_dalek_loose}")
        if flag:
            print(f"  {flag}")
        print()

        results_summary.append({
            "id": vec_id,
            "firedancer_emulation": result,
            "reason": reason,
            "expected_firedancer": expected_fd,
            "expected_dalek_strict": expected_dalek_strict,
            "match_dalek_strict": result == expected_dalek_strict if expected_dalek_strict != "unknown" else "N/A",
        })

    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)

    total = len(vectors)
    accepts = sum(1 for r in results_summary if r["firedancer_emulation"] == "ACCEPT")
    rejects = total - accepts
    matches_dalek = sum(1 for r in results_summary
                        if r["match_dalek_strict"] is True)
    mismatches_dalek = sum(1 for r in results_summary
                           if r["match_dalek_strict"] is False)
    unknown_fd = sum(1 for r in results_summary
                     if r["expected_firedancer"] == "unknown")
    matches_fd = sum(1 for r in results_summary
                     if r["expected_firedancer"] != "unknown"
                     and r["firedancer_emulation"] == r["expected_firedancer"])
    mismatches_fd = sum(1 for r in results_summary
                        if r["expected_firedancer"] != "unknown"
                        and r["firedancer_emulation"] != r["expected_firedancer"])

    print(f"Total vectors:          {total}")
    print(f"ACCEPT:                 {accepts}")
    print(f"REJECT:                 {rejects}")
    print()
    print(f"Match expected_firedancer:     {matches_fd} (of {total - unknown_fd} with known expected)")
    print(f"Mismatch expected_firedancer:  {mismatches_fd}")
    print(f"Unknown expected_firedancer:   {unknown_fd}")
    print()
    print(f"Match dalek_strict:     {matches_dalek}")
    print(f"Mismatch dalek_strict:  {mismatches_dalek}")
    print()

    if discrepancies:
        print("!!! DISCREPANCIES WITH expected_firedancer !!!")
        for vec_id, our_result, expected_fd, expected_dalek, reason in discrepancies:
            print(f"  {vec_id}: ours={our_result}, expected_fd={expected_fd}, "
                  f"expected_dalek_strict={expected_dalek}, reason={reason}")
    else:
        print("No discrepancies with expected_firedancer values.")

    # Show cases where our Firedancer emulation differs from Dalek strict
    fd_vs_dalek_diffs = [(r["id"], r["firedancer_emulation"], r["expected_dalek_strict"])
                         for r in results_summary
                         if r["match_dalek_strict"] is False]
    if fd_vs_dalek_diffs:
        print()
        print("FIREDANCER EMULATION vs DALEK_STRICT DIFFERENCES:")
        for vec_id, fd_result, dalek_result in fd_vs_dalek_diffs:
            print(f"  {vec_id}: firedancer={fd_result}, dalek_strict={dalek_result}")
    else:
        print()
        print("No differences between Firedancer emulation and dalek_strict.")

    print()
    print("=" * 80)
    return results_summary


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(script_dir, "test_vectors.json")

    if not os.path.exists(json_path):
        print(f"ERROR: test_vectors.json not found at {json_path}")
        sys.exit(1)

    run_tests(json_path)
