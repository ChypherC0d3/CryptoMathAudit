#!/usr/bin/env python3
"""
Hypothesis H3: Small-order point detection differences between
Firedancer and Dalek with non-canonical encodings.

This script:
1. Enumerates ALL 8 small-order points on Ed25519
2. Generates both canonical and non-canonical encodings for each
3. Tests whether Firedancer's small-order detection catches non-canonical encodings
4. Tests whether non-canonical small-order points as A or R cause different behavior
5. Compares expected Firedancer vs Dalek behavior

Key finding from source analysis:
  - fd_ed25519_point_frombytes calls fd_f25519_frombytes(y, buf) which reduces y mod p
  - THEN fd_ed25519_affine_is_small_order checks the REDUCED y
  - The small-order table contains CANONICAL (reduced) y-coordinates
  - So non-canonical encodings WILL be caught after reduction
  - BUT: the hash uses ORIGINAL bytes, not re-encoded canonical bytes
"""

import hashlib
import os
import sys
import time

# Import the Firedancer emulator
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)
from firedancer_verify import (
    p, L, B, IDENTITY, SQRT_M1,
    fe_add, fe_sub, fe_mul, fe_sq, fe_inv, fe_neg, fe_pow,
    fe_is_zero, fe_eq, fe_is_negative,
    sqrt_mod_p, point_add, point_neg, point_double, scalar_mult,
    point_decompress, is_small_order, firedancer_verify,
    ORDER8_Y0, ORDER8_Y1, d
)

# =============================================================================
# Constants
# =============================================================================

output_lines = []

def log(msg=""):
    print(msg)
    output_lines.append(msg)

# =============================================================================
# Enumerate all 8 small-order points
# =============================================================================

def compute_small_order_points():
    """
    Compute all 8 small-order points on Ed25519.
    The curve equation: -x^2 + y^2 = 1 + d*x^2*y^2

    Points of small order (dividing 8):
    - Order 1: Identity (0, 1)
    - Order 2: (0, -1) = (0, p-1)
    - Order 4: (sqrt(-1), 0) and (-sqrt(-1), 0)
    - Order 8: 4 points with y-coords ORDER8_Y0 and ORDER8_Y1
    """
    points = []

    # P0: Identity (0, 1) - order 1
    points.append({
        'name': 'P0 (identity)',
        'order': 1,
        'x': 0,
        'y': 1,
    })

    # P1: (0, -1) = (0, p-1) - order 2
    points.append({
        'name': 'P1 (order 2)',
        'order': 2,
        'x': 0,
        'y': p - 1,
    })

    # P2: (sqrt(-1), 0) - order 4
    sqrt_m1 = SQRT_M1
    points.append({
        'name': 'P2 (order 4)',
        'order': 4,
        'x': sqrt_m1,
        'y': 0,
    })

    # -P2: (-sqrt(-1), 0) - order 4
    points.append({
        'name': '-P2 (order 4)',
        'order': 4,
        'x': fe_neg(sqrt_m1),
        'y': 0,
    })

    # Order 8 points: y = ORDER8_Y0
    # Compute x from y: x^2 = (y^2 - 1) / (d*y^2 + 1)  ... for -x^2 + y^2 = 1 + d*x^2*y^2
    # Rearranging: y^2 - 1 = x^2(d*y^2 + 1)  ... wait, that's for x^2 + y^2 = 1 + d*x^2*y^2
    # For TWISTED Edwards: -x^2 + y^2 = 1 + d*x^2*y^2
    #   y^2 - 1 = x^2 + d*x^2*y^2 = x^2(1 + d*y^2)
    #   x^2 = (y^2 - 1) / (1 + d*y^2)
    # But we also need: -x^2 + y^2 = 1 + d*x^2*y^2
    #   y^2 - 1 = x^2 + d*x^2*y^2 = x^2(1 + d*y^2)
    # Hmm wait, that gives x^2 positive. Let me redo:
    # -x^2 + y^2 = 1 + d*x^2*y^2
    # y^2 - 1 = x^2 + d*x^2*y^2 = x^2(1 + d*y^2)
    # x^2 = (y^2 - 1) / (1 + d*y^2)
    # This is different from what the decompression uses!
    # The decompression uses: u = y^2 - 1, v = d*y^2 + 1, x = sqrt(u/v)
    # Which is exactly the same. Good.

    for y_val, name_base in [(ORDER8_Y0, 'P3'), (ORDER8_Y1, 'P4')]:
        u = fe_sub(fe_sq(y_val), 1)
        v = fe_add(fe_mul(d, fe_sq(y_val)), 1)
        x_val = sqrt_mod_p(fe_mul(u, fe_inv(v)))
        if x_val is None:
            log(f"WARNING: Could not compute x for {name_base}")
            continue

        # Two x values: x and -x
        for x_sign, neg_prefix in [(0, ''), (1, '-')]:
            x_use = x_val if x_sign == 0 else fe_neg(x_val)
            # Ensure the sign bit matches what we want
            if fe_is_negative(x_use) != x_sign:
                x_use = fe_neg(x_use)

            points.append({
                'name': f'{neg_prefix}{name_base} (order 8)',
                'order': 8,
                'x': x_use,
                'y': y_val,
            })

    return points

def encode_point(x, y):
    """Encode a point as 32 bytes (canonical encoding)."""
    y_bytes = y.to_bytes(32, 'little')
    buf = bytearray(y_bytes)
    if fe_is_negative(x):
        buf[31] |= 0x80
    return bytes(buf)

def make_non_canonical_encoding(y, x_sign):
    """
    Create a non-canonical encoding where the lower 255 bits represent y + p.

    In Ed25519 encoding, the lower 255 bits store y, and bit 255 stores sign of x.
    A non-canonical encoding has the lower 255 bits representing a value >= p.

    Since p = 2^255 - 19, we have y + p = y + 2^255 - 19.
    For this to fit in 255 bits (without overflowing into the sign bit),
    we need y + p < 2^255, i.e., y < 19.

    So only y-values 0 through 18 have non-canonical representations.
    """
    y_nc = y + p  # y + p
    if y_nc >= (1 << 255):
        return None  # Doesn't fit in 255 bits

    buf = bytearray(y_nc.to_bytes(32, 'little'))
    if x_sign:
        buf[31] |= 0x80
    return bytes(buf)

# =============================================================================
# Test construction helpers
# =============================================================================

def make_zero_signature():
    """Create a signature with S=0, R=identity."""
    # R = identity point encoding
    R_bytes = encode_point(0, 1)  # (0, 1) = identity
    S_bytes = (0).to_bytes(32, 'little')
    return R_bytes + S_bytes

def make_test_signature_with_R(R_bytes, S_val=0):
    """Create a signature with given R encoding and S value."""
    S_bytes = S_val.to_bytes(32, 'little')
    return R_bytes + S_bytes

# =============================================================================
# Main analysis
# =============================================================================

def analyze_firedancer_source():
    """Document the Firedancer small-order detection mechanism."""
    log("=" * 80)
    log("FIREDANCER SMALL-ORDER DETECTION ANALYSIS")
    log("=" * 80)
    log()
    log("Source: fd_curve25519.h, fd_ed25519_affine_is_small_order()")
    log()
    log("The function checks if a decompressed (affine, Z==1) point has small order by:")
    log("  1. X == 0  (catches identity and order-2 point)")
    log("  2. Y == 0  (catches both order-4 points)")
    log("  3. Y == order8_y0  (catches 2 order-8 points)")
    log("  4. Y == order8_y1  (catches 2 order-8 points)")
    log()
    log("The small-order y-coordinate table values:")
    log(f"  order8_y0 = 0x{ORDER8_Y0:064x}")
    log(f"  order8_y1 = 0x{ORDER8_Y1:064x}")
    log()
    log("CRITICAL FLOW in fd_ed25519_verify():")
    log("  1. fd_ed25519_point_frombytes_2x(Aprime, pubkey, R, r)")
    log("     -> calls fd_f25519_frombytes(y, buf) which REDUCES y mod p")
    log("     -> then computes x from the REDUCED y")
    log("     -> result: affine point with Z==1, canonical coordinates")
    log("  2. fd_ed25519_affine_is_small_order(Aprime)")
    log("     -> checks REDUCED X and Y values against table")
    log("  3. Hash computation: SHA-512(R_bytes || A_bytes || msg)")
    log("     -> uses ORIGINAL bytes (possibly non-canonical)")
    log()
    log("CONSEQUENCE:")
    log("  - Non-canonical encoding of small-order point y + p")
    log("  - fd_f25519_frombytes reduces to canonical y")
    log("  - Small-order check uses CANONICAL y -> CORRECTLY detects small order")
    log("  - Firedancer REJECTS non-canonical small-order points (same as canonical)")
    log()
    log("  BUT: If decompression succeeds and the point is NOT small-order,")
    log("  the hash uses the ORIGINAL non-canonical bytes, producing a")
    log("  DIFFERENT hash than the canonical encoding of the same point.")
    log("  This is NOT a bug per se, as both Firedancer and Dalek accept")
    log("  non-canonical encodings and hash the original bytes.")
    log()

def test_small_order_points():
    """Test all small-order points with canonical and non-canonical encodings."""
    log("=" * 80)
    log("SMALL-ORDER POINT ENUMERATION AND ENCODING TEST")
    log("=" * 80)
    log()

    points = compute_small_order_points()

    log(f"Found {len(points)} small-order points:")
    log()

    results = []

    for pt in points:
        name = pt['name']
        x = pt['x']
        y = pt['y']
        order = pt['order']
        x_sign = fe_is_negative(x)

        log(f"--- {name} (order {order}) ---")
        log(f"  x = 0x{x:064x}")
        log(f"  y = 0x{y:064x}")
        log(f"  x_sign = {x_sign}")

        # Canonical encoding
        canonical = encode_point(x, y)
        log(f"  Canonical encoding: {canonical.hex()}")

        # Verify decompression of canonical
        decomp = point_decompress(canonical)
        if decomp is None:
            log(f"  Canonical decompression: FAILED")
        else:
            dx, dy, dz, dt = decomp
            log(f"  Canonical decompression: OK (x_match={fe_eq(dx, x)}, y_match={fe_eq(dy, y)})")
            log(f"  Small-order check (canonical): {is_small_order(decomp)}")

        # Non-canonical encoding
        nc = make_non_canonical_encoding(y, x_sign)
        if nc is None:
            log(f"  Non-canonical encoding: NOT POSSIBLE (y >= 19)")
            nc_possible = False
        else:
            nc_possible = True
            log(f"  Non-canonical encoding: {nc.hex()}")

            # Verify the non-canonical bytes differ
            if nc == canonical:
                log(f"  WARNING: Non-canonical same as canonical!")
            else:
                log(f"  Encodings differ: YES")

            # Verify decompression of non-canonical
            nc_decomp = point_decompress(nc)
            if nc_decomp is None:
                log(f"  Non-canonical decompression: FAILED")
            else:
                ncx, ncy, ncz, nct = nc_decomp
                log(f"  Non-canonical decompression: OK")
                log(f"    Reduced y matches canonical y: {fe_eq(ncy, y)}")
                log(f"    Reduced x matches canonical x: {fe_eq(ncx, x)}")
                log(f"  Small-order check (non-canonical): {is_small_order(nc_decomp)}")

                same_point = fe_eq(ncx, x) and fe_eq(ncy, y)
                log(f"  Same point after decompression: {same_point}")

        results.append({
            'name': name,
            'order': order,
            'canonical': canonical,
            'non_canonical': nc if nc_possible else None,
            'nc_possible': nc_possible,
        })
        log()

    return results

def test_as_pubkey(encoding, name, encoding_type):
    """Test a small-order point encoding as a public key."""
    # Create a dummy signature: R = base point encoding with S = 0
    # This will fail the equation check, but we want to see if it gets past
    # the small-order check first.
    msg = b"test message"

    # Use identity as R (will be rejected as small-order too)
    # Let's use a non-small-order R instead
    # R = B (base point), S = 0
    # This won't satisfy the equation but will let us test A rejection
    R_bytes = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")
    S_bytes = (0).to_bytes(32, 'little')
    sig = R_bytes + S_bytes

    accept, reason = firedancer_verify(msg, sig, encoding)
    return accept, reason

def test_as_R(encoding, name, encoding_type):
    """Test a small-order point encoding as R in a signature."""
    msg = b"test message"

    # Use base point as pubkey (non-small-order)
    pubkey = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")

    S_bytes = (0).to_bytes(32, 'little')
    sig = encoding + S_bytes

    accept, reason = firedancer_verify(msg, sig, pubkey)
    return accept, reason

def test_verification_behavior():
    """Test small-order points as A and R with both canonical and non-canonical encodings."""
    log("=" * 80)
    log("VERIFICATION BEHAVIOR TESTS")
    log("=" * 80)
    log()

    points = compute_small_order_points()

    all_results = []

    for pt in points:
        name = pt['name']
        x = pt['x']
        y = pt['y']
        order = pt['order']
        x_sign = fe_is_negative(x)

        canonical = encode_point(x, y)
        nc = make_non_canonical_encoding(y, x_sign)

        log(f"--- {name} ---")

        # Test canonical as pubkey
        accept_a, reason_a = test_as_pubkey(canonical, name, "canonical")
        log(f"  As pubkey A (canonical):      {('ACCEPT' if accept_a else 'REJECT'):8s} - {reason_a}")

        # Test canonical as R
        accept_r, reason_r = test_as_R(canonical, name, "canonical")
        log(f"  As R       (canonical):       {('ACCEPT' if accept_r else 'REJECT'):8s} - {reason_r}")

        result = {
            'name': name,
            'canonical_A': ('ACCEPT' if accept_a else 'REJECT', reason_a),
            'canonical_R': ('ACCEPT' if accept_r else 'REJECT', reason_r),
        }

        if nc is not None:
            # Test non-canonical as pubkey
            accept_a_nc, reason_a_nc = test_as_pubkey(nc, name, "non-canonical")
            log(f"  As pubkey A (non-canonical):  {('ACCEPT' if accept_a_nc else 'REJECT'):8s} - {reason_a_nc}")

            # Test non-canonical as R
            accept_r_nc, reason_r_nc = test_as_R(nc, name, "non-canonical")
            log(f"  As R       (non-canonical):   {('ACCEPT' if accept_r_nc else 'REJECT'):8s} - {reason_r_nc}")

            result['nc_A'] = ('ACCEPT' if accept_a_nc else 'REJECT', reason_a_nc)
            result['nc_R'] = ('ACCEPT' if accept_r_nc else 'REJECT', reason_r_nc)

            # Check for behavioral difference
            if accept_a != accept_a_nc:
                log(f"  *** BEHAVIORAL DIFFERENCE AS PUBKEY: canonical={accept_a}, non-canonical={accept_a_nc} ***")
            if accept_r != accept_r_nc:
                log(f"  *** BEHAVIORAL DIFFERENCE AS R: canonical={accept_r}, non-canonical={accept_r_nc} ***")

            # The critical check: do both reject for the SAME reason?
            if reason_a != reason_a_nc:
                log(f"  NOTE: Different rejection reasons as A: '{reason_a}' vs '{reason_a_nc}'")
            if reason_r != reason_r_nc:
                log(f"  NOTE: Different rejection reasons as R: '{reason_r}' vs '{reason_r_nc}'")
        else:
            log(f"  Non-canonical encoding: NOT POSSIBLE (y >= 19)")
            result['nc_A'] = None
            result['nc_R'] = None

        all_results.append(result)
        log()

    return all_results

def analyze_non_canonical_small_order_y_values():
    """
    Analyze which small-order y-values can have non-canonical representations.

    Non-canonical means y + p fits in 255 bits, i.e., y + p < 2^255.
    Since p = 2^255 - 19, this means y < 19.

    Small-order y-values:
    - y = 1 (identity): 1 < 19 -> HAS non-canonical
    - y = p-1: p-1 >= 19 -> NO non-canonical
    - y = 0 (order 4): 0 < 19 -> HAS non-canonical
    - y = ORDER8_Y0: large number -> NO non-canonical
    - y = ORDER8_Y1: large number -> NO non-canonical
    """
    log("=" * 80)
    log("NON-CANONICAL ENCODING ANALYSIS FOR SMALL-ORDER Y-VALUES")
    log("=" * 80)
    log()

    y_values = [
        ("y=1 (identity)", 1),
        ("y=p-1 (order 2)", p - 1),
        ("y=0 (order 4)", 0),
        ("y=ORDER8_Y0", ORDER8_Y0),
        ("y=ORDER8_Y1", ORDER8_Y1),
    ]

    for name, y in y_values:
        nc_val = y + p
        fits = nc_val < (1 << 255)
        log(f"  {name}:")
        log(f"    y = {y}")
        log(f"    y + p = {nc_val}")
        log(f"    Fits in 255 bits: {fits}")
        if fits:
            log(f"    -> HAS non-canonical encoding")
            # Verify: lower 255 bits of (y+p) encoded as LE, reduced mod p, should give y
            nc_bytes = nc_val.to_bytes(32, 'little')
            reduced = int.from_bytes(nc_bytes, 'little') % p
            log(f"    -> Reduced mod p: {reduced} (matches y: {reduced == y})")
        else:
            log(f"    -> NO non-canonical encoding")
        log()

def analyze_firedancer_vs_dalek_expected():
    """
    Analyze expected Firedancer vs Dalek behavior for non-canonical small-order points.

    Firedancer flow:
    1. Decompress (reduces y mod p, computes x)
    2. Check small-order on REDUCED point
    3. Both canonical and non-canonical get REJECTED

    Dalek (ed25519-dalek 2.x, used by Agave):
    - verify_strict: rejects small-order A and R
    - Also accepts non-canonical y (reduces mod p)
    - Should also reject non-canonical small-order points

    The code comment in fd_ed25519_user.c lines 171-190 is illuminating:
    "There's another check that we currently do NOT enforce:
     whether public key and point r are canonical."
    "Dalek 2.x (currently used by Agave) does NOT do any check."
    "Dalek 4.x checks that the point r is canonical, but accepts
     a non canonical public key."
    """
    log("=" * 80)
    log("FIREDANCER vs DALEK EXPECTED BEHAVIOR ANALYSIS")
    log("=" * 80)
    log()
    log("From Firedancer source comments (fd_ed25519_user.c:171-190):")
    log("  - Neither Firedancer nor Dalek 2.x enforce canonicality checks")
    log("  - Both accept non-canonical points (y >= p)")
    log("  - Both reduce y mod p during decompression")
    log("  - Both check small-order AFTER decompression")
    log()
    log("For non-canonical small-order points:")
    log("  Firedancer: decompress (reduces y) -> small-order check -> REJECT")
    log("  Dalek 2.x:  decompress (reduces y) -> small-order check -> REJECT")
    log()
    log("CONCLUSION: No behavioral difference expected for H3.")
    log("  Both implementations reduce y mod p before small-order checking,")
    log("  so non-canonical encodings of small-order points are correctly")
    log("  detected and rejected by both.")
    log()
    log("HOWEVER, there is a related edge case worth noting:")
    log("  The point comparison in Firedancer uses projective equality")
    log("  (line 226: fd_ed25519_point_eq_z1), while many implementations")
    log("  compress R_computed and compare bytes. This could cause differences")
    log("  for non-canonical NON-small-order points (tested separately).")
    log()

def test_edge_case_non_canonical_non_small_order():
    """
    Test edge case: non-canonical encoding of points that are NOT small-order.

    For y values 2-18 (not 0 or 1), if they correspond to valid curve points
    that are NOT small-order, the non-canonical encoding creates an interesting case:
    - Firedancer: decompresses, passes small-order check, hashes ORIGINAL bytes
    - If another implementation hashes CANONICAL bytes: different hash -> different result

    But both Firedancer and Dalek hash the original bytes, so this shouldn't differ.
    """
    log("=" * 80)
    log("EDGE CASE: NON-CANONICAL NON-SMALL-ORDER POINTS")
    log("=" * 80)
    log()

    # Check y values 2-18 for valid curve points
    for y_val in range(2, 19):
        u = fe_sub(fe_sq(y_val), 1)
        v = fe_add(fe_mul(d, fe_sq(y_val)), 1)
        x_sq = fe_mul(u, fe_inv(v))
        x = sqrt_mod_p(x_sq)

        if x is not None:
            # Valid point! Check if it's small-order
            pt = (x, y_val, 1, fe_mul(x, y_val))
            so = is_small_order(pt)

            # Check if non-canonical encoding is possible
            nc = make_non_canonical_encoding(y_val, fe_is_negative(x))

            log(f"  y={y_val}: valid point, small_order={so}")
            if not so and nc is not None:
                log(f"    -> Non-canonical, non-small-order point exists!")
                log(f"    -> Canonical encoding: {encode_point(x, y_val).hex()}")
                log(f"    -> Non-canonical encoding: {nc.hex()}")

                # Both should decompress to the same point
                d1 = point_decompress(encode_point(x, y_val))
                d2 = point_decompress(nc)
                if d1 and d2:
                    same = fe_eq(d1[0], d2[0]) and fe_eq(d1[1], d2[1])
                    log(f"    -> Same point after decompression: {same}")
        else:
            log(f"  y={y_val}: NOT on curve")
    log()

def comprehensive_signature_test():
    """
    Create and test actual signatures involving non-canonical small-order points.

    For each small-order point with a non-canonical encoding, test:
    1. As A (pubkey) with various R and S
    2. As R with a valid pubkey
    """
    log("=" * 80)
    log("COMPREHENSIVE SIGNATURE TESTS")
    log("=" * 80)
    log()

    msg = b"test"

    # Valid non-small-order pubkey: the base point
    valid_pubkey_hex = "5866666666666666666666666666666666666666666666666666666666666666"
    valid_pubkey = bytes.fromhex(valid_pubkey_hex)

    points = compute_small_order_points()

    discrepancies = []

    for pt in points:
        name = pt['name']
        x = pt['x']
        y = pt['y']
        x_sign = fe_is_negative(x)

        canonical = encode_point(x, y)
        nc = make_non_canonical_encoding(y, x_sign)

        log(f"--- {name} ---")

        # Test 1: As pubkey A, R = valid non-small-order, S = 0
        for enc_name, enc in [("canonical", canonical), ("non-canonical", nc)]:
            if enc is None:
                continue

            # R = base point, S = 0
            R_hex = "5866666666666666666666666666666666666666666666666666666666666666"
            sig = bytes.fromhex(R_hex) + (0).to_bytes(32, 'little')

            accept, reason = firedancer_verify(msg, sig, enc)
            log(f"  A={enc_name}, R=basepoint, S=0: {'ACCEPT' if accept else 'REJECT'} ({reason})")

        # Test 2: As R, A = valid non-small-order, S = 0
        for enc_name, enc in [("canonical", canonical), ("non-canonical", nc)]:
            if enc is None:
                continue

            sig = enc + (0).to_bytes(32, 'little')
            accept, reason = firedancer_verify(msg, sig, valid_pubkey)
            log(f"  R={enc_name}, A=basepoint, S=0: {'ACCEPT' if accept else 'REJECT'} ({reason})")

        # Test 3: As R, A = valid non-small-order, S = 1
        for enc_name, enc in [("canonical", canonical), ("non-canonical", nc)]:
            if enc is None:
                continue

            sig = enc + (1).to_bytes(32, 'little')
            accept, reason = firedancer_verify(msg, sig, valid_pubkey)
            log(f"  R={enc_name}, A=basepoint, S=1: {'ACCEPT' if accept else 'REJECT'} ({reason})")

        # Check for any behavioral differences between canonical and non-canonical
        if nc is not None:
            # Re-run the key tests and compare
            sig_test = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666") + (0).to_bytes(32, 'little')
            a_can, r_can = firedancer_verify(msg, sig_test, canonical)
            a_nc, r_nc = firedancer_verify(msg, sig_test, nc)

            if a_can != a_nc:
                discrepancies.append((name, "as pubkey", a_can, r_can, a_nc, r_nc))
                log(f"  *** DISCREPANCY AS PUBKEY: canonical={a_can}({r_can}), non-canonical={a_nc}({r_nc}) ***")

            sig_test2 = canonical + (0).to_bytes(32, 'little')
            sig_test3 = nc + (0).to_bytes(32, 'little')
            a_can2, r_can2 = firedancer_verify(msg, sig_test2, valid_pubkey)
            a_nc2, r_nc2 = firedancer_verify(msg, sig_test3, valid_pubkey)

            if a_can2 != a_nc2:
                discrepancies.append((name, "as R", a_can2, r_can2, a_nc2, r_nc2))
                log(f"  *** DISCREPANCY AS R: canonical={a_can2}({r_can2}), non-canonical={a_nc2}({r_nc2}) ***")

        log()

    return discrepancies

# =============================================================================
# Main
# =============================================================================

def main():
    start_time = time.time()

    log("=" * 80)
    log("HYPOTHESIS H3: Small-Order Point Non-Canonical Encoding Analysis")
    log(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("=" * 80)
    log()

    # Step 1: Analyze source code
    analyze_firedancer_source()

    # Step 2: Analyze which y-values can have non-canonical encodings
    analyze_non_canonical_small_order_y_values()

    # Step 3: Enumerate and test all small-order points
    encoding_results = test_small_order_points()

    # Step 4: Test verification behavior
    verify_results = test_verification_behavior()

    # Step 5: Firedancer vs Dalek analysis
    analyze_firedancer_vs_dalek_expected()

    # Step 6: Edge case - non-canonical non-small-order points
    test_edge_case_non_canonical_non_small_order()

    # Step 7: Comprehensive signature tests
    discrepancies = comprehensive_signature_test()

    # ==========================================================================
    # FINAL SUMMARY
    # ==========================================================================
    log("=" * 80)
    log("FINAL SUMMARY - HYPOTHESIS H3")
    log("=" * 80)
    log()

    if discrepancies:
        log(f"FOUND {len(discrepancies)} BEHAVIORAL DISCREPANCIES:")
        for d in discrepancies:
            log(f"  {d}")
        log()
        log("VERDICT: H3 CONFIRMED - Potential consensus split found!")
    else:
        log("NO BEHAVIORAL DISCREPANCIES FOUND between canonical and non-canonical")
        log("encodings of small-order points in the Firedancer emulator.")
        log()
        log("VERDICT: H3 NOT CONFIRMED")
        log()
        log("Reason: Firedancer's verification flow is:")
        log("  1. fd_f25519_frombytes() reduces y mod p FIRST")
        log("  2. Decompression computes x from REDUCED y")
        log("  3. Small-order check operates on REDUCED (canonical) coordinates")
        log("  4. Both canonical and non-canonical encodings reduce to the same point")
        log("  5. Small-order detection works correctly for both")
        log()
        log("The small-order table contains CANONICAL y-values,")
        log("and since decompression reduces y mod p before the check,")
        log("non-canonical encodings do NOT bypass the small-order filter.")
        log()
        log("Key y-values with non-canonical representations:")
        log("  y=0 (order 4): canonical 0x00, non-canonical 0x00 + p")
        log("  y=1 (identity): canonical 0x01, non-canonical 0x01 + p")
        log("  Both correctly detected as small-order after reduction.")
        log()
        log("NOTE: This analysis is based on the Python Firedancer emulator.")
        log("The actual C implementation should be tested with the Rust harness")
        log("for definitive confirmation.")

    elapsed = time.time() - start_time
    log()
    log(f"Elapsed time: {elapsed:.2f} seconds")
    log("=" * 80)

    # Save results
    findings_dir = os.path.join(script_dir, "..", "..", "bounties", "findings")
    os.makedirs(findings_dir, exist_ok=True)
    findings_path = os.path.join(findings_dir, "firedancer_h3_results.txt")
    with open(findings_path, 'w') as f:
        f.write('\n'.join(output_lines))
    log(f"\nResults saved to: {findings_path}")


if __name__ == "__main__":
    main()
