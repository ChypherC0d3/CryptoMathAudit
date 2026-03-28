#!/usr/bin/env python3
"""
Hypothesis H1: Cofactor equation mismatch between Firedancer and Agave/Dalek.

THEORY:
  Firedancer uses cofactorless: [S]B = R + [k]A
  Dalek verify_strict ALSO uses cofactorless: [S]B = R + [k]A
    (Despite docs falsely claiming cofactored - see dalek issue #663)
  Both reject small-order R and A.

  A consensus split would require a signature that passes one equation
  but fails the other. For cofactored vs cofactorless to diverge, we need
  a point with a torsion component (order dividing 8 but != 1).

  If R or A has a torsion component T, then:
    - Cofactorless: [S]B = R + [k]A  (torsion NOT zeroed out)
    - Cofactored:   [8][S]B = [8]R + [8][k]A  (torsion zeroed out)

  Key: a point P = Q + T where Q has prime order L and T has order dividing 8
  is NOT small-order (it has order 8*L), so it may pass small-order checks.

TEST APPROACH:
  1. Use ed25519-speccheck test vectors (especially case 4)
  2. Construct our own mixed-order point test cases
  3. Test against Firedancer emulator
  4. Compare with known Dalek verify_strict behavior

Ed25519 curve facts:
  p = 2^255 - 19
  L = 2^252 + 27742317777372353535851937790883648493  (prime subgroup order)
  h = 8  (cofactor)
  Full group order = 8 * L
  Points of order 8*L exist and are NOT small-order.
"""

import hashlib
import sys
import os
import json
from datetime import datetime

# Import our Firedancer emulator
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from firedancer_verify import (
    firedancer_verify, p, L, B, IDENTITY, SQRT_M1,
    fe_mul, fe_add, fe_sub, fe_sq, fe_inv, fe_pow, fe_neg, fe_eq, fe_is_zero,
    fe_is_negative,
    point_add, point_neg, point_double, scalar_mult, point_eq,
    point_decompress, is_small_order, sha512_modL,
    sqrt_mod_p, sqrt_ratio_m1, d,
    ORDER8_Y0, ORDER8_Y1,
)

# =============================================================================
# Helper functions
# =============================================================================

def point_encode(P):
    """Encode a point in extended coordinates to 32 bytes (standard Ed25519)."""
    X, Y, Z, T = P
    # Convert to affine
    z_inv = fe_inv(Z)
    x = fe_mul(X, z_inv)
    y = fe_mul(Y, z_inv)

    # Encode y as 32 bytes little-endian, set high bit of last byte to sign of x
    y_bytes = bytearray(y.to_bytes(32, 'little'))
    if fe_is_negative(x):
        y_bytes[31] |= 0x80
    return bytes(y_bytes)


def point_to_affine(P):
    """Convert extended coords to affine (x, y, 1, t)."""
    X, Y, Z, T = P
    z_inv = fe_inv(Z)
    x = fe_mul(X, z_inv)
    y = fe_mul(Y, z_inv)
    return (x, y, 1, fe_mul(x, y))


def point_order_check(P, label="P"):
    """Check the order of a point by multiplying by L, 8, and 8*L."""
    PL = scalar_mult(L, P)
    P8 = scalar_mult(8, P)
    P8L = scalar_mult(8 * L, P)

    PL_is_identity = point_eq(PL, IDENTITY) if not (fe_is_zero(PL[0]) and fe_eq(PL[1], PL[2])) else True
    # More robust identity check
    PL_aff = point_to_affine(PL)
    PL_is_id = fe_is_zero(PL_aff[0]) and fe_eq(PL_aff[1], 1)

    P8_aff = point_to_affine(P8)
    P8_is_id = fe_is_zero(P8_aff[0]) and fe_eq(P8_aff[1], 1)

    P8L_aff = point_to_affine(P8L)
    P8L_is_id = fe_is_zero(P8L_aff[0]) and fe_eq(P8L_aff[1], 1)

    info = {
        "label": label,
        "[L]P == O": PL_is_id,
        "[8]P == O": P8_is_id,
        "[8L]P == O": P8L_is_id,
    }

    if PL_is_id and not P8_is_id:
        info["order"] = "L (prime subgroup)"
    elif P8_is_id and not PL_is_id:
        info["order"] = "divides 8 (small order)"
    elif P8_is_id and PL_is_id:
        info["order"] = "1 (identity)"
    elif not PL_is_id and not P8_is_id and P8L_is_id:
        info["order"] = "8*L or divisor (mixed/full order)"
    else:
        info["order"] = "unknown (does not divide 8*L?!)"

    return info


# =============================================================================
# Known small-order points on Ed25519
# =============================================================================

def get_small_order_points():
    """
    Return the 8 small-order points on Ed25519.
    These are points P where [8]P = O (identity).
    """
    points = {}

    # Order 1: identity (0, 1)
    points["order1_identity"] = (0, 1, 1, 0)

    # Order 2: (0, -1 mod p) = (0, p-1)
    points["order2"] = (0, p - 1, 1, 0)

    # Order 4: (sqrt(-1), 0) and (-sqrt(-1), 0)
    points["order4_pos"] = (SQRT_M1, 0, 1, 0)
    points["order4_neg"] = (fe_neg(SQRT_M1), 0, 1, 0)

    # Order 8: decode from known encodings
    enc1 = bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
    enc2 = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")

    p1 = point_decompress(enc1)
    p2 = point_decompress(enc2)

    if p1:
        points["order8_a"] = p1
        points["order8_a_neg"] = point_neg(p1)
    if p2:
        points["order8_b"] = p2
        points["order8_b_neg"] = point_neg(p2)

    return points


# =============================================================================
# Construct mixed-order points (order 8*L)
# =============================================================================

def construct_mixed_order_point(base_point, torsion_point):
    """
    Construct a point P = base_point + torsion_point.
    If base_point has order L and torsion_point has order dividing 8,
    then P has order 8*L (or a divisor, depending on exact orders).
    """
    return point_add(base_point, torsion_point)


# =============================================================================
# Cofactored verification (for comparison)
# =============================================================================

def verify_cofactored(msg_bytes, sig_bytes, pubkey_bytes):
    """
    Verify using the COFACTORED equation: [8][S]B = [8]R + [8][k]A
    This is what Dalek docs CLAIM verify_strict uses (but it doesn't).
    """
    if len(sig_bytes) != 64 or len(pubkey_bytes) != 32:
        return (False, "ERR: bad lengths")

    r_bytes = sig_bytes[:32]
    s_bytes = sig_bytes[32:]

    S = int.from_bytes(s_bytes, 'little')
    if S >= L:
        return (False, "ERR: S >= L")

    A = point_decompress(pubkey_bytes)
    if A is None:
        return (False, "ERR: A decompression failed")

    R = point_decompress(r_bytes)
    if R is None:
        return (False, "ERR: R decompression failed")

    if is_small_order(A):
        return (False, "ERR: A small order")
    if is_small_order(R):
        return (False, "ERR: R small order")

    hash_input = bytes(r_bytes) + bytes(pubkey_bytes) + bytes(msg_bytes)
    k = sha512_modL(hash_input)

    # Cofactored: [8]([S]B) == [8](R + [k]A)
    SB = scalar_mult(S, B)
    kA = scalar_mult(k, A)
    RHS_inner = point_add(R, kA)

    LHS = scalar_mult(8, SB)
    RHS = scalar_mult(8, RHS_inner)

    if point_eq(LHS, RHS):
        return (True, "SUCCESS (cofactored)")
    else:
        return (False, "ERR: cofactored equation failed")


def verify_cofactored_v2(msg_bytes, sig_bytes, pubkey_bytes):
    """
    Alternative cofactored: [8*S]B = [8]R + [8*k]A
    This is the "wrong" cofactored form that some implementations use.
    """
    if len(sig_bytes) != 64 or len(pubkey_bytes) != 32:
        return (False, "ERR: bad lengths")

    r_bytes = sig_bytes[:32]
    s_bytes = sig_bytes[32:]

    S = int.from_bytes(s_bytes, 'little')
    if S >= L:
        return (False, "ERR: S >= L")

    A = point_decompress(pubkey_bytes)
    if A is None:
        return (False, "ERR: A decompression failed")

    R = point_decompress(r_bytes)
    if R is None:
        return (False, "ERR: R decompression failed")

    if is_small_order(A):
        return (False, "ERR: A small order")
    if is_small_order(R):
        return (False, "ERR: R small order")

    hash_input = bytes(r_bytes) + bytes(pubkey_bytes) + bytes(msg_bytes)
    k = sha512_modL(hash_input)

    # [8*S]B = [8]R + [8*k]A
    LHS = scalar_mult(8 * S, B)
    R8 = scalar_mult(8, R)
    kA8 = scalar_mult(8 * k, A)
    RHS = point_add(R8, kA8)

    if point_eq(LHS, RHS):
        return (True, "SUCCESS (cofactored_v2)")
    else:
        return (False, "ERR: cofactored_v2 equation failed")


# =============================================================================
# ed25519-speccheck test vectors
# =============================================================================

SPECCHECK_VECTORS = [
    {
        "id": 0,
        "desc": "Small A, small R, S=0",
        "message": "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
        "pub_key": "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "signature": "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
    },
    {
        "id": 1,
        "desc": "Small A, mixed R, 0 < S < L",
        "message": "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "pub_key": "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "signature": "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
    },
    {
        "id": 2,
        "desc": "Mixed A, small R, 0 < S < L",
        "message": "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
        "pub_key": "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "signature": "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
    },
    {
        "id": 3,
        "desc": "Mixed A, mixed R, 0 < S < L (both have torsion)",
        "message": "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "pub_key": "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "signature": "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
    },
    {
        "id": 4,
        "desc": "CRITICAL: passes cofactored, fails cofactorless (mixed A and R)",
        "message": "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "pub_key": "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "signature": "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
    },
    {
        "id": 5,
        "desc": "Distinguishes [8](R+kA)=[8]sB from [8]R+[8k]A=[8s]B",
        "message": "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "pub_key": "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "signature": "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
    },
    {
        "id": 6,
        "desc": "S > L (out of bounds scalar)",
        "message": "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "pub_key": "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "signature": "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
    },
    {
        "id": 7,
        "desc": "S >> L (extremely out of bounds scalar)",
        "message": "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "pub_key": "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "signature": "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
    },
    {
        "id": 8,
        "desc": "Non-canonical R (reduces differently for hashing)",
        "message": "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "pub_key": "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "signature": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
    },
    {
        "id": 9,
        "desc": "Non-canonical R (alternative)",
        "message": "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "pub_key": "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "signature": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
    },
    {
        "id": 10,
        "desc": "Non-canonical A, same sig as case 11",
        "message": "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
        "pub_key": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "signature": "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
    },
    {
        "id": 11,
        "desc": "Non-canonical A, same sig as case 10 (different msg)",
        "message": "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
        "pub_key": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "signature": "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
    },
]


# =============================================================================
# Main test runner
# =============================================================================

def run_all_tests():
    output_lines = []

    def log(s=""):
        print(s)
        output_lines.append(s)

    log("=" * 80)
    log("HYPOTHESIS H1: Cofactor Equation Mismatch Test")
    log(f"Date: {datetime.now().isoformat()}")
    log("=" * 80)
    log()
    log("BACKGROUND:")
    log("  Firedancer: cofactorless [S]B = R + [k]A")
    log("  Dalek verify_strict: cofactorless [S]B = R + [k]A")
    log("    (Dalek docs FALSELY claim cofactored - see issue #663)")
    log("  Both reject small-order R and A.")
    log()
    log("  A cofactor divergence needs a point with torsion component that")
    log("  passes small-order checks but causes different equation results.")
    log()

    # =========================================================================
    # PART 1: Analyze the speccheck test vectors
    # =========================================================================
    log("=" * 80)
    log("PART 1: ed25519-speccheck Test Vectors")
    log("=" * 80)
    log()

    speccheck_results = []

    for vec in SPECCHECK_VECTORS:
        vid = vec["id"]
        desc = vec["desc"]
        msg = bytes.fromhex(vec["message"])
        pub = bytes.fromhex(vec["pub_key"])
        sig = bytes.fromhex(vec["signature"])

        log(f"--- Case {vid}: {desc} ---")

        # Analyze the public key
        A = point_decompress(pub)
        if A:
            A_aff = point_to_affine(A)
            A_small = is_small_order(A_aff)
            A_order = point_order_check(A_aff, f"A (case {vid})")
            log(f"  Public key A: small_order={A_small}, order_info={A_order['order']}")
            log(f"    [L]A==O: {A_order['[L]P == O']}, [8]A==O: {A_order['[8]P == O']}")
        else:
            log(f"  Public key A: DECOMPRESSION FAILED")

        # Analyze R
        R = point_decompress(sig[:32])
        if R:
            R_aff = point_to_affine(R)
            R_small = is_small_order(R_aff)
            R_order = point_order_check(R_aff, f"R (case {vid})")
            log(f"  Signature R: small_order={R_small}, order_info={R_order['order']}")
            log(f"    [L]R==O: {R_order['[L]P == O']}, [8]R==O: {R_order['[8]P == O']}")
        else:
            log(f"  Signature R: DECOMPRESSION FAILED")

        # Analyze S
        S = int.from_bytes(sig[32:], 'little')
        log(f"  Scalar S: {S}")
        log(f"  S < L: {S < L}")

        # Test with Firedancer (cofactorless)
        fd_accept, fd_reason = firedancer_verify(msg, sig, pub)
        log(f"  Firedancer (cofactorless): {'ACCEPT' if fd_accept else 'REJECT'} - {fd_reason}")

        # Test with cofactored equation (for comparison)
        cof_accept, cof_reason = verify_cofactored(msg, sig, pub)
        log(f"  Cofactored [8](SB) = [8](R+kA): {'ACCEPT' if cof_accept else 'REJECT'} - {cof_reason}")

        # Test with alternative cofactored
        cof2_accept, cof2_reason = verify_cofactored_v2(msg, sig, pub)
        log(f"  Cofactored_v2 [8S]B = [8]R+[8k]A: {'ACCEPT' if cof2_accept else 'REJECT'} - {cof2_reason}")

        # Flag divergences
        if fd_accept != cof_accept:
            log(f"  *** DIVERGENCE: cofactorless vs cofactored ***")
        if fd_accept != cof2_accept:
            log(f"  *** DIVERGENCE: cofactorless vs cofactored_v2 ***")

        speccheck_results.append({
            "case": vid,
            "desc": desc,
            "firedancer": fd_accept,
            "cofactored": cof_accept,
            "cofactored_v2": cof2_accept,
        })
        log()

    # =========================================================================
    # PART 2: Focus on Case 4 - The Critical Cofactor Discriminator
    # =========================================================================
    log("=" * 80)
    log("PART 2: Deep Dive on Case 4 (Cofactor Discriminator)")
    log("=" * 80)
    log()

    vec4 = SPECCHECK_VECTORS[4]
    msg4 = bytes.fromhex(vec4["message"])
    pub4 = bytes.fromhex(vec4["pub_key"])
    sig4 = bytes.fromhex(vec4["signature"])

    A4 = point_decompress(pub4)
    R4 = point_decompress(sig4[:32])
    S4 = int.from_bytes(sig4[32:], 'little')

    log("Case 4 is designed to PASS cofactored but FAIL cofactorless.")
    log("This is the primary indicator for a cofactored verification equation.")
    log()

    if A4:
        A4_aff = point_to_affine(A4)
        log(f"A4 public key (hex): {vec4['pub_key']}")
        log(f"  is_small_order: {is_small_order(A4_aff)}")
        order_info = point_order_check(A4_aff, "A4")
        log(f"  order: {order_info['order']}")
        log(f"  [L]A4==O: {order_info['[L]P == O']}")
        log(f"  [8]A4==O: {order_info['[8]P == O']}")
        # Check if A4 has a torsion component
        A4_L = scalar_mult(L, A4_aff)
        A4_L_aff = point_to_affine(A4_L)
        log(f"  [L]A4 (torsion component): x={A4_L_aff[0]}, y={A4_L_aff[1]}")
        A4_torsion_is_id = fe_is_zero(A4_L_aff[0]) and fe_eq(A4_L_aff[1], 1)
        log(f"  [L]A4 == identity: {A4_torsion_is_id}")
        if not A4_torsion_is_id:
            log(f"  ==> A4 has a non-trivial torsion component!")
            # Check order of torsion
            for i in [2, 4, 8]:
                t_i = scalar_mult(i, A4_L_aff)
                t_i_aff = point_to_affine(t_i)
                is_id = fe_is_zero(t_i_aff[0]) and fe_eq(t_i_aff[1], 1)
                log(f"  [{i}]*[L]A4 == O: {is_id}")
    log()

    if R4:
        R4_aff = point_to_affine(R4)
        log(f"R4 signature point (hex): {sig4[:32].hex()}")
        log(f"  is_small_order: {is_small_order(R4_aff)}")
        order_info = point_order_check(R4_aff, "R4")
        log(f"  order: {order_info['order']}")
        R4_L = scalar_mult(L, R4_aff)
        R4_L_aff = point_to_affine(R4_L)
        R4_torsion_is_id = fe_is_zero(R4_L_aff[0]) and fe_eq(R4_L_aff[1], 1)
        log(f"  [L]R4 == identity: {R4_torsion_is_id}")
        if not R4_torsion_is_id:
            log(f"  ==> R4 has a non-trivial torsion component!")
    log()

    log("Case 4 results:")
    fd_acc, fd_rsn = firedancer_verify(msg4, sig4, pub4)
    cof_acc, cof_rsn = verify_cofactored(msg4, sig4, pub4)
    cof2_acc, cof2_rsn = verify_cofactored_v2(msg4, sig4, pub4)
    log(f"  Firedancer (cofactorless): {'ACCEPT' if fd_acc else 'REJECT'} - {fd_rsn}")
    log(f"  Cofactored:               {'ACCEPT' if cof_acc else 'REJECT'} - {cof_rsn}")
    log(f"  Cofactored_v2:            {'ACCEPT' if cof2_acc else 'REJECT'} - {cof2_rsn}")
    log()

    if not fd_acc and cof_acc:
        log("CONFIRMED: Case 4 passes cofactored but fails cofactorless.")
        log("This means IF Dalek used cofactored (as docs claim), there would be a split.")
        log("But Dalek verify_strict actually uses cofactorless (issue #663),")
        log("so both Firedancer and Dalek would REJECT this case.")
    elif fd_acc and cof_acc:
        log("UNEXPECTED: Both cofactorless and cofactored pass case 4.")
    elif not fd_acc and not cof_acc:
        log("Both cofactorless and cofactored reject case 4.")
        log("The torsion component may have been caught by small-order check.")
    log()

    # =========================================================================
    # PART 3: Construct our own mixed-order test
    # =========================================================================
    log("=" * 80)
    log("PART 3: Custom Mixed-Order Point Tests")
    log("=" * 80)
    log()

    log("Constructing points of order 8*L by adding small-order torsion to B...")
    log()

    small_order_pts = get_small_order_points()

    for name, T in small_order_pts.items():
        if name == "order1_identity":
            continue  # Skip identity, it's trivial

        # P = B + T (B has order L, T has small order)
        P = point_add(B, T)
        P_aff = point_to_affine(P)

        # Check properties
        P_small = is_small_order(P_aff)
        P_enc = point_encode(P_aff)

        # Verify P decompresses correctly
        P_dec = point_decompress(P_enc)
        if P_dec is None:
            log(f"  {name}: P = B + T failed to re-decompress (encoding issue)")
            continue

        P_dec_aff = point_to_affine(P_dec)
        P_dec_small = is_small_order(P_dec_aff)
        order_info = point_order_check(P_dec_aff, f"B+{name}")

        log(f"  T = {name}:")
        log(f"    P = B + T encoded: {P_enc.hex()}")
        log(f"    is_small_order(P): {P_dec_small}")
        log(f"    order: {order_info['order']}")
        log(f"    [L]P==O: {order_info['[L]P == O']}, [8]P==O: {order_info['[8]P == O']}")

        if not P_dec_small:
            log(f"    ==> P passes small-order check (NOT rejected)!")
            log(f"    ==> But P has torsion: [L]P != O means cofactor matters!")

            # Now test: use P as a public key in a crafted signature
            # For a real sig, we'd need the private key. But we can test if the
            # point passes the decompression + small-order pipeline.
            log(f"    This point WOULD cause cofactored != cofactorless divergence")
            log(f"    if used as A in a valid signature (requires knowledge of discrete log).")
        else:
            log(f"    P is detected as small-order by Firedancer check (REJECTED)")

        log()

    # =========================================================================
    # PART 4: Check speccheck key cdb267... specifically
    # =========================================================================
    log("=" * 80)
    log("PART 4: Analyze speccheck Public Key cdb267...")
    log("=" * 80)
    log()

    pub_hex = "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d"
    pub_bytes = bytes.fromhex(pub_hex)
    A = point_decompress(pub_bytes)

    if A:
        A_aff = point_to_affine(A)
        log(f"Public key: {pub_hex}")
        log(f"  is_small_order: {is_small_order(A_aff)}")

        # Decompose: check if [L]A is identity (pure prime-order subgroup) or not
        AL = scalar_mult(L, A_aff)
        AL_aff = point_to_affine(AL)
        AL_is_id = fe_is_zero(AL_aff[0]) and fe_eq(AL_aff[1], 1)
        log(f"  [L]A == O (prime subgroup?): {AL_is_id}")

        if not AL_is_id:
            log(f"  ==> A has a TORSION COMPONENT")
            log(f"  [L]A = ({AL_aff[0]}, {AL_aff[1]})")

            # Check what small-order point this torsion is
            # Compare against known small-order points
            for so_name, so_pt in small_order_pts.items():
                so_aff = point_to_affine(so_pt)
                if fe_eq(AL_aff[0], so_aff[0]) and fe_eq(AL_aff[1], so_aff[1]):
                    log(f"  Torsion component matches: {so_name}")
                    break

            # The Firedancer small-order check works on affine coords
            # Check if this TORSION point itself would be caught
            AL_small = is_small_order(AL_aff)
            log(f"  is_small_order([L]A): {AL_small}")
            log()
            log(f"  KEY FINDING: A is NOT small-order (passes check),")
            log(f"  but A has torsion. Under cofactored equation, [8]A maps")
            log(f"  to the prime-order subgroup, zeroing the torsion.")
            log(f"  Under cofactorless, the torsion affects the result.")
        else:
            log(f"  A is in the prime-order subgroup (no torsion)")
            log(f"  Cofactored vs cofactorless makes NO difference for this key")
    log()

    # =========================================================================
    # PART 5: Test what happens with ecffffff... key (cases 10-11)
    # =========================================================================
    log("=" * 80)
    log("PART 5: Non-canonical Point ecffffff... (cases 10-11)")
    log("=" * 80)
    log()

    nc_pub_hex = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    nc_pub = bytes.fromhex(nc_pub_hex)
    A_nc = point_decompress(nc_pub)

    if A_nc:
        A_nc_aff = point_to_affine(A_nc)
        log(f"Non-canonical public key: {nc_pub_hex}")
        y_raw = int.from_bytes(bytes.fromhex(nc_pub_hex), 'little') & ((1 << 255) - 1)
        log(f"  Raw y value: {y_raw}")
        log(f"  y >= p: {y_raw >= p}")
        if y_raw >= p:
            log(f"  y mod p: {y_raw % p}")
        log(f"  is_small_order: {is_small_order(A_nc_aff)}")

        order_info = point_order_check(A_nc_aff, "A_nc")
        log(f"  order: {order_info['order']}")
        log(f"  [L]A==O: {order_info['[L]P == O']}, [8]A==O: {order_info['[8]P == O']}")
    else:
        log(f"Non-canonical key: DECOMPRESSION FAILED")
    log()

    # =========================================================================
    # PART 6: Key Consensus Analysis
    # =========================================================================
    log("=" * 80)
    log("PART 6: Consensus Split Analysis")
    log("=" * 80)
    log()

    log("CRITICAL QUESTION: Can Firedancer and Dalek verify_strict disagree?")
    log()
    log("Both implementations:")
    log("  1. Use cofactorless equation: [S]B = R + [k]A")
    log("  2. Reject S >= L")
    log("  3. Reject small-order A and R")
    log()

    log("The cofactor equation hypothesis (H1) CANNOT cause a consensus split IF:")
    log("  - Both truly use cofactorless (which they do)")
    log("  - Both have the same small-order rejection criteria")
    log()

    log("HOWEVER, there are still potential divergence points:")
    log("  a) Do both define 'small order' identically?")
    log("     Firedancer checks: X==0 OR Y==0 OR Y==order8_y0 OR Y==order8_y1")
    log("     Dalek checks: calls is_small_order() which multiplies by cofactor")
    log()

    # Test: Is Firedancer's small-order check equivalent to [8]P == O?
    log("Testing if Firedancer's Y/X check is equivalent to [8]P == O:")
    log()

    # Test all small-order points
    for name, pt in small_order_pts.items():
        pt_aff = point_to_affine(pt)
        fd_small = is_small_order(pt_aff)
        # Check [8]P
        p8 = scalar_mult(8, pt_aff)
        p8_aff = point_to_affine(p8)
        actual_small = fe_is_zero(p8_aff[0]) and fe_eq(p8_aff[1], 1)
        match = "MATCH" if fd_small == actual_small else "MISMATCH!"
        log(f"  {name}: fd_check={fd_small}, [8]P==O={actual_small} => {match}")

    log()

    # Also test mixed-order points
    log("Testing mixed-order points (order 8*L):")
    for name, T in small_order_pts.items():
        if name == "order1_identity":
            continue
        P = point_add(B, T)
        P_aff = point_to_affine(P)
        fd_small = is_small_order(P_aff)
        p8 = scalar_mult(8, P_aff)
        p8_aff = point_to_affine(p8)
        actual_small = fe_is_zero(p8_aff[0]) and fe_eq(p8_aff[1], 1)
        match = "MATCH" if fd_small == actual_small else "MISMATCH!"
        log(f"  B+{name}: fd_check={fd_small}, [8]P==O={actual_small} => {match}")

    log()

    # =========================================================================
    # PART 7: Summary of speccheck results table
    # =========================================================================
    log("=" * 80)
    log("PART 7: Summary Results Table")
    log("=" * 80)
    log()
    log(f"{'Case':>4} | {'FD cofactorless':>16} | {'Cofactored':>12} | {'Cofactored_v2':>14} | {'Diverge?':>9}")
    log("-" * 70)

    divergences_found = []
    for r in speccheck_results:
        fd_str = "ACCEPT" if r["firedancer"] else "REJECT"
        cof_str = "ACCEPT" if r["cofactored"] else "REJECT"
        cof2_str = "ACCEPT" if r["cofactored_v2"] else "REJECT"
        div = "YES" if (r["firedancer"] != r["cofactored"] or r["firedancer"] != r["cofactored_v2"]) else "no"
        if div == "YES":
            divergences_found.append(r["case"])
        log(f"{r['case']:>4} | {fd_str:>16} | {cof_str:>12} | {cof2_str:>14} | {div:>9}")

    log()

    # =========================================================================
    # CONCLUSION
    # =========================================================================
    log("=" * 80)
    log("CONCLUSION")
    log("=" * 80)
    log()

    if divergences_found:
        log(f"Cofactored vs cofactorless divergences found in cases: {divergences_found}")
        log()
        log("However, the KEY question is: does Dalek verify_strict use cofactored?")
        log()
        log("ANSWER: NO. Despite the documentation claiming cofactored,")
        log("Dalek verify_strict uses COFACTORLESS [S]B = R + [k]A (issue #663).")
        log("This is the SAME equation Firedancer uses.")
        log()
        log("THEREFORE: Hypothesis H1 (cofactor equation mismatch) is")
        log("UNLIKELY to cause a consensus split between Firedancer and Agave/Dalek,")
        log("because both use the same cofactorless equation.")
        log()
        log("REMAINING RISK: If the small-order rejection criteria differ subtly,")
        log("a mixed-order point could still slip through one but not the other.")
        log("This is a separate hypothesis (small-order check divergence) worth testing")
        log("with the actual Dalek/Agave implementations.")
    else:
        log("No divergences found between cofactored and cofactorless equations.")
        log("This could mean the test vectors' torsion components were caught by")
        log("the small-order check before the equation was evaluated.")
    log()

    log("NEXT STEPS:")
    log("  1. Run speccheck cases against actual Dalek verify_strict (Rust harness)")
    log("  2. Focus on small-order CHECK differences (separate from equation)")
    log("  3. Test non-canonical encoding edge cases (cases 8-11)")
    log("  4. Investigate if batch verification uses different equations")
    log()

    return output_lines


if __name__ == "__main__":
    lines = run_all_tests()

    # Save findings
    findings_dir = os.path.join("F:", os.sep, "Claude", "BugBounty", "bounties", "findings")
    os.makedirs(findings_dir, exist_ok=True)
    findings_path = os.path.join(findings_dir, "firedancer_h1_results.txt")

    with open(findings_path, 'w') as f:
        f.write("\n".join(lines))

    print(f"\nFindings saved to: {findings_path}")
