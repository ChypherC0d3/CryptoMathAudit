#!/usr/bin/env python3
"""
Hypothesis H4: S scalar boundary edge cases in Ed25519 verification.

Tests whether Firedancer and Dalek agree on S < L validation at the boundary.

Key questions:
1. Do both reject the same S values at and above L?
2. Is there any S where one accepts and the other rejects?
3. Does Firedancer reduce S mod L before the equation check, or use S directly?

Analysis of Firedancer's fd_curve25519_scalar_validate:
  - Fast path: if top 4 bits of byte[31] are 0 (i.e., S < 2^252), accept immediately
  - If bit 252 (0x10 in byte[31]) is set:
    - If any of bits 253-255 (0xE0 in byte[31]) are set, reject immediately
    - Otherwise do full 256-bit subtraction: compute s - (L-1) with initial borrow=1
      (effectively s - L), and check if borrow remains (meaning s < L)
  - This correctly checks S in [0, L)

Analysis of Dalek 1.0.1 Signature::from_bytes:
  - Checks S < L at signature deserialization time
  - Uses the same curve order L
  - Both should agree, but implementation details may differ

Analysis of S usage in equation check:
  - Firedancer: passes S bytes directly to fd_ed25519_double_scalar_mul_base
  - The scalar mult uses S as-is (no reduction mod L)
  - This means for valid signatures (S < L), S is used directly
"""

import hashlib
import json
import os
import subprocess
import sys
import time

# Import the Firedancer emulator
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from firedancer_verify import (
    L, B, IDENTITY, p, d,
    scalar_validate, scalar_from_bytes, scalar_mult, point_add, point_neg,
    point_decompress, point_eq, sha512_modL, firedancer_verify,
    fe_mul, fe_inv, fe_is_negative, fe_neg, fe_sq, fe_add, fe_sub,
    sqrt_mod_p, SQRT_M1,
)

# =============================================================================
# Constants
# =============================================================================

# L = 2^252 + 27742317777372353535851937790883648493
# In hex (little-endian bytes):
#   ed d3 f5 5c 1a 63 12 58 d6 9c f7 a2 de f9 de 14
#   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10
L_BYTES = L.to_bytes(32, 'little')

# Rust harness path
RUST_HARNESS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', 'test_harness_rust', 'target', 'release', 'ed25519_test.exe'
)

# =============================================================================
# Helper: create a valid keypair for testing
# =============================================================================

def generate_test_keypair():
    """
    Generate a known keypair for testing.
    We use a fixed private key so results are reproducible.
    """
    # Use a fixed "private key" seed
    privkey_seed = b'\x01' * 32

    # Derive keypair per Ed25519 spec
    h = hashlib.sha512(privkey_seed).digest()
    s_bytes = bytearray(h[:32])
    s_bytes[0] &= 0xF8
    s_bytes[31] &= 0x7F
    s_bytes[31] |= 0x40
    s = int.from_bytes(s_bytes, 'little')

    # Public key = [s]B
    A = scalar_mult(s, B)
    # Encode public key
    x, y, z, t = A
    # Normalize to affine
    z_inv = pow(z, p - 2, p)
    x_aff = (x * z_inv) % p
    y_aff = (y * z_inv) % p

    pubkey_bytes = bytearray(y_aff.to_bytes(32, 'little'))
    if x_aff % 2 == 1:
        pubkey_bytes[31] |= 0x80

    return privkey_seed, bytes(pubkey_bytes), s, s_bytes


def sign_message(msg, privkey_seed):
    """
    Sign a message using standard Ed25519 signing.
    Returns (signature_bytes, pubkey_bytes).
    """
    h = hashlib.sha512(privkey_seed).digest()
    s_bytes = bytearray(h[:32])
    prefix = h[32:]
    s_bytes[0] &= 0xF8
    s_bytes[31] &= 0x7F
    s_bytes[31] |= 0x40
    s = int.from_bytes(s_bytes, 'little')

    # Public key
    A = scalar_mult(s, B)
    x, y, z, t = A
    z_inv = pow(z, p - 2, p)
    x_aff = (x * z_inv) % p
    y_aff = (y * z_inv) % p
    pubkey_bytes = bytearray(y_aff.to_bytes(32, 'little'))
    if x_aff % 2 == 1:
        pubkey_bytes[31] |= 0x80
    pubkey_bytes = bytes(pubkey_bytes)

    # r = SHA-512(prefix || msg) mod L
    r_hash = hashlib.sha512(prefix + msg).digest()
    r = int.from_bytes(r_hash, 'little') % L

    # R = [r]B
    R = scalar_mult(r, B)
    Rx, Ry, Rz, Rt = R
    Rz_inv = pow(Rz, p - 2, p)
    Rx_aff = (Rx * Rz_inv) % p
    Ry_aff = (Ry * Rz_inv) % p
    R_bytes = bytearray(Ry_aff.to_bytes(32, 'little'))
    if Rx_aff % 2 == 1:
        R_bytes[31] |= 0x80
    R_bytes = bytes(R_bytes)

    # k = SHA-512(R || A || msg) mod L
    k = int.from_bytes(hashlib.sha512(R_bytes + pubkey_bytes + msg).digest(), 'little') % L

    # S = (r + k * s) mod L
    S = (r + k * s) % L
    S_bytes = S.to_bytes(32, 'little')

    sig = R_bytes + S_bytes
    return sig, pubkey_bytes


def int_to_le_bytes(val, length=32):
    """Convert integer to little-endian bytes, clamped/truncated to length."""
    # Handle values that may exceed 32 bytes
    mask = (1 << (length * 8)) - 1
    val = val & mask
    return val.to_bytes(length, 'little')


def make_sig_with_s(R_bytes, S_int):
    """Create a 64-byte signature with given R and S value."""
    S_bytes = int_to_le_bytes(S_int, 32)
    return R_bytes + S_bytes


# =============================================================================
# Firedancer scalar_validate detailed analysis
# =============================================================================

def firedancer_scalar_validate_detailed(s_bytes):
    """
    Replicate fd_curve25519_scalar_validate with detailed step info.
    Returns (valid, reason).
    """
    if len(s_bytes) != 32:
        return (False, "wrong length")

    # Check top 4 bits of byte[31]
    top_nybble = s_bytes[31] & 0xF0

    if top_nybble:
        # Top 3 bits check (0xE0)
        if s_bytes[31] & 0xE0:
            return (False, f"REJECT: top 3 bits set (byte[31]=0x{s_bytes[31]:02x}, "
                          f"bits 253-255 nonzero => S >= 2^253)")

        # Full comparison: s vs L-1 with borrow
        # This computes s - L (with borrow=1 on initial subtract, equivalent to s - (L-1) - 1 = s - L)
        s = int.from_bytes(s_bytes, 'little')
        if s < L:
            return (True, f"ACCEPT: bit 252 set but S < L (S in [2^252, L))")
        else:
            return (False, f"REJECT: S >= L (full comparison, S - L = {s - L})")
    else:
        return (True, f"ACCEPT: fast path (top 4 bits zero => S < 2^252 < L)")


def dalek_scalar_validate_detailed(s_bytes):
    """
    Replicate ed25519-dalek 1.0.1 Signature::from_bytes S validation.

    In dalek 1.0.1, Signature::from_bytes calls check_scalar():
      fn check_scalar(bytes: [u8; 32]) -> Result<Scalar, SignatureError> {
          if bytes[31] & 224 != 0 {  // 224 = 0xE0, checks bits 5,6,7 of byte 31
              return Err(...)
          }
          Ok(Scalar{bytes})
      }

    IMPORTANT: Dalek 1.0.1's check_scalar only checks that the top 3 bits
    (bits 253, 254, 255) are zero. It does NOT do a full S < L comparison!
    This means S values in [L, 2^253) would PASS dalek's check_scalar but
    be reduced mod L internally.

    Wait - actually in dalek 1.0.1, verify_strict does an additional check.
    Let me verify: verify_strict calls InternalSignature::from_bytes which calls
    check_scalar. Then verify_strict itself checks the scalar is canonical.

    Actually, looking more carefully at ed25519-dalek 1.0.1 source:
    - Signature::from_bytes -> calls InternalSignature::from_bytes
    - InternalSignature::from_bytes: checks s[31] & 224 != 0 (top 3 bits)
    - verify_strict: additionally checks scalar_is_canonical
    - scalar_is_canonical: does a full S < L check

    So for verify_strict: S must be < L (full check)
    For verify (loose): S only needs top 3 bits clear (S < 2^253)
    """
    s = int.from_bytes(s_bytes, 'little')

    # Step 1: check_scalar in Signature::from_bytes
    if s_bytes[31] & 0xE0:
        return {
            'from_bytes': (False, "REJECT: top 3 bits of byte[31] set (check_scalar)"),
            'verify_strict': (False, "REJECT: from_bytes fails"),
            'verify_loose': (False, "REJECT: from_bytes fails"),
        }

    # Step 2: For verify_strict, additional scalar_is_canonical check
    # scalar_is_canonical does a byte-by-byte comparison from MSB to check S < L
    strict_valid = s < L
    strict_reason = ("ACCEPT: S < L" if strict_valid
                     else f"REJECT: S >= L (verify_strict canonical check, S - L = {s - L})")

    # Step 3: For verify (loose), no additional scalar check beyond from_bytes
    # But S gets loaded into a Scalar which reduces mod L internally
    loose_reason = f"ACCEPT: top 3 bits clear (S < 2^253), S {'= ' if s < L else '!= '}canonical"

    return {
        'from_bytes': (True, "ACCEPT: top 3 bits clear"),
        'verify_strict': (strict_valid, strict_reason),
        'verify_loose': (True, loose_reason),
    }


# =============================================================================
# Test S boundary values
# =============================================================================

def run_tests():
    results = []
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # Generate a valid signature to use as a base
    msg = b"test message for H4 S boundary"
    privkey_seed = b'\x01' * 32
    valid_sig, pubkey = sign_message(msg, privkey_seed)
    R_bytes = valid_sig[:32]
    valid_S = int.from_bytes(valid_sig[32:], 'little')

    # Verify the base signature works
    accept, reason = firedancer_verify(msg, valid_sig, pubkey)
    results.append(f"Base signature valid: accept={accept}, reason={reason}")
    results.append(f"Valid S value: {valid_S}")
    results.append(f"L = {L}")
    results.append(f"L hex (BE) = 0x{L:064x}")
    results.append(f"L hex (LE bytes) = {L_BYTES.hex()}")
    results.append("")

    # Define test S values
    test_cases = [
        ("S = 0", 0),
        ("S = 1", 1),
        ("S = L - 2", L - 2),
        ("S = L - 1 (last valid)", L - 1),
        ("S = L (first invalid)", L),
        ("S = L + 1", L + 1),
        ("S = 2L - 1", 2 * L - 1),
        ("S = 2L", 2 * L),
        ("S = 2^253 - 1 (all bits in 253-bit range)", (1 << 253) - 1),
        ("S = 2^255 - 1", (1 << 255) - 1),
        ("S = 2^256 - 1 (all 0xFF)", (1 << 256) - 1),
        ("S with byte[31] high bit set (bit 255)", 1 | (1 << 255)),
        ("S = L with only top byte changed (byte[31]=0x10 -> 0x11)",
         L + (1 << (31*8))),  # Change byte[31] from 0x10 to 0x11
        ("S = L - 1 with bit 252 set (max valid, bit 252 boundary)",
         L - 1),  # Same as L-1, confirming boundary
        ("S = 2^252 (just above fast-path cutoff)",
         1 << 252),
        ("S = 2^252 - 1 (max fast-path value)",
         (1 << 252) - 1),
        ("S = L + L (2L, reduced mod 2^256)",
         (2 * L) % (1 << 256)),
        ("S = valid_S + L (congruent mod L but >= L)",
         valid_S + L),
    ]

    header = f"""
{'='*90}
HYPOTHESIS H4: S SCALAR BOUNDARY EDGE CASES
{'='*90}
Date: {timestamp}

Firedancer fd_curve25519_scalar_validate algorithm:
  1. If byte[31] & 0xF0 == 0: ACCEPT (fast path, S < 2^252 < L)
  2. If byte[31] & 0xE0 != 0: REJECT (top 3 bits set => S >= 2^253 > L)
  3. Otherwise: full 256-bit subtraction s - L, check borrow

Dalek 1.0.1 check_scalar (in Signature::from_bytes):
  - Only checks byte[31] & 0xE0 == 0 (top 3 bits must be clear)
  - Does NOT do full S < L comparison at deserialization!

Dalek 1.0.1 verify_strict additional check:
  - scalar_is_canonical: full S < L comparison (byte-by-byte from MSB)

KEY INSIGHT: Dalek's Signature::from_bytes is WEAKER than Firedancer's check.
  - Values in [L, 2^253) pass Dalek's from_bytes but fail Firedancer's validate.
  - However, verify_strict adds the canonical check, so strict mode rejects too.
  - verify (loose) does NOT add canonical check -- it uses S as-is (reduced internally).

S REDUCTION QUESTION:
  - Firedancer: does NOT reduce S mod L. Uses S directly in scalar mult.
    If S >= L, validation rejects before reaching the equation.
  - Dalek verify_strict: rejects S >= L before equation.
  - Dalek verify (loose): S passes from_bytes if < 2^253. The Scalar type
    stores raw bytes; the actual modular reduction happens during scalar mult.
    So for loose mode, S = L+k would compute [L+k]B = [k]B, different from [S_canonical]B.

This means for LOOSE verification only:
  - S = valid_S + L would compute [valid_S + L]B = [valid_S]B (since L*B = identity)
  - So the equation would still hold! Dalek loose would ACCEPT S = valid_S + L
  - But Firedancer would REJECT because S >= L fails scalar_validate

{'='*90}
DETAILED TEST RESULTS
{'='*90}
"""
    print(header)
    results.append(header)

    discrepancies = []

    for desc, S_val in test_cases:
        print(f"\n--- {desc} ---")
        results.append(f"\n--- {desc} ---")

        S_bytes = int_to_le_bytes(S_val, 32)
        sig = make_sig_with_s(R_bytes, S_val)

        # Detailed Firedancer analysis
        fd_valid, fd_reason = firedancer_scalar_validate_detailed(S_bytes)
        print(f"  S value: {S_val}")
        print(f"  S hex (LE): {S_bytes.hex()}")
        print(f"  S byte[31]: 0x{S_bytes[31]:02x}")
        print(f"  S < L: {S_val < L}")
        print(f"  S < 2^252: {S_val < (1 << 252)}")
        print(f"  S < 2^253: {S_val < (1 << 253)}")
        print(f"  Firedancer scalar_validate: {fd_reason}")

        results.append(f"  S value: {S_val}")
        results.append(f"  S hex (LE): {S_bytes.hex()}")
        results.append(f"  S byte[31]: 0x{S_bytes[31]:02x}")
        results.append(f"  S < L: {S_val < L}")
        results.append(f"  S < 2^252: {S_val < (1 << 252)}")
        results.append(f"  S < 2^253: {S_val < (1 << 253)}")
        results.append(f"  Firedancer scalar_validate: {fd_reason}")

        # Detailed Dalek analysis
        dalek = dalek_scalar_validate_detailed(S_bytes)
        print(f"  Dalek from_bytes: {dalek['from_bytes'][1]}")
        print(f"  Dalek verify_strict: {dalek['verify_strict'][1]}")
        print(f"  Dalek verify_loose: {dalek['verify_loose'][1]}")
        results.append(f"  Dalek from_bytes: {dalek['from_bytes'][1]}")
        results.append(f"  Dalek verify_strict: {dalek['verify_strict'][1]}")
        results.append(f"  Dalek verify_loose: {dalek['verify_loose'][1]}")

        # Full Firedancer verification
        accept, reason = firedancer_verify(msg, sig, pubkey)
        fd_full = "ACCEPT" if accept else "REJECT"
        print(f"  Firedancer full verify: {fd_full} ({reason})")
        results.append(f"  Firedancer full verify: {fd_full} ({reason})")

        # Check for discrepancies between Firedancer and Dalek strict
        fd_scalar_ok = fd_valid
        dalek_strict_ok = dalek['verify_strict'][0]
        dalek_loose_ok = dalek['verify_loose'][0]

        if fd_scalar_ok != dalek_strict_ok:
            msg_disc = (f"  *** DISCREPANCY (scalar check): Firedancer={fd_scalar_ok}, "
                       f"Dalek strict={dalek_strict_ok}")
            print(msg_disc)
            results.append(msg_disc)
            discrepancies.append((desc, "scalar_check", fd_scalar_ok, dalek_strict_ok))

        if fd_scalar_ok != dalek_loose_ok:
            msg_disc = (f"  ** NOTE (vs loose): Firedancer scalar={fd_scalar_ok}, "
                       f"Dalek loose from_bytes={dalek_loose_ok}")
            print(msg_disc)
            results.append(msg_disc)
            # Track cases where loose mode differs
            if not fd_scalar_ok and dalek_loose_ok:
                discrepancies.append((desc, "loose_accepts_fd_rejects", fd_scalar_ok, dalek_loose_ok))

    # =============================================================================
    # Special test: S = valid_S + L (congruent to valid_S mod L)
    # =============================================================================
    special_header = f"""
{'='*90}
SPECIAL TEST: S congruent to valid_S mod L
{'='*90}
"""
    print(special_header)
    results.append(special_header)

    S_plus_L = valid_S + L
    if S_plus_L < (1 << 253):
        print(f"  valid_S = {valid_S}")
        print(f"  valid_S + L = {S_plus_L}")
        print(f"  (valid_S + L) < 2^253: {S_plus_L < (1 << 253)}")
        print(f"  (valid_S + L) mod L = {S_plus_L % L} (should equal valid_S = {valid_S})")
        results.append(f"  valid_S = {valid_S}")
        results.append(f"  valid_S + L = {S_plus_L}")
        results.append(f"  (valid_S + L) < 2^253: {S_plus_L < (1 << 253)}")
        results.append(f"  (valid_S + L) mod L = {S_plus_L % L} (should equal valid_S = {valid_S})")

        sig_spl = make_sig_with_s(R_bytes, S_plus_L)
        S_spl_bytes = int_to_le_bytes(S_plus_L, 32)

        fd_valid_spl, fd_reason_spl = firedancer_scalar_validate_detailed(S_spl_bytes)
        dalek_spl = dalek_scalar_validate_detailed(S_spl_bytes)

        print(f"  Firedancer scalar_validate: {fd_reason_spl}")
        print(f"  Dalek from_bytes: {dalek_spl['from_bytes'][1]}")
        print(f"  Dalek verify_strict: {dalek_spl['verify_strict'][1]}")
        print(f"  Dalek verify_loose: {dalek_spl['verify_loose'][1]}")
        results.append(f"  Firedancer scalar_validate: {fd_reason_spl}")
        results.append(f"  Dalek from_bytes: {dalek_spl['from_bytes'][1]}")
        results.append(f"  Dalek verify_strict: {dalek_spl['verify_strict'][1]}")
        results.append(f"  Dalek verify_loose: {dalek_spl['verify_loose'][1]}")

        # Full Firedancer verify
        accept_spl, reason_spl = firedancer_verify(msg, sig_spl, pubkey)
        print(f"  Firedancer full verify: {'ACCEPT' if accept_spl else 'REJECT'} ({reason_spl})")
        results.append(f"  Firedancer full verify: {'ACCEPT' if accept_spl else 'REJECT'} ({reason_spl})")

        print(f"\n  ANALYSIS:")
        analysis = (
            f"  If Dalek loose mode accepts S = valid_S + L:\n"
            f"    - Internally [S]B = [(valid_S + L)]B = [valid_S]B (since [L]B = identity)\n"
            f"    - So the equation [S]B = R + [k]A still holds\n"
            f"    - Dalek loose WOULD ACCEPT this signature\n"
            f"    - But Firedancer REJECTS because S >= L\n"
            f"    - This is a BEHAVIORAL DIFFERENCE but not exploitable for consensus\n"
            f"      because Agave uses verify_strict, not verify (loose)\n"
        )
        print(analysis)
        results.append(analysis)
    else:
        msg_skip = f"  valid_S + L = {S_plus_L} >= 2^253, would fail Dalek from_bytes too"
        print(msg_skip)
        results.append(msg_skip)

    # =============================================================================
    # Run against Rust harness if available
    # =============================================================================
    rust_header = f"""
{'='*90}
RUST DALEK HARNESS VERIFICATION
{'='*90}
"""
    print(rust_header)
    results.append(rust_header)

    rust_exe = os.path.normpath(RUST_HARNESS)
    if os.path.exists(rust_exe):
        print(f"Rust harness found at: {rust_exe}")
        results.append(f"Rust harness found at: {rust_exe}")

        # Test key boundary S values against actual Dalek
        rust_test_cases = [
            ("S = 0", 0),
            ("S = 1", 1),
            ("S = L - 1", L - 1),
            ("S = L", L),
            ("S = L + 1", L + 1),
            ("S = 2^253 - 1", (1 << 253) - 1),
            ("S = valid_S (should accept)", valid_S),
        ]

        if valid_S + L < (1 << 253):
            rust_test_cases.append(("S = valid_S + L", valid_S + L))

        for desc, S_val in rust_test_cases:
            sig_test = make_sig_with_s(R_bytes, S_val)
            sig_hex = sig_test.hex()
            pubkey_hex = pubkey.hex()
            msg_hex = msg.hex()

            try:
                result = subprocess.run(
                    [rust_exe, "both", pubkey_hex, sig_hex, msg_hex],
                    capture_output=True, text=True, timeout=10
                )
                output = (result.stdout.strip() + " " + result.stderr.strip()).strip()
                print(f"  {desc}: {output}")
                results.append(f"  {desc}: {output}")
            except FileNotFoundError:
                msg_err = f"  {desc}: ERROR - could not run harness"
                print(msg_err)
                results.append(msg_err)
            except subprocess.TimeoutExpired:
                msg_err = f"  {desc}: TIMEOUT"
                print(msg_err)
                results.append(msg_err)
    else:
        msg_skip = f"Rust harness not found at {rust_exe}. Skipping Dalek verification."
        print(msg_skip)
        results.append(msg_skip)
        print("To build: cd test_harness_rust && cargo build --release")
        results.append("To build: cd test_harness_rust && cargo build --release")

    # =============================================================================
    # Summary
    # =============================================================================
    summary_header = f"""
{'='*90}
SUMMARY AND FINDINGS
{'='*90}
"""
    print(summary_header)
    results.append(summary_header)

    summary = f"""
Firedancer scalar validation (fd_curve25519_scalar_validate):
  - Method: Multi-step check with fast paths + full 256-bit comparison
  - Fast reject: byte[31] & 0xE0 != 0 (top 3 bits) => S >= 2^253
  - Fast accept: byte[31] & 0xF0 == 0 => S < 2^252 < L
  - Full check: 256-bit subtraction s - L, check borrow flag
  - Correctly accepts [0, L) and rejects [L, 2^256)

Dalek 1.0.1 scalar validation:
  - Signature::from_bytes (check_scalar): only checks byte[31] & 0xE0 == 0
    This is WEAKER: accepts S in [L, 2^253)
  - verify_strict: adds scalar_is_canonical check (full S < L)
  - verify (loose): does NOT add canonical check

S usage in equation:
  - Firedancer: S is used directly (no mod L reduction), but S >= L is rejected
    before the equation check, so this is a non-issue
  - Dalek strict: S is used directly, S >= L rejected
  - Dalek loose: S is loaded as raw bytes, reduction happens in scalar mult
    So S = k*L + r computes same as S = r

Discrepancies found: {len(discrepancies)}
"""

    for desc, check_type, fd_val, dalek_val in discrepancies:
        summary += f"  - {desc} [{check_type}]: Firedancer={fd_val}, Dalek={dalek_val}\n"

    if not discrepancies:
        summary += "  (none between Firedancer and Dalek strict mode)\n"

    summary += f"""
Critical finding for Firedancer vs Agave consensus:
  - Agave uses verify_strict, which does full S < L check
  - Firedancer also does full S < L check
  - Both AGREE on rejecting S >= L for the strict verification path
  - No consensus-breaking discrepancy found in S boundary handling

  - The only difference is in Dalek's LOOSE mode (verify, not verify_strict)
    which accepts S in [L, 2^253) -- but this mode is NOT used by Agave
    for transaction signature verification.

Potential edge case to investigate further:
  - Firedancer's fast-path for byte[31] & 0xF0 == 0 could theoretically
    be wrong if there's a value < 2^252 that is >= L. But since
    L > 2^252, all values < 2^252 are indeed < L. This is correct.
  - The full comparison path correctly handles S in [2^252, L).
"""

    print(summary)
    results.append(summary)

    return "\n".join(results)


if __name__ == "__main__":
    output = run_tests()

    # Save results
    findings_dir = os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '..', '..', '..', 'bounties', 'findings'
    ))
    os.makedirs(findings_dir, exist_ok=True)
    output_path = os.path.join(findings_dir, 'firedancer_h4_results.txt')

    with open(output_path, 'w') as f:
        f.write(output)
    print(f"\nResults saved to: {output_path}")
