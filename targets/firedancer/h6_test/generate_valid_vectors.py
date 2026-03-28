#!/usr/bin/env python3
"""
generate_valid_vectors.py -- Generate VALID Ed25519 signatures that exercise
field arithmetic edge cases in Firedancer's ref vs AVX512 backends.

Strategy:
  All signatures are genuinely valid (verified with PyNaCl).
  We target specific categories:

  1. random       -- baseline random valid signatures
  2. y_high_bits  -- pubkey.y with high bits set (top byte 0x70-0x7f)
  3. y_low_bits   -- pubkey.y with low value (first byte < 0x10)
  4. y_limb_carry -- pubkey.y with bits set near r43x6 limb boundaries
                     (bytes 5-6, 10-11, 16-17, 21-22 where carries happen)
  5. R_high_bits  -- R.y with high bits
  6. R_low_bits   -- R.y with low value
  7. R_limb_carry -- R.y near limb boundaries
  8. S_extreme    -- S scalar near 0 or L
  9. multi_msg    -- same key, many messages (different R each time)
  10. long_msg    -- longer messages

For limb-carry stress: in the r43x6 representation, the 32-byte value is
split into 6 limbs of 43 bits each. Limb boundaries fall at bit positions
0, 43, 86, 129, 172, 215. Byte boundaries: 0, 5.375, 10.75, 16.125, 21.5, 26.875.
So bytes ~5, ~10-11, ~16, ~21-22, ~26-27 are where limb splits happen.
Values with many 1-bits near these positions cause carries during multiplication.
"""

import json
import os
import sys
import time

import nacl.signing

P = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493

# r43x6 limb bit positions
LIMB_BITS = 43
LIMB_POSITIONS = [LIMB_BITS * i for i in range(6)]  # 0, 43, 86, 129, 172, 215

# Byte positions where limb boundaries fall (approximate)
# Bit 43 -> byte 5 (bit 3 of byte 5)
# Bit 86 -> byte 10 (bit 6 of byte 10)
# Bit 129 -> byte 16 (bit 1 of byte 16)
# Bit 172 -> byte 21 (bit 4 of byte 21)
# Bit 215 -> byte 26 (bit 7 of byte 26)
LIMB_BOUNDARY_BYTES = [5, 10, 16, 21, 26]


def decode_y(point_bytes):
    """Extract y-coordinate from 32-byte compressed Ed25519 point."""
    b = bytearray(point_bytes)
    b[31] &= 0x7F
    return int.from_bytes(b, 'little')


def decode_S(sig):
    """Extract scalar S from 64-byte signature."""
    return int.from_bytes(sig[32:64], 'little')


def has_high_y(point_bytes):
    """Check if y has high bits set (top byte 0x70-0x7f before sign bit)."""
    top = point_bytes[31] & 0x7F
    return top >= 0x70


def has_low_y(point_bytes):
    """Check if y is small (top byte is 0x00, second-top byte < 0x10)."""
    top = point_bytes[31] & 0x7F
    return top == 0x00 and point_bytes[30] < 0x10


def has_limb_carry_pattern(point_bytes):
    """Check if bytes near limb boundaries have all-1s patterns (0xF0+ or 0xFF)
    which cause carries during multiplication in r43x6 representation."""
    b = bytearray(point_bytes)
    b[31] &= 0x7F  # Clear sign bit for analysis
    for pos in LIMB_BOUNDARY_BYTES:
        if pos < 31:
            # Check if this byte and adjacent byte have high bit patterns
            if b[pos] >= 0xF0 or b[pos] == 0xFF:
                return True
            if pos > 0 and b[pos-1] >= 0xF0:
                return True
    return False


def has_alternating_bits(point_bytes):
    """Check for bit patterns like 0xAA or 0x55 near limb boundaries,
    which stress carry propagation differently."""
    b = bytearray(point_bytes)
    b[31] &= 0x7F
    for pos in LIMB_BOUNDARY_BYTES:
        if pos < 31:
            if b[pos] in (0xAA, 0x55, 0xA5, 0x5A):
                return True
    return False


def classify_pubkey(pk):
    """Return list of categories this pubkey matches."""
    cats = []
    if has_high_y(pk):
        cats.append("y_high_bits")
    if has_low_y(pk):
        cats.append("y_low_bits")
    if has_limb_carry_pattern(pk):
        cats.append("y_limb_carry")
    if has_alternating_bits(pk):
        cats.append("y_alt_bits")
    return cats


def classify_R(sig):
    """Return list of categories the R-point in this signature matches."""
    R = sig[:32]
    cats = []
    if has_high_y(R):
        cats.append("R_high_bits")
    if has_low_y(R):
        cats.append("R_low_bits")
    if has_limb_carry_pattern(R):
        cats.append("R_limb_carry")
    if has_alternating_bits(R):
        cats.append("R_alt_bits")
    return cats


def classify_S(sig):
    """Classify the S scalar."""
    S = decode_S(sig)
    cats = []
    if S < (1 << 128):
        cats.append("S_small")
    if S > L - (1 << 128):
        cats.append("S_near_L")
    # Check if S has interesting bit patterns near limb boundaries
    # S is reduced mod L, so it's at most ~253 bits
    for bp in LIMB_POSITIONS[1:]:
        mask = 0xFF << (bp - 4)
        val = (S >> (bp - 4)) & 0xFF
        if val >= 0xF0 or val <= 0x0F:
            cats.append("S_limb_edge")
            break
    return cats


def make_vector(vid, category, pk_bytes, sig_bytes, msg_bytes, annotations=None):
    """Create a test vector dict."""
    v = {
        "id": vid,
        "category": category,
        "pubkey_hex": pk_bytes.hex(),
        "sig_hex": sig_bytes.hex(),
        "msg_hex": msg_bytes.hex(),
        "expected": 1,
    }
    if annotations:
        v["annotations"] = annotations
    return v


def generate_vectors():
    vectors = []
    stats = {}

    def add(vid, cat, pk, sig, msg, ann=None):
        vectors.append(make_vector(vid, cat, pk, sig, msg, ann))
        stats[cat] = stats.get(cat, 0) + 1

    print("=== Generating valid Ed25519 test vectors ===", flush=True)

    # Category quotas
    RANDOM_TARGET = 200
    PK_HIGH_TARGET = 100
    PK_LOW_TARGET = 100
    PK_LIMB_TARGET = 100
    PK_ALT_TARGET = 50
    R_HIGH_TARGET = 100
    R_LOW_TARGET = 100
    R_LIMB_TARGET = 100
    R_ALT_TARGET = 50
    S_SMALL_TARGET = 50
    S_NEAR_L_TARGET = 50
    S_LIMB_TARGET = 50
    MULTI_MSG_TARGET = 100
    LONG_MSG_TARGET = 50

    pk_high_count = 0
    pk_low_count = 0
    pk_limb_count = 0
    pk_alt_count = 0
    r_high_count = 0
    r_low_count = 0
    r_limb_count = 0
    r_alt_count = 0
    s_small_count = 0
    s_near_L_count = 0
    s_limb_count = 0
    random_count = 0

    # Phase 1: Generate many keypairs and categorize
    print("[Phase 1] Generating and categorizing keypairs + signatures...", flush=True)

    MAX_ITER = 2_000_000
    batch_report = 100_000

    # Keep a pool of interesting keys for later reuse
    interesting_keys = []  # list of (sk, pk_bytes, categories)

    for i in range(MAX_ITER):
        if i > 0 and i % batch_report == 0:
            total = len(vectors)
            print(f"  Iteration {i}: {total} vectors so far "
                  f"(rnd={random_count} pkH={pk_high_count} pkL={pk_low_count} "
                  f"pkLimb={pk_limb_count} pkAlt={pk_alt_count} "
                  f"rH={r_high_count} rL={r_low_count} rLimb={r_limb_count} "
                  f"rAlt={r_alt_count} sS={s_small_count} sL={s_near_L_count} "
                  f"sLe={s_limb_count})", flush=True)

        # Check if all quotas met
        all_met = (random_count >= RANDOM_TARGET and
                   pk_high_count >= PK_HIGH_TARGET and
                   pk_low_count >= PK_LOW_TARGET and
                   pk_limb_count >= PK_LIMB_TARGET and
                   pk_alt_count >= PK_ALT_TARGET and
                   r_high_count >= R_HIGH_TARGET and
                   r_low_count >= R_LOW_TARGET and
                   r_limb_count >= R_LIMB_TARGET and
                   r_alt_count >= R_ALT_TARGET and
                   s_small_count >= S_SMALL_TARGET and
                   s_near_L_count >= S_NEAR_L_TARGET and
                   s_limb_count >= S_LIMB_TARGET)
        if all_met:
            print(f"  All quotas met at iteration {i}", flush=True)
            break

        sk = nacl.signing.SigningKey.generate()
        pk = bytes(sk.verify_key)
        msg = f"v{i}".encode()
        sig = bytes(sk.sign(msg).signature)

        pk_cats = classify_pubkey(pk)
        r_cats = classify_R(sig)
        s_cats = classify_S(sig)

        placed = False

        # Try to place in a pubkey category
        if "y_high_bits" in pk_cats and pk_high_count < PK_HIGH_TARGET:
            add(f"pk_high_{pk_high_count:04d}", "y_high_bits", pk, sig, msg,
                {"pubkey_y_hex": hex(decode_y(pk))})
            pk_high_count += 1
            placed = True
            interesting_keys.append((sk, pk, pk_cats))

        if "y_low_bits" in pk_cats and pk_low_count < PK_LOW_TARGET:
            add(f"pk_low_{pk_low_count:04d}", "y_low_bits", pk, sig, msg,
                {"pubkey_y_hex": hex(decode_y(pk))})
            pk_low_count += 1
            placed = True
            interesting_keys.append((sk, pk, pk_cats))

        if "y_limb_carry" in pk_cats and pk_limb_count < PK_LIMB_TARGET:
            add(f"pk_limb_{pk_limb_count:04d}", "y_limb_carry", pk, sig, msg,
                {"pubkey_y_hex": hex(decode_y(pk))})
            pk_limb_count += 1
            placed = True
            interesting_keys.append((sk, pk, pk_cats))

        if "y_alt_bits" in pk_cats and pk_alt_count < PK_ALT_TARGET:
            add(f"pk_alt_{pk_alt_count:04d}", "y_alt_bits", pk, sig, msg,
                {"pubkey_y_hex": hex(decode_y(pk))})
            pk_alt_count += 1
            placed = True

        # Try to place in an R category
        if "R_high_bits" in r_cats and r_high_count < R_HIGH_TARGET:
            add(f"r_high_{r_high_count:04d}", "R_high_bits", pk, sig, msg,
                {"R_y_hex": hex(decode_y(sig[:32]))})
            r_high_count += 1
            placed = True

        if "R_low_bits" in r_cats and r_low_count < R_LOW_TARGET:
            add(f"r_low_{r_low_count:04d}", "R_low_bits", pk, sig, msg,
                {"R_y_hex": hex(decode_y(sig[:32]))})
            r_low_count += 1
            placed = True

        if "R_limb_carry" in r_cats and r_limb_count < R_LIMB_TARGET:
            add(f"r_limb_{r_limb_count:04d}", "R_limb_carry", pk, sig, msg,
                {"R_y_hex": hex(decode_y(sig[:32]))})
            r_limb_count += 1
            placed = True

        if "R_alt_bits" in r_cats and r_alt_count < R_ALT_TARGET:
            add(f"r_alt_{r_alt_count:04d}", "R_alt_bits", pk, sig, msg,
                {"R_y_hex": hex(decode_y(sig[:32]))})
            r_alt_count += 1
            placed = True

        # Try to place in an S category
        if "S_small" in s_cats and s_small_count < S_SMALL_TARGET:
            add(f"s_small_{s_small_count:04d}", "S_small", pk, sig, msg,
                {"S_hex": hex(decode_S(sig))})
            s_small_count += 1
            placed = True

        if "S_near_L" in s_cats and s_near_L_count < S_NEAR_L_TARGET:
            add(f"s_near_L_{s_near_L_count:04d}", "S_near_L", pk, sig, msg,
                {"S_hex": hex(decode_S(sig))})
            s_near_L_count += 1
            placed = True

        if "S_limb_edge" in s_cats and s_limb_count < S_LIMB_TARGET:
            add(f"s_limb_{s_limb_count:04d}", "S_limb_edge", pk, sig, msg,
                {"S_hex": hex(decode_S(sig))})
            s_limb_count += 1
            placed = True

        # Fill random quota
        if not placed and random_count < RANDOM_TARGET:
            add(f"random_{random_count:04d}", "random", pk, sig, msg)
            random_count += 1

    # Phase 2: Multi-message vectors (same key, many messages)
    print("[Phase 2] Generating multi-message vectors...", flush=True)
    if interesting_keys:
        sk0, pk0, _ = interesting_keys[0]
    else:
        sk0 = nacl.signing.SigningKey.generate()
        pk0 = bytes(sk0.verify_key)
    for j in range(MULTI_MSG_TARGET):
        msg = f"multi_msg_test_{j}_{'A' * (j % 64)}".encode()
        sig = bytes(sk0.sign(msg).signature)
        add(f"multi_msg_{j:04d}", "multi_msg", pk0, sig, msg)

    # Phase 3: Long message vectors
    print("[Phase 3] Generating long message vectors...", flush=True)
    for j in range(LONG_MSG_TARGET):
        # Messages of various lengths: 128, 256, 512, 1024, 2048 bytes
        length = 128 * (2 ** (j % 5))
        msg = (f"long_{j}_" + "X" * length)[:length].encode()
        sk_l = nacl.signing.SigningKey.generate()
        pk_l = bytes(sk_l.verify_key)
        sig = bytes(sk_l.sign(msg).signature)
        add(f"long_msg_{j:04d}", "long_msg", pk_l, sig, msg,
            {"msg_len": length})

    # Phase 4: Additional targeted vectors - keys reused with many different messages
    # to explore different R values from the same key
    print("[Phase 4] Generating R-diversity vectors from interesting keys...", flush=True)
    r_diversity_count = 0
    R_DIVERSITY_TARGET = 200
    for sk_i, pk_i, _ in interesting_keys[:20]:
        if r_diversity_count >= R_DIVERSITY_TARGET:
            break
        for j in range(50):
            if r_diversity_count >= R_DIVERSITY_TARGET:
                break
            msg = f"rdiv_{r_diversity_count}_{j}_{os.urandom(4).hex()}".encode()
            sig = bytes(sk_i.sign(msg).signature)
            add(f"r_diversity_{r_diversity_count:04d}", "R_diversity", pk_i, sig, msg)
            r_diversity_count += 1

    print(flush=True)
    print(f"=== Total vectors: {len(vectors)} ===", flush=True)
    print("Category breakdown:", flush=True)
    for cat, n in sorted(stats.items()):
        print(f"  {cat}: {n}", flush=True)

    return vectors


def verify_all(vectors):
    """Verify every vector with PyNaCl."""
    print("\nVerifying all vectors...", flush=True)
    failures = 0
    for i, v in enumerate(vectors):
        pk = bytes.fromhex(v["pubkey_hex"])
        sig = bytes.fromhex(v["sig_hex"])
        msg = bytes.fromhex(v["msg_hex"])
        vk = nacl.signing.VerifyKey(pk)
        try:
            vk.verify(msg, sig)
        except Exception as e:
            print(f"  FAILED: {v['id']}: {e}", flush=True)
            failures += 1
    if failures:
        print(f"  {failures} FAILURES!", flush=True)
    else:
        print(f"  All {len(vectors)} vectors verified OK.", flush=True)
    return failures == 0


def main():
    t0 = time.time()
    vectors = generate_vectors()

    if not verify_all(vectors):
        print("ERROR: Some vectors failed verification. Aborting.", flush=True)
        sys.exit(1)

    elapsed = time.time() - t0
    output_dir = os.path.dirname(os.path.abspath(__file__))

    # Full annotated output
    annotated_path = os.path.join(output_dir, "valid_vectors_annotated.json")
    with open(annotated_path, 'w') as f:
        json.dump({
            "description": "Valid Ed25519 signatures targeting field arithmetic edge cases in Firedancer",
            "generator": "generate_valid_vectors.py",
            "count": len(vectors),
            "vectors": vectors,
        }, f, indent=2)
    print(f"\nWrote annotated vectors to: {annotated_path}", flush=True)

    # Compact output for C test
    compact_vectors = []
    for v in vectors:
        compact_vectors.append({
            "id": v["id"],
            "category": v["category"],
            "pubkey_hex": v["pubkey_hex"],
            "sig_hex": v["sig_hex"],
            "msg_hex": v["msg_hex"],
            "expected": v["expected"],
        })

    compact_path = os.path.join(output_dir, "valid_vectors.json")
    with open(compact_path, 'w') as f:
        json.dump({
            "description": "Valid Ed25519 test vectors for Firedancer differential testing",
            "count": len(compact_vectors),
            "vectors": compact_vectors,
        }, f, indent=1)
    print(f"Wrote compact vectors to: {compact_path}", flush=True)
    print(f"Generation took {elapsed:.1f}s", flush=True)


if __name__ == "__main__":
    main()
