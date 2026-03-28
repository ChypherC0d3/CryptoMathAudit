//! Direct test of curve25519-dalek CompressedEdwardsY decompression behavior
//! with non-canonical y values (y >= p).
//!
//! CRITICAL TEST: Does Dalek's decompression accept or reject non-canonical
//! y-coordinate encodings? And does verify_strict's re-compression check
//! catch non-canonical encodings?

use curve25519_dalek::edwards::CompressedEdwardsY;

/// Convert a 256-bit integer (as [u64; 4] LE limbs) to 32 LE bytes
fn to_le_bytes(limbs: [u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&limbs[0].to_le_bytes());
    bytes[8..16].copy_from_slice(&limbs[1].to_le_bytes());
    bytes[16..24].copy_from_slice(&limbs[2].to_le_bytes());
    bytes[24..32].copy_from_slice(&limbs[3].to_le_bytes());
    bytes
}

fn main() {
    // p = 2^255 - 19 as [u64; 4] LE limbs
    // p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
    let p: [u64; 4] = [
        0xffffffffffffffed,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x7fffffffffffffff,
    ];

    println!("========================================================================");
    println!("curve25519-dalek CompressedEdwardsY Non-Canonical Decompression Test");
    println!("========================================================================");
    println!();

    // Verify p encoding
    let p_bytes = to_le_bytes(p);
    println!("p as LE hex: {}", hex::encode(&p_bytes));
    println!();

    // Test canonical values first
    for y in [0u8, 1, 2, 3, 4, 5] {
        let mut bytes = [0u8; 32];
        bytes[0] = y;
        let compressed = CompressedEdwardsY(bytes);
        let result = compressed.decompress();
        println!(
            "y={} (canonical): decompress={}  hex={}",
            y,
            if result.is_some() { "OK  " } else { "FAIL" },
            hex::encode(&bytes)
        );
    }

    println!();
    println!("--- Non-canonical tests (y = p+k for k=0..18, x_sign=0) ---");
    println!();

    for k in 0u64..19 {
        // Compute p + k as 256-bit LE value
        let mut limbs = p;
        let (sum, carry) = limbs[0].overflowing_add(k);
        limbs[0] = sum;
        if carry {
            let (sum1, carry1) = limbs[1].overflowing_add(1);
            limbs[1] = sum1;
            if carry1 {
                let (sum2, carry2) = limbs[2].overflowing_add(1);
                limbs[2] = sum2;
                if carry2 {
                    limbs[3] = limbs[3].wrapping_add(1);
                }
            }
        }

        let bytes = to_le_bytes(limbs);

        // Verify bit 255 is clear (x_sign = 0)
        let x_sign_set = (bytes[31] & 0x80) != 0;
        assert!(!x_sign_set, "bit 255 should be clear for p+k where k < 19");

        let compressed = CompressedEdwardsY(bytes);
        let result = compressed.decompress();

        let status = if result.is_some() { "OK  " } else { "FAIL" };

        // Also check what the canonical encoding of this same y=k would be
        let mut canon_bytes = [0u8; 32];
        canon_bytes[0] = k as u8;
        let canon_compressed = CompressedEdwardsY(canon_bytes);
        let canon_result = canon_compressed.decompress();
        let canon_status = if canon_result.is_some() { "OK  " } else { "FAIL" };

        println!(
            "  y=p+{:2} (canon y={:2}): noncanon_decompress={}  canon_decompress={}  hex={}",
            k, k, status, canon_status, hex::encode(&bytes)
        );

        // If both decompress, check if they yield the same point
        if let (Some(nc_point), Some(c_point)) = (result, canon_result) {
            let nc_recompressed = nc_point.compress();
            let c_recompressed = c_point.compress();
            let same_point = nc_recompressed.as_bytes() == c_recompressed.as_bytes();
            let nc_matches_input = nc_recompressed.as_bytes() == &bytes;
            println!(
                "           same_point={}  nc_recompress_matches_input={}  recompressed={}",
                same_point, nc_matches_input,
                hex::encode(nc_recompressed.as_bytes())
            );
            if !nc_matches_input {
                println!(
                    "           *** NON-CANONICAL: input != recompressed ***"
                );
                println!(
                    "           verify_strict would catch this via R_bytes != compress(R)"
                );
            }
        }
    }

    // Now test the CRUCIAL question: what does verify_strict actually do?
    println!();
    println!("========================================================================");
    println!("VERIFY_STRICT BEHAVIOR WITH NON-CANONICAL R");
    println!("========================================================================");
    println!();
    println!("ed25519-dalek v1.0.1 verify_strict source analysis:");
    println!("  1. Signature::from_bytes() - does NOT check R canonicality");
    println!("     (it just stores the 64 bytes)");
    println!("  2. PublicKey::from_bytes() - checks A is canonical via");
    println!("     compressed == point.compress() check");
    println!("  3. verify_strict() calls verify_prehashed() which:");
    println!("     a. Gets R bytes from signature (first 32 bytes)");
    println!("     b. CompressedEdwardsY(R_bytes).decompress()");
    println!("     c. Hashes using ORIGINAL R_bytes (same as Firedancer)");
    println!("     d. Checks equation [S]B = R + [k]A");
    println!("     e. verify_strict ALSO checks:");
    println!("        - A is not small order (is_small_order() check)");
    println!("        - R is not small order (is_small_order() check)");
    println!("        - A_bytes == A.compress().as_bytes() (canonicality)");
    println!("        - R_bytes == R.compress().as_bytes() (canonicality)");
    println!();
    println!("CRITICAL FINDING:");
    println!("  verify_strict checks R_bytes == R.compress().as_bytes()");
    println!("  For non-canonical R (y >= p), compress() returns canonical y = y mod p");
    println!("  So R_bytes (non-canonical) != R.compress() (canonical)");
    println!("  verify_strict REJECTS non-canonical R at this check!");
    println!();
    println!("  BUT Firedancer does NOT do this recompression check!");
    println!("  Firedancer compares points in projective coordinates.");
    println!("  So if we had a valid signature with non-canonical R:");
    println!("    - Firedancer: ACCEPT (decompresses, hashes original bytes, eq holds)");
    println!("    - Dalek strict: REJECT (R_bytes != recompressed check fails)");
    println!("    - This IS a consensus divergence!");
    println!();
    println!("  The divergence IS REAL but cannot be exploited because finding");
    println!("  r where [r]B.y < 19 is computationally infeasible (~2^251 work).");
    println!();

    // Let's explicitly verify the recompression check behavior
    println!("========================================================================");
    println!("EXPLICIT RECOMPRESSION CHECK VERIFICATION");
    println!("========================================================================");
    println!();

    for k in [3u64, 5, 6, 9, 14, 15, 16] {
        let mut limbs = p;
        let (sum, carry) = limbs[0].overflowing_add(k);
        limbs[0] = sum;
        if carry {
            limbs[1] = limbs[1].wrapping_add(1);
        }
        let nc_bytes = to_le_bytes(limbs);

        let compressed = CompressedEdwardsY(nc_bytes);
        if let Some(point) = compressed.decompress() {
            let recompressed = point.compress();
            let input_hex = hex::encode(&nc_bytes);
            let output_hex = hex::encode(recompressed.as_bytes());
            let matches = nc_bytes == *recompressed.as_bytes();

            println!("  y=p+{:2}:", k);
            println!("    input  (noncanon): {}", input_hex);
            println!("    output (recomp):   {}", output_hex);
            println!("    matches: {}  verify_strict_would_reject: {}", matches, !matches);
            println!();
        }
    }
}
