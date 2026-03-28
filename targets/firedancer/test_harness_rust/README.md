# Ed25519 Test Harness (Rust) - Agave/Solana Reference Implementation

## Purpose

This is a standalone Rust binary that replicates Agave/Solana's Ed25519 signature
verification behavior. It uses the **exact same** `ed25519-dalek` version that
Agave pins: `=1.0.1`.

The primary use case is **differential testing** against Firedancer's Ed25519
implementation to find edge-case discrepancies that could be exploitable.

## What Agave Does

Based on analysis of the Agave source code:

- **Dependency**: `ed25519-dalek = "=1.0.1"` (pinned in workspace `Cargo.toml`)
- **Transaction sigverify** (`sdk/signature/src/lib.rs`):
  `ed25519_dalek::PublicKey::verify_strict(message_bytes, &signature)`
- **Ed25519 precompile** (native program):
  Originally used `verify()` (cofactored). After feature gate
  `ed9tNscbWLYBooxWA7FE2B5KHWs8A6sxfY8EzezEcoo` (activated in v2.0.4),
  the precompile also uses `verify_strict()`.

### verify_strict vs verify

| Property | `verify_strict` | `verify` |
|---|---|---|
| Equation | `[S]B = R + [k]A` (cofactorless) | `[8][S]B = [8]R + [8][k]A` (cofactored) |
| Small-order A (pubkey) | **Rejected** (is_weak check) | Allowed |
| Small-order R | **Rejected** (is_small_order check) | Allowed (absorbed by cofactor) |
| S >= L | Rejected at Signature::from_bytes | Rejected at Signature::from_bytes |
| Non-canonical point encoding | Rejected by CompressedEdwardsY::decompress | Rejected by CompressedEdwardsY::decompress |

## Building

Requires Rust toolchain (tested with stable Rust, ed25519-dalek 1.0.1 needs edition 2021).

```bash
cargo build --release
```

The binary will be at `target/release/ed25519_test` (or `ed25519_test.exe` on Windows).

## Usage

### Single Signature Verification

```bash
# Using verify_strict (matches current Agave behavior)
./ed25519_test strict <pubkey_hex> <signature_hex> <message_hex>

# Using verify (cofactored, old precompile behavior)
./ed25519_test loose <pubkey_hex> <signature_hex> <message_hex>

# Run both and compare
./ed25519_test both <pubkey_hex> <signature_hex> <message_hex>
```

**Output**: Prints `ACCEPT` or `REJECT`. Exit code 0 = accept, 1 = reject, 2 = usage error.

### Example (RFC 8032 Test Vector 1)

```bash
./ed25519_test strict \
  d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b0b8d183f8e3 \
  e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b \
  ""
# Output: ACCEPT
```

### Batch Mode (Test Vectors)

```bash
# Run all test vectors from JSON, write results back to same file
./ed25519_test batch ../test_harness/test_vectors.json

# Or write results to a separate output file
./ed25519_test batch ../test_harness/test_vectors.json results.json
```

This reads the shared `test_vectors.json` format, runs both `verify_strict` and
`verify` on each vector, and writes `result_dalek_strict` and `result_dalek_loose`
fields back into the JSON.

## Test Vector Format

The test vectors are stored in `../test_harness/test_vectors.json` in a format
shared between the Rust and C test harnesses:

```json
{
  "vectors": [
    {
      "id": "unique_id",
      "hypothesis": "H1/H2/H3/H4/baseline",
      "description": "Human-readable description",
      "pubkey": "32-byte hex",
      "signature": "64-byte hex (R || S)",
      "message": "hex (can be empty string for empty message)",
      "expected_firedancer": "ACCEPT/REJECT/unknown",
      "expected_dalek_strict": "ACCEPT/REJECT/unknown",
      "expected_dalek_loose": "ACCEPT/REJECT/unknown",
      "result_dalek_strict": "filled after batch run",
      "result_dalek_loose": "filled after batch run"
    }
  ]
}
```

## Test Hypotheses

- **H1**: Cofactor equation mismatch - differences between cofactored and cofactorless verification
- **H2**: Non-canonical point encoding - y-coordinates >= p in R or pubkey encoding
- **H3**: Small-order component handling - identity, order-2, order-4, order-8 points as A or R
- **H4**: Scalar S boundary values - S = 0, S = L-1, S = L, S = L+1, S = 2^255-1

## Key Constants

- **L** (group order): `edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010` (LE hex)
- **p** (field prime): `edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f` (LE hex)
- **Small-order points**: See `test_vectors.json` notes section

## Sources

- Agave workspace Cargo.toml: https://github.com/anza-xyz/agave/blob/master/Cargo.toml
- Agave sigverify: https://github.com/anza-xyz/agave/blob/master/perf/src/sigverify.rs
- Agave Signature::verify: https://github.com/anza-xyz/agave/blob/v2.1.13/sdk/signature/src/lib.rs
- ed25519-dalek 1.0.1 docs: https://docs.rs/ed25519-dalek/1.0.1/ed25519_dalek/
- verify_strict feature gate: https://github.com/anza-xyz/agave/releases/tag/v2.0.4
