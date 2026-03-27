# Methodology

## Our Approach: Math-First Security Auditing

We don't scan for Solidity reentrancy bugs. We break the math that protocols assume is unbreakable.

## Phase 1: Cryptographic Primitive Analysis

For each target protocol:

1. **Identify all cryptographic operations**
   - Signature generation/verification (ECDSA, BLS, EdDSA, Schnorr)
   - Key derivation (HKDF, PBKDF2, BIP32)
   - Hash functions (SHA-256, Keccak-256, Poseidon)
   - Random number generation (entropy sources)

2. **Map the implementation to the specification**
   - Is the implementation faithful to the standard?
   - Are there custom modifications?
   - What language/library is used?

3. **Identify deviation surface**
   - Non-standard nonce generation
   - Missing input validation
   - Incorrect modular arithmetic
   - Edge case handling (point at infinity, zero scalar, etc.)

## Phase 2: GPU-Accelerated Testing

Using our custom CUDA tools:

1. **Nonce quality analysis** — Extract signatures from on-chain data, analyze R-value distribution for bias
2. **Key generation audit** — Test if generated keys fall in predictable ranges
3. **Brute-force edge cases** — Test millions of boundary inputs per second
4. **Statistical analysis** — Chi-squared tests on signature distributions

## Phase 3: Mathematical Verification

Before reporting:

1. **Formal proof** of the vulnerability's mathematical basis
2. **Working PoC** demonstrating exploitability
3. **Impact assessment** — exact funds at risk
4. **Remediation recommendation** — how to fix it properly

## Tools We Use

| Tool | Purpose | Speed |
|------|---------|-------|
| WeakDirect | Scan for weak private keys via EC point comparison | 395M+ eff. keys/sec |
| WeakDerived | Scan for weak HD wallet seeds via BIP32 derivation | ~12K seeds/sec (CPU) |
| RValueScanner | Detect ECDSA nonce reuse from blockchain signatures | Algebraic (instant) |
| Custom CUDA kernels | Protocol-specific testing | Varies |

## Known Vulnerability Classes We Target

### 1. ECDSA Nonce Bias
If `k` (the signing nonce) has even 1 bit of bias, lattice attacks can recover the private key from ~100 signatures. We scan for:
- Duplicate R-values (same nonce reused)
- R-values with statistical bias (partial nonce leak)
- Affinely-related nonces (polynomial recurrence)

### 2. Weak Key Generation
Private keys generated from insufficient entropy. We test:
- Sequential keys (1, 2, 3, ...)
- Timestamp-based seeds
- PRNG with known weaknesses (MT19937, MWC1616, LCG)
- BIP39 mnemonics from weak entropy

### 3. Elliptic Curve Implementation Bugs
- Missing cofactor multiplication
- Invalid curve attacks (accepting points not on the curve)
- Twist attacks
- Small subgroup attacks
- Incorrect point serialization/deserialization

### 4. ZK Proof Soundness
- Under-constrained circuits
- Missing range checks
- Arithmetic overflow in field operations
- Incorrect Fiat-Shamir transform
