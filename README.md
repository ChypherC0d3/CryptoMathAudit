# CryptoMathAudit

**Cryptographic vulnerability research through mathematics, not guessing.**

We specialize in **elliptic curve cryptography**, **ECDSA implementation flaws**, and **GPU-accelerated security auditing** of blockchain protocols. Our focus is the mathematical foundation that secures billions of dollars in digital assets.

---

## What We Do

We hunt for vulnerabilities in the **cryptographic primitives** that blockchains depend on:

| Area | What We Audit | Why It Matters |
|------|--------------|----------------|
| **ECDSA Implementations** | Nonce generation, signature verification, key derivation | A single weak nonce = private key recovery |
| **Key Generation** | Entropy sources, PRNG quality, seed derivation | Weak entropy = predictable keys = stolen funds |
| **Elliptic Curve Operations** | Scalar multiplication, point validation, endomorphisms | Implementation bugs can leak private keys |
| **HD Wallet Derivation** | BIP32/BIP39/BIP44 chains, HMAC-SHA512 | Flawed derivation = entire wallet tree compromised |
| **ZK Proof Systems** | Finite field arithmetic, polynomial commitments | Math errors in ZK = soundness breaks |

---

## Research

Published analyses of real-world cryptographic vulnerabilities:

### [Profanity MT19937 Analysis](research/profanity-mt19937/)
Complete teardown of the Profanity vanity address generator vulnerability. Precomputed full 2^32 seed table. The same flaw that led to the **$160M Wintermute hack**.

### [ECDSA Nonce Reuse Attack](research/ecdsa-nonce-reuse/)
Implemented and executed R-value duplicate scanning across Bitcoin's entire transaction history. Recovered **115 private keys** from nonce-reusing signatures. Demonstrates the attack with mathematical proofs and working code.

### [Randstorm / BitcoinJS](research/randstorm-analysis/)
Analysis of the MWC1616 PRNG vulnerability in Chrome's V8 engine (2011-2015) that affected BitcoinJS-lib, Blockchain.info, and other major wallet providers. Full chain: MWC1616 -> JSBN SecureRandom -> RC4 -> private key.

### [Weak Entropy Survey](research/weak-entropy-survey/)
Comprehensive audit of weak key generation across BTC, ETH, and TRON. Tested 7 independent attack vectors against 50M+ funded addresses. Includes Debian OpenSSL (CVE-2008-0166), Android SecureRandom (CVE-2013-7372), Trust Wallet (CVE-2023-31290), and BIP39 weak entropy patterns.

---

## Tools

GPU-accelerated security auditing tools. Open source. Built for speed.

### [WeakDirect](tools/WeakDirect/) - Weak Key Scanner
Scans 2^N private keys against target public keys using **GLV 6x endomorphism** and **Montgomery batch inversion** on CUDA.

- **395M+ effective keys/sec** on a single GTX 1080
- **38.4B+ effective keys/sec** on 12x RTX 4090
- Multi-GPU support with checkpoint/resume
- Covers: Profanity, Trust Wallet, weak entropy, timestamp-based keys

### [WeakDerived](tools/WeakDerived/) - HD Wallet Derivation Scanner
Scans weak BIP32 seeds with full BIP44 derivation (HMAC-SHA512 + secp256k1) on CUDA.

- Full derivation chain: seed -> master key -> m/44'/60'/0'/0/index
- Configurable derivation depth (1-100 addresses per seed)
- Multi-GPU with checkpoint/resume
- Multi-chain: same seed covers ETH, BTC, TRX, BNB, SOL

### [RValueScanner](tools/RValueScanner/) - ECDSA Nonce Reuse Detector
Scans blockchain signatures for duplicate R-values and recovers private keys algebraically.

- **Zero brute force** - pure mathematical recovery
- Supports BTC (DER parsing), ETH (raw r,s,v), TRON (protobuf)
- Verified: recovered 115 real Bitcoin private keys

---

## Performance Benchmarks

| Tool | GTX 1080 | RTX 4090 | 12x RTX 4090 |
|------|----------|----------|--------------|
| WeakDirect (eff. keys/sec) | 395M | ~3.2B | ~38.4B |
| WeakDerived (seeds/sec) | ~12K | ~100K | ~1.2M |
| RValueScanner | Algebraic (instant per pair) | - | - |

---

## Active Bug Bounty Targets

We focus on programs where **cryptographic/mathematical** vulnerabilities are in scope:

| Program | Max Bounty | Crypto Scope | Link |
|---------|-----------|--------------|------|
| LayerZero | $15,000,000 | Cross-chain signature verification | [Immunefi](https://immunefi.com/bug-bounty/layerzero/) |
| MakerDAO/Sky | $10,000,000 | Oracle and protocol crypto | [Immunefi](https://immunefi.com/bug-bounty/sky/) |
| Wormhole | $5,000,000 | Guardian multi-sig, VAA verification | [Immunefi](https://immunefi.com/bug-bounty/wormhole/) |
| Ethereum Foundation | $1,000,000 | Consensus crypto, secp256r1 precompile, BLS | [ethereum.org](https://ethereum.org/bug-bounty/) |
| ZKsync | $2,300,000 | ZK circuit soundness | [Immunefi](https://immunefi.com/bug-bounty/zksync/) |

See [bounties/active-targets.md](bounties/active-targets.md) for full list and methodology.

---

## Contributing

We welcome collaborators with expertise in:

- **Elliptic curve cryptography** (secp256k1, BN254, BLS12-381, Curve25519)
- **CUDA/GPU programming** for cryptographic operations
- **Zero-knowledge proof systems** (Groth16, PLONK, STARKs)
- **Formal verification** of cryptographic implementations
- **Blockchain protocol analysis**

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Responsible Disclosure

All vulnerabilities are reported through official channels **before** public disclosure. We follow a strict 90-day disclosure timeline. See [SECURITY.md](SECURITY.md) for our policy.

---

## Tech Stack

- **Languages**: CUDA C/C++, Python, Solidity
- **Cryptography**: secp256k1, ECDSA, SHA-256/512, Keccak-256, HMAC, PBKDF2, RC4, BLS
- **GPU**: NVIDIA CUDA (sm_61 to sm_89), Montgomery multiplication, GLV endomorphism
- **Data**: Google BigQuery, Etherscan/TronGrid APIs, on-chain analysis
- **Verification**: Mathematical proofs with working PoC code

---

## License

MIT License. See [LICENSE](LICENSE).

---

*Mathematics doesn't lie. Neither do we.*
