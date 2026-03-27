# Contributing to CryptoMathAudit

We're building the most rigorous cryptographic security research in the blockchain space. If you think in math before code, you're in the right place.

## What We're Looking For

### High-Value Contributions
- **New attack vectors** on ECDSA, BLS, or ZK implementations
- **GPU-optimized algorithms** for cryptographic auditing (CUDA/OpenCL)
- **Mathematical proofs** of vulnerability exploitability
- **Protocol-specific analysis** of signature schemes and key derivation
- **Tooling improvements** to WeakDirect, WeakDerived, or RValueScanner

### Areas of Interest
- Elliptic curve arithmetic optimization (secp256k1, BN254, BLS12-381)
- Lattice attacks on biased ECDSA nonces
- Pollard's Kangaroo / BSGS implementations
- ZK proof system soundness analysis
- Cross-chain bridge signature verification

## How to Contribute

1. **Fork** the repository
2. **Create a branch** for your work (`feature/lattice-attack-nonce-bias`)
3. **Include mathematical documentation** — we value proofs over code comments
4. **Add benchmarks** if your contribution affects performance
5. **Submit a PR** with a clear description of the mathematical basis

## Code Standards

- CUDA code: use PTX inline assembly for critical paths, benchmark before/after
- Python: include test vectors with known answers
- All crypto: cite the paper/specification you're implementing
- Performance claims must include reproducible benchmarks

## Responsible Disclosure

If your research discovers a live vulnerability:
1. **DO NOT** publish it in this repo
2. Report through the protocol's official bug bounty program
3. After the disclosure period (90 days), publish the analysis here
4. Credit the protocol's security team for their response

## Communication

- Open an **Issue** for discussion of new research directions
- Use **Discussions** for general cryptography questions
- Tag PRs with appropriate labels: `research`, `tooling`, `optimization`, `bounty`

## Recognition

All contributors are credited in published research and tool releases. Significant contributions may lead to shared bug bounty rewards (discussed case-by-case).
