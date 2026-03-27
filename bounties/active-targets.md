# Active Bug Bounty Targets

Our focus: **cryptographic and mathematical vulnerabilities** in blockchain protocols.

## Tier 1 — Maximum Bounty Programs

| Program | Max Bounty | Crypto Scope | Status | Link |
|---------|-----------|--------------|--------|------|
| LayerZero | $15,000,000 | Cross-chain message verification, DVN signature schemes, ULN proof verification | Researching | [Immunefi](https://immunefi.com/bug-bounty/layerzero/) |
| MakerDAO/Sky | $10,000,000 | Oracle signature verification, governance crypto | Queued | [Immunefi](https://immunefi.com/bug-bounty/sky/) |
| Wormhole | $5,000,000 | Guardian ECDSA multi-sig, VAA signature verification, cross-chain attestation | Queued | [Immunefi](https://immunefi.com/bug-bounty/wormhole/) |

## Tier 2 — High-Value Crypto-Specific

| Program | Max Bounty | Crypto Scope | Status | Link |
|---------|-----------|--------------|--------|------|
| Ethereum Foundation | $1,000,000 | Consensus BLS signatures, secp256r1 precompile (Fusaka), RANDAO | Priority | [ethereum.org](https://ethereum.org/bug-bounty/) |
| ZKsync Lite | $2,300,000 | ZK circuit soundness, PLONK verifier, field arithmetic | Queued | [Immunefi](https://immunefi.com/bug-bounty/zksync/) |
| Scroll | $1,000,000 | zkEVM circuit constraints, proof generation | Queued | [Immunefi](https://immunefi.com/bug-bounty/scroll/) |
| SSV Network | $1,000,000 | Distributed validator technology, threshold signatures | Queued | [Immunefi](https://immunefi.com/bug-bounty/ssvnetwork/) |

## Tier 3 — Specialized Targets

| Program | Max Bounty | Crypto Scope | Link |
|---------|-----------|--------------|------|
| Polygon zkEVM | $500,000 | ZK proof soundness | [Immunefi](https://immunefi.com/bug-bounty/polygonzkevm/) |
| zkVerify | $50,000 | Proof verification layer | [Immunefi](https://immunefi.com/bug-bounty/zkverify/) |
| Light Protocol | $50,000 | ZK compression on Solana | [Immunefi](https://immunefi.com/bug-bounty/lightprotocol/) |

## Our Methodology

For each target we:
1. **Study the cryptographic primitives** used (ECDSA, BLS, ZK circuits)
2. **Review the implementation** for deviations from specification
3. **Test edge cases** using GPU-accelerated tools at scale
4. **Verify mathematically** before reporting
5. **Report privately** through the program's official channel

## What We Look For

- Nonce bias in ECDSA signature generation
- Weak entropy in key derivation
- Missing point validation in EC operations
- Signature malleability in verification
- Arithmetic errors in finite field operations
- Soundness breaks in ZK proof systems
- Cross-chain replay vulnerabilities in signature schemes

## Findings Log

| Date | Protocol | Severity | Status | Bounty | Report |
|------|----------|----------|--------|--------|--------|
| — | — | — | — | — | — |

*Findings published here only after responsible disclosure period.*
