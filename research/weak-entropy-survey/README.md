# Weak Entropy Survey — Multi-Chain Key Generation Audit

## Summary

Comprehensive audit of weak private key generation across BTC and ETH. Tested 7 independent attack vectors against 50M+ funded Bitcoin addresses and 829K funded Ethereum addresses.

## Attack Vectors Tested

| # | Vector | Keys Tested | Matches | Balance Found |
|---|--------|-------------|---------|---------------|
| 1 | Debian OpenSSL (CVE-2008-0166) | 327,680 | 2 (puzzle addr) | ~$1.50 |
| 2 | Android SecureRandom (CVE-2013-7372) | 393,124 | 2 (puzzle addr) | ~$1.50 |
| 3 | Randstorm / BitcoinJS MWC1616 | ~3,300 seeds | 0 | $0 |
| 4 | BIP39 Weak Entropy | ~546,000 mnemonics | 0 | $0 |
| 5 | Brainwallet (16M phrases) | 8,295,424 | 0 | $0 |
| 6 | ECDSA Nonce Reuse (R-value) | 492 groups | 115 keys | $0 (drained) |
| 7 | Profanity MT19937 (ETH) | 4.3B seeds | 0 | $0 |

## Conclusion

All known weak key generation vulnerabilities in BTC and ETH have been thoroughly exploited by automated monitoring bots. Vulnerable addresses are swept within minutes of receiving funds. New approaches require either:
- Scanning less-monitored ecosystems (TRON, L2s)
- Finding novel vulnerability classes (lattice attacks on biased nonces)
- Auditing new protocol implementations before deployment

## Tools Used

- Custom CUDA kernels on GTX 1080 (395M effective keys/sec)
- BigQuery for blockchain data extraction
- Etherscan/Alchemy APIs for public key recovery
- Python for orchestration and verification

## Detailed Analysis

See individual subdirectories for each attack vector's methodology and results.
