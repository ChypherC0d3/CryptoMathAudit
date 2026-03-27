# ECDSA Nonce Reuse Attack — Full Bitcoin Blockchain Scan

## Summary

When two ECDSA signatures share the same nonce `k`, the private key can be recovered with pure algebra. No brute force needed.

## The Math

Given signatures `(r, s1, h1)` and `(r, s2, h2)` with same nonce:

```
k = (h1 - h2) * inverse(s1 - s2, n) mod n
private_key = (s1 * k - h1) * inverse(r, n) mod n
```

Where `n` is the secp256k1 curve order.

## Our Results

| Metric | Value |
|--------|-------|
| Signatures analyzed | Entire BTC blockchain via BigQuery |
| Exploitable R-value groups | 492 |
| **Private keys recovered** | **115** |
| Keys with current balance | 0 (all previously drained) |
| Verification | 100% — all recovered keys produce correct addresses |

## Methodology

1. **BigQuery**: Extracted all DER-encoded signatures from `bigquery-public-data.crypto_bitcoin.inputs`
2. **DER Parsing**: Extracted R and S values from scriptSig hex data
3. **Grouping**: Found R-values appearing 2+ times (same signer)
4. **Recovery**: Applied algebraic formula to each duplicate pair
5. **Verification**: Derived addresses from recovered keys, confirmed match
6. **Balance Check**: Cross-referenced with funded address dataset (50M+ addresses)

## Key Findings

- All 115 vulnerable addresses were already drained by automated bots
- Duplicate R-values concentrate in 2012-2014 (Android SecureRandom bug era)
- Monitoring bots sweep vulnerable addresses within minutes of deposit

## Files

- `programa6_rvalue_scanner.py` — Full scanner with demo and scan modes
- `bigquery_queries.sql` — Ready-to-use BigQuery queries for signature extraction

## References

- [Brengel & Rossow, RAID 2018: "Identifying Key Leakage of Bitcoin Users"](https://christian-rossow.de/publications/btcsteal-raid2018.pdf)
- [ECDSA Nonce Reuse — Wikipedia](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Security)
