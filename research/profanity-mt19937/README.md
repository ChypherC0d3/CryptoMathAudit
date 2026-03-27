# Profanity MT19937 Vulnerability Analysis

## Summary

Profanity, a popular Ethereum vanity address generator, used Mersenne Twister (MT19937) seeded with a 32-bit value to generate private keys. This reduces the keyspace from 2^256 to **2^32** (4.3 billion possible keys).

This vulnerability led to the **$160M Wintermute hack** in September 2022.

## Our Work

- Precomputed the **complete 2^32 seed table** (32 GB) mapping every possible Profanity seed to its public key X-coordinate
- Scanned **794,405 funded ETH addresses** (balance > 1 ETH) against the table
- Result: 0 matches in addresses > 1 ETH (vulnerable addresses likely already drained or hold smaller balances)

## The Vulnerability Chain

```
seed (32-bit) → MT19937 PRNG → 4x uint64 → 256-bit private key
                                              → secp256k1 scalar_mul
                                              → public key
                                              → keccak256 → ETH address
```

## Key Technical Details

- MT19937 state: seeded with single `uint32_t`
- Private key generation: `std::mt19937_64 eng(seed32)` then 4 calls to `eng()` concatenated
- Total possible private keys: exactly 2^32 = 4,294,967,296
- Table format: 8 bytes of pubkey X-coordinate per seed (32 GB total)

## Timeline

| Date | Event |
|------|-------|
| 2017 | Profanity released with MT19937 PRNG |
| 2022-01-15 | 1inch discloses vulnerability |
| 2022-09-20 | Wintermute hacked for $160M |
| 2022-09 | Amber Group publishes full exploit methodology |
| 2026-03 | Our independent analysis and full table precomputation |

## Files

- `profanity_table_generator.cu` — CUDA kernel for table generation
- `profanity_matcher.py` — Python script to match pubkeys against table
- `analysis.md` — Detailed mathematical analysis

## References

- [1inch Profanity Disclosure](https://blog.1inch.io/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool/)
- [Amber Group Exploit Analysis](https://medium.com/amber-group/exploiting-the-profanity-flaw-e986576de7ab)
- [Wintermute Hack Postmortem](https://rekt.news/wintermute-rekt/)
