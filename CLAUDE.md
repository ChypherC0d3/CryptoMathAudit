# CLAUDE.md - Diario de Bitacora CryptoMathAudit

> **LEE ESTO AL INICIO DE CADA SESION** - Contiene toda la memoria del proyecto.

## Identidad
- **Empresa**: Chronos Technology (https://c5s.xyz)
- **Proyecto**: CryptoMathAudit (CMA) — division de ciberseguridad + matematica aplicada
- **Contacto**: team@c5s.xyz
- **Repo GitHub**: https://github.com/ChypherC0d3/CryptoMathAudit
- **Objetivo**: Bug bounties en blockchain via auditoria criptografica + Solidity
- **Skills core**: EC math (secp256k1, Ed25519, BN254, BLS12-381), CUDA/GPU, Solidity security
- **Hardware local**: GTX 1080 + i7-7700K + WSL Ubuntu con GCC 13.3
- **Cuentas**: Immunefi (researcher), Alchemy (ETH RPC), GitHub (ChypherC0d3)

---

## ESTADO ACTUAL (Actualizar diariamente)

### Ultima actualizacion: 2026-03-29 (fin de dia)

### PIVOT ESTRATEGICO (2026-03-29)
**ANTES**: Crypto puro (Rust/C backends) → encontramos bugs reales pero FUERA DE SCOPE
**AHORA**: Crypto + Solidity intersection → BLS, VRF, ZK verifiers ON-CHAIN
**RAZON**: Los bounties listan smart contracts como scope. Crypto backend code (Rust/C) raramente esta in-scope.

### PROXIMA SESION — Plan claro:
1. **EigenLayer BLS audit** — Solidity, $2M bounty, BLS signature aggregation on-chain
2. **Chainlink VRF v2** — $3M, precedente $300K payout, VRF math en Solidity
3. **Lido V3 BLS** — $2M, predeposit guarantee verification

---

## Bug Bounties - Historial COMPLETO

### Round 1: Crypto puro (Firedancer, LayerZero, ZKsync, Wormhole)
| Target | Bounty | Resultado | Estado |
|---|---|---|---|
| Hyperlane WeightedMultisigIsm | $2.5M | Bug REAL (Math.min bound error) | REJECTED — asset fuera de scope |
| ZKsync OS BLOBBASEFEE | $100K | Bug real pero documented + L2 standard | NO SUBMIT — verificador lo pillo |
| Firedancer H1-H5 | $500K | 6 hipotesis testadas, todas negativas | CLOSED |
| Firedancer H6 (AVX512 vs ref) | $500K | 1300 valid vectors, 0 divergencia | CLOSED — Firedancer esta clean |
| Wormhole VAA sigs | $1M | 7 chains auditadas, 0 findings | CLOSED |
| LayerZero DVN MultiSig | $15M | Todos LOW/informational | CLOSED |

### Round 2: Protocolos jovenes
| Target | Bounty | Resultado | Estado |
|---|---|---|---|
| monero-oxide | $100K | 0 bugs explotables (bien escrito) | CLOSED |
| Serai DEX FROST/DKG | $30K | 0 explotables (buen defensive coding) | CLOSED |
| SP1 value_assertions | $150K | DISPUTED — experimental flag only | CLOSED |
| zkVerify Fflonk panic | $50K | DISPUTED — WASM catches panic safely | CLOSED |
| Threshold retry triplet | $150K | Bug REAL pero Go code fuera de scope | CLOSED |
| RISC Zero rv32im | $150K | Necesita deep analysis de 28K lineas | OPEN (low priority) |
| ZKsync Era FFLONK/P256 | $1.1M | 1 Medium (Modexp 256-bit limit) | CLOSED |
| ZKsync OS gates/RAM | $100K | Constraint system sound | CLOSED |

### Verificador Ciego — Score
| Finding | Verificador dice | Nos salvo de |
|---|---|---|
| ZKsync BLOBBASEFEE | DISPUTED (documented) | Submit malo |
| ZKsync reframe | DO NOT SUBMIT (L2 standard) | Submit malo |
| SP1 value_assertions | DISPUTED (test flag) | Submit malo |
| Threshold retry | CONFIRMED pero OOS | Submit de bajo impacto |
| zkVerify Fflonk | DISPUTED (WASM safe) | Submit con impacto incorrecto |
| **TOTAL: 5 submits malos evitados** |

---

## BTC Audit - COMPLETADO (todo drenado por bots)
| Programa | Keys | Matches | Balance |
|---|---|---|---|
| P5 Debian OpenSSL | 327K | 2 (key=17) | ~$1.50 |
| P6 R-value reuse | 492 grupos | 115 keys | $0 |
| P2 Android SecureRandom | 393K | 2 (key=17) | ~$1.50 |
| P1 Brainwallet GPU | 8.3M | 0 | - |
| P3 Randstorm | Parado | 0 | GPU lenta |

## ETH Audit - Profanity 0 matches en >1 ETH
- Tabla Profanity 32GB: COMPLETADA
- 794K pubkeys recuperadas via Alchemy
- 0 matches contra 829K addresses >1 ETH
- WeakDirect v4.1: 395M/sec (listo para cloud)
- WeakDerived: listo para cloud
- Pendiente: vanity addresses + L2s + ERC-20

---

## HERRAMIENTAS

### GPU Kernels
- `eth_weakkey_scan_v4.cu` — 395M/sec, 6x GLV, Montgomery batch 32
- `WeakDirect/weakdirect.cu` — Multi-GPU, checkpoint/resume
- `WeakDerived/weakderived.cu` — BIP32 + SHA-512 HMAC CUDA

### Scanners
- `programa6_rvalue_scanner.py` — BTC/ETH R-value nonce reuse
- `tron_rvalue_scanner.py` — TRON R-value scanner
- `eth_recover_pubkeys.py` — Batch ETH pubkey recovery via Alchemy

### Bug Bounty
- `tools/verify_bug.md` — Agente verificador ciego (**CRITICO — usar SIEMPRE antes de submit**)
- `knowledge/solidity_security_guide.md` — 50 vulns, 20 hacks, toolchain
- `knowledge/bounty_strategy_v2.md` — Crypto+Solidity targets + metodologia

### Datasets
- `btc_dataset/hash160_all.bin` — 50M BTC addresses
- `btc_audit/eth_pubkeys.bin` — 794K ETH pubkeys (108MB)
- `v3_500M_target/profanity_table.bin` — 32GB tabla Profanity

---

## LECCIONES APRENDIDAS (CRITICAS)

1. **VERIFICAR SCOPE ANTES DE TODO** — Hyperlane rechazado por asset incorrecto
2. **USAR VERIFICADOR CIEGO SIEMPRE** — Nos salvo de 5 submits malos
3. **Crypto puro ≠ in-scope** — Los bounties listan smart contracts, no backends
4. **Nuestro sweet spot**: Contratos Solidity que implementan crypto (BLS, VRF, ZK verifiers)
5. **BTC esta drenado** — Bots 24/7 desde hace 10+ anos
6. **ETH Profanity >1 ETH = 0** — Probar vanity + L2s + ERC-20 + contract admins
7. **Bugs encontrados != bugs pagados** — Scope + impact + in-scope asset son TAN importantes como el bug
8. **Los bugs de math en DeFi son los mas caros** — Cetus $223M, Euler $197M, Balancer $128M

---

## PRECIOS CLOUD (Vast.ai)
| GPU | $/hr | Nuestro workload |
|---|---|---|
| RTX 3090 | $0.13 | Mejor $/key |
| RTX 4090 | $0.29 | Mejor balance |
| RTX 5090 | $0.37 | Mas rapido |
| H100/H200 | $1.65-2.06 | NO USAR (5-7x mas caro, diseñadas para AI) |
