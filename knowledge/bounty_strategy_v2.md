# Bounty Hunting Strategy v2: Crypto + Solidity Intersection
## Date: 2026-03-28

---

## Executive Summary

**Core Lesson Learned:** Pure cryptographic bugs (in libraries, off-chain code) are almost always OUT OF SCOPE in bounty programs. Our sweet spot is **Solidity contracts that perform cryptographic operations on-chain** -- where our EC math expertise meets in-scope smart contract code.

**Strategy:** Target protocols where cryptographic primitives (BLS signatures, ECDSA verification, ZK proof verification, VRF) are implemented or consumed **inside Solidity contracts** that handle user funds.

---

## PART 1: Market Research -- Crypto + Solidity Bounty Landscape

### 1.1 Signature Verification in Solidity

**Key finding:** Signature verification bugs (ecrecover misuse, EIP-712 replay, missing nonce checks, signature malleability) remain a top vulnerability class. The Feb 2026 ERC-4337 disclosure (Trust Security) earned $109,500 combined from Ethereum Foundation + affected DeFi apps (Safe, Biconomy). The root cause was a hidden assumption that all account abstraction transactions would run isolated.

**Active programs with sig verification in scope:**
- CoW Protocol: Explicitly lists "forgery of a user's signature" as in-scope impact
- Kleidi Wallet: EIP-712 signatures for emergency recovery spells on Safe
- Safe ecosystem: Module system, guard contracts, multi-sig verification

### 1.2 Bridge / Cross-Chain Verification

**Key finding:** Cross-chain bridges are the highest-value targets. The Wormhole $10M payout (satya0x) remains the largest single bounty ever.

**Active programs:**
- **Wormhole**: Up to 20M W tokens. Scope: smart contracts, guardian nodes, blockchain integrations. Tiered by TVL impact.
- **LayerZero**: Up to $15M. Scope: all deployed smart contracts. Group 1 chains (ETH, BNB, AVAX, MATIC, ARB, OP, FTM) pay $250K-$15M for critical. ~$1M awarded to date.
- **Immutable**: Up to $1M. Scope: bridge modules, adapter contracts on Ethereum + zkEVM.

### 1.3 ZK Verifier Contracts

**Key finding:** ZK verification on-chain is growing rapidly. The Solidity verifier contract is the trust boundary -- bugs here can be catastrophic.

**Active programs:**
- **ZKsync Era**: Comprehensive scope covering smart contracts, ZK-SNARK circuits. On Immunefi.
- **ZKsync Lite**: ZK Rollup architecture. SNARK circuits in scope. Critical reward capped at $20K (low for our effort).
- **zkVerify**: Modular proof verification. Up to $50K.
- **Lido V3**: On-chain BLS signature verification for predeposit guarantee. $200K bonus pool for competition.

### 1.4 Oracle / VRF

**Key finding:** Chainlink VRF v2 critical bug (rerollable randomness) paid $300K to Zach Obront + Or Cyngiser (Trust). This is exactly our wheelhouse -- understanding the math behind VRF and how Solidity consumes it.

**Active programs:**
- **Chainlink**: Up to $3M. Scope: infrastructure + oracle across 12+ chains. VRF delivery delays explicitly in scope. Testing on mainnet prohibited; must use private testnets.

### 1.5 Account Abstraction (EIP-4337)

**Key finding:** Feb 2026 -- Trust Security found high-severity bug in ERC-4337 code. $50K from Ethereum Foundation + $59.5K from affected apps. The bug class (hidden assumptions about transaction isolation) is perfect for our skillset.

**Active programs:**
- Ethereum Foundation: Direct bounty for ERC-4337 core
- XION: Chain abstraction L1, up to $250K on Immunefi
- Safe ecosystem: Heavy EIP-4337 integration

### 1.6 BLS Signature Aggregation

**Key finding:** BLS signatures in Solidity are complex and error-prone. Rogue-key attacks, proof-of-possession requirements, pairing check edge cases. EigenLayer's AVS framework uses BLS multi-signatures extensively.

**Active programs:**
- **EigenLayer**: Up to $2M on Immunefi. BLS signature aggregation in AVS contracts is core functionality. Operators sign with BLS, aggregator merges signatures, on-chain contract verifies aggregate.
- **Lido V3**: BLS signature verification for validator deposit credentials. $200K bonus pool.

---

## PART 2: Specific Target Analysis

### Tier 1: HIGH PRIORITY (Crypto is core to the protocol's Solidity code)

#### 1. EigenLayer -- BLS Signature Aggregation
- **Immunefi URL:** https://immunefi.com/bounty/eigenlayer/
- **Max bounty:** $2,000,000
- **Crypto code IN SCOPE (Solidity):**
  - BLS multi-signature verification in AVS contracts
  - Aggregate signature merging and on-chain verification
  - Proof-of-possession checks
  - Slashing conditions based on signature validity
- **What they worry about:** Rogue-key attacks bypassing aggregate signature verification, operators avoiding slashing through signature manipulation, incorrect threshold validation
- **Past payouts:** Program active since 2023. Specific payout amounts not publicly disclosed.
- **OUR EDGE:** Deep BN254/BLS12-381 pairing math knowledge. We can analyze the Solidity precompile calls, check for edge cases in pairing checks, verify proof-of-possession logic.

#### 2. Lido -- BLS Verification + Withdrawal Credentials
- **Immunefi URL:** https://immunefi.com/bug-bounty/lido/
- **Competition URL:** https://immunefi.com/audit-competition/lido-v3-bug-bounty-competition/
- **Max bounty:** $2,000,000 (ongoing) + $200K bonus pool (V3 competition) + $100K bonus (Dual Governance)
- **Crypto code IN SCOPE (Solidity):**
  - On-chain BLS signature verification for predeposit guarantee
  - Deposit credential validation
  - Withdrawal credential verification
  - stVault minting based on cryptographic proofs
- **What they worry about:** Deposit frontrunning (validator key substitution), withdrawal credential manipulation, oracle data integrity
- **Past payouts:** $200K for deposit frontrunning vulnerability (Dmitri Tsumak, RocketPool+Lido). March 2026: 3 low-moderate weaknesses disclosed (no funds at risk).
- **OUR EDGE:** BLS signature verification is literally our specialty. The predeposit guarantee mechanism requires deep understanding of BLS math to audit properly.

#### 3. LayerZero -- Cross-Chain Message Verification
- **Immunefi URL:** https://immunefi.com/bug-bounty/layerzero/
- **Max bounty:** $15,000,000 (Group 1 chains)
- **Crypto code IN SCOPE (Solidity):**
  - Cross-chain message verification contracts
  - Oracle/relayer verification logic
  - Endpoint contracts across 12+ chains
- **What they worry about:** Message forgery, replay attacks across chains, verification bypass
- **Past payouts:** ~$1M total awarded to whitehats
- **OUR EDGE:** Cross-chain verification involves cryptographic proof validation. Understanding how signatures and proofs travel between chains is where crypto + Solidity intersect.

#### 4. Chainlink -- VRF + CCIP
- **Immunefi URL:** https://immunefi.com/bug-bounty/chainlink/
- **Max bounty:** $3,000,000
- **Crypto code IN SCOPE (Solidity):**
  - VRF v2 consumer contracts and verification
  - CCIP cross-chain interoperability
  - Oracle delivery mechanisms
- **What they worry about:** VRF randomness manipulation (reroll attacks), oracle delivery delays, CCIP message integrity
- **Past payouts:** $300K for VRF v2 critical (rerollable randomness). $500K+ total across 75+ reports, 50+ researchers.
- **OUR EDGE:** VRF math (discrete log proofs, hash-to-curve). We understand the cryptographic guarantees and can spot where the Solidity implementation diverges from the security model.

### Tier 2: MEDIUM PRIORITY (Crypto is used but not the primary attack surface)

#### 5. Wormhole -- Guardian Signature Verification
- **Immunefi URL:** https://immunefi.com/bounty/wormhole/
- **Max bounty:** Up to 20,000,000 W tokens (~millions USD)
- **Crypto code IN SCOPE:** Guardian multi-sig verification, VAA (Verified Action Approval) signature checks
- **What they worry about:** TVL extraction via forged messages, guardian key compromise implications
- **Past payouts:** $10M (satya0x) -- largest ever Immunefi payout
- **OUR EDGE:** Multi-sig threshold verification, signature aggregation in the guardian network

#### 6. Aave -- Flash Loan + Oracle Interactions
- **Immunefi URL:** https://immunefi.com/bug-bounty/aave/
- **Max bounty:** $1,000,000
- **Crypto code IN SCOPE (Solidity):**
  - Oracle price feed consumption
  - Flash loan interaction logic
  - Liquidation calculations
- **What they worry about:** Oracle manipulation via flash loans (realistic scenarios required), collateral manipulation
- **Past payouts:** Not publicly detailed. Active since legacy program.
- **OUR EDGE:** Understanding oracle price feed math, rounding attacks in liquidation, flash loan economic exploits. Less crypto-specific but our math skills apply.

#### 7. Uniswap v4 -- Oracle + Hooks
- **Platform:** Cantina (NOT Immunefi)
- **URL:** https://blog.uniswap.org/v4-bug-bounty
- **Max bounty:** $15,500,000
- **Crypto code IN SCOPE:** TWAP oracle manipulation, concentrated liquidity math, hook interactions
- **What they worry about:** Hook exploits (first major V4 hook exploit caused $12M loss), oracle manipulation, liquidity math edge cases
- **Past payouts:** No critical bugs found in security competition.
- **OUR EDGE:** Deep understanding of AMM math, sqrt price calculations, tick arithmetic. Less cryptographic but heavy on field arithmetic.
- **NOTE:** Oracle testing is OUT OF SCOPE on the zkSync Immunefi bounty. Main V4 bounty is on Cantina.

#### 8. Safe (Gnosis Safe) -- Signature Verification + Modules
- **Immunefi URL:** No dedicated Safe bounty found on Immunefi (as of March 2026)
- **Related:** Kleidi (https://immunefi.com/bug-bounty/kleidi/) -- Safe-based wallet with EIP-712 signatures
- **Max bounty:** $50K (Kleidi). Safe's own bounty historically $1M but current Immunefi status unclear.
- **Crypto code IN SCOPE:** EIP-712 signature verification, multi-sig threshold logic, guard contracts, timelock modules
- **What they worry about:** Signature forgery, module bypass, timelock circumvention
- **Past payouts:** Part of ERC-4337 disclosure ($59.5K combined)
- **OUR EDGE:** ecrecover edge cases, EIP-712 domain separator issues, signature malleability in multi-sig contexts

### Tier 3: OPPORTUNISTIC

#### 9. Compound Finance -- Governance + Liquidation
- **Immunefi URL:** https://immunefi.com/bug-bounty/compoundfinance/
- **Max bounty:** Paid in COMP, amount varies by severity
- **Crypto code IN SCOPE:** Governance voting verification, liquidation math
- **What they worry about:** Governance vote manipulation, liquidation calculation errors
- **Past payouts:** Monthly DAO proposals for grouped payouts
- **OUR EDGE:** Math-heavy liquidation logic, governance signature verification

#### 10. 1inch -- Aggregation + Order Execution
- **Platform:** HackenProof (NOT Immunefi -- migrated)
- **URL:** https://hackenproof.com/programs/1inch-smart-contract
- **Max bounty:** $500,000 (smart contracts)
- **Crypto code IN SCOPE:** Limit order signature verification, aggregation routing math
- **What they worry about:** Order execution manipulation, signature replay
- **OUR EDGE:** Order signature verification, permit-style approvals

---

## PART 3: Audit Methodology -- Crypto-Focused Solidity Review

### Step 1: SCOPE VERIFICATION (ALWAYS FIRST)

**Rationale:** We found 3 real bugs but all had scope/impact issues. Never again.

```
SCOPE CHECKLIST:
[ ] Read the FULL bounty page on Immunefi/platform (not just the summary)
[ ] Identify EXACT contract addresses and repos in scope
[ ] Check "Assets in Scope" table -- only those contracts count
[ ] Verify chain coverage (some programs only cover mainnet, not L2s)
[ ] Read "Out of Scope" section completely -- look for crypto exclusions
[ ] Check if "third-party libraries" are excluded (this kills many crypto bugs)
[ ] Verify that the specific crypto primitive code is IN the scoped contracts
[ ] Check if off-chain components (relayers, aggregators) are in scope
[ ] Confirm severity classification for crypto bugs specifically
[ ] Look for "known issues" exclusions from prior audits
[ ] Check if testing against oracles/third-party contracts is prohibited
[ ] Document scope evidence with screenshots/URLs before starting work
```

**SCOPE RED FLAGS (walk away):**
- "Smart contracts only" when the crypto happens off-chain
- "Third-party libraries out of scope" when they use OpenZeppelin/Solady for crypto
- "Testing with pricing oracles prohibited" when oracle math is the target
- Previous audit covered the exact code you're looking at

### Step 2: CRYPTO PRIMITIVE MAPPING

For each contract in scope, identify and document:

```
CRYPTO INVENTORY:
[ ] ECDSA/ecrecover usage -- signature verification, EIP-712, EIP-191
[ ] BLS signatures -- BN254 pairing checks, aggregate verification
[ ] Hash functions -- keccak256, SHA256, RIPEMD160 (precompiles)
[ ] Merkle proofs -- verification logic, tree construction assumptions
[ ] ZK proof verification -- Groth16, PLONK verifier contracts
[ ] VRF -- randomness verification, seed handling
[ ] Commitment schemes -- hash commitments, reveal logic
[ ] Modular arithmetic -- field operations, overflow potential
[ ] Precompile usage -- ecRecover (0x01), SHA256 (0x02), modexp (0x05),
    ecAdd (0x06), ecMul (0x07), ecPairing (0x08), blake2f (0x09)
[ ] Custom crypto -- any hand-rolled cryptographic operations
```

**For each primitive found, document:**
1. What precompiles/libraries are used
2. What inputs come from untrusted sources (users, other contracts, off-chain)
3. What the security assumption is (e.g., "signature proves authorization")
4. What happens if the primitive returns unexpected results

### Step 3: INPUT VALIDATION AUDIT

This is where most crypto bugs live. For each cryptographic operation:

```
INPUT VALIDATION CHECKLIST:
[ ] Are EC points validated to be on the curve?
[ ] Are points checked for being in the correct subgroup?
[ ] Is the identity/infinity point handled?
[ ] Are signature components (r, s, v) range-checked?
    - s <= n/2 (malleability)? v in {27, 28}?
[ ] Is ecrecover return value checked for address(0)?
[ ] Are hash inputs properly domain-separated?
[ ] Are nonces checked for replay prevention?
[ ] Are Merkle proof leaves properly hashed (double-hash for 2nd preimage)?
[ ] Are ZK proof public inputs validated against expected values?
[ ] Are VRF proofs checked for correct seed binding?
[ ] Is msg.sender/tx.origin conflation possible?
[ ] Are abi.encode vs abi.encodePacked collisions possible?
[ ] Are cross-chain replay protections in place (chain ID)?
```

**HIGH-VALUE BUG PATTERNS:**
1. **Signature malleability:** Contract accepts both (r, s) and (r, n-s), allowing replay
2. **Missing ecrecover zero-check:** ecrecover returns 0x0 on invalid input, matches uninitialized storage
3. **abi.encodePacked collision:** Two different inputs produce same hash
4. **Cross-chain replay:** Same signature valid on multiple chains (missing chain ID)
5. **Merkle proof second preimage:** Internal nodes interpretable as leaves
6. **BLS rogue-key attack:** Missing proof-of-possession allows aggregate forgery
7. **VRF reroll:** Subscription owner can block and retry for desired randomness
8. **ZK public input mismatch:** Verifier doesn't bind proof to expected state

### Step 4: BUSINESS LOGIC AROUND CRYPTO

The crypto primitive itself may be correct, but the business logic using it may be flawed.

```
BUSINESS LOGIC CHECKLIST:
[ ] What happens when signature verification SUCCEEDS? (authorization granted)
[ ] What happens when signature verification FAILS? (revert? silent fail? fallback?)
[ ] Can the same valid signature be used twice? (replay across functions)
[ ] Is there a time window where a valid signature becomes dangerous?
[ ] Can signature verification be front-run?
[ ] Are there race conditions between verification and execution?
[ ] Does the contract correctly handle batch/aggregate verification failure?
[ ] If one signature in a batch is invalid, does the whole batch fail?
[ ] Are there emergency/admin bypasses around crypto verification?
[ ] Can governance change crypto parameters (e.g., threshold) to weaken security?
[ ] What oracle data is consumed after crypto verification?
[ ] Can flash loans be used between verification and fund movement?
```

### Step 5: INTEGRATION POINTS

How does on-chain crypto interact with the rest of the system?

```
INTEGRATION CHECKLIST:
[ ] Off-chain -> On-chain: How do signatures/proofs get submitted?
    - Can the relayer/submitter manipulate them?
    - Is the submitter identity verified separately?
[ ] Cross-contract calls: Does verification result pass through delegatecall/call?
    - Can a malicious callback re-enter during verification?
[ ] Upgradability: Can the crypto verification logic be upgraded?
    - Who controls upgrades? Timelock? Multi-sig?
[ ] Oracle dependencies: Does crypto verification depend on external price data?
    - Can oracle manipulation invalidate crypto guarantees?
[ ] Gas limits: Can crypto operations be DoS'd by gas manipulation?
    - Pairing checks are expensive (~100K+ gas)
    - Can an attacker force gas exhaustion in verification?
[ ] Precompile assumptions: Does the code handle precompile failures?
    - What if ecRecover returns empty? What if pairing check runs out of gas?
```

### Step 6: BLIND VERIFICATION BEFORE SUBMIT

**Before submitting ANY report:**

```
PRE-SUBMISSION CHECKLIST:
[ ] RE-VERIFY SCOPE: Is the affected contract still in the Assets in Scope table?
[ ] WRITE THE PoC: Code a complete, runnable proof of concept
    - Use Foundry fork test against mainnet state
    - Show exact steps from initial state to impact
    - Calculate exact financial impact in USD
[ ] CLASSIFY IMPACT: Map to Immunefi Severity Classification V2.3
    - Critical: Direct theft/permanent freezing of funds > $X
    - High: Theft that requires specific conditions
    - Medium: Temporary DoS or limited fund impact
[ ] CHECK KNOWN ISSUES: Search all prior audits for this exact bug pattern
[ ] CHECK DUPLICATES: Search Immunefi disclosures, Medium writeups, Twitter
[ ] PEER REVIEW: Have someone else verify the PoC independently
[ ] CALCULATE REALISTIC IMPACT: Use actual TVL/fund amounts, not theoretical max
[ ] DRAFT THE REPORT: Clear title, description, impact, PoC, fix suggestion
[ ] SLEEP ON IT: Wait 24 hours, re-read with fresh eyes
```

---

## PART 4: Target Ranking

### Scoring Formula
```
Score = bounty_amount * P(finding_crypto_bug_in_solidity) * in_scope_certainty
```

Where:
- **bounty_amount**: Maximum realistic payout (not theoretical max)
- **P(finding_crypto_bug)**: Probability of finding a crypto-specific bug given our skillset (0.0-1.0)
- **in_scope_certainty**: Confidence that crypto code is genuinely in scope (0.0-1.0)

### Rankings

| Rank | Target | Max Bounty | P(crypto bug) | Scope Certainty | Score | Rationale |
|------|--------|-----------|---------------|-----------------|-------|-----------|
| 1 | **EigenLayer** | $2,000,000 | 0.15 | 0.90 | **$270,000** | BLS aggregation is core Solidity. Complex pairing math = high bug probability. AVS contracts are explicitly in scope. |
| 2 | **Lido V3** | $2,000,000 | 0.12 | 0.95 | **$228,000** | On-chain BLS verification for predeposit guarantee. Competition format means focused scope. March 2026 disclosures show active bugs exist. |
| 3 | **LayerZero** | $15,000,000 | 0.05 | 0.80 | **$600,000** | Huge bounty but heavily audited. Cross-chain verification is in scope. Lower P(bug) due to extensive prior review. |
| 4 | **Chainlink VRF** | $3,000,000 | 0.08 | 0.85 | **$204,000** | VRF math is our wheelhouse. $300K precedent payout for VRF bug. Oracle delivery explicitly in scope. |
| 5 | **Wormhole** | $5,000,000 | 0.06 | 0.80 | **$240,000** | Guardian sig verification in scope. $10M precedent but heavily watched now. |
| 6 | **Uniswap v4** | $15,500,000 | 0.03 | 0.70 | **$325,500** | Massive bounty but on Cantina, not Immunefi. Math-heavy (sqrt price, tick) but less crypto-specific. Hook exploits are the real target. |
| 7 | **Aave** | $1,000,000 | 0.07 | 0.85 | **$59,500** | Oracle + flash loan interactions. "Realistic scenario" requirement is strict but fair. Less crypto-pure. |
| 8 | **Safe/Kleidi** | $50,000 | 0.15 | 0.90 | **$6,750** | EIP-712 sigs are in scope and we know them well. Low bounty cap limits reward. But ERC-4337 interaction bugs can earn from multiple projects. |
| 9 | **Compound** | ~$500,000 | 0.04 | 0.75 | **$15,000** | Governance sig verification. COMP-denominated payouts add price risk. Monthly DAO process is slow. |
| 10 | **1inch** | $500,000 | 0.06 | 0.70 | **$21,000** | On HackenProof, not Immunefi. Order signature verification is relevant. Good scope but less crypto-dense. |

### Adjusted Priority Order (accounting for effort and time-to-payout)

1. **EigenLayer** -- Best ratio of crypto density to bounty size. BLS aggregation in Solidity is exactly our expertise. Start here.
2. **Lido V3** -- Competition format means time-bounded effort. BLS predeposit verification is a focused target. High scope certainty.
3. **Chainlink VRF** -- Proven $300K payout for VRF bug. We understand the math. Clear scope.
4. **LayerZero** -- Largest bounty pool. Worth deep-diving the cross-chain verification contracts even with lower P(bug).
5. **Wormhole** -- Guardian verification is high-value but heavily watched. Worth a periodic review.
6. **Uniswap v4** -- Different platform (Cantina) but massive bounty. Hook + oracle math plays to our strengths.
7. **Aave** -- Flash loan + oracle is well-studied but our math skills give an edge on rounding/precision bugs.
8. **Safe/Kleidi** -- Low cap but high P(finding something). Good for quick wins and building reputation.
9. **1inch** -- Order signature verification on HackenProof. Decent secondary target.
10. **Compound** -- Governance focus. Lower priority due to slow payout process.

---

## PART 5: Execution Plan

### Week 1-2: EigenLayer Deep Dive
- Clone all in-scope contracts from GitHub
- Map every BLS precompile call (ecAdd, ecMul, ecPairing at 0x06, 0x07, 0x08)
- Trace aggregate signature verification logic end-to-end
- Check proof-of-possession requirements
- Look for rogue-key attack vectors
- Test edge cases: identity point, wrong subgroup, gas limits on pairing

### Week 3-4: Lido V3 BLS Verification
- Focus on predeposit guarantee mechanism
- Audit BLS signature verification against BLS12-381 spec
- Check deposit credential binding
- Look for frontrunning windows between commitment and deposit
- Review stVault minting authorization chain

### Week 5-6: Chainlink VRF + CCIP
- Study VRF v2 verification contracts
- Understand the subscription model and how randomness is delivered
- Look for reroll/blocking vectors (similar to the $300K bug)
- Review CCIP message verification on supported chains

### Ongoing: Rotation through Tier 2 targets
- Spend 2-3 days per target on initial reconnaissance
- If promising attack surface found, allocate a full week
- Monitor new bounty launches and competitions on Immunefi

### Weekly Process
1. **Monday:** Check for new programs/scope changes on Immunefi
2. **Tuesday-Thursday:** Deep audit work on current target
3. **Friday:** Write up any findings, peer review, scope verification
4. **Weekend:** Background reading on new vulnerability classes, tool development

---

## PART 6: Key Statistics & Context

- Immunefi total payouts: $100.21M+ across 3,000+ reports
- Smart contract bugs: 77.5% of all payouts ($77.97M)
- Largest single payout: $10M (Wormhole, satya0x)
- Average critical payout minimum: $10K
- Successful hunters earn: $50K-$200K annually
- Web3 losses H1 2025: $3B+ (access control #1 at $1.83B)
- Top vulnerability class 2025: Access control > oracle manipulation > reentrancy

---

## PART 7: Tool Stack for Crypto-Solidity Auditing

```
ESSENTIAL TOOLS:
- Foundry (forge): Fork testing, fuzzing, PoC development
- Slither: Static analysis for common patterns
- Echidna: Property-based fuzzing
- Our CUDA kernels: Brute-force edge cases in field arithmetic
- Python/SageMath: Verify cryptographic correctness off-chain
- Etherscan/Blockscout: Verify deployed bytecode matches source

CRYPTO-SPECIFIC:
- BN254 test vectors: Validate pairing check implementations
- EIP-712 struct hash calculator: Verify domain separators
- ecrecover edge case generator: Test v=0, s>n/2, r=0, etc.
- VRF proof generator: Create valid/invalid proofs for testing
```

---

## Appendix: Immunefi URLs Quick Reference

| Protocol | Immunefi URL | Max Bounty | Platform |
|----------|-------------|-----------|----------|
| EigenLayer | https://immunefi.com/bounty/eigenlayer/ | $2M | Immunefi |
| Lido | https://immunefi.com/bug-bounty/lido/ | $2M | Immunefi |
| Lido V3 Competition | https://immunefi.com/audit-competition/lido-v3-bug-bounty-competition/ | $200K bonus | Immunefi |
| LayerZero | https://immunefi.com/bug-bounty/layerzero/ | $15M | Immunefi |
| Chainlink | https://immunefi.com/bug-bounty/chainlink/ | $3M | Immunefi |
| Wormhole | https://immunefi.com/bounty/wormhole/ | 20M W | Immunefi |
| Aave | https://immunefi.com/bug-bounty/aave/ | $1M | Immunefi |
| Uniswap v4 | https://blog.uniswap.org/v4-bug-bounty | $15.5M | Cantina |
| Uniswap zkSync | https://immunefi.com/bug-bounty/uniswaponzksync/ | $20K | Immunefi |
| Compound | https://immunefi.com/bug-bounty/compoundfinance/ | COMP | Immunefi |
| 1inch | https://hackenproof.com/programs/1inch-smart-contract | $500K | HackenProof |
| Safe/Kleidi | https://immunefi.com/bug-bounty/kleidi/ | $50K | Immunefi |
| Immutable | https://immunefi.com/bug-bounty/immutable/ | $1M | Immunefi |
| ZKsync | https://immunefi.com/bug-bounty/zksync/ | $20K | Immunefi |
| zkVerify | https://immunefi.com/bug-bounty/zkverify/ | $50K | Immunefi |
| Sky (MakerDAO) | https://immunefi.com/bug-bounty/sky/ | $10M | Immunefi |
| 0x Protocol | https://immunefi.com/bug-bounty/0x/ | $1M | Immunefi |
| XION | https://immunefi.com/bug-bounty/xion/ | $250K | Immunefi |
| Gnosis Chain | https://immunefi.com/bug-bounty/gnosischain/ | varies | Immunefi |
| CoW Protocol | https://immunefi.com/bounty/cowprotocol/ | varies | Immunefi |
