# Solidity & DeFi Security Knowledge Base

**Team Training Manual -- March 2026**
**Audience:** Cryptographic math experts transitioning to Solidity/DeFi security research

---

## Table of Contents

1. [Part 1: Top 50 Solidity Vulnerability Patterns](#part-1-top-50-solidity-vulnerability-patterns)
2. [Part 2: Biggest DeFi Hacks 2023-2026](#part-2-biggest-defi-hacks-2023-2026)
3. [Part 3: Bug Bounty Strategy](#part-3-bug-bounty-strategy-for-solidity)
4. [Part 4: Our Competitive Edge -- Crypto Math Meets Solidity](#part-4-our-competitive-edge--crypto-math-meets-solidity)

---

# Part 1: Top 50 Solidity Vulnerability Patterns

The following vulnerability catalog is derived from the OWASP Smart Contract Top 10 (2025 and 2026 editions), Immunefi incident data, SolidityScan's Web3HackHub (149 incidents in 2024), and DeFiHackLabs (150+ contract attacks in 2024 totaling $328M+). Access control vulnerabilities alone caused $953M in losses in 2024, while the combined 2024 on-chain exploit total exceeded $1.42 billion.

---

## Category 1: Reentrancy

### 1. Classic (Single-Function) Reentrancy

**Description:** An attacker calls back into the same function before the first invocation completes, exploiting the fact that state updates have not yet occurred. The canonical pattern is a withdraw function that sends ETH before zeroing the caller's balance.

**Real-world example:** The DAO hack (2016) -- $60M drained from TheDAO. The attacker's fallback function recursively called `withdraw()` before the balance was set to zero.

**Detection:** Look for external calls (`.call{value:}`, `.send()`, `.transfer()`) that occur BEFORE state variable updates. Static analyzers like Slither flag this with the `reentrancy-eth` detector.

**Pattern to audit:**
- Any function that sends ETH or tokens and then updates a mapping/balance
- Functions that violate the Checks-Effects-Interactions (CEI) pattern
- Missing `nonReentrant` modifier on functions that transfer value

### 2. Cross-Function Reentrancy

**Description:** The attacker re-enters a DIFFERENT function in the same contract that shares state with the originally called function. A reentrancy guard on function A does not protect function B if both read/write the same storage slot.

**Real-world example:** Lendf.Me / dForce (2020) -- $25M. The attacker used an ERC777 token hook to re-enter a different function (supply) during a withdraw, exploiting shared balance state.

**Detection:** Map all functions that share state variables. Check whether an external call in function A allows re-entry into function B while shared state is inconsistent.

**Pattern to audit:**
- Multiple public/external functions that read and write the same storage variable
- `nonReentrant` applied to only some functions sharing state
- Token transfers using ERC777 or tokens with transfer hooks

### 3. Cross-Contract Reentrancy

**Description:** Contract A calls Contract B, which calls back into Contract A through Contract C. Single-contract reentrancy guards are ineffective because the re-entry comes from a different contract address.

**Real-world example:** Curve Finance / Vyper reentrancy (July 2023) -- $70M+. A Vyper compiler bug caused reentrancy locks to malfunction across pool contracts, enabling cross-contract reentrancy on Curve pools.

**Detection:** Trace the full call graph across all contracts in the system. Look for callbacks, hooks, or any mechanism where an external contract can execute code during a state-changing operation.

**Pattern to audit:**
- Protocol systems with multiple interacting contracts sharing state via cross-contract reads
- Callback patterns (ERC777 `tokensReceived`, ERC721 `onERC721Received`, flash loan callbacks)
- Composable DeFi integrations where Protocol A reads Protocol B's state

### 4. Read-Only Reentrancy

**Description:** A view function returns stale data during an ongoing transaction because the state it reads has not yet been updated. An attacker exploits this by calling a third-party protocol that reads the stale view function mid-transaction.

**Real-world example:** Sentiment Protocol (2023) -- $1M. The attacker exploited a read-only reentrancy on Balancer's pool to get an inflated token price from a view function, using it to over-borrow on Sentiment.

**Detection:** Check all `view`/`pure` functions that are called by external protocols. If the data they return could be inconsistent during an external call within a state-changing function, the contract is vulnerable.

**Pattern to audit:**
- `getPrice()`, `getRate()`, `totalAssets()` view functions that external protocols depend on
- Composability risks: Does any external protocol use your view functions for pricing or collateral valuation?
- State-changing functions that make external calls before updating the values that view functions return

---

## Category 2: Flash Loan Attacks

### 5. Price Manipulation via Flash Loans

**Description:** An attacker borrows a massive amount of tokens via flash loan, uses them to skew a DEX spot price or AMM pool ratio, then exploits a protocol that reads that price as an oracle, and repays the loan -- all in a single transaction.

**Real-world example:** Sonne Finance (May 2024) -- $20M. Exploited a known Compound V2 fork vulnerability amplified by flash-loaned capital. Also Euler Finance (2023) -- $197M via flash-loan-powered manipulation of donate/liquidation mechanics.

**Detection:** Identify any on-chain price reads from AMM pools (`getReserves()`, `slot0()`, `balanceOf()` ratios). If the protocol uses spot prices without TWAP or multi-oracle validation, it is vulnerable.

**Pattern to audit:**
- `price = reserveA / reserveB` or similar spot price calculations
- Single-source oracles without staleness checks
- Functions callable within the same transaction as a large swap

### 6. Flash Loan Governance Attacks

**Description:** An attacker flash-loans governance tokens, votes on (or creates and passes) a malicious proposal, and repays -- all in one transaction. This bypasses the economic assumption that governance power requires long-term capital commitment.

**Real-world example:** Beanstalk (April 2022) -- $182M. Attacker flash-loaned tokens, gained supermajority voting power, passed a malicious proposal draining the treasury, and repaid the loan.

**Detection:** Check whether governance voting power is snapshot-based or based on current balances. If voting power is checked at the same block as the vote, flash loans can be used.

**Pattern to audit:**
- `balanceOf(msg.sender)` used directly in voting logic instead of historical snapshots
- Missing time-lock between token acquisition and voting eligibility
- Proposals that can be created and executed within the same block or without delay

### 7. Flash Loan Liquidation Manipulation

**Description:** An attacker uses flash loans to temporarily push a borrower's position into liquidation territory, liquidates them for a profit, then restores the price.

**Real-world example:** Abracadabra Finance (March 2025) -- $13M. Attacker used a flash-loan-assisted self-liquidation technique to drain approximately 6,260 ETH from lending markets.

**Detection:** Check if liquidation thresholds can be triggered by single-block price movements. Look for oracle dependencies on manipulable sources.

**Pattern to audit:**
- Liquidation functions that use spot prices rather than time-weighted prices
- Missing protections against self-liquidation or same-block liquidation
- Absence of circuit breakers for abnormal price movements

---

## Category 3: Oracle Manipulation

### 8. Spot Price Oracle Manipulation

**Description:** Protocols that use instantaneous DEX prices (spot prices) as oracles are vulnerable to manipulation because an attacker can temporarily shift the price with a large trade, exploit the protocol, and trade back.

**Real-world example:** Harvest Finance (2020) -- $34M. Attacker repeatedly manipulated Curve pool prices to exploit Harvest's USDC/USDT vault pricing.

**Detection:** Search for any price derived from `getReserves()`, `slot0()`, or `balanceOf` ratios on pool contracts. Any single-block price read from an AMM is suspect.

**Pattern to audit:**
- Direct calls to Uniswap V2 `getReserves()` or V3 `slot0()` for pricing
- Price calculation from `token.balanceOf(pool) / otherToken.balanceOf(pool)`

### 9. TWAP Oracle Manipulation

**Description:** Time-Weighted Average Prices are harder to manipulate but not immune. If the TWAP window is short (e.g., 1-5 blocks), an attacker with sufficient capital can sustain a manipulated price across multiple blocks.

**Real-world example:** Multiple smaller exploits on Uniswap V3 TWAP oracles with short observation windows. Protocols using 10-minute TWAPs have been exploited during low-liquidity periods.

**Detection:** Check the TWAP observation window length. Windows under 30 minutes are increasingly risky. Also check if the TWAP is calculated over a single pool with low liquidity.

**Pattern to audit:**
- `observe()` or `consult()` calls with short time windows
- TWAP over a single low-liquidity pool
- Missing liquidity depth checks alongside price checks

### 10. Chainlink Stale Data / Heartbeat Issues

**Description:** Chainlink oracles have heartbeat intervals and deviation thresholds. If a protocol does not check the `updatedAt` timestamp from `latestRoundData()`, it may use stale prices during network congestion or oracle downtime.

**Real-world example:** Multiple lending protocols have been reported vulnerable on L2s where Chainlink sequencer uptime feeds were not checked, enabling stale-price exploits during sequencer outages.

**Detection:** Check every `latestRoundData()` call. The `updatedAt` and `answeredInRound` fields must be validated. On L2s, the sequencer uptime feed must be checked.

**Pattern to audit:**
- `latestRoundData()` called without checking `updatedAt > block.timestamp - heartbeat`
- Missing `answeredInRound >= roundId` check
- Missing L2 sequencer uptime feed validation
- No fallback oracle if Chainlink is down

### 11. Oracle Decimal Mismatch

**Description:** Different Chainlink feeds return prices with different decimal precision (8 vs 18 decimals). Mixing feeds without normalization causes catastrophic pricing errors.

**Detection:** Check all oracle feed decimal handling. Verify `decimals()` is called and used for normalization.

---

## Category 4: Access Control

### 12. Missing Access Control on Critical Functions

**Description:** Sensitive functions like `mint()`, `burn()`, `setOracle()`, `pause()`, or `upgradeTo()` lack proper access modifiers, allowing any address to call them. This was the #1 vulnerability category in 2024, causing $953M in losses.

**Real-world example:** UPCX (April 2025) -- $70M. Malicious smart contract update attributed to compromised access, enabling the attacker to drain funds. Munchables (March 2024) -- $62.5M. A rogue developer exploited an upgradeable proxy with deployment address control.

**Detection:** Enumerate all `external`/`public` functions. Verify every state-changing function has appropriate access control (`onlyOwner`, `onlyRole`, `onlyAdmin`).

**Pattern to audit:**
- `external` or `public` functions without `onlyOwner` / access control modifiers
- `initialize()` functions callable by anyone (see #15)
- Admin functions that accept arbitrary addresses for privileged roles

### 13. Role Confusion and Privilege Escalation

**Description:** Complex role-based access control systems (e.g., OpenZeppelin's AccessControl) can have misconfigured role hierarchies, where a lower-privileged role can grant itself higher privileges.

**Detection:** Trace the role hierarchy. Verify who can call `grantRole()`, `revokeRole()`, and whether `DEFAULT_ADMIN_ROLE` is properly secured.

**Pattern to audit:**
- `AccessControl` contracts where multiple roles can call `grantRole`
- Missing `onlyRole(ADMIN)` on `grantRole` calls
- `renounceRole` not implemented or not used for initial deployer privileges

### 14. Centralization Risks / Admin Key Compromise

**Description:** Single-owner or multi-sig contracts where compromise of the owner key allows full protocol takeover. This is the #1 off-chain attack vector, responsible for 43.8% of stolen crypto in 2024.

**Real-world example:** Radiant Capital (2024) -- $53M. Attacker used malware to collect legitimate multi-sig signatures on malicious transactions. Bybit (Feb 2025) -- $1.4B. Supply chain attack on signing infrastructure.

**Detection:** Check ownership model. Is it a single EOA? A multi-sig? A timelock? What's the threshold?

### 15. Unprotected Initializer Functions

**Description:** Upgradeable proxy contracts use `initialize()` instead of constructors. If `initialize()` can be called by anyone after deployment, or called again after initialization, an attacker can take ownership.

**Real-world example:** Multiple proxy contracts have been exploited by calling `initialize()` on the implementation contract directly (not through the proxy), taking ownership of the implementation.

**Detection:** Check that `initializer` modifier (OpenZeppelin) is used, that `_disableInitializers()` is called in the implementation constructor, and that `initialize()` has access control.

**Pattern to audit:**
- `initialize()` without `initializer` modifier
- Implementation contract constructor missing `_disableInitializers()`
- `reinitializer` used without proper version tracking

---

## Category 5: Integer Overflow / Underflow

### 16. Pre-Solidity 0.8 Overflow/Underflow

**Description:** Before Solidity 0.8, arithmetic operations silently wrapped around. `uint256(0) - 1` would yield `2^256 - 1` instead of reverting.

**Real-world example:** Beauty Chain (BEC) token (2018) -- $900M market cap destroyed. A `batchTransfer` function had an unchecked multiplication overflow allowing infinite token minting.

**Detection:** Check the Solidity version. If < 0.8.0, every arithmetic operation is suspect. Look for missing SafeMath usage.

### 17. Post-Solidity 0.8 `unchecked` Block Vulnerabilities

**Description:** Solidity 0.8+ reverts on overflow by default, BUT developers can use `unchecked {}` blocks for gas optimization. If the math inside `unchecked` is incorrect, overflows silently occur.

**Real-world example:** Cetus Protocol (May 2025) -- $223M. A missed overflow check in the protocol's concentrated liquidity math allowed an attacker to manipulate liquidity calculations. This is the single most expensive pure arithmetic vulnerability in DeFi history.

**Detection:** Search for all `unchecked {}` blocks. Verify that every arithmetic operation inside them has been formally proven to be safe, or has explicit bounds checks before the unchecked block.

**Pattern to audit:**
- `unchecked { ... }` blocks containing user-influenced arithmetic
- Custom math libraries that use `unchecked` for gas optimization
- Casting between different integer sizes (`uint256` to `uint128`, etc.) inside or outside unchecked blocks

### 18. Unsafe Casting / Type Truncation

**Description:** Casting a `uint256` to a `uint128` or smaller type silently truncates the value in Solidity < 0.8. Even in 0.8+, explicit casts like `uint128(x)` do NOT revert on overflow -- they silently truncate.

**Detection:** Search for all explicit type casts. Verify bounds checks exist.

**Pattern to audit:**
- `uint128(someUint256)` without prior range validation
- `int256` to `uint256` casts (sign issues)
- Downcasting in price or liquidity calculations

---

## Category 6: Delegatecall Vulnerabilities

### 19. Storage Collision in Proxy Patterns

**Description:** In proxy patterns, `delegatecall` executes the implementation's code using the proxy's storage. If the storage layouts don't align (e.g., the proxy has a variable in slot 0 that the implementation doesn't expect), variables are read/written incorrectly, potentially allowing ownership hijack.

**Real-world example:** Audius Protocol (2022) -- $6M. Storage collision in proxy allowed attacker to overwrite governance configuration. Parity Wallet (2017) -- $30M (initial hack). `delegatecall` to library allowed re-initialization and ownership takeover.

**Detection:** Compare storage layouts between proxy and implementation contracts. Use `slither-check-upgradeability` to detect storage collisions automatically.

**Pattern to audit:**
- Proxy and implementation contracts with mismatched storage variable ordering
- Upgrades that add new storage variables in the middle of existing layouts (must always append)
- Missing OpenZeppelin storage gap (`__gap`) in base contracts

### 20. Function Selector Collision in Proxies

**Description:** The proxy's admin functions and the implementation's user functions share the same 4-byte selector space. A collision means a user calling a function on the implementation actually triggers the proxy's admin function (or vice versa).

**Detection:** Use `solc --hashes` or Slither's Function ID printer to compare selectors between proxy and implementation.

### 21. Unprotected `delegatecall` to User-Supplied Address

**Description:** If a contract uses `delegatecall` to an address provided by a user or derived from user input, the attacker can execute arbitrary code in the context of the calling contract, reading and writing its storage.

**Real-world example:** Parity Multi-Sig Wallet Kill (Nov 2017) -- $150M frozen. A user called `delegatecall` on the library contract, re-initialized it, became the owner, then called `selfdestruct`, freezing all dependent wallets.

**Pattern to audit:**
- `delegatecall` where the target address is not hardcoded or strictly validated
- Missing whitelist checks on delegatecall targets

---

## Category 7: Front-Running / Sandwich Attacks

### 22. DEX Sandwich Attacks

**Description:** An MEV bot sees a pending swap in the mempool, places a buy order before it (front-run) and a sell order after it (back-run), profiting from the price impact of the victim's trade.

**Scale:** Sandwich attacks account for 51% of all MEV volume in 2025, with over $1.2 billion extracted through MEV and front-running on Ethereum alone.

**Detection:** Check if user-facing swap functions enforce slippage parameters. Look for missing `amountOutMin` / `deadline` parameters.

**Pattern to audit:**
- Swap functions without user-configurable slippage protection
- Missing `deadline` parameter on DEX interactions
- Hardcoded slippage tolerance (especially 0% or 100%)

### 23. Transaction Ordering Dependence (Front-Running)

**Description:** Any transaction whose outcome depends on its position in a block is vulnerable. This includes auctions, NFT mints, reward claims, and oracle updates.

**Detection:** Ask: "Does knowing the content of this transaction give someone an advantage?" If yes, it is front-runnable.

**Pattern to audit:**
- Commit-reveal schemes with insufficient commitment hiding
- First-come-first-served reward distributions
- Approval transactions followed by transferFrom (see #33)

---

## Category 8: Signature Vulnerabilities

### 24. Signature Replay (Same Chain)

**Description:** If a signed message lacks a nonce or the nonce is not properly invalidated, an attacker can resubmit the same signature to execute the action multiple times.

**Detection:** Check that every signature-consuming function includes and validates a nonce, and that the nonce is incremented/invalidated after use.

**Pattern to audit:**
- `ecrecover` usage without nonce in the signed payload
- Nonce stored but not incremented after signature consumption
- Missing EIP-712 domain separator

### 25. Cross-Chain Signature Replay

**Description:** A signature valid on chain A is replayed on chain B where the same contract is deployed. Without `chainId` in the signed data, all cross-chain deployments are vulnerable.

**Detection:** Verify that `chainId` is included in the EIP-712 domain separator and validated at runtime.

### 26. Signature Malleability

**Description:** ECDSA signatures have a malleability property: given a valid signature `(r, s, v)`, a second valid signature `(r, n-s, v')` exists for the same message. If signatures are used as unique identifiers (e.g., in mappings), the same authorization can be used twice with different byte representations.

**Detection:** Check that signature validation uses OpenZeppelin's ECDSA library, which enforces `s` to be in the lower half of the curve order, preventing malleability.

**Pattern to audit:**
- Raw `ecrecover` without `s`-value range check
- Signatures used as mapping keys or unique identifiers
- EIP-2098 compact signature handling without malleability protection

### 27. `ecrecover` Returns `address(0)`

**Description:** If `ecrecover` receives an invalid signature, it returns `address(0)` instead of reverting. If the result is not checked against `address(0)`, an attacker can forge signatures for the zero address.

**Pattern to audit:**
- `ecrecover` result not checked for `!= address(0)`
- Using raw `ecrecover` instead of OpenZeppelin's `ECDSA.recover` (which reverts on invalid signatures)

---

## Category 9: ERC20 / Token Standard Issues

### 28. ERC20 Approval Race Condition

**Description:** When changing an allowance from N to M, the spender can front-run and spend N, then spend the new M allowance, extracting N+M total.

**Detection:** Check if the protocol uses `approve()` to change non-zero allowances. Use `increaseAllowance()`/`decreaseAllowance()` or approve-to-zero-first patterns.

### 29. Fee-on-Transfer Token Handling

**Description:** Some ERC20 tokens (like USDT on certain chains) deduct a fee on transfer. If a contract assumes `balanceAfter - balanceBefore == amountTransferred`, the accounting is wrong.

**Detection:** Check if the contract uses `transferFrom` amounts directly without verifying actual received amounts via balance differentials.

**Pattern to audit:**
- `transferFrom(user, address(this), amount)` followed by crediting `amount` to internal accounting
- Missing `balanceOf(address(this))` before/after comparison

### 30. ERC777 Token Hooks (Transfer Callbacks)

**Description:** ERC777 tokens invoke `tokensReceived` hooks on the recipient and `tokensToSend` hooks on the sender during transfers. These callbacks enable reentrancy in any contract that transfers ERC777 tokens.

**Real-world example:** imBTC on Uniswap (2020) -- $300K. ERC777 `tokensToSend` hook enabled reentrancy during a Uniswap swap.

**Pattern to audit:**
- Contracts that handle arbitrary ERC20 tokens without considering ERC777 hooks
- Missing reentrancy guards on functions that transfer tokens

### 31. Rebasing Token Handling

**Description:** Rebasing tokens (like stETH, AMPL) change balances automatically. Contracts that cache `balanceOf` values or use them in share calculations without accounting for rebases produce incorrect results.

### 32. Non-Standard Return Values

**Description:** Some ERC20 tokens (notably USDT on Ethereum) do not return a `bool` on `transfer`/`approve`. Calling these through the standard interface causes a revert in Solidity 0.8+ due to ABI decoding failure.

**Detection:** Check if the contract uses `IERC20.transfer()` or `IERC20.approve()` directly. Use OpenZeppelin's `SafeERC20` (`safeTransfer`, `safeApprove`) which handles non-standard returns.

---

## Category 10: Unchecked Return Values

### 33. Unchecked Low-Level Call Return

**Description:** Low-level calls (`.call()`, `.send()`) return a boolean success flag. If it is not checked, a failed transfer silently continues execution, leading to loss of funds or inconsistent state.

**Detection:** Search for `.call{value:}` and `.send()`. Verify the return value is checked. Prefer `.transfer()` or higher-level patterns.

**Pattern to audit:**
- `(bool success, ) = addr.call{value: amount}(""); ` without `require(success)`
- `payable(addr).send(amount)` without checking the return bool

### 34. Unchecked ERC20 Transfer Return

**Description:** Identical to #32 but from the caller's perspective. If `transfer()` returns `false` instead of reverting (some tokens do this), and the return value is unchecked, the contract believes the transfer succeeded.

---

## Category 11: Denial of Service

### 35. DOS via Unbounded Loops / Gas Limit

**Description:** Functions that iterate over arrays of unbounded size can exceed the block gas limit, making the function permanently uncallable. This is especially dangerous for withdrawal or distribution functions.

**Real-world example:** GovernMental Ponzi (2016). The payout loop exceeded block gas limit, locking 1,100 ETH permanently.

**Pattern to audit:**
- `for` loops iterating over dynamic arrays (especially user-growable arrays)
- Batch operations (airdrops, distributions) without pagination
- Functions processing all stakers/depositors in a single call

### 36. DOS via Unexpected Revert

**Description:** If a contract sends ETH to a list of recipients and one of them is a contract that reverts on receive, the entire transaction fails, blocking all other recipients.

**Detection:** Look for loops that send ETH or tokens where a single failure reverts the whole operation. Use a pull-over-push pattern.

### 37. Block Stuffing

**Description:** An attacker fills blocks with high-gas transactions to prevent others from interacting with a contract during a critical time window (e.g., an auction ending, an oracle update, a governance vote deadline).

---

## Category 12: Forced ETH via Selfdestruct

### 38. Forced ETH Breaking Contract Logic

**Description:** ETH can be forcibly sent to any contract via `selfdestruct` (pre-Cancun) or mining rewards. Contracts that use `address(this).balance` for logic (e.g., game mechanics, threshold triggers) can be broken.

**Note:** Post-Cancun (EIP-6780), `selfdestruct` no longer destroys code except when called in the same transaction as contract creation. However, it STILL transfers ETH to the target. Forced ETH via mining/coinbase also still works.

**Pattern to audit:**
- `require(address(this).balance == expectedAmount)` (strict equality checks on balance)
- Game/lottery logic dependent on exact ETH balance
- Use self-tracked accounting variables instead of `address(this).balance`

---

## Category 13: tx.origin Authentication

### 39. tx.origin Phishing

**Description:** `tx.origin` returns the original external account that initiated the transaction chain, not the immediate caller. If used for authentication, a malicious intermediary contract can trick a user into calling it, then call the target contract -- and `tx.origin` will be the victim's address.

**Detection:** Search for `tx.origin` in any `require` or `if` statement. It should almost never be used for authentication. The only legitimate use is `require(tx.origin == msg.sender)` to prevent contract callers.

---

## Category 14: Uninitialized Storage / Proxy Issues

### 40. Uninitialized Local Storage Pointers (Pre-0.5.0)

**Description:** Before Solidity 0.5.0, local variables of struct/array type defaulted to storage. An uninitialized local struct would point to storage slot 0, allowing accidental overwriting of critical state variables.

### 41. Uninitialized Proxy Implementation

**Description:** The implementation contract behind a proxy is deployed but never initialized (because initialization happens through the proxy). An attacker can call `initialize()` directly on the implementation, becoming its owner, and potentially using it to influence the proxy.

**Real-world example:** Wormhole's uninitialized implementation allowed an attacker to take control, leading to the $320M exploit (2022).

---

## Category 15: DeFi Math / Precision Errors

### 42. Rounding Errors in Share/Asset Calculations

**Description:** Integer division in Solidity always rounds toward zero. In vault/staking/lending protocols, this creates rounding errors that can be exploited, especially at extreme ratios (very large deposits, very small shares, or vice versa).

**Real-world example:** Balancer V2 (2025) -- $128M. Precision rounding errors combined with invariant manipulation drained liquidity pools across Ethereum, Base, and Polygon.

**Detection:** Check all division operations in exchange-rate, share-minting, and fee calculations. Look for division before multiplication (amplifies rounding error).

**Pattern to audit:**
- `shares = amount * totalSupply / totalAssets` without rounding protection
- Division before multiplication: `(a / b) * c` instead of `(a * c) / b`
- Missing minimum amount checks allowing dust-amount exploitation

### 43. Vault Share Inflation (First Depositor Attack)

**Description:** The first depositor in an ERC4626 vault deposits 1 wei, receives 1 share, then donates a large amount directly to the vault. This inflates the share price so that subsequent depositors' deposits round down to 0 shares, and the attacker claims all deposited assets.

**Real-world example:** sDOLA Llamalend exploit (March 2026) proved this attack class remains live. Multiple Code4rena findings in 2024 on Karak and other protocols.

**Detection:** Check ERC4626 vaults for virtual share/offset protection. If `_decimalsOffset()` returns 0 (the OpenZeppelin default), the vault is unprotected.

**Pattern to audit:**
- ERC4626 vaults without virtual shares (OpenZeppelin's `_decimalsOffset()` override)
- Missing minimum initial deposit requirements
- Share calculation using `totalAssets()` that includes direct-transfer donations

---

## Category 16: Governance Attacks

### 44. Flash Loan Governance (covered in #6)

### 45. Timelock Bypass / Inadequate Delays

**Description:** Governance timelocks that are too short or have bypass mechanisms allow attackers to push through malicious proposals before the community can react.

**Pattern to audit:**
- Timelock delays under 24 hours
- Emergency execution paths with insufficient safeguards
- Guardian/admin roles that can bypass the timelock

---

## Category 17: Cross-Chain Replay

### 46. Cross-Chain Message Replay

**Description:** Messages or transactions valid on one chain are replayed on another. After chain forks (ETH/ETC, post-merge), or across L1/L2 deployments, transactions without proper chain identification can be replayed.

**Detection:** Verify that all signed messages include `chainId`. For cross-chain protocols, verify replay protection through nonces and chain-specific identifiers.

---

## Category 18: Token Standard Violations

### 47. Non-Compliant ERC20 Implementations

**Description:** Tokens that deviate from the ERC20 standard in subtle ways: returning `false` instead of reverting, not returning anything, having fee-on-transfer, or implementing blocklists. Protocols that assume standard behavior break with these tokens.

**Pattern to audit:**
- Hard-coding token behavior assumptions without SafeERC20
- Missing support for tokens with blocklists (USDC, USDT)
- Assuming `decimals() == 18`

---

## Category 19: Vault / First Depositor (covered in #43)

### 48. Donation Attack on Vaults (Beyond First Depositor)

**Description:** Even after the first deposit, direct token donations to a vault can manipulate the share-to-asset ratio, causing future depositors to receive fewer shares than expected.

---

## Category 20: Liquidation Manipulation

### 49. Oracle-Dependent Liquidation Exploitation

**Description:** Liquidation bots or attackers manipulate oracle prices (or exploit stale oracles) to push healthy positions into liquidatable territory, then liquidate them at a profit.

### 50. Self-Liquidation Exploits

**Description:** A user creates a position, then manipulates the price (via flash loan or oracle manipulation) to liquidate their own position, extracting liquidation bonuses or protocol reserves.

**Real-world example:** Abracadabra Finance (March 2025) -- $13M via flash-loan-assisted self-liquidation.

**Pattern to audit:**
- Missing checks preventing self-liquidation (liquidator == borrower)
- Liquidation bonuses that exceed the cost of manipulation
- Liquidation functions that use manipulable price sources

---

# Part 2: Biggest DeFi Hacks 2023-2026

The total stolen in crypto by year: 2023 -- $2B, 2024 -- $2.2B (303 incidents), 2025 -- $2.7B-$3.4B (record year). North Korea's Lazarus Group alone stole $2.02B in 2025.

## The Top 20 Hacks

| # | Protocol | Date | Amount | Root Cause | Auditable? |
|---|----------|------|--------|------------|------------|
| 1 | **Bybit** | Feb 2025 | $1.4B | Supply chain attack on signing infrastructure (Lazarus Group). Attackers compromised the project's signing pipeline, tricking multi-sig signers into approving malicious transactions transferring 401K ETH. | No -- off-chain supply chain attack. Operational security failure, not a smart contract bug. |
| 2 | **Mixin Network** | Sep 2023 | $200M | Cloud service provider database compromise leading to private key theft. | No -- infrastructure attack, not contract-level. |
| 3 | **Euler Finance** | Mar 2023 | $197M | Logic flaw in donate/liquidation mechanics exploited via flash loan. Attacker created an over-leveraged position then donated collateral, causing bad debt the protocol could not recover. | Yes -- logic flaw in core protocol math. Formal verification or invariant testing could have caught it. |
| 4 | **DMM Bitcoin** | May 2024 | $305M | Private key compromise via social engineering on custody partner Ginco executive (Lazarus Group). | No -- social engineering / operational security failure. |
| 5 | **PlayDapp** | Feb 2024 | $290M | Smart contract vulnerability in the blockchain gaming platform. | Partially -- contract-level vulnerability. |
| 6 | **WazirX** | Jul 2024 | $235M | Centralized exchange hot wallet compromise. | No -- operational security failure. |
| 7 | **Cetus Protocol** | May 2025 | $223M | Mathematical overflow error in concentrated liquidity calculations. Missed overflow check allowed manipulation of tick/liquidity math. $162M frozen by Sui validators. | Yes -- this is precisely the kind of bug that formal verification or property-based fuzzing catches. Teams with strong math backgrounds should excel at finding these. |
| 8 | **Balancer V2** | 2025 | $128M | Precision rounding errors combined with invariant manipulation. Attacker exploited numerical edge cases in Balancer's weighted math across Ethereum, Base, and Polygon. | Yes -- mathematical invariant violation. Formal verification of the weighted math invariants would have caught this. |
| 9 | **Nobitex** | Jun 2025 | $90M | Politically-motivated attack (Predatory Sparrow group), likely via compromised private keys on Iran's largest exchange. | No -- targeted state-actor attack on infrastructure. |
| 10 | **Phemex** | Jan 2025 | $73-85M | Hot wallet compromise across 16 blockchains. Likely compromised private keys. | No -- operational security failure. |
| 11 | **UPCX** | Apr 2025 | $70M | Malicious smart contract update via compromised private key. | Partially -- the upgrade itself could have been caught by monitoring, but the key compromise was off-chain. |
| 12 | **Curve Finance** | Jul 2023 | $70M+ | Vyper compiler reentrancy lock bug. Compiler generated incorrect reentrancy protection, enabling cross-contract reentrancy on Curve pools. | Yes, but at the compiler level -- auditing the Solidity/Vyper contract would not have revealed the compiler-generated bug. |
| 13 | **Munchables** | Mar 2024 | $62.5M | Rogue insider developer exploited upgradeable proxy with deployment address control, assigning themselves a 1M balance. | Partially -- privileged deployment access is detectable, but requires operational trust auditing. |
| 14 | **Multichain** | Jul 2023 | $126M | CEO's private key compromise. Centralized control of cross-chain bridge keys. | No -- centralization risk / key management failure. |
| 15 | **BtcTurk** | Jun 2024 | $55M | Hot wallet private key compromise on Turkish exchange. | No -- operational security failure. |
| 16 | **Radiant Capital** | Oct 2024 | $53M | Malware collected legitimate multi-sig signatures on malicious transactions, hijacking Pool Provider contract. | No -- sophisticated malware-based attack on signers' machines. |
| 17 | **Abracadabra** | Mar 2025 | $13M | Flash-loan-assisted self-liquidation in lending markets. | Yes -- liquidation logic flaw detectable by invariant testing. |
| 18 | **Cork Protocol** | May 2025 | $12M | Exploited beforeSwap hook logic flaws and missing access controls. | Yes -- logic error and access control. Standard audit finding. |
| 19 | **Sonne Finance** | May 2024 | $20M | Known Compound V2 fork vulnerability exploited via flash loan. | Yes -- the vulnerability was publicly known. The team did not apply the known mitigation. |
| 20 | **KyberSwap** | Nov 2023 | $48M | Precision/tick-boundary exploit in concentrated liquidity implementation. | Yes -- mathematical edge case in AMM math. |

### Key Insight for Our Team

Of the top 20 hacks, approximately 8-9 were on-chain smart contract vulnerabilities that could potentially have been found in an audit. The highest-value purely contract-level exploits (Cetus $223M, Balancer $128M, Euler $197M) were all **mathematical/logic errors** -- exactly the kind of bugs that a team with strong cryptographic math skills is positioned to find. The majority of the largest hacks by dollar amount (Bybit, DMM, WazirX, Phemex, Nobitex) were off-chain key compromises, not auditable smart contract bugs.

---

# Part 3: Bug Bounty Strategy for Solidity

## Vulnerability Types Most Likely in Production

Based on 2024-2025 data, the vulnerability classes most commonly found in deployed contracts:

1. **Logic errors** (50 incidents in 2024, most common on-chain root cause) -- business logic flaws, incorrect state machine transitions, edge cases in DeFi math
2. **Access control flaws** ($953M in losses, #1 by dollar value) -- missing modifiers, improper role management
3. **Input validation failures** (34.6% of on-chain exploits in 2024) -- unchecked parameters, missing bounds
4. **Price oracle manipulation** (18 incidents in 2024) -- spot price dependence, stale data
5. **Arithmetic/precision errors** -- rounding, overflow in unchecked blocks, unsafe casting
6. **Reentrancy** ($35.7M in 2024) -- declining but cross-contract and read-only variants still dangerous
7. **Vault share inflation** -- continues to appear in 2025-2026, including the sDOLA exploit

## Highest-Paying Bounty Categories

- **Cross-chain bridge vulnerabilities**: Wormhole paid $10M for a single bug. Bridge bugs involve signature verification, message validation, and replay protection -- highly relevant to our cryptographic expertise.
- **Core DeFi protocol logic**: Aurora paid $6M, multiple $1M+ payouts for lending/borrowing logic flaws.
- **Critical access control / fund drainage**: Typical critical bounty payouts range $50K-$1M on major protocols.
- **Smart contract bugs account for 77.5% of Immunefi's total $100M+ in payouts** ($78M), making them the dominant bounty category.

## Tools of Top Bounty Hunters

### Static Analysis
- **Slither** (Trail of Bits): 93 detectors, fast triage of known vulnerability patterns. Run first on any codebase to catch low-hanging fruit. Install: `pip3 install slither-analyzer`
- **Aderyn** (Cyfrin, 2024): Rust-based, faster than Slither on large codebases, catches Solidity-specific patterns
- **Semgrep**: Custom rule-based pattern matching across Solidity codebases

### Fuzzing
- **Foundry (forge fuzz)**: Industry standard. Tests written in Solidity. Best for comprehensive pre-deployment testing and finding edge cases in complex DeFi protocols. The 2026 benchmark shows Foundry replacing Echidna in most workflows.
- **Echidna** (Trail of Bits): Property-based fuzzing. Excels at finding invariant violations. Version 2.3.0 adds symbolic execution and Foundry test case generation for reproducers.
- **Medusa**: Similar to Echidna, growing adoption. Good Foundry integration.
- **Recon**: Cloud platform integrating Echidna, Medusa, and Foundry for parallel fuzzing with zero setup.

### Formal Verification
- **Certora Prover**: CVL-based formal verification, used by Aave and Compound. Proves mathematical properties hold for ALL inputs. Highest assurance level.
- **Halmos**: Symbolic execution tool for Foundry tests. Converts fuzz tests into formally verified properties.

### Research Resources
- **Solodit**: Aggregates 15,000+ security vulnerabilities and bug bounty findings from audit firms and researchers
- **DeFiHackLabs**: Repository of real-world DeFi exploit reproductions in Foundry
- **Immunefi bug bounty listings**: 330+ active programs, critical bounties from $10K to $10M+

## The $100K+ Bounty Hunter Workflow

Based on aggregated advice from top Immunefi researchers:

**Phase 1: Target Selection (1-2 hours)**
- Choose protocols with high TVL and high bounty caps ($500K+)
- Prefer protocols with recent deployments or upgrades (new code = more bugs)
- Focus on areas matching your expertise (for our team: math-heavy DeFi -- AMMs, lending, vaults)

**Phase 2: Architecture Understanding (2-4 hours)**
- Read the documentation and whitepaper
- Map the contract system: who calls what, what state is shared
- Understand the economic model: where does money flow, what are the invariants?

**Phase 3: Static Analysis Triage (1-2 hours)**
- Run Slither/Aderyn on the full codebase
- Triage findings: dismiss false positives, investigate real issues
- Use this to build a mental map of risky areas

**Phase 4: Manual Deep Audit (days/weeks)**
- Focus on the highest-value code paths (deposit, withdraw, liquidate, swap)
- Manually verify all mathematical invariants
- Check every external interaction for reentrancy, oracle manipulation, access control
- Question every assumption the code makes

**Phase 5: Exploit Development (hours/days)**
- Write a Proof of Concept in Foundry
- Fork mainnet state to test against real deployment
- Quantify the impact (how much can be stolen/drained)

**Phase 6: Report Submission**
- Write a clear report: vulnerability description, step-by-step reproduction, impact, recommended fix
- Accurate severity rating (over-inflating severity gets reports rejected)
- Include working PoC code

**Critical Success Factors:**
- Quality over quantity -- one well-researched critical finding beats twenty speculative reports
- If you cannot write a working PoC, you probably do not have a real bug
- Expect 3+ months of learning before first payout
- AI-generated reports are banned and result in instant platform bans

---

# Part 4: Our Competitive Edge -- Crypto Math Meets Solidity

As a team with deep cryptographic math expertise, we have significant advantages in several high-value areas that are under-served by most security researchers. The most expensive smart contract bugs in 2024-2025 were mathematical: Cetus ($223M, overflow), Balancer ($128M, precision/invariant), Euler ($197M, logic in liquidation math). Math bugs are where the biggest bounties live.

## Area 1: ZK Circuit Verification On-Chain

### Groth16 Verifiers in Solidity

Groth16 is the most gas-efficient ZK-SNARK for on-chain verification (~230K gas). Protocols like zkBridge implement Solidity contracts that verify Groth16 proofs and maintain block header lists.

**Security considerations we can audit:**
- **Trusted setup integrity**: Groth16 requires a per-circuit trusted setup. If the toxic waste is not properly destroyed, proofs can be forged.
- **Pairing check correctness**: The on-chain verifier performs elliptic curve pairings (using EVM precompiles at addresses 0x06, 0x07, 0x08 for BN254). Incorrect handling of point validation, subgroup checks, or field arithmetic allows proof forgery.
- **Fiat-Shamir transformation bugs**: Trail of Bits has disclosed critical soundness-breaking vulnerabilities in multiple ZK implementations caused by insecure Fiat-Shamir implementations. This is a high-value audit target where our math skills directly apply.
- **Circuit-specific verification**: Does the Solidity verifier correctly check all public inputs? Are the verification key parameters correctly encoded?

### PLONK Verifiers

PLONK uses a universal trusted setup (one setup for all circuits up to a size limit). SnarkJS generates PLONK proofs and Solidity verifier contracts. Noir/Barretenberg also generates PLONK proofs with Solidity output.

**Security considerations:**
- Universal SRS reuse across protocols -- a compromise affects all dependent contracts
- Verifier contract correctness: do the polynomial commitment checks match the circuit constraints?
- Gas costs are higher than Groth16 (~300K-500K gas) -- gas limit interactions in complex transactions

## Area 2: Bridge Signature Verification

Cross-chain bridges are the highest-bounty targets. Wormhole's $10M bounty was for a signature verification vulnerability. Bridge security is fundamentally a cryptographic verification problem.

**What to audit:**
- **Multi-sig verification**: Are all signatures validated? Is the threshold enforced correctly? Can signatures be replayed across chains?
- **Guardian set rotation**: When the set of valid signers changes, can old signatures be used with the new set? Is there a proper transition period?
- **Message encoding**: Is the signed message structure unambiguous? Can different messages produce the same hash (hash collision via structure ambiguity)?
- **Chain ID binding**: Are messages bound to source and destination chains?
- **Merkle proof verification**: Many bridges use Merkle proofs for state verification. Check tree construction, leaf encoding, and second-preimage resistance.

## Area 3: Oracle Cryptography

### Chainlink VRF (Verifiable Random Functions)

VRF combines block data with the oracle's pre-committed private key to produce verifiable randomness. On-chain verification ensures the oracle cannot manipulate results.

**Our audit edge:**
- Verify the VRF proof verification math in consumer contracts
- Check for integration vulnerabilities: accepting inputs after randomness request, missing confirmation time tuning, callback gas griefing
- Audit custom VRF implementations (non-Chainlink) for correct discrete-log proof verification

### Threshold Signatures

Threshold signature schemes (TSS) allow N-of-M signing without any single party holding the full key. Used in bridges, MPC wallets, and cross-chain protocols.

**What to audit:**
- Distributed Key Generation (DKG) implementation correctness
- Threshold enforcement: can fewer than T parties produce a valid signature?
- Key resharing and rotation: does the new key set properly invalidate old shares?
- On-chain verification of threshold signatures: are aggregated signatures correctly validated against the group public key?

## Area 4: Custom EVM Precompiles

EVM precompiles at specific addresses provide gas-efficient cryptographic operations: ecRecover (0x01), SHA256 (0x02), RIPEMD160 (0x03), bn128Add (0x06), bn128Mul (0x07), bn128Pairing (0x08), blake2f (0x09).

**Our audit edge:**
- L2s and app-chains often add custom precompiles for BLS12-381, KZG, or other curves
- Verify that custom precompile implementations match the mathematical specification
- Check gas costs: are they set correctly to prevent DOS? Underpriced precompiles enable gas-based attacks.
- Point validation: do precompiles check that input points are on the correct curve and in the correct subgroup?

## Area 5: Cross-Chain Message Verification

Cross-chain messaging protocols (LayerZero, Axelar, Hyperlane) rely on various cryptographic verification methods.

**What to audit:**
- Light client verification: is the header chain validation correct? Are difficulty/stake checks accurate?
- Merkle-Patricia trie proof verification for storage/receipt proofs
- ZK-based cross-chain verification (zkBridge pattern): verify the ZK circuit correctly encodes the consensus rules
- Replay protection across chains and within the same chain (nonce management)
- Message encoding: check for ABI encoding ambiguity that could allow message forgery

## Area 6: Account Abstraction (EIP-4337) Signature Validation

ERC-4337 enables custom signature validation in smart contract wallets. The `validateUserOp` function can implement any signature scheme: ECDSA, BLS, Schnorr, passkeys (WebAuthn/P-256), or ZK proofs.

**Our audit edge:**
- **Custom signature scheme implementation**: Many AA wallets implement novel signature schemes. Our cryptographic expertise allows us to verify mathematical correctness.
- **P-256/secp256r1 verification**: WebAuthn/passkey wallets implement P-256 in Solidity (no native precompile on Ethereum mainnet). These implementations must be audited for correctness and side-channel resistance.
- **BLS signature aggregation**: Bundlers can aggregate BLS signatures across UserOps. Verify aggregation correctness and rogue-key attack protection.
- **Paymaster signature validation**: Paymasters often use signed approvals. Check for replay, expiry, and malleability.
- **Counterfactual wallet security**: The generated wallet address must depend on the initial signature/credentials. If not, an attacker can front-run wallet creation with different credentials.
- **Assembly-level revert manipulation**: Paymasters can use assembly to create un-parseable responses causing reverts that bypass Solidity's try/catch, a known vulnerability found by OpenZeppelin.

---

## Recommended Learning Path

### Month 1: Foundations
- Complete the Damn Vulnerable DeFi challenges (all levels)
- Study the Ethernaut CTF challenges
- Read every Solidity vulnerability in SunWeb3Sec/DeFiVulnLabs (Foundry-based examples)
- Set up local environment: Foundry, Slither, a fork of Ethereum mainnet

### Month 2: Protocol Deep Dives
- Study Uniswap V3 concentrated liquidity math (our math background makes this accessible)
- Study Aave V3 / Compound V3 lending math (liquidation thresholds, health factors, interest rate models)
- Study ERC4626 vault mechanics and share calculation edge cases
- Read 10+ audit reports from Trail of Bits, OpenZeppelin, Spearbit

### Month 3: Active Hunting
- Pick 3-5 Immunefi programs matching our expertise (math-heavy protocols, bridges, ZK applications)
- Run Slither on target codebases, triage results
- Write invariant tests in Foundry for target protocols
- Attempt first bounty submissions

### Ongoing
- Follow rekt.news for real-time hack postmortems
- Monitor Solodit for new vulnerability patterns
- Study every new audit report from top firms
- Build and maintain a personal vulnerability pattern library

---

## Quick Reference: Vulnerability Severity Cheat Sheet

| Severity | Criteria | Typical Bounty |
|----------|----------|----------------|
| **Critical** | Direct loss of funds, unlimited drainage, protocol takeover | $50K - $10M |
| **High** | Theft of unclaimed yield, temporary freezing of funds > $1M, governance manipulation | $10K - $200K |
| **Medium** | Griefing attacks, temporary DOS, minor fund loss, incorrect accounting that does not lead to direct theft | $1K - $25K |
| **Low** | Gas inefficiency, informational, best practice violations, theoretical issues without working PoC | $100 - $2K |

---

## Appendix: Key Resources

- **OWASP Smart Contract Top 10** (2025, 2026): Canonical vulnerability ranking updated annually
- **SWC Registry** (swcregistry.io): Smart Contract Weakness Classification -- formal taxonomy of vulnerabilities
- **Immunefi** (immunefi.com): Primary bounty platform, 330+ programs, $100M+ paid
- **Solodit**: Aggregated database of 15,000+ audit findings
- **DeFiHackLabs** (GitHub): Foundry reproductions of real exploits
- **Rekt.news**: Real-time DeFi hack postmortems
- **DefiLlama Hacks** (defillama.com/hacks): Comprehensive hack database with filters
- **ERC-4337 Bug Bounty** (docs.erc4337.io): Up to $250K for Account Abstraction vulnerabilities
- **Halborn Top 100 DeFi Hacks Report 2025**: Detailed analysis of the year's exploits
- **Chainalysis 2025/2026 Crypto Hacking Reports**: Macro-level theft data and trends

---

*Document compiled March 2026. Data sourced from Immunefi, OWASP, Chainalysis, Halborn, DeFiHackLabs, and public postmortem analyses. Update quarterly as new vulnerability patterns emerge.*
