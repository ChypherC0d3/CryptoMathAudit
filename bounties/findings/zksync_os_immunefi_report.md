# Bug Report: BLOBBASEFEE opcode returns hardcoded value instead of actual blob base fee in EVM interpreter

## Target

- **Program:** ZKsync OS Bug Bounty (Immunefi)
- **Asset:** EVM interpreter — https://github.com/matter-labs/zksync-os/tree/4af87fdb6d30b8215d4affd81e6e5e9a8dbf8f52/evm_interpreter
- **Asset type:** Blockchain/DLT
- **Severity:** Medium — Undocumented deviation from EVM behavior (not related to gas)
- **Bounty:** $5,000 (flat)

---

## Brief/Intro

The EVM interpreter in ZKsync OS contains incorrect implementations of two EIP-specified opcodes: BLOBBASEFEE (0x4A) and BLOBHASH (0x49). The BLOBBASEFEE handler pushes a hardcoded `U256::from(1)` onto the stack instead of reading the actual blob base fee from `system.metadata.blob_base_fee_per_gas()`. The BLOBHASH handler discards the index argument entirely and always pushes `U256::ZERO` instead of looking up the versioned hash via `system.get_blob_hash(index)`. These are undocumented deviations from EVM behavior — smart contracts receive silently incorrect values with no revert or error indication.

---

## Vulnerability Details

**Affected file:** `evm_interpreter/src/instructions/environment.rs`
**Affected commit:** `4af87fdb6d30b8215d4affd81e6e5e9a8dbf8f52` (in-scope commit)

### Bug 1: BLOBBASEFEE (opcode 0x4A)

The handler for the BLOBBASEFEE opcode pushes a hardcoded constant instead of reading the actual blob base fee from the execution environment:

```rust
// Current implementation (buggy):
stack.push(U256::from(1));
```

Per [EIP-7516](https://eips.ethereum.org/EIPS/eip-7516), the BLOBBASEFEE opcode must push the value of the blob base fee of the current block onto the stack. The correct implementation reads this value from the system metadata:

```rust
// Correct implementation (from dev branch fix commit 7d4eb61b):
stack.push(U256::from(system.metadata.blob_base_fee_per_gas()));
```

The system metadata already exposes a `blob_base_fee_per_gas()` accessor — it is simply not being called.

### Bug 2: BLOBHASH (opcode 0x49)

The handler for the BLOBHASH opcode discards the index argument and unconditionally returns zero:

```rust
// Current implementation (buggy) — comment in source says "We ignore argument":
let _index = stack.pop();
stack.push(U256::ZERO);
```

Per [EIP-4844](https://eips.ethereum.org/EIPS/eip-4844), the BLOBHASH opcode must pop an index from the stack and push the versioned hash of the blob at that index in the current transaction. The correct implementation performs this lookup:

```rust
// Correct implementation (from dev branch fix commit a92c2d0a):
let index = stack.pop();
stack.push(system.get_blob_hash(index));
```

### Root Cause

Both opcodes appear to have been stubbed during initial development and never completed with actual system calls. The infrastructure to support them (`system.metadata.blob_base_fee_per_gas()` and `system.get_blob_hash()`) already exists in the codebase.

### Fix Confirmation

The development branch of the same repository contains fixes for both issues:
- Commit `7d4eb61b`: Fixes BLOBBASEFEE to read from `system.metadata.blob_base_fee_per_gas()`
- Commit `a92c2d0a`: Fixes BLOBHASH to call `system.get_blob_hash(index)` with the popped index

These fixes confirm the intended correct behavior and that the system APIs are available and functional.

---

## Impact Details

### Direct Impact

1. **BLOBBASEFEE always returns 1:** Any smart contract that reads the blob base fee via the `BLOBBASEFEE` opcode will receive the value `1` regardless of the actual blob base fee. Protocols that use this value for pricing calculations — such as blob-posting protocols, L2 fee market mechanisms, or economic models tied to blob gas pricing — will compute incorrect results.

2. **BLOBHASH always returns zero:** Any smart contract that reads blob versioned hashes via the `BLOBHASH` opcode will receive `bytes32(0)` for every index. Protocols that use blob hashes for data availability verification, blob commitment checks, or KZG proof validation will have their verification logic silently broken.

### Severity Justification

This vulnerability matches the program's **Medium** severity tier: *"Undocumented deviation from EVM behavior (not related to gas)."*

- Both opcodes are EVM-specified (EIP-7516 and EIP-4844) and return incorrect values.
- The deviation is not documented in ZKsync's [known EVM differences](https://docs.zksync.io/zksync-protocol/era-vm/evm-interpreter/evm-differences).
- The failure is silent — no revert, no error, just wrong data returned to the calling contract.
- This is not a gas-related deviation; it concerns execution semantics and data correctness.

### Affected Parties

- Smart contracts deployed on ZKsync that use `BLOBBASEFEE` or `BLOBHASH` opcodes
- Protocols porting EIP-4844-aware contracts from L1 to ZKsync
- Any blob-based data availability verification systems on ZKsync

---

## References

- **EIP-7516 (BLOBBASEFEE opcode):** https://eips.ethereum.org/EIPS/eip-7516
- **EIP-4844 (Shard Blob Transactions / BLOBHASH opcode):** https://eips.ethereum.org/EIPS/eip-4844
- **ZKsync documented EVM differences:** https://docs.zksync.io/zksync-protocol/era-vm/evm-interpreter/evm-differences
- **In-scope asset (commit 4af87fdb):** https://github.com/matter-labs/zksync-os/tree/4af87fdb6d30b8215d4affd81e6e5e9a8dbf8f52/evm_interpreter
- **Fix commit for BLOBBASEFEE:** `7d4eb61b` (dev branch)
- **Fix commit for BLOBHASH:** `a92c2d0a` (dev branch)

---

## Proof of Concept

### Step 1: Identify the bug location

The vulnerable code is in the in-scope asset at the following location:

- **Repository:** https://github.com/matter-labs/zksync-os
- **Commit:** `4af87fdb6d30b8215d4affd81e6e5e9a8dbf8f52`
- **File:** `evm_interpreter/src/instructions/environment.rs`

Clone the repository and check out the in-scope commit:

```bash
git clone https://github.com/matter-labs/zksync-os.git
cd zksync-os
git checkout 4af87fdb6d30b8215d4affd81e6e5e9a8dbf8f52
```

### Step 2: Examine the BLOBBASEFEE handler (opcode 0x4A)

Open `evm_interpreter/src/instructions/environment.rs` and locate the BLOBBASEFEE handler. The implementation pushes a hardcoded value:

```rust
// Buggy: hardcoded return value
stack.push(U256::from(1));
```

This violates EIP-7516, which specifies that BLOBBASEFEE must push the blob base fee of the current block. The correct implementation (confirmed by dev branch commit `7d4eb61b`) is:

```rust
// Correct: reads actual blob base fee from execution environment
stack.push(U256::from(system.metadata.blob_base_fee_per_gas()));
```

### Step 3: Examine the BLOBHASH handler (opcode 0x49)

In the same file, locate the BLOBHASH handler. The implementation ignores the index argument:

```rust
// Buggy: ignores index, always returns zero
let _index = stack.pop();
stack.push(U256::ZERO);
```

This violates EIP-4844, which specifies that BLOBHASH must return the versioned hash at the given index. The correct implementation (confirmed by dev branch commit `a92c2d0a`) is:

```rust
// Correct: looks up versioned hash by index
let index = stack.pop();
stack.push(system.get_blob_hash(index));
```

### Step 4: Demonstrate impact with a Solidity contract

Deploy the following contract on a local ZKsync fork to observe the incorrect behavior:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract BlobOpcodeTest {
    /// @notice Returns the blob base fee via the BLOBBASEFEE opcode (0x4A).
    ///         Expected: actual blob base fee of the current block.
    ///         Actual on ZKsync (buggy): always returns 1.
    function getBlobBaseFee() external view returns (uint256 fee) {
        assembly {
            fee := blobbasefee()
        }
    }

    /// @notice Returns the blob versioned hash at the given index via BLOBHASH (0x49).
    ///         Expected: versioned hash if index < len(tx.blob_versioned_hashes), else 0.
    ///         Actual on ZKsync (buggy): always returns bytes32(0) regardless of index.
    function getBlobHash(uint256 index) external view returns (bytes32 hash) {
        assembly {
            hash := blobhash(index)
        }
    }

    /// @notice Demonstrates that a blob fee pricing check is broken.
    ///         A protocol using this to verify blob costs will always see fee == 1.
    function isBlobFeeAboveThreshold(uint256 threshold) external view returns (bool) {
        uint256 fee;
        assembly {
            fee := blobbasefee()
        }
        return fee > threshold;
        // Bug: always returns (1 > threshold), which is false for any threshold >= 1
    }

    /// @notice Demonstrates that blob data availability verification is broken.
    ///         A protocol using this to verify blob commitments will always fail.
    function verifyBlobExists(uint256 index, bytes32 expectedHash) external view returns (bool) {
        bytes32 hash;
        assembly {
            hash := blobhash(index)
        }
        return hash == expectedHash;
        // Bug: always returns (0x00...00 == expectedHash), which is false for any real hash
    }
}
```

**Reproduction steps on a local fork:**

1. Start a local ZKsync node (e.g., via `era_test_node fork mainnet`).
2. Deploy the `BlobOpcodeTest` contract.
3. Call `getBlobBaseFee()` — observe it returns `1` regardless of actual blob base fee.
4. Call `getBlobHash(0)` — observe it returns `0x0000000000000000000000000000000000000000000000000000000000000000` regardless of any blobs in the transaction.
5. Call `isBlobFeeAboveThreshold(0)` — returns `true` (fee is 1 > 0), but `isBlobFeeAboveThreshold(1)` returns `false` even if actual blob base fee is much higher.
6. Call `verifyBlobExists(0, <any_real_hash>)` — always returns `false`, breaking any blob verification logic.

### Step 5: Verify the fix exists on the dev branch

```bash
git log dev --oneline | grep -i blob
# Output includes:
# 7d4eb61b fix blobbasefee opcode
# a92c2d0a Fixed issue with blobbase fee
```

Compare the buggy and fixed implementations:

```bash
# View the fix for BLOBBASEFEE
git diff 4af87fdb..7d4eb61b -- evm_interpreter/src/instructions/environment.rs

# View the fix for BLOBHASH
git diff 4af87fdb..a92c2d0a -- evm_interpreter/src/instructions/environment.rs
```

Both diffs confirm the replacement of hardcoded values with proper system calls, validating that the current in-scope implementation is incorrect.
