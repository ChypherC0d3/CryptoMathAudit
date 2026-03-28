# Bug Report: WeightedMultisigIsm Validator Matching Bound Error

## Summary

The `AbstractStaticWeightedMultisigIsm.verify()` function incorrectly caps its validator scanning range to `Math.min(validators.length, signatureCount)`, preventing the two-pointer matching algorithm from reaching validators whose array index is greater than or equal to the number of submitted signatures. This causes valid weighted quorums composed of higher-indexed validators to be rejected with "Invalid signer", creating a denial-of-service on cross-chain message delivery for any route secured by a `WeightedMultisigIsm`.

## Vulnerability Details

### Root Cause

At line 64 of `AbstractWeightedMultisigIsm.sol`, a single variable `_validatorCount` is computed as the minimum of the validator array length and the number of signatures in the metadata:

```solidity
// AbstractWeightedMultisigIsm.sol, line 64-67
uint256 _validatorCount = Math.min(
    _validators.length,
    signatureCount(_metadata)
);
```

This variable is then used as the upper bound for **both**:

1. **The outer signature iteration loop** (line 74): `signatureIndex < _validatorCount`
2. **The inner validator scanning loop** (line 83): `_validatorIndex < _validatorCount`
3. **The match validity check** (line 89): `require(_validatorIndex < _validatorCount, "Invalid signer")`

When a weighted quorum requires fewer signatures than the total number of validators (the common case), `_validatorCount` is clamped to `signatureCount`. The inner while-loop that scans the sorted validator array for a signer match can therefore never access any validator at an index >= `signatureCount`. Those validators are invisible to the verification logic.

### Affected Code

```solidity
// AbstractWeightedMultisigIsm.sol, lines 49-100
function verify(
    bytes calldata _metadata,
    bytes calldata _message
) public view virtual returns (bool) {
    bytes32 _digest = digest(_metadata, _message);
    (
        ValidatorInfo[] memory _validators,
        uint96 _thresholdWeight
    ) = validatorsAndThresholdWeight(_message);

    require(
        _thresholdWeight > 0 && _thresholdWeight <= TOTAL_WEIGHT,
        "Invalid threshold weight"
    );

    // BUG: _validatorCount is capped at signatureCount, but this cap is also
    // applied to the inner validator-scanning loop, making higher-indexed
    // validators unreachable.
    uint256 _validatorCount = Math.min(           // <-- LINE 64
        _validators.length,
        signatureCount(_metadata)
    );
    uint256 _validatorIndex = 0;
    uint96 _totalWeight = 0;

    for (
        uint256 signatureIndex = 0;
        _totalWeight < _thresholdWeight && signatureIndex < _validatorCount;  // <-- uses capped bound
        ++signatureIndex
    ) {
        address _signer = ECDSA.recover(
            _digest,
            signatureAt(_metadata, signatureIndex)
        );
        while (
            _validatorIndex < _validatorCount &&   // <-- uses SAME capped bound for validator scan
            _signer != _validators[_validatorIndex].signingAddress
        ) {
            ++_validatorIndex;
        }
        require(_validatorIndex < _validatorCount, "Invalid signer");  // <-- checked against capped bound

        _totalWeight += _validators[_validatorIndex].weight;
        ++_validatorIndex;
    }
    require(
        _totalWeight >= _thresholdWeight,
        "Insufficient validator weight"
    );
    return true;
}
```

### Correct Code (for comparison)

The non-weighted `AbstractMultisigIsm.verify()` in `AbstractMultisigIsm.sol` (lines 95-123) does **not** have this bug. It correctly uses the full validator array length for scanning and a separate threshold for the signature iteration:

```solidity
// AbstractMultisigIsm.sol, lines 95-123 (CORRECT implementation)
function verify(
    bytes calldata _metadata,
    bytes calldata _message
) public view returns (bool) {
    bytes32 _digest = digest(_metadata, _message);
    (
        address[] memory _validators,
        uint8 _threshold
    ) = validatorsAndThreshold(_message);
    require(_threshold > 0, "No MultisigISM threshold present for message");

    uint256 _validatorCount = _validators.length;    // <-- FULL array length, not capped
    uint256 _validatorIndex = 0;
    for (uint256 i = 0; i < _threshold; ++i) {       // <-- outer loop bound: _threshold (signature count)
        address _signer = ECDSA.recover(_digest, signatureAt(_metadata, i));
        while (
            _validatorIndex < _validatorCount &&      // <-- inner loop bound: full validator array
            _signer != _validators[_validatorIndex]
        ) {
            ++_validatorIndex;
        }
        require(_validatorIndex < _validatorCount, "!threshold");
        ++_validatorIndex;
    }
    return true;
}
```

The key difference: in `AbstractMultisigIsm`, the outer loop iterates up to `_threshold` (number of required signatures) while the inner loop scans up to `_validators.length` (full validator set). These are independent bounds. In `AbstractStaticWeightedMultisigIsm`, both loops share the same capped `_validatorCount`, conflating two separate concepts.

## Impact

- **Who is affected?** Any cross-chain messaging route secured by a `WeightedMultisigIsm` (either `StaticMerkleRootWeightedMultisigIsm` or `StaticMessageIdWeightedMultisigIsm`).
- **What happens?** When the signing validators occupy positions in the validator array at indices >= the number of submitted signatures, `verify()` reverts with "Invalid signer" despite the signatures being cryptographically valid and the weight threshold being satisfied. This causes the relayer to be unable to deliver the message.
- **Worst case scenario:** If low-indexed validators go offline and only high-indexed validators are available to form a quorum, **all messages on affected routes become undeliverable**. For warp routes (token bridges), this means bridged funds on the source chain are stuck until low-indexed validators return or the ISM is reconfigured.
- **Is fund loss possible?** Funds are not directly stolen, but they can be **temporarily locked** in bridge contracts. The duration depends on how quickly the validator set can be reconfigured or low-indexed validators brought back online.

## Risk Assessment

- **Severity**: High
- **Likelihood**: Medium (requires specific validator set configuration where signing validators are not at the lowest array indices; triggered when some validators are offline)
- **Impact**: DoS on cross-chain message delivery; potential temporary fund lockup in warp routes

## Proof of Concept

### Setup

- 5 validators `[V0, V1, V2, V3, V4]` sorted by address (required by the two-pointer algorithm)
- Each validator has equal weight: `TOTAL_WEIGHT / 5 = 2e9`
- Threshold weight: `6e9` (requires any 3 of 5 validators)
- 3 valid signatures submitted from validators `V2, V3, V4` (array indices 2, 3, 4)

### Steps to Reproduce

1. Deploy a `StaticMessageIdWeightedMultisigIsm` via factory with 5 equally-weighted validators and threshold weight of `6e9` (3-of-5).
2. Dispatch a message through the Mailbox to generate a valid message and checkpoint.
3. Create metadata containing 3 valid ECDSA signatures from validators at indices 2, 3, and 4 (sorted by address, as required).
4. Call `verify()` with this metadata.
5. **Expected**: Returns `true` (valid quorum: `3 * 2e9 = 6e9 >= 6e9`).
6. **Actual**: Reverts with `"Invalid signer"`.

### Execution Trace

```
_validatorCount = Math.min(5, 3) = 3   // BUG: capped at signatureCount

Outer loop, signatureIndex=0:
  _signer = recover(sig[0]) = V2
  Inner while: _validatorIndex=0, validators[0]=V0 != V2 -> index=1
  Inner while: _validatorIndex=1, validators[1]=V1 != V2 -> index=2
  Inner while: _validatorIndex=2, validators[2]=V2 == V2 -> match!
  require(2 < 3) -> OK
  _totalWeight = 2e9, _validatorIndex = 3

Outer loop, signatureIndex=1:
  _signer = recover(sig[1]) = V3
  Inner while: _validatorIndex=3, but 3 < 3 is FALSE -> exits loop immediately
  require(3 < 3) -> REVERTS "Invalid signer"
```

Validator V3 at index 3 is unreachable because `_validatorCount` is 3 (not 5).

### Solidity PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IStaticWeightedMultisigIsm} from
    "../../contracts/interfaces/isms/IWeightedMultisigIsm.sol";
import {StaticMessageIdWeightedMultisigIsmFactory} from
    "../../contracts/isms/multisig/WeightedMultisigIsm.sol";
import {AbstractStaticWeightedMultisigIsm} from
    "../../contracts/isms/multisig/AbstractWeightedMultisigIsm.sol";
import {StaticWeightedValidatorSetFactory} from
    "../../contracts/libs/StaticWeightedValidatorSetFactory.sol";
import {TestMailbox} from "../../contracts/test/TestMailbox.sol";
import {TestMerkleTreeHook} from "../../contracts/test/TestMerkleTreeHook.sol";
import {TestPostDispatchHook} from "../../contracts/test/TestPostDispatchHook.sol";
import {MessageIdMultisigIsmMetadata} from
    "../../contracts/isms/libs/MessageIdMultisigIsmMetadata.sol";
import {TypeCasts} from "../../contracts/libs/TypeCasts.sol";
import {Message} from "../../contracts/libs/Message.sol";
import {CheckpointLib} from "../../contracts/libs/CheckpointLib.sol";

contract WeightedMultisigBugPoC is Test {
    using Message for bytes;
    using TypeCasts for address;

    uint96 constant TOTAL_WEIGHT = 1e10;
    uint32 constant ORIGIN = 1;
    uint32 constant DESTINATION = 2;

    TestMailbox mailbox;
    TestMerkleTreeHook merkleTreeHook;
    TestPostDispatchHook noopHook;
    StaticMessageIdWeightedMultisigIsmFactory factory;

    // 5 validator private keys and addresses
    uint256[5] private keys;
    address[5] private addrs;

    function setUp() public {
        mailbox = new TestMailbox(ORIGIN);
        merkleTreeHook = new TestMerkleTreeHook(address(mailbox));
        noopHook = new TestPostDispatchHook();
        factory = new StaticMessageIdWeightedMultisigIsmFactory();
        mailbox.setDefaultHook(address(merkleTreeHook));
        mailbox.setRequiredHook(address(noopHook));

        // Generate 5 validator keys, sorted by address (required by two-pointer algorithm)
        for (uint256 i = 0; i < 5; i++) {
            keys[i] = uint256(keccak256(abi.encode("validator", i)));
            addrs[i] = vm.addr(keys[i]);
        }
        // Sort by address (bubble sort for PoC simplicity)
        for (uint256 i = 0; i < 4; i++) {
            for (uint256 j = i + 1; j < 5; j++) {
                if (addrs[i] > addrs[j]) {
                    (addrs[i], addrs[j]) = (addrs[j], addrs[i]);
                    (keys[i], keys[j]) = (keys[j], keys[i]);
                }
            }
        }
    }

    function _deployIsm(uint96 threshold)
        internal
        returns (AbstractStaticWeightedMultisigIsm)
    {
        IStaticWeightedMultisigIsm.ValidatorInfo[] memory validators =
            new IStaticWeightedMultisigIsm.ValidatorInfo[](5);
        uint96 weightEach = uint96(TOTAL_WEIGHT / 5); // 2e9 each
        for (uint256 i = 0; i < 5; i++) {
            validators[i] = IStaticWeightedMultisigIsm.ValidatorInfo({
                signingAddress: addrs[i],
                weight: weightEach
            });
        }
        address ism = factory.deploy(validators, threshold);
        return AbstractStaticWeightedMultisigIsm(ism);
    }

    function _buildMetadata(
        bytes memory message,
        uint256[] memory signerIndices
    ) internal view returns (bytes memory) {
        (bytes32 root, uint32 index) = merkleTreeHook.latestCheckpoint();
        bytes32 digest = CheckpointLib.digest(
            ORIGIN,
            address(merkleTreeHook).addressToBytes32(),
            root,
            index,
            message.id()
        );

        // Build metadata prefix: originMerkleTreeHook (32) + root (32) + index (4)
        bytes memory metadata = abi.encodePacked(
            address(merkleTreeHook).addressToBytes32(),
            root,
            index
        );

        // Append signatures in ascending validator index order
        for (uint256 i = 0; i < signerIndices.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                keys[signerIndices[i]],
                digest
            );
            metadata = abi.encodePacked(metadata, r, s, v);
        }
        return metadata;
    }

    /// @notice PASSING: Low-index validators (0,1,2) are within the capped range
    function test_lowIndexValidators_succeeds() public {
        uint96 threshold = uint96(TOTAL_WEIGHT * 3 / 5); // 6e9, needs 3 validators
        AbstractStaticWeightedMultisigIsm ism = _deployIsm(threshold);

        bytes memory message = mailbox.buildOutboundMessage(
            DESTINATION,
            address(0x1234).addressToBytes32(),
            "hello"
        );
        mailbox.dispatch(
            DESTINATION,
            address(0x1234).addressToBytes32(),
            "hello"
        );

        // Sign with validators at indices 0, 1, 2 (low indices)
        uint256[] memory signers = new uint256[](3);
        signers[0] = 0;
        signers[1] = 1;
        signers[2] = 2;

        bytes memory metadata = _buildMetadata(message, signers);

        // This SUCCEEDS because all signers are at indices < signatureCount (3)
        bool result = ism.verify(metadata, message);
        assertTrue(result, "Low-index validators should succeed");
    }

    /// @notice FAILING: High-index validators (2,3,4) exceed the capped range
    function test_highIndexValidators_reverts() public {
        uint96 threshold = uint96(TOTAL_WEIGHT * 3 / 5); // 6e9, needs 3 validators
        AbstractStaticWeightedMultisigIsm ism = _deployIsm(threshold);

        bytes memory message = mailbox.buildOutboundMessage(
            DESTINATION,
            address(0x1234).addressToBytes32(),
            "hello"
        );
        mailbox.dispatch(
            DESTINATION,
            address(0x1234).addressToBytes32(),
            "hello"
        );

        // Sign with validators at indices 2, 3, 4 (high indices)
        uint256[] memory signers = new uint256[](3);
        signers[0] = 2;
        signers[1] = 3;
        signers[2] = 4;

        bytes memory metadata = _buildMetadata(message, signers);

        // BUG: This REVERTS with "Invalid signer" even though these are valid
        // validators with sufficient combined weight (3 * 2e9 = 6e9 >= threshold).
        // _validatorCount = min(5, 3) = 3, so validators at indices 3 and 4
        // are unreachable by the inner scanning loop.
        vm.expectRevert("Invalid signer");
        ism.verify(metadata, message);
    }
}
```

### Test Execution

```bash
cd solidity
forge test --match-contract WeightedMultisigBugPoC -vvv
```

Both tests should pass, confirming that:
- `test_lowIndexValidators_succeeds`: 3 signatures from validators at indices 0,1,2 are correctly accepted.
- `test_highIndexValidators_reverts`: 3 signatures from validators at indices 2,3,4 incorrectly revert, demonstrating the bug.

## Fix Recommendation

Separate the signature iteration bound from the validator scanning bound. The outer loop should iterate over signatures (capped at the smaller of `validators.length` and `signatureCount`), while the inner loop must scan the **full** validator array:

```solidity
// BEFORE (buggy, line 64):
uint256 _validatorCount = Math.min(_validators.length, signatureCount(_metadata));

// AFTER (fixed):
uint256 _signatureCount = signatureCount(_metadata);
uint256 _validatorCount = _validators.length;
uint256 _loopBound = Math.min(_validatorCount, _signatureCount);
```

Then update the outer loop to use `_loopBound` while leaving the inner loop and require check using `_validatorCount`:

```solidity
for (
    uint256 signatureIndex = 0;
    _totalWeight < _thresholdWeight && signatureIndex < _loopBound;  // iterate over signatures
    ++signatureIndex
) {
    address _signer = ECDSA.recover(
        _digest,
        signatureAt(_metadata, signatureIndex)
    );
    while (
        _validatorIndex < _validatorCount &&  // scan FULL validator array
        _signer != _validators[_validatorIndex].signingAddress
    ) {
        ++_validatorIndex;
    }
    require(_validatorIndex < _validatorCount, "Invalid signer");  // check against FULL array

    _totalWeight += _validators[_validatorIndex].weight;
    ++_validatorIndex;
}
```

This matches the pattern used in the non-weighted `AbstractMultisigIsm.verify()` which has been in production without issue.

### Minimal One-Line Fix (Alternative)

If the goal is a minimal change, simply remove the `Math.min` cap entirely:

```solidity
// BEFORE (buggy):
uint256 _validatorCount = Math.min(_validators.length, signatureCount(_metadata));

// AFTER (fixed):
uint256 _validatorCount = _validators.length;
```

This works because the outer loop already has a secondary termination condition (`_totalWeight < _thresholdWeight`) that prevents reading more signatures than necessary, and the `signatureAt()` function will revert on out-of-bounds access if `signatureIndex` exceeds the actual signature count in the metadata. However, the three-variable approach above is more explicit and defensive.

## References

- `AbstractWeightedMultisigIsm.sol` line 64 -- the vulnerable `Math.min` computation
- `AbstractMultisigIsm.sol` lines 95-123 -- correct implementation for comparison
- PR [#4170](https://github.com/hyperlane-xyz/hyperlane-monorepo/pull/4170) -- initial commit introducing `WeightedMultisigIsm` (bug present from inception)
- PR [#4468](https://github.com/hyperlane-xyz/hyperlane-monorepo/pull/4468) -- subsequent fix for duplicate signature replay that did not address this separate issue
- Existing test suite blind spot: `WeightedMultisigIsm.t.sol` always signs starting from index 0 upward, never testing high-index-only validator subsets
