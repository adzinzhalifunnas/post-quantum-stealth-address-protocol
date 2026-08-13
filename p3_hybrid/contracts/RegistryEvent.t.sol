// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {IStealthRegistry} from "../../shared/contracts/IStealthRegistry.sol";
import {RegistryCommit} from "./RegistryCommit.sol";
import {RegistryEvent} from "./RegistryEvent.sol";
import {RegistryFull} from "./RegistryFull.sol";

/// @notice P3 variant R2: emit-only.
/// @dev Deliberately does *not* inherit `RegistryBehaviourTest`. That base
///      asserts storage round-trips and that re-registration is cheaper than a
///      first registration, and neither holds here — R2 stores nothing, so
///      there is no cold slot to warm. Those differences are the design, so
///      they are asserted directly rather than inherited away.
contract RegistryEventTest is Test {
    RegistryEvent internal registry;

    uint256 internal constant SCHEME_ID = 0x50513348; // "PQ3H"
    uint256 internal constant META_LENGTH = 1217; // M ‖ ek_view at ML-KEM-768

    event StealthMetaAddressSet(
        address indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
    );

    function setUp() public {
        registry = new RegistryEvent();
    }

    function _payload(uint256 length, bytes32 seed) internal pure returns (bytes memory out) {
        out = new bytes(length);
        for (uint256 i = 0; i < length; i += 32) {
            bytes32 chunk = keccak256(abi.encode(seed, i));
            for (uint256 j = 0; j < 32 && i + j < length; ++j) {
                out[i + j] = chunk[j];
            }
        }
    }

    function test_emitsTheFullMetaAddress() public {
        bytes memory payload = _payload(META_LENGTH, "alice");

        vm.expectEmit(true, true, true, true);
        emit StealthMetaAddressSet(address(0xA11CE), SCHEME_ID, payload);

        vm.prank(address(0xA11CE));
        registry.registerKeys(SCHEME_ID, payload);
    }

    /// @dev The property being traded away, asserted rather than described.
    function test_storesNothingAndIsNotContractReadable() public {
        bytes memory payload = _payload(META_LENGTH, "bob");

        vm.prank(address(0xB0B));
        registry.registerKeys(SCHEME_ID, payload);

        assertEq(registry.stealthMetaAddressOf(address(0xB0B), SCHEME_ID).length, 0);
    }

    function test_lookupIsEmptyForEveryone() public view {
        assertEq(registry.stealthMetaAddressOf(address(0xB0B), SCHEME_ID).length, 0);
        assertEq(registry.stealthMetaAddressOf(address(0), 0).length, 0);
    }

    /// @dev The full meta-address must be recoverable from the log, or R2 has
    ///      published nothing usable and the gas saving is meaningless.
    function test_metaAddressIsRecoverableFromTheLog() public {
        bytes memory payload = _payload(META_LENGTH, "recover");

        vm.recordLogs();
        vm.prank(address(0xC0FFEE));
        registry.registerKeys(SCHEME_ID, payload);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(address(uint160(uint256(logs[0].topics[1]))), address(0xC0FFEE));
        assertEq(uint256(logs[0].topics[2]), SCHEME_ID);

        bytes memory recovered = abi.decode(logs[0].data, (bytes));
        assertEq(recovered, payload, "log must carry the full meta-address");
    }

    /// @dev R2 has no first-registration penalty, because it writes no storage
    ///      and so has no cold slot to warm.
    ///
    ///      Asserted as a comparison against R1 rather than as equality. A
    ///      second call is still slightly cheaper here — the contract account
    ///      itself warms, at 2,600 gas under EIP-2929 — but that is an artifact
    ///      of two calls sharing one transaction context and is unrelated to
    ///      storage. What matters is the scale: R1's first-versus-second gap is
    ///      forty cold SSTOREs, R2's is one account access.
    function test_hasNoColdStoragePenaltyUnlikeR1() public {
        RegistryFull stored = new RegistryFull();
        bytes memory first = _payload(META_LENGTH, "first");
        bytes memory second = _payload(META_LENGTH, "second");

        uint256 emitDelta = _firstVersusSecond(IStealthRegistry(address(registry)), first, second);
        uint256 storeDelta = _firstVersusSecond(IStealthRegistry(address(stored)), first, second);

        // R1 pays ~40 cold SSTOREs on the first write and far less on the second.
        assertGt(storeDelta, 100_000, "R1 must show a large cold-storage penalty");
        // R2's gap is account warming alone, well under a single cold SSTORE.
        assertLt(emitDelta, 20_000, "R2 must show no cold-storage penalty");
        assertLt(emitDelta * 10, storeDelta, "R2's gap must be an order of magnitude smaller");
    }

    /// @dev Gas spent on a first registration minus a second, by the same
    ///      registrant, against the same registry.
    function _firstVersusSecond(
        IStealthRegistry target,
        bytes memory first,
        bytes memory second
    ) internal returns (uint256) {
        address registrant = address(0xFEE);

        vm.prank(registrant);
        uint256 before = gasleft();
        target.registerKeys(SCHEME_ID, first);
        uint256 firstGas = before - gasleft();

        vm.prank(registrant);
        before = gasleft();
        target.registerKeys(SCHEME_ID, second);
        uint256 secondGas = before - gasleft();

        return firstGas > secondGas ? firstGas - secondGas : 0;
    }

    /// @dev The comparison that motivates R2 existing at all. Foundry excludes
    ///      intrinsic and calldata costs, so this measures exactly the storage
    ///      difference — which is the point.
    function test_farCheaperThanStoringTheSamePayload() public {
        RegistryFull stored = new RegistryFull();
        bytes memory payload = _payload(META_LENGTH, "compare");

        vm.prank(address(1));
        uint256 before = gasleft();
        stored.registerKeys(SCHEME_ID, payload);
        uint256 storedGas = before - gasleft();

        vm.prank(address(2));
        before = gasleft();
        registry.registerKeys(SCHEME_ID, payload);
        uint256 emittedGas = before - gasleft();

        assertLt(emittedGas * 10, storedGas, "emit-only should be an order of magnitude cheaper");
    }

    /// @dev R2 and R3 give up different things, so neither dominates. R3 keeps
    ///      the spending key readable on-chain; R2 keeps nothing readable but
    ///      keeps every byte on-chain.
    function test_r3RemainsContractReadableWhereR2IsNot() public {
        RegistryCommit commitRegistry = new RegistryCommit();
        bytes memory commitment = _payload(65, "commit");
        bytes memory full = _payload(META_LENGTH, "full");

        vm.prank(address(0xD1));
        commitRegistry.registerKeys(SCHEME_ID, commitment);
        vm.prank(address(0xD1));
        registry.registerKeys(SCHEME_ID, full);

        assertEq(commitRegistry.stealthMetaAddressOf(address(0xD1), SCHEME_ID).length, 65);
        assertEq(registry.stealthMetaAddressOf(address(0xD1), SCHEME_ID).length, 0);
    }

    function test_acceptsBothParameterSets() public {
        vm.prank(address(0x768));
        registry.registerKeys(SCHEME_ID, _payload(1217, "mlkem768"));
        vm.prank(address(0x512));
        registry.registerKeys(SCHEME_ID, _payload(833, "mlkem512"));
    }

    function test_conformsToTheSharedInterface() public {
        IStealthRegistry(address(registry)).registerKeys(SCHEME_ID, _payload(META_LENGTH, "iface"));
    }

    function testFuzz_emitsAnyPayload(bytes calldata payload, address registrant) public {
        vm.assume(payload.length <= 4096);
        vm.prank(registrant);
        registry.registerKeys(SCHEME_ID, payload);
        assertEq(registry.stealthMetaAddressOf(registrant, SCHEME_ID).length, 0);
    }
}
