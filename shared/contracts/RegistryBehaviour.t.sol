// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IStealthRegistry} from "./IStealthRegistry.sol";

/// @title RegistryBehaviourTest
/// @notice Behaviour every registry in this study must exhibit, written once.
/// @dev The Solidity counterpart of `pqsap_core/testing.py`: P1, P2 and P3 are
///      held to one standard by one piece of code, so the registries cannot
///      quietly drift apart and start being tested for different things.
///      Concrete test contracts supply the registry under test and its payload
///      size; everything else is inherited.
///
///      These are correctness and regression checks only. Foundry's gas
///      accounting excludes the 21k intrinsic cost and the per-byte calldata
///      cost, which is precisely the component that differs between protocols,
///      so no number produced here belongs in the thesis. Authoritative figures
///      come from real transaction receipts via `bench/gas.py`.
abstract contract RegistryBehaviourTest is Test {
    IStealthRegistry internal registry;
    uint256 internal schemeId;
    uint256 internal payloadLength;

    event StealthMetaAddressSet(
        address indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
    );

    /// @dev Pseudorandom payload of the protocol's meta-address length. Content
    ///      matters: calldata costs 4 gas per zero byte against 16 per non-zero,
    ///      so a payload of zeros would not exercise realistic storage or cost.
    function _payload(bytes32 seed) internal view returns (bytes memory out) {
        out = new bytes(payloadLength);
        for (uint256 i = 0; i < payloadLength; i += 32) {
            bytes32 chunk = keccak256(abi.encode(seed, i));
            for (uint256 j = 0; j < 32 && i + j < payloadLength; ++j) {
                out[i + j] = chunk[j];
            }
        }
    }

    function test_storesPayloadVerbatim() public {
        bytes memory payload = _payload("alice");
        vm.prank(address(0xA11CE));
        registry.registerKeys(schemeId, payload);

        assertEq(registry.stealthMetaAddressOf(address(0xA11CE), schemeId), payload);
    }

    function test_emitsRegistrationEvent() public {
        bytes memory payload = _payload("bob");

        vm.expectEmit(true, true, true, true);
        emit StealthMetaAddressSet(address(0xB0B), schemeId, payload);

        vm.prank(address(0xB0B));
        registry.registerKeys(schemeId, payload);
    }

    function test_payloadIsTheExpectedLength() public {
        bytes memory payload = _payload("len");
        assertEq(payload.length, payloadLength);

        vm.prank(address(0xC0FFEE));
        registry.registerKeys(schemeId, payload);
        assertEq(registry.stealthMetaAddressOf(address(0xC0FFEE), schemeId).length, payloadLength);
    }

    function test_unregisteredAccountReturnsEmpty() public view {
        assertEq(registry.stealthMetaAddressOf(address(0xDEAD), schemeId).length, 0);
    }

    function test_registrationsAreIsolatedPerAccount() public {
        bytes memory a = _payload("a");
        bytes memory b = _payload("b");

        vm.prank(address(1));
        registry.registerKeys(schemeId, a);
        vm.prank(address(2));
        registry.registerKeys(schemeId, b);

        assertEq(registry.stealthMetaAddressOf(address(1), schemeId), a);
        assertEq(registry.stealthMetaAddressOf(address(2), schemeId), b);
    }

    function test_registrationsAreIsolatedPerScheme() public {
        bytes memory a = _payload("scheme-a");
        bytes memory b = _payload("scheme-b");

        vm.startPrank(address(3));
        registry.registerKeys(schemeId, a);
        registry.registerKeys(schemeId + 1, b);
        vm.stopPrank();

        assertEq(registry.stealthMetaAddressOf(address(3), schemeId), a);
        assertEq(registry.stealthMetaAddressOf(address(3), schemeId + 1), b);
    }

    /// @dev The charter's measurement pitfall made executable: a first
    ///      registration writes cold zero-to-non-zero slots at 20k each, while
    ///      an overwrite touches warm non-zero slots for far less. Benchmarks
    ///      must therefore always use fresh accounts. This asserts the two are
    ///      genuinely different so the harness cannot silently conflate them.
    function test_reRegistrationIsCheaperThanFirstRegistration() public {
        address registrant = address(0xFEE);
        bytes memory first = _payload("first");
        bytes memory second = _payload("second");

        vm.prank(registrant);
        uint256 before = gasleft();
        registry.registerKeys(schemeId, first);
        uint256 coldGas = before - gasleft();

        vm.prank(registrant);
        before = gasleft();
        registry.registerKeys(schemeId, second);
        uint256 warmGas = before - gasleft();

        assertLt(warmGas, coldGas, "overwrite must be cheaper than a fresh registration");
        assertEq(registry.stealthMetaAddressOf(registrant, schemeId), second);
    }

    function test_acceptsArbitraryPayloadLengths() public {
        // No on-chain length validation, matching the ERC-6538 reference. Sizes
        // are the client's responsibility and are checked in the Python schemes.
        vm.prank(address(0xBEEF));
        registry.registerKeys(schemeId, hex"00");
        assertEq(registry.stealthMetaAddressOf(address(0xBEEF), schemeId), hex"00");
    }

    function testFuzz_storesAnyPayload(bytes calldata payload, address registrant) public {
        vm.assume(payload.length <= 4096);
        vm.prank(registrant);
        registry.registerKeys(schemeId, payload);
        assertEq(registry.stealthMetaAddressOf(registrant, schemeId), payload);
    }
}
