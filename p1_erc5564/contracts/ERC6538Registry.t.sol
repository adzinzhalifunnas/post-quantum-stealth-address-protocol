// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {RegistryBehaviourTest} from "../../shared/contracts/RegistryBehaviour.t.sol";
import {IStealthRegistry} from "../../shared/contracts/IStealthRegistry.sol";
import {ERC6538Registry} from "./ERC6538Registry.sol";

/// @notice P1's registry against the shared registry behaviour, plus the parts
///         of ERC-6538 that only the faithful port has.
/// @dev The port does not declare `is IStealthRegistry`, deliberately — it keeps
///      the standard's own event and shape. Its ABI satisfies the interface
///      anyway, which is what lets one benchmark harness drive all three
///      registries, and casting here asserts exactly that compatibility.
contract ERC6538RegistryTest is RegistryBehaviourTest {
    ERC6538Registry internal erc6538;

    function setUp() public {
        erc6538 = new ERC6538Registry();
        registry = IStealthRegistry(address(erc6538));
        schemeId = 1; // the one scheme id ERC-5564 standardises
        payloadLength = 66; // M_spend ‖ M_view, compressed
    }

    function test_abiSatisfiesSharedInterface() public {
        bytes memory payload = _payload("interface");
        vm.prank(address(0x5AFE));
        registry.registerKeys(schemeId, payload);
        assertEq(erc6538.stealthMetaAddressOf(address(0x5AFE), schemeId), payload);
    }

    function test_domainSeparatorIsChainBound() public view {
        assertTrue(erc6538.DOMAIN_SEPARATOR() != bytes32(0));
    }

    function test_nonceStartsAtZeroAndIncrements() public {
        assertEq(erc6538.nonceOf(address(0x1234)), 0);

        vm.prank(address(0x1234));
        erc6538.incrementNonce();
        assertEq(erc6538.nonceOf(address(0x1234)), 1);
    }

    function test_registerKeysOnBehalfRejectsBadSignature() public {
        vm.expectRevert();
        erc6538.registerKeysOnBehalf(address(0x1111), schemeId, hex"", _payload("nope"));
    }
}
