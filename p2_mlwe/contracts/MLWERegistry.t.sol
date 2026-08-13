// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {RegistryBehaviourTest} from "../../shared/contracts/RegistryBehaviour.t.sol";
import {MLWERegistry} from "./MLWERegistry.sol";

/// @notice P2's registry: two ML-KEM-768 encapsulation keys, 2368 bytes.
contract MLWERegistryTest is RegistryBehaviourTest {
    function setUp() public {
        registry = new MLWERegistry();
        schemeId = 0x4D4C5745; // "MLWE"
        payloadLength = 2368; // ek_K ‖ ek_V at ML-KEM-768
    }

    /// @dev The paper's own experiments use Kyber512, giving 1600 bytes. Both
    ///      parameter sets go through the same contract; only the payload
    ///      changes. See p2_mlwe/NOTES.md.
    function test_acceptsPaperFaithfulParameterSet() public {
        payloadLength = 1600;
        bytes memory payload = _payload("mlkem512");

        vm.prank(address(0x512));
        registry.registerKeys(schemeId, payload);
        assertEq(registry.stealthMetaAddressOf(address(0x512), schemeId).length, 1600);
    }
}
