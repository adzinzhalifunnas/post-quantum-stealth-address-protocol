// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {RegistryBehaviourTest} from "../../shared/contracts/RegistryBehaviour.t.sol";
import {MLWERegistry} from "./MLWERegistry.sol";

/// @notice P2's registry: Dilithium-structured spending key + Kyber768 viewing key, 5600 bytes.
contract MLWERegistryTest is RegistryBehaviourTest {
    function setUp() public {
        registry = new MLWERegistry();
        schemeId = 0x4D4C5745; // "MLWE"
        payloadLength = 5600; // K (4416) ‖ V (1184), Mikić et al. 2026, Table 5
    }

    /// @dev The paper's primary instantiation is Kyber512, giving 5216 bytes.
    ///      Both parameter sets go through the same contract; only the payload
    ///      changes. See p2_mlwe/NOTES.md.
    function test_acceptsPaperFaithfulParameterSet() public {
        payloadLength = 5216;
        bytes memory payload = _payload("mlkem512");

        vm.prank(address(0x512));
        registry.registerKeys(schemeId, payload);
        assertEq(registry.stealthMetaAddressOf(address(0x512), schemeId).length, 5216);
    }
}
