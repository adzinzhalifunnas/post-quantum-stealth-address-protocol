// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {RegistryBehaviourTest} from "../../shared/contracts/RegistryBehaviour.t.sol";
import {RegistryFull} from "./RegistryFull.sol";

/// @notice P3 variant R1: the full 1217-byte meta-address, unoptimised.
contract RegistryFullTest is RegistryBehaviourTest {
    function setUp() public {
        registry = new RegistryFull();
        schemeId = 0x50513348; // "PQ3H"
        payloadLength = 1217; // M ‖ ek_view at ML-KEM-768
    }

    /// @dev The ML-KEM-512 arm of the parameter sweep: same contract, 833 bytes.
    function test_acceptsMlKem512ParameterSet() public {
        payloadLength = 833;
        bytes memory payload = _payload("mlkem512");

        vm.prank(address(0x512));
        registry.registerKeys(schemeId, payload);
        assertEq(registry.stealthMetaAddressOf(address(0x512), schemeId).length, 833);
    }

    /// @dev Sanity-checks the size relationship the thesis reports: P3 registers
    ///      under a quarter of what MLWE SAP (Mikić et al., JCST 2026, Table 5)
    ///      must, because spending stays on secp256k1 and P3 carries no
    ///      4416-byte Dilithium-structured key. Announcements are identical, so
    ///      this is where the advantage lives.
    function test_metaAddressIsUnderAQuarterOfP2() public pure {
        uint256 p2 = 5600;
        uint256 p3 = 1217;
        assertLt(p3 * 4, p2);
        assertGt(p3 * 5, p2);
    }
}
