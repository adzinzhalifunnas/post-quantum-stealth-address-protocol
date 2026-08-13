// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {RegistryBehaviourTest} from "../../shared/contracts/RegistryBehaviour.t.sol";
import {ERC6538Registry} from "../../p1_erc5564/contracts/ERC6538Registry.sol";
import {IStealthRegistry} from "../../shared/contracts/IStealthRegistry.sol";
import {RegistryCommit} from "./RegistryCommit.sol";

/// @notice P3 variant R3: 65 bytes, `M ‖ keccak256(ek_view)`.
contract RegistryCommitTest is RegistryBehaviourTest {
    function setUp() public {
        registry = new RegistryCommit();
        schemeId = 0x50513348; // "PQ3H"
        payloadLength = 65; // M(33) ‖ keccak256(ek_view)(32)
    }

    /// @dev The headline hypothesis, tested directly rather than inferred from
    ///      byte counts: R3's registration must cost essentially what an
    ///      ordinary ERC-5564 registration costs. Both store a dynamic `bytes`
    ///      spanning three data slots plus a length slot, so the only remaining
    ///      difference is one byte of calldata.
    ///
    ///      Foundry gas excludes intrinsic and calldata costs, which is exactly
    ///      why this asserts a *bound* rather than reporting a number. The
    ///      figure for the thesis comes from real receipts in bench/gas.py.
    function test_registrationCostReachesParityWithErc6538() public {
        ERC6538Registry baseline = new ERC6538Registry();
        RegistryCommit commitRegistry = new RegistryCommit();

        bytes memory erc6538Payload = _payloadOfLength(66); // M_spend ‖ M_view
        bytes memory commitPayload = _payloadOfLength(65); // M ‖ keccak256(ek_view)

        uint256 before = gasleft();
        vm.prank(address(0xA11CE));
        baseline.registerKeys(1, erc6538Payload);
        uint256 erc6538Gas = before - gasleft();

        before = gasleft();
        vm.prank(address(0xB0B));
        commitRegistry.registerKeys(schemeId, commitPayload);
        uint256 commitGas = before - gasleft();

        // Within 1% of each other: same slots, same code, one byte apart.
        assertApproxEqRel(commitGas, erc6538Gas, 0.01e18, "R3 must reach ERC-6538 parity");
    }

    /// @dev And the variant it replaces must be dramatically more expensive, or
    ///      the optimisation is not doing anything.
    function test_registrationIsFarCheaperThanTheFullMetaAddress() public {
        RegistryCommit commitRegistry = new RegistryCommit();
        bytes memory full = _payloadOfLength(1217);
        bytes memory committed = _payloadOfLength(65);

        uint256 before = gasleft();
        vm.prank(address(1));
        commitRegistry.registerKeys(schemeId, full);
        uint256 fullGas = before - gasleft();

        before = gasleft();
        vm.prank(address(2));
        commitRegistry.registerKeys(schemeId, committed);
        uint256 commitGas = before - gasleft();

        assertLt(commitGas * 5, fullGas, "R3 should be many times cheaper than R1");
    }

    function test_storesCommitmentNotTheKey() public {
        bytes memory payload = _payload("commit");
        vm.prank(address(0xC0));
        registry.registerKeys(schemeId, payload);

        bytes memory stored = IStealthRegistry(address(registry)).stealthMetaAddressOf(
            address(0xC0), schemeId
        );
        assertEq(stored.length, 65);
        assertEq(stored, payload);
    }

    function _payloadOfLength(uint256 length) internal pure returns (bytes memory out) {
        out = new bytes(length);
        for (uint256 i = 0; i < length; i += 32) {
            bytes32 chunk = keccak256(abi.encode(i));
            for (uint256 j = 0; j < 32 && i + j < length; ++j) {
                out[i + j] = chunk[j];
            }
        }
    }
}
