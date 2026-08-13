// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {StealthAnnouncer} from "../../shared/contracts/StealthAnnouncer.sol";
import {AnnouncerMinLog} from "./AnnouncerMinLog.sol";

/// @notice P3 variant A2, measured against the shared announcer it optimises.
contract AnnouncerMinLogTest is Test {
    AnnouncerMinLog internal minLog;
    StealthAnnouncer internal shared;

    event AnnouncementMin(
        uint256 indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes1 viewTag
    );

    function setUp() public {
        minLog = new AnnouncerMinLog();
        shared = new StealthAnnouncer();
    }

    function _ciphertext(uint256 length) internal pure returns (bytes memory out) {
        out = new bytes(length);
        for (uint256 i = 0; i < length; i += 32) {
            bytes32 chunk = keccak256(abi.encode(i));
            for (uint256 j = 0; j < 32 && i + j < length; ++j) {
                out[i + j] = chunk[j];
            }
        }
    }

    function test_emitsMinimalAnnouncement() public {
        vm.expectEmit(true, true, true, true);
        emit AnnouncementMin(0x50513348, address(0x51EA17), address(this), bytes1(0x5A));

        minLog.announce(0x50513348, address(0x51EA17), _ciphertext(1088), bytes1(0x5A));
    }

    /// @dev The whole point: the ciphertext must not appear in the log, but must
    ///      still be present in the transaction's calldata for the recipient to
    ///      retrieve. A2 that silently dropped the payload would be cheaper and
    ///      useless.
    function test_ciphertextIsAbsentFromTheLogButPaidForInCalldata() public {
        bytes memory ct = _ciphertext(1088);

        vm.recordLogs();
        minLog.announce(0x50513348, address(0xABCD), ct, bytes1(0x07));
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(logs.length, 1);
        // Only the one-byte view tag, ABI-padded to a single word.
        assertEq(logs[0].data.length, 32);
        assertEq(logs[0].topics.length, 4);

        // The calldata a recipient would fetch still carries the full ciphertext.
        bytes memory callData =
            abi.encodeCall(AnnouncerMinLog.announce, (0x50513348, address(0xABCD), ct, bytes1(0x07)));
        assertGt(callData.length, 1088);
    }

    /// @dev Quantifies the saving in the log rather than asserting a total, since
    ///      Foundry excludes intrinsic and calldata costs. Log data is billed at
    ///      8 gas per byte, so the shared announcer's extra bytes are the saving.
    function test_sharedAnnouncerLogsFarMoreData() public {
        bytes memory ct = _ciphertext(1088);

        vm.recordLogs();
        shared.announce(0x50513348, address(0xABCD), ct, hex"07");
        uint256 sharedBytes = vm.getRecordedLogs()[0].data.length;

        vm.recordLogs();
        minLog.announce(0x50513348, address(0xABCD), ct, bytes1(0x07));
        uint256 minBytes = vm.getRecordedLogs()[0].data.length;

        assertGt(sharedBytes, 1088);
        assertEq(minBytes, 32);
        // 8 gas per log byte is the floor on what A2 saves.
        assertGt((sharedBytes - minBytes) * 8, 8000);
    }

    function test_topicsStillIdentifyTheRecipient() public {
        vm.recordLogs();
        minLog.announce(0x50513348, address(0xBEEF), _ciphertext(768), bytes1(0xFF));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(uint256(logs[0].topics[1]), 0x50513348);
        assertEq(address(uint160(uint256(logs[0].topics[2]))), address(0xBEEF));
        assertEq(address(uint160(uint256(logs[0].topics[3]))), address(this));
    }

    function test_acceptsBothParameterSetCiphertexts() public {
        minLog.announce(1, address(0x1), _ciphertext(1088), bytes1(0x01));
        minLog.announce(1, address(0x2), _ciphertext(768), bytes1(0x02));
    }

    function testFuzz_acceptsAnyCiphertext(bytes calldata ct, bytes1 viewTag) public {
        vm.assume(ct.length <= 4096);
        minLog.announce(0x50513348, address(0x1), ct, viewTag);
    }
}
