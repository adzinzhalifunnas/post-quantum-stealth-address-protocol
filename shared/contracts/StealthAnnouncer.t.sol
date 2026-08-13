// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {StealthAnnouncer} from "./StealthAnnouncer.sol";
import {IStealthAnnouncer} from "./IStealthAnnouncer.sol";

/// @notice The shared announcer — the experiment's control variable.
/// @dev What these tests are really asserting is *indifference*: the same
///      contract handles 33, 768, 1088 and 2368-byte payloads identically, so
///      any difference in measured per-payment cost between P1, P2 and P3 comes
///      from payload size and content rather than from anything the announcer
///      does differently. Correctness only — see RegistryBehaviour.t.sol on why
///      Foundry gas numbers do not go in the thesis.
contract StealthAnnouncerTest is Test {
    StealthAnnouncer internal announcer;

    event Announcement(
        uint256 indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes ephemeralPubKey,
        bytes metadata
    );

    function setUp() public {
        announcer = new StealthAnnouncer();
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

    function test_emitsAnnouncementWithCallerAsThirdTopic() public {
        bytes memory ct = _payload(1088, "p3");
        bytes memory tag = hex"5A";
        address stealth = address(0x51EA17);

        vm.expectEmit(true, true, true, true);
        emit Announcement(0x50513348, stealth, address(0xA11CE), ct, tag);

        vm.prank(address(0xA11CE));
        announcer.announce(0x50513348, stealth, ct, tag);
    }

    /// @dev One contract, every protocol. This is the charter's control variable
    ///      stated as a test: P1's 33-byte ephemeral public key and P2/P3's
    ///      1088-byte ciphertext travel the same path.
    function test_acceptsEveryProtocolPayloadSize() public {
        uint256[5] memory sizes = [uint256(33), 768, 1088, 1600, 2368];

        for (uint256 i = 0; i < sizes.length; ++i) {
            string memory tag = vm.toString(i);
            vm.prank(makeAddr(string.concat("caller", tag)));
            announcer.announce(
                i + 1, makeAddr(string.concat("stealth", tag)), _payload(sizes[i], "x"), hex"01"
            );
        }
    }

    function test_viewTagIsTheFirstMetadataByte() public {
        // ERC-5564 requires the first metadata byte to be the view tag. This
        // study sends exactly that one byte and nothing more.
        bytes memory tag = hex"FF";
        vm.recordLogs();
        announcer.announce(1, address(0x1), _payload(33, "p1"), tag);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        (, bytes memory metadata) = abi.decode(logs[0].data, (bytes, bytes));
        assertEq(metadata.length, 1);
        assertEq(uint8(metadata[0]), 0xFF);
    }

    function test_schemeIdAndStealthAddressAreIndexed() public {
        vm.recordLogs();
        announcer.announce(0x50513348, address(0xABCD), _payload(1088, "idx"), hex"07");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        // topic0 is the event signature, then schemeId, stealthAddress, caller.
        assertEq(logs[0].topics.length, 4);
        assertEq(uint256(logs[0].topics[1]), 0x50513348);
        assertEq(address(uint160(uint256(logs[0].topics[2]))), address(0xABCD));
        assertEq(address(uint160(uint256(logs[0].topics[3]))), address(this));
    }

    function test_conformsToSharedInterface() public {
        IStealthAnnouncer(address(announcer)).announce(1, address(0x1), hex"00", hex"00");
    }

    function testFuzz_acceptsAnyPayload(bytes calldata ct, bytes calldata metadata, uint256 schemeId)
        public
    {
        vm.assume(ct.length <= 4096 && metadata.length <= 256);
        announcer.announce(schemeId, address(0x1), ct, metadata);
    }
}
