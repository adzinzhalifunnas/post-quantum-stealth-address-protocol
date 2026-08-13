// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.28;

import {IStealthAnnouncer} from "./IStealthAnnouncer.sol";

/// @title StealthAnnouncer — A1, the shared announcement path
/// @notice Faithful port of ERC-5564's reference `ERC5564Announcer`.
/// @dev Source: `assets/erc-5564/contracts/ERC5564Announcer.sol` in
///      ethereum/ERCs, CC0-1.0, retrieved 2026-08-07. The body is unchanged; the
///      pragma is raised from 0.8.23 to this project's pinned 0.8.28 so that
///      every contract in the study is compiled by one compiler with one
///      optimizer setting. Cross-protocol comparability matters more here than
///      byte-identical reproduction of the reference deployment, and the
///      methodology chapter states the substitution.
///
///      **All three protocols announce through this one contract.** That is the
///      charter's control variable: `announce` takes `bytes` and is indifferent
///      to whether it receives 33, 768 or 1088 bytes, so any difference in
///      measured per-payment cost is attributable to payload size and content
///      alone. It is never forked per protocol.
///
///      P3's `AnnouncerMinLog` (A2, milestone M5) is measured *against* this
///      contract; it is an object of study rather than a replacement, which is
///      why it lives in `p3_hybrid/` and this one does not.
contract StealthAnnouncer is IStealthAnnouncer {
    /// @inheritdoc IStealthAnnouncer
    function announce(
        uint256 schemeId,
        address stealthAddress,
        bytes memory ephemeralPubKey,
        bytes memory metadata
    ) external {
        emit Announcement(schemeId, stealthAddress, msg.sender, ephemeralPubKey, metadata);
    }
}
