// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IStealthAnnouncer
/// @notice Per-payment announcement interface, shared by all three protocols.
/// @dev This is the experiment's control variable and is deliberately identical
///      to ERC-5564's announcer. `announce` takes `bytes`, so it does not care
///      whether the payload is P1's 33-byte ephemeral public key, P3's 1088-byte
///      ML-KEM ciphertext, or anything else — which is exactly what makes the
///      per-payment costs of the three protocols comparable. Never fork this
///      per protocol.
///
///      Field semantics for the post-quantum schemes: `ephemeralPubKey` carries
///      the KEM ciphertext, reusing the standard's field rather than inventing a
///      new frame, and `metadata` is the single ERC-5564 view-tag byte.
interface IStealthAnnouncer {
    /// @notice Emitted once per payment, for recipients to scan.
    /// @param schemeId Stealth address scheme identifier.
    /// @param stealthAddress The address the payment is directed to.
    /// @param caller The announcing account.
    /// @param ephemeralPubKey Ephemeral public key (P1) or KEM ciphertext (P2, P3).
    /// @param metadata View tag, and any scheme-specific trailing bytes.
    event Announcement(
        uint256 indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes ephemeralPubKey,
        bytes metadata
    );

    /// @notice Publish one payment announcement.
    function announce(
        uint256 schemeId,
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        bytes calldata metadata
    ) external;
}
