// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IStealthRegistry} from "../../shared/contracts/IStealthRegistry.sol";

/// @title RegistryFull — P3 variant R1, the naive registration
/// @notice Stores a P3 meta-address in full: `M ‖ ek_view`.
/// @dev 1217 bytes at ML-KEM-768 (33-byte compressed secp256k1 spending key plus
///      a 1184-byte ML-KEM encapsulation key), or 833 at ML-KEM-512. Roughly 39
///      storage slots plus a length slot, all cold on a first registration.
///
///      This is the deliberately unoptimised variant. It exists to be beaten:
///      `RegistryCommit` (R3, milestone M5) stores `M ‖ keccak256(ek_view)` in 65
///      bytes and serves `ek_view` off-chain, and the interesting hypothesis is
///      that R3 lands at parity with ERC-6538's own 66-byte registration. If it
///      does, the registration penalty for post-quantum unlinkability disappears
///      entirely and the remaining cost gap is purely the announcement.
///
///      Under a quarter of P2's 5600 bytes, because P3 keeps spending on
///      secp256k1 and so carries no 4416-byte Dilithium-structured spending key.
///      Announcements are identical in size between the two, so this is where
///      P3's entire advantage over the post-quantum state of the art lives.
///
///      `registerKeys` is byte-identical to ERC-6538's, and there is no on-chain
///      length validation, both for the same reason: the registries must differ
///      only in payload, or the measurement is confounded. Sizes are validated
///      off-chain in `p3_hybrid/scheme.py`.
contract RegistryFull is IStealthRegistry {
    /// @notice Maps a registrant and scheme id to their stored meta-address.
    mapping(address registrant => mapping(uint256 schemeId => bytes)) public override
        stealthMetaAddressOf;

    /// @notice Emitted when a registrant sets their stealth meta-address.
    /// @param registrant The account that registered.
    /// @param schemeId Identifier corresponding to the applied stealth address scheme.
    /// @param stealthMetaAddress The spending public key and encapsulation key, `M ‖ ek_view`.
    event StealthMetaAddressSet(
        address indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
    );

    /// @inheritdoc IStealthRegistry
    function registerKeys(uint256 schemeId, bytes calldata stealthMetaAddress) external override {
        stealthMetaAddressOf[msg.sender][schemeId] = stealthMetaAddress;
        emit StealthMetaAddressSet(msg.sender, schemeId, stealthMetaAddress);
    }
}
