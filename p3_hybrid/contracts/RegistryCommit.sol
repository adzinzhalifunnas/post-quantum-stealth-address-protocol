// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IStealthRegistry} from "../../shared/contracts/IStealthRegistry.sol";

/// @title RegistryCommit — P3 variant R3, the registration optimisation
/// @notice Stores `M ‖ keccak256(ek_view)`: 65 bytes instead of 1217.
/// @dev The encapsulation key never goes on-chain. Only a commitment to it does,
///      and `ek_view` is served off-chain — from a directory, an ENS text
///      record, the recipient's own site, anywhere — with the sender hashing
///      what it receives and comparing against the commitment stored here before
///      encapsulating to it. A substituted key fails that check, so the registry
///      still binds the recipient to exactly one viewing key while paying for 65
///      bytes rather than 1217.
///
///      **This contract is byte-identical to `RegistryFull`.** That is the
///      finding, not an oversight: R3 needs no new on-chain logic at all. The
///      entire saving comes from what the client chooses to register, so any
///      existing ERC-6538 deployment could serve R3 today without redeployment.
///      It exists as a separate contract only so that its storage is independent
///      and its measurements cannot be contaminated by warm slots from R1.
///
///      The hypothesis this exists to test: at 65 bytes against ERC-6538's 66,
///      R3 occupies the same number of storage slots as an ordinary ERC-5564
///      registration. If registration cost reaches parity, the registration
///      penalty for post-quantum unlinkability disappears entirely and the whole
///      remaining gap is the announcement.
///
///      A further slot could be saved by storing `M` and the commitment in fixed
///      layout rather than a dynamic `bytes` — dropping the length slot, worth
///      one cold SSTORE. Deliberately not done: the dynamic layout is what
///      ERC-6538 uses, and the parity comparison is only meaningful if both
///      sides use identical machinery.
contract RegistryCommit is IStealthRegistry {
    /// @notice Maps a registrant and scheme id to their stored commitment payload.
    mapping(address registrant => mapping(uint256 schemeId => bytes)) public override
        stealthMetaAddressOf;

    /// @notice Emitted when a registrant sets their committed meta-address.
    /// @param registrant The account that registered.
    /// @param schemeId Identifier corresponding to the applied stealth address scheme.
    /// @param stealthMetaAddress The spending key and viewing-key commitment,
    ///        `M ‖ keccak256(ek_view)`.
    event StealthMetaAddressSet(
        address indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
    );

    /// @inheritdoc IStealthRegistry
    function registerKeys(uint256 schemeId, bytes calldata stealthMetaAddress) external override {
        stealthMetaAddressOf[msg.sender][schemeId] = stealthMetaAddress;
        emit StealthMetaAddressSet(msg.sender, schemeId, stealthMetaAddress);
    }
}
