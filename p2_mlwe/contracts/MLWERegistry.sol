// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IStealthRegistry} from "../../shared/contracts/IStealthRegistry.sol";

/// @title MLWERegistry — P2's registry
/// @notice Stores an MLWE SAP meta-address: two lattice encapsulation keys.
/// @dev The recipient in Mikić et al.'s protocol holds *two* lattice keypairs,
///      one spending and one viewing, so the registered payload is `ek_K ‖ ek_V`:
///      2368 bytes at ML-KEM-768, or 1600 at the ML-KEM-512 parameter set the
///      paper's own experiments use. At 32 bytes per storage slot that is 74 or
///      50 slots of cold `SSTORE`, plus a length slot — which is why
///      registration dominates this protocol's cost profile.
///
///      `registerKeys` is byte-identical to ERC-6538's, deliberately. The whole
///      point of the comparison is that the three registries differ *only* in
///      the payload they are given, so any difference in measured gas is
///      attributable to payload size and content and to nothing else. For the
///      same reason there is no length validation on-chain: adding a check here
///      but not to the faithful P1 port would introduce a confound. Payload
///      sizes are validated off-chain, in `p2_mlwe/scheme.py`.
///
///      This contract stores bytes, hashes nothing, and performs no lattice
///      arithmetic. Per the project charter there is no ML-KEM arithmetic in
///      Solidity anywhere in this study, ever.
contract MLWERegistry is IStealthRegistry {
    /// @notice Maps a registrant and scheme id to their stored meta-address.
    mapping(address registrant => mapping(uint256 schemeId => bytes)) public override
        stealthMetaAddressOf;

    /// @notice Emitted when a registrant sets their stealth meta-address.
    /// @param registrant The account that registered.
    /// @param schemeId Identifier corresponding to the applied stealth address scheme.
    /// @param stealthMetaAddress The concatenated encapsulation keys, `ek_K ‖ ek_V`.
    event StealthMetaAddressSet(
        address indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
    );

    /// @inheritdoc IStealthRegistry
    function registerKeys(uint256 schemeId, bytes calldata stealthMetaAddress) external override {
        stealthMetaAddressOf[msg.sender][schemeId] = stealthMetaAddress;
        emit StealthMetaAddressSet(msg.sender, schemeId, stealthMetaAddress);
    }
}
