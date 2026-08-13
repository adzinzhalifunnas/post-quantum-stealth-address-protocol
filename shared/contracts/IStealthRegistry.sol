// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IStealthRegistry
/// @notice One-time meta-address registration, common call shape across protocols.
/// @dev Registries are what this study actually varies, so unlike the announcer
///      each protocol supplies its own implementation. The function signatures
///      stay common — and identical to ERC-6538's — so `bench/gas.py` drives
///      every variant through one code path and the only thing differing between
///      measurements is the payload.
///
///      Payload semantics per implementation:
///      - P1 (ERC6538Registry): M_spend ‖ M_view                   66 bytes
///      - P2 (MLWERegistry):    ek_K ‖ ek_V                       2368 bytes
///      - P3 R1 (RegistryFull): M ‖ ek_view                       1217 bytes
///      - P3 R3 (RegistryCommit, M5): M ‖ keccak256(ek_view)        65 bytes
///
///      Events are deliberately *not* declared here. P1 must keep ERC-6538's own
///      `StealthMetaAddressSet` to remain a faithful port, so each registry
///      declares its own. All of them use the same shape — two indexed
///      parameters plus the payload as data — so log cost differs only by
///      payload length, which is the quantity under study.
interface IStealthRegistry {
    /// @notice Register the caller's meta-address for a scheme.
    /// @param schemeId Stealth address scheme identifier.
    /// @param stealthMetaAddress The meta-address payload to store.
    function registerKeys(uint256 schemeId, bytes calldata stealthMetaAddress) external;

    /// @notice Read a registrant's stored meta-address payload.
    /// @param registrant The account that registered.
    /// @param schemeId Stealth address scheme identifier.
    /// @return The stored payload, or empty bytes if never registered.
    function stealthMetaAddressOf(address registrant, uint256 schemeId)
        external
        view
        returns (bytes memory);
}
