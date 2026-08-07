// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IStealthRegistry
/// @notice One-time meta-address registration, shared shape across all protocols.
/// @dev Registries are what this study actually varies, so unlike the announcer
///      each protocol supplies its own implementation. The *interface* stays
///      common so the benchmark harness can drive them all through one code
///      path and the only thing that differs between measurements is the
///      payload content and length.
///
///      Payload semantics per implementation:
///      - P1 (ERC-6538):     M_spend ‖ M_view                     66 bytes
///      - P2 (MLWERegistry): ek_K ‖ ek_V                        2368 bytes
///      - P3 R1 (Full):      M ‖ ek_view                        1217 bytes
///      - P3 R3 (Commit):    M ‖ keccak256(ek_view)               65 bytes
interface IStealthRegistry {
    /// @notice Emitted when an account registers or updates its meta-address.
    event StealthKeysRegistered(address indexed registrant, uint256 indexed schemeId, bytes data);

    /// @notice Register the caller's meta-address for a scheme.
    function registerKeys(uint256 schemeId, bytes calldata data) external;

    /// @notice Read a registrant's stored meta-address payload.
    function stealthMetaAddressOf(address registrant, uint256 schemeId)
        external
        view
        returns (bytes memory);
}
