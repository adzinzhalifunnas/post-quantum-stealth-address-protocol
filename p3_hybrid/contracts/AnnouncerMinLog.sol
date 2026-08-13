// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title AnnouncerMinLog — P3 variant A2, the recurring-cost optimisation
/// @notice Carries the full ciphertext in calldata but keeps it out of the log.
/// @dev ERC-5564's announcer pays for the payload twice: once as calldata, at
///      16 gas per non-zero byte, and again as log data at 8 gas per byte. For
///      a 33-byte ephemeral public key that second charge is negligible. For a
///      1088-byte ML-KEM ciphertext it is not.
///
///      This variant emits only what an indexer needs to find the transaction —
///      the stealth address and the view tag — and leaves the ciphertext in
///      calldata, where a recipient retrieves it from the transaction input.
///      Indexing still works: the small log says which transaction to fetch.
///      The cost is an extra RPC round trip per candidate during scanning,
///      which `bench/scan.py` measures rather than hand-waves.
///
///      The `bytes calldata` parameter is deliberately unnamed and unread. It
///      exists solely so the ciphertext lands in the transaction's calldata,
///      which the caller is charged for at the intrinsic rate whether or not
///      the contract touches it, and which stays permanently retrievable.
///
///      **Measured, this saves 730 gas of 67,730 — 1.1%, not the third the
///      design predicted.** EIP-7623 is why. Since Pectra a transaction pays at
///      least a floor derived from its calldata alone, and a post-quantum
///      announcement is large and computationally trivial, so it sits exactly on
///      that floor: 4,673 tokens gives a 67,730-gas floor, and 67,730 is what
///      the shared announcer actually costs. Below the floor, execution gas is
///      free, so the ~9,984 gas of log data this contract eliminates buys
///      nothing whatsoever.
///
///      The 730 gas it does save is an ABI artifact, not the log: a `bytes1`
///      view tag needs no offset and length words where ERC-5564's dynamic
///      `bytes` metadata does, which is 73 fewer calldata tokens at 10 gas each.
///
///      Kept in the study as a measured negative result. It remains worthwhile
///      for a reason that is not gas — a 32-byte log against a 1,248-byte one is
///      far less data for every indexer and archive node to store and serve.
///      See p3_hybrid/NOTES.md for the full decomposition and what it implies:
///      with the floor binding, calldata size is the only lever on announcement
///      cost, which makes the ML-KEM parameter set the decision that matters.
///
///      This contract lives in `p3_hybrid/` rather than `shared/` because it is
///      an object of study, measured *against* the shared announcer. The shared
///      announcer remains the control variable and is never forked.
contract AnnouncerMinLog {
    /// @notice Emitted once per payment. Deliberately omits the payload.
    /// @param schemeId Stealth address scheme identifier.
    /// @param stealthAddress The address the payment is directed to.
    /// @param caller The announcing account.
    /// @param viewTag The ERC-5564 view tag, the recipient's cheap first filter.
    event AnnouncementMin(
        uint256 indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes1 viewTag
    );

    /// @notice Publish one payment announcement with a minimal log.
    /// @param schemeId Stealth address scheme identifier.
    /// @param stealthAddress The address the payment is directed to.
    /// @param viewTag The ERC-5564 view tag.
    /// @dev The third argument is the KEM ciphertext. It is never read on-chain;
    ///      recipients read it from this transaction's calldata.
    function announce(
        uint256 schemeId,
        address stealthAddress,
        bytes calldata,
        bytes1 viewTag
    ) external {
        emit AnnouncementMin(schemeId, stealthAddress, msg.sender, viewTag);
    }
}
