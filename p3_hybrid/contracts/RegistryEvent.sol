// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IStealthRegistry} from "../../shared/contracts/IStealthRegistry.sol";

/// @title RegistryEvent — P3 variant R2, the emit-only registration
/// @notice Publishes the full meta-address as an event and writes nothing to storage.
/// @dev The third point in the registry design space, and the one that makes the
///      other two comparable. R1 stores everything on-chain; R3 stores a
///      commitment and moves the key off-chain; R2 keeps every byte on-chain but
///      in logs rather than storage.
///
///      Why that is worth measuring: cold `SSTORE` is 20,000 gas per slot, and
///      R1 pays it roughly forty times. R2 pays none, at the price of the one
///      thing storage gives that logs do not — **readability from within the
///      EVM**. `stealthMetaAddressOf` here returns empty for everybody, always,
///      and that is not a stub. It is the honest signal of what this design
///      gives up: no contract can read a meta-address registered this way, and
///      senders must index logs instead.
///
///      For stealth addresses that trade may be cheap, because the reader is an
///      off-chain sender rather than a contract. It is not free, though: a
///      protocol that ever wanted on-chain resolution — a paymaster, a router, a
///      contract paying a stealth address — could not build on R2.
///
///      Against R3 the comparison is not simply cost. R2's data stays on-chain
///      and is therefore as available and as censorship-resistant as Ethereum
///      itself, where R3 depends on an off-chain directory that can refuse to
///      answer. R2 buys availability back and spends contract-readability;
///      R3 does the reverse. Neither dominates, which is why the thesis reports
///      a trade-off map rather than a winner.
///
///      One measurement consequence to expect: with no storage writes, this
///      contract's cost is almost entirely calldata, so it should land on the
///      EIP-7623 floor — and unlike R1 and R3, a re-registration should cost the
///      same as a first one, because there is no cold-versus-warm slot to
///      distinguish them.
contract RegistryEvent is IStealthRegistry {
    /// @notice Emitted when a registrant publishes their stealth meta-address.
    /// @param registrant The account that registered.
    /// @param schemeId Identifier corresponding to the applied stealth address scheme.
    /// @param stealthMetaAddress The full meta-address. This log is the only
    ///        record; nothing is written to storage.
    event StealthMetaAddressSet(
        address indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
    );

    /// @inheritdoc IStealthRegistry
    /// @dev Identical in shape to ERC-6538's `registerKeys`, minus the storage
    ///      write. The payload is the same full meta-address R1 stores, so the
    ///      measured difference between the two is the storage cost alone.
    function registerKeys(uint256 schemeId, bytes calldata stealthMetaAddress) external override {
        emit StealthMetaAddressSet(msg.sender, schemeId, stealthMetaAddress);
    }

    /// @inheritdoc IStealthRegistry
    /// @dev **Always returns empty.** Not unimplemented — unimplementable. This
    ///      registry holds no state, so there is nothing on-chain to return, and
    ///      that is precisely the property being traded away for the gas saving.
    ///      Callers wanting a meta-address registered here must read the
    ///      `StealthMetaAddressSet` logs.
    function stealthMetaAddressOf(address, uint256)
        external
        pure
        override
        returns (bytes memory)
    {
        return "";
    }
}
