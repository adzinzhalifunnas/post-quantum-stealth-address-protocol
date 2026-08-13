// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {StealthAnnouncer} from "../shared/contracts/StealthAnnouncer.sol";
import {ERC6538Registry} from "../p1_erc5564/contracts/ERC6538Registry.sol";
import {MLWERegistry} from "../p2_mlwe/contracts/MLWERegistry.sol";
import {AnnouncerMinLog} from "../p3_hybrid/contracts/AnnouncerMinLog.sol";
import {RegistryCommit} from "../p3_hybrid/contracts/RegistryCommit.sol";
import {RegistryEvent} from "../p3_hybrid/contracts/RegistryEvent.sol";
import {RegistryFull} from "../p3_hybrid/contracts/RegistryFull.sol";

/// @title Deploy
/// @notice Deploys the full measurement surface: one shared announcer and one
///         registry per protocol.
/// @dev Identical bytecode goes to every network in the study — anvil first for
///      harness validation, then Ethereum Sepolia and Base Sepolia. Gas *units*
///      will match across all three; the L1 data fee will not, and that
///      difference is a finding rather than noise.
///
///      Run against a local anvil:
///        forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 \
///          --broadcast --private-key <anvil key>
///
///      The broadcast artefact under `broadcast/` is committed as the
///      deployment audit trail, and `bench/` reads contract addresses from it,
///      so results can always be traced back to specific deployed bytecode.
contract Deploy is Script {
    function run() external {
        vm.startBroadcast();

        StealthAnnouncer announcer = new StealthAnnouncer();
        ERC6538Registry p1Registry = new ERC6538Registry();
        MLWERegistry p2Registry = new MLWERegistry();
        RegistryFull p3RegistryFull = new RegistryFull();
        RegistryEvent p3RegistryEvent = new RegistryEvent();
        RegistryCommit p3RegistryCommit = new RegistryCommit();
        AnnouncerMinLog p3AnnouncerMinLog = new AnnouncerMinLog();

        vm.stopBroadcast();

        console2.log("chainId           ", block.chainid);
        console2.log("StealthAnnouncer  ", address(announcer));
        console2.log("ERC6538Registry   ", address(p1Registry));
        console2.log("MLWERegistry      ", address(p2Registry));
        console2.log("RegistryFull      ", address(p3RegistryFull));
        console2.log("RegistryEvent     ", address(p3RegistryEvent));
        console2.log("RegistryCommit    ", address(p3RegistryCommit));
        console2.log("AnnouncerMinLog   ", address(p3AnnouncerMinLog));
    }
}
