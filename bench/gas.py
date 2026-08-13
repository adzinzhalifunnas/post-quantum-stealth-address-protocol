"""On-chain gas measurement — one harness for all three protocols.

Every protocol is driven through the same code path here. That is not tidiness:
a separate harness per protocol would drift methodologically and the numbers
would stop being comparable, which is the one thing this study cannot afford.

Four charter pitfalls are handled structurally rather than by remembering to be
careful:

**Repetition measures nothing.** Gas units are deterministic, so running one
identical call twenty times produces twenty identical numbers. What genuinely
varies is payload *content* — lattice output is pseudorandom, and a zero
calldata byte costs 4 gas against 16 for a non-zero one — so each sample uses a
freshly generated keypair and the distribution across samples is what gets
reported.

**A first registration is not a re-registration.** Cold zero-to-non-zero
`SSTORE` is 20,000 gas; overwriting a warm non-zero slot is a fraction of that.
Every registration sample therefore uses a brand-new EOA that has never
registered before.

**L2 execution gas and L1 data fee are different quantities.** They go in
separate columns, never summed.

**Results must be auditable.** Each row records the git commit, the chain, the
block, the seed that generated the keypair, and a keccak digest of the exact
bytes that went on-chain. ML-KEM key generation is derandomised, so a seed
regenerates its keypair exactly; encapsulation is not, which is why the digest
is recorded too.

    anvil &
    forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 \\
      --broadcast --private-key <anvil key>
    uv run python -m bench.gas --network anvil --samples 20
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eth_account import Account
from eth_account.signers.local import LocalAccount
from pqsap_core import chain, derive, kem
from pqsap_core.chain import ANVIL_FUNDER_KEY, ChainError, Network
from pqsap_core.scheme import StealthScheme
from web3 import Web3

from bench.sizes import git_commit
from p1_erc5564.scheme import P1Erc5564
from p2_mlwe.scheme import P2Mlwe
from p3_hybrid.scheme import P3Hybrid

__all__ = ["GasRow", "MeasurementTarget", "run", "targets"]

RESULTS_DIR = Path(__file__).parent / "results"

#: Headroom on the funding sent to each sample account, covering the gap between
#: an estimate and the real cost plus any base-fee rise mid-sample. Whatever is
#: left over is swept back, so a generous margin costs nothing but one transfer.
FUNDING_MARGIN = 1.5

#: Flat funding for a local chain, where the currency is worthless and sweeping
#: back would only add noise to the run.
LOCAL_FUNDING_WEI = 10**18  # 1 ETH

#: Intrinsic cost of a plain transfer, used for funding and sweeping.
TRANSFER_GAS = 21_000


@dataclass(frozen=True)
class GasRow:
    """One measured transaction. The unit of the results CSV."""

    git_commit: str
    network: str
    chain_id: int
    block_number: int | None
    protocol: str
    operation: str  # "register" | "announce"
    registry_variant: str
    announcer_variant: str
    param_set: str
    sample_id: int
    seed: str
    payload_bytes: int
    payload_keccak: str
    gas_used: int | None
    effective_gas_price: int | None
    l1_gas_used: int | None
    l1_fee_wei: int | None
    tx_hash: str
    timestamp: str


@dataclass(frozen=True)
class MeasurementTarget:
    """A protocol/variant/parameter-set combination to measure."""

    scheme: StealthScheme
    registry_contract: str
    registry_variant: str
    announcer_variant: str = "A1"


def targets() -> list[MeasurementTarget]:
    """The M4 measurement grid.

    Registration variants R3 and announcer variant A2 arrive in M5; this is the
    naive baseline for all three protocols, which is what Q2's first cut needs.
    P2 is measured at both parameter sets because the paper's own experiments
    use the 512 set while a level-matched comparison against P3 needs 768. See
    p2_mlwe/NOTES.md.
    """
    return [
        MeasurementTarget(P1Erc5564(), "ERC6538Registry", "erc6538"),
        MeasurementTarget(P2Mlwe(kem.ML_KEM_768), "MLWERegistry", "mlwe_full"),
        MeasurementTarget(P2Mlwe(kem.ML_KEM_512), "MLWERegistry", "mlwe_full"),
        MeasurementTarget(P3Hybrid(kem.ML_KEM_768), "RegistryFull", "R1"),
        MeasurementTarget(P3Hybrid(kem.ML_KEM_512), "RegistryFull", "R1"),
    ]


def _funder(w3: Web3, net: Network) -> LocalAccount:
    """The account that pays for sample accounts."""
    if net.is_local:
        account: LocalAccount = Account.from_key(ANVIL_FUNDER_KEY)
        return account

    key = os.environ.get("DEPLOYER_PRIVATE_KEY", "")
    if not key:
        raise ChainError(
            "DEPLOYER_PRIVATE_KEY is not set. Copy .env.example to .env and fill it in. "
            "Use a testnet-only key."
        )
    funder_account: LocalAccount = Account.from_key(key)
    return funder_account


def _measure_sample(
    w3: Web3,
    net: Network,
    target: MeasurementTarget,
    addresses: dict[str, str],
    funder: LocalAccount,
    sample_id: int,
    run_label: str,
    commit: str,
) -> list[GasRow]:
    """Measure one fresh registration and one announcement."""
    scheme = target.scheme
    seed = f"{run_label}/{scheme.name}/{scheme.param_set}/{sample_id:04d}"
    keys = scheme.keygen(seed.encode())

    registry = w3.eth.contract(
        address=Web3.to_checksum_address(addresses[target.registry_contract]),
        abi=chain.load_abi(target.registry_contract),
    )
    announcer = w3.eth.contract(
        address=Web3.to_checksum_address(addresses["StealthAnnouncer"]),
        abi=chain.load_abi("StealthAnnouncer"),
    )

    # A brand-new account, so every storage slot it writes is cold.
    sample_account = chain.new_account()

    register_call = registry.functions.registerKeys(scheme.scheme_id, keys.meta.payload)
    announcement = scheme.announce(keys.meta)
    announce_call = announcer.functions.announce(
        scheme.scheme_id,
        Web3.to_checksum_address(announcement.stealth_address),
        announcement.payload,
        bytes([announcement.view_tag]),
    )

    chain.fund_account(
        w3,
        funder,
        sample_account.address,
        _sample_funding(w3, net, funder.address, register_call, announce_call),
    )

    now = datetime.now(UTC).isoformat()
    rows: list[GasRow] = []

    registration = chain.send(
        w3, sample_account, register_call.build_transaction({"from": sample_account.address})
    )
    rows.append(
        _row(
            commit,
            net,
            target,
            scheme,
            "register",
            sample_id,
            seed,
            keys.meta.payload,
            registration,
            now,
        )
    )

    receipt = chain.send(
        w3, sample_account, announce_call.build_transaction({"from": sample_account.address})
    )
    rows.append(
        _row(
            commit,
            net,
            target,
            scheme,
            "announce",
            sample_id,
            seed,
            announcement.payload,
            receipt,
            now,
        )
    )

    # Recover what the sample did not spend. Pointless on a local chain, and on
    # a testnet it is the difference between needing a faucet once and needing
    # one every day.
    if not net.is_local:
        chain.sweep_to(w3, sample_account, funder.address)

    return rows


def _sample_funding(w3: Web3, net: Network, funder_address: str, *calls: Any) -> int:
    """Fund a sample account for exactly the work it is about to do.

    A flat allowance would have to be sized for the most expensive target — P2's
    1.75M-gas registration — and then paid to every sample of every target,
    stranding the difference in a hundred accounts. Estimating per sample and
    sweeping the remainder afterwards keeps a full run within what a testnet
    faucet actually dispenses.
    """
    if net.is_local:
        return LOCAL_FUNDING_WEI

    gas = sum(int(call.estimate_gas({"from": funder_address})) for call in calls)
    gas += TRANSFER_GAS  # the sweep-back transfer the sample pays for itself
    return int(gas * chain.gas_price_now(w3) * FUNDING_MARGIN)


def _row(
    commit: str,
    net: Network,
    target: MeasurementTarget,
    scheme: StealthScheme,
    operation: str,
    sample_id: int,
    seed: str,
    payload: bytes,
    receipt: dict[str, Any],
    timestamp: str,
) -> GasRow:
    costs = chain.receipt_costs(receipt, net)
    return GasRow(
        git_commit=commit,
        network=net.name,
        chain_id=net.chain_id,
        block_number=costs["block_number"],
        protocol=scheme.name,
        operation=operation,
        registry_variant=target.registry_variant,
        announcer_variant=target.announcer_variant,
        param_set=scheme.param_set,
        sample_id=sample_id,
        seed=seed,
        payload_bytes=len(payload),
        payload_keccak=derive.keccak256(payload).hex(),
        gas_used=costs["gas_used"],
        effective_gas_price=costs["effective_gas_price"],
        l1_gas_used=costs["l1_gas_used"],
        l1_fee_wei=costs["l1_fee_wei"],
        tx_hash=str(receipt.get("transactionHash", "")),
        timestamp=timestamp,
    )


def run(network: str, samples: int, run_label: str) -> list[GasRow]:
    """Measure the full grid on one network."""
    w3, net = chain.connect(network)
    addresses = chain.load_deployment(net.chain_id)
    funder = _funder(w3, net)
    commit = git_commit()

    print(f"network {net.name} (chain {net.chain_id}), {samples} samples per target")
    print(f"funder {funder.address}")
    for name, address in sorted(addresses.items()):
        print(f"  {name:<18} {address}")
    print()

    rows: list[GasRow] = []
    for target in targets():
        scheme = target.scheme
        label = f"{scheme.name}/{scheme.param_set}/{target.registry_variant}"
        print(f"  {label} ... ", end="", flush=True)
        for sample_id in range(samples):
            rows.extend(
                _measure_sample(w3, net, target, addresses, funder, sample_id, run_label, commit)
            )
        print("done")
    return rows


def estimate_run_cost(network: str, samples: int) -> str:
    """Project what a full run will cost, without sending anything.

    Testnet ETH is rationed and a full grid is close to a hundred million gas,
    so the cost of finding out the hard way is a day of waiting on faucets.
    This asks the target network to estimate every call it would make, prices
    the total at the current gas price, and reports it.

    Estimates are made against the deployed contracts on the real network, so
    they account for that chain's actual state rather than a model of it.
    """
    w3, net = chain.connect(network)
    addresses = chain.load_deployment(net.chain_id)
    price = chain.gas_price_now(w3)
    funder = _funder(w3, net)
    balance = w3.eth.get_balance(funder.address)

    lines = [
        f"projected cost — {net.name} (chain {net.chain_id}), {samples} samples per target",
        f"gas price now: {price / 1e9:.3f} gwei",
        "",
        f"{'protocol':<12}{'params':<11}{'gas/sample':>12}{'total gas':>14}{'ETH':>10}",
        "-" * 59,
    ]

    grand_total = 0
    for target in targets():
        scheme = target.scheme
        keys = scheme.keygen(b"estimate")
        registry = w3.eth.contract(
            address=Web3.to_checksum_address(addresses[target.registry_contract]),
            abi=chain.load_abi(target.registry_contract),
        )
        announcer = w3.eth.contract(
            address=Web3.to_checksum_address(addresses["StealthAnnouncer"]),
            abi=chain.load_abi("StealthAnnouncer"),
        )
        announcement = scheme.announce(keys.meta)

        per_sample = int(
            registry.functions.registerKeys(scheme.scheme_id, keys.meta.payload).estimate_gas(
                {"from": funder.address}
            )
        )
        per_sample += int(
            announcer.functions.announce(
                scheme.scheme_id,
                Web3.to_checksum_address(announcement.stealth_address),
                announcement.payload,
                bytes([announcement.view_tag]),
            ).estimate_gas({"from": funder.address})
        )
        # Each sample also costs one funding transfer and one sweep-back.
        per_sample += 2 * TRANSFER_GAS

        total = per_sample * samples
        grand_total += total
        lines.append(
            f"{scheme.name:<12}{scheme.param_set:<11}{per_sample:>12,}"
            f"{total:>14,}{total * price / 1e18:>10.4f}"
        )

    lines += [
        "-" * 59,
        f"{'TOTAL':<23}{'':>12}{grand_total:>14,}{grand_total * price / 1e18:>10.4f}",
        "",
        f"funder {funder.address}",
        f"balance {balance / 1e18:.4f} ETH",
    ]

    needed = grand_total * price / 1e18
    have = balance / 1e18
    if have >= needed:
        lines.append(f"sufficient — {have - needed:.4f} ETH to spare at the current gas price")
    else:
        lines.append(f"SHORT by {needed - have:.4f} ETH at the current gas price")
    lines.append(
        "Gas prices move. Treat this as an order of magnitude, not a guarantee, "
        "and re-run it just before measuring."
    )
    return "\n".join(lines)


def write_csv(rows: list[GasRow], network: str, path: Path | None = None) -> Path:
    """Append-safe write to `bench/results/`. Committed, never hand-edited."""
    path = path or RESULTS_DIR / f"gas_{network}.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[f.name for f in fields(GasRow)])
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))
    return path


def write_run_meta(network: str, samples: int, path: Path | None = None) -> Path:
    """Record the measurement environment alongside the numbers."""
    path = path or RESULTS_DIR / f"run_meta_{network}.json"
    meta = {
        "git_commit": git_commit(),
        "network": network,
        "samples_per_target": samples,
        "timestamp": datetime.now(UTC).isoformat(),
        "kem_backend": kem.backend_info(),
        "machine": {
            "platform": platform.platform(),
            "processor": platform.processor(),
            "python": platform.python_version(),
        },
        "solc": "0.8.28",
        "optimizer_runs": 200,
    }
    path.write_text(json.dumps(meta, indent=2, default=str) + "\n")
    return path


def summarise(rows: list[GasRow]) -> str:
    """Median and spread per target — never a lone mean."""
    groups: dict[tuple[str, str, str], list[int]] = {}
    for row in rows:
        if row.gas_used is None:
            continue
        groups.setdefault((row.protocol, row.param_set, row.operation), []).append(row.gas_used)

    header = f"{'protocol':<12}{'params':<11}{'op':<10}{'n':>4}{'median':>10}{'min':>10}{'max':>10}"
    lines = [header, "-" * len(header)]
    for (protocol, params, operation), values in groups.items():
        values.sort()
        median = values[len(values) // 2]
        lines.append(
            f"{protocol:<12}{params:<11}{operation:<10}{len(values):>4}"
            f"{median:>10,}{values[0]:>10,}{values[-1]:>10,}"
        )
    return "\n".join(lines)


#: Intrinsic cost of any transaction. The charter reports Q2 net of this,
#: because it is paid identically by every protocol and would compress the
#: differences under study.
INTRINSIC_TX_GAS = 21_000


def crossover(rows: list[GasRow]) -> str:
    """Q2's first cut: when do cumulative announcements overtake registration?

    Registration is the largest single cost but is paid once; announcements
    recur. The crossover point is where a protocol's recurring cost equals its
    one-off cost, and it is the number the cumulative curves in M6 are built
    around. Reported net of the intrinsic transaction cost, per the charter.
    """
    medians: dict[tuple[str, str, str], int] = {}
    groups: dict[tuple[str, str, str], list[int]] = {}
    for row in rows:
        if row.gas_used is not None:
            groups.setdefault((row.protocol, row.param_set, row.operation), []).append(row.gas_used)
    for key, values in groups.items():
        values.sort()
        medians[key] = values[len(values) // 2]

    header = f"{'protocol':<12}{'params':<11}{'register':>11}{'announce':>10}{'crossover':>11}"
    lines = [header, "-" * len(header), ""]
    lines[2] = f"{'':<23}{'(net of the 21,000 intrinsic cost)':>32}"
    lines.append("-" * len(header))

    for (protocol, params, operation), value in sorted(medians.items()):
        if operation != "register":
            continue
        announce = medians.get((protocol, params, "announce"))
        if announce is None:
            continue
        reg_net = value - INTRINSIC_TX_GAS
        ann_net = announce - INTRINSIC_TX_GAS
        payments = reg_net / ann_net if ann_net > 0 else float("inf")
        lines.append(f"{protocol:<12}{params:<11}{reg_net:>11,}{ann_net:>10,}{payments:>10.1f}x")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", default="anvil", choices=sorted(chain.NETWORKS))
    parser.add_argument(
        "--samples", type=int, default=20, help="samples per target; charter requires >= 20"
    )
    parser.add_argument(
        "--run-label", default="run1", help="prefix for sample seeds, making keypairs reproducible"
    )
    parser.add_argument(
        "--estimate",
        action="store_true",
        help="project the run's cost against the live network and exit, sending nothing",
    )
    args = parser.parse_args()

    if args.estimate:
        print(estimate_run_cost(args.network, args.samples))
        return

    rows = run(args.network, args.samples, args.run_label)
    print()
    print(summarise(rows))
    print()
    print(crossover(rows))
    print()
    print(f"written: {write_csv(rows, args.network)}")
    print(f"written: {write_run_meta(args.network, args.samples)}")


if __name__ == "__main__":
    main()
