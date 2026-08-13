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

#: Native currency sent to each fresh sample account. Generous on anvil, and
#: enough on a testnet for one large registration plus one announcement.
SAMPLE_FUNDING_WEI = 5 * 10**16  # 0.05 ETH


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
    chain.fund_account(w3, funder, sample_account.address, SAMPLE_FUNDING_WEI)

    now = datetime.now(UTC).isoformat()
    rows: list[GasRow] = []

    registration = chain.send(
        w3,
        sample_account,
        registry.functions.registerKeys(scheme.scheme_id, keys.meta.payload).build_transaction(
            {"from": sample_account.address}
        ),
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

    announcement = scheme.announce(keys.meta)
    receipt = chain.send(
        w3,
        sample_account,
        announcer.functions.announce(
            scheme.scheme_id,
            Web3.to_checksum_address(announcement.stealth_address),
            announcement.payload,
            bytes([announcement.view_tag]),
        ).build_transaction({"from": sample_account.address}),
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
    return rows


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
    args = parser.parse_args()

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
