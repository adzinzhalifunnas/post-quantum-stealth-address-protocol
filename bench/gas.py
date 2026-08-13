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
from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eth_account import Account
from eth_account.signers.local import LocalAccount
from pqsap_core import chain, derive, kem
from pqsap_core.chain import ANVIL_FUNDER_KEY, ChainError, Network
from pqsap_core.scheme import RecipientKeys, StealthScheme
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
    #: Full transaction calldata, and the EIP-7623 floor it implies. Recorded
    #: because announcements in this study sit on that floor, which is why
    #: execution-side optimisations do not reduce their cost.
    calldata_bytes: int
    calldata_tokens: int
    eip7623_floor_gas: int
    floor_bound: bool
    gas_used: int | None
    effective_gas_price: int | None
    #: OP Stack only. Null on an L1 chain — null meaning "not applicable here",
    #: never zero, which would read as "measured and found to be nothing".
    l1_gas_used: int | None
    l1_fee_wei: int | None
    l1_gas_price: int | None
    l1_blob_base_fee: int | None
    l1_base_fee_scalar: int | None
    l1_blob_base_fee_scalar: int | None
    tx_hash: str
    timestamp: str


@dataclass(frozen=True)
class MeasurementTarget:
    """A protocol/variant/parameter-set combination to measure."""

    scheme: StealthScheme
    registry_contract: str
    registry_variant: str
    announcer_contract: str = "StealthAnnouncer"
    announcer_variant: str = "A1"
    #: R3 registers a commitment to the viewing key rather than the key itself.
    use_commitment: bool = False


def targets() -> list[MeasurementTarget]:
    """The measurement grid.

    Registration and announcement are separate transactions, and neither cost
    depends on the other's variant, so each registry variant and each announcer
    variant needs measuring once and the rest of the cross product is composed
    from those medians. `crossover` builds it on that basis, which saves a
    substantial share of a testnet run's funding.

    Three registry variants for P3, not two. R2 emits the full meta-address and
    stores nothing, sitting between R1's full on-chain storage and R3's
    commitment. It is here because R3's claim of ERC-5564 parity is not
    defensible without it: an examiner will ask what the intermediate design
    costs, and the answer has to be measured rather than argued.

    P2 appears at both parameter sets because the paper's own experiments use
    the 512 set while a level-matched comparison against P3 needs 768. See
    p2_mlwe/NOTES.md.
    """
    return [
        MeasurementTarget(P1Erc5564(), "ERC6538Registry", "erc6538"),
        MeasurementTarget(P2Mlwe(kem.ML_KEM_768), "MLWERegistry", "mlwe_full"),
        MeasurementTarget(P2Mlwe(kem.ML_KEM_512), "MLWERegistry", "mlwe_full"),
        MeasurementTarget(P3Hybrid(kem.ML_KEM_768), "RegistryFull", "R1"),
        MeasurementTarget(P3Hybrid(kem.ML_KEM_512), "RegistryFull", "R1"),
        # R2 registers the same full meta-address as R1 — only the contract
        # differs, so the measured gap between them is the storage cost alone.
        MeasurementTarget(P3Hybrid(kem.ML_KEM_768), "RegistryEvent", "R2"),
        MeasurementTarget(P3Hybrid(kem.ML_KEM_512), "RegistryEvent", "R2"),
        MeasurementTarget(
            P3Hybrid(kem.ML_KEM_768),
            "RegistryCommit",
            "R3",
            announcer_contract="AnnouncerMinLog",
            announcer_variant="A2",
            use_commitment=True,
        ),
        MeasurementTarget(
            P3Hybrid(kem.ML_KEM_512),
            "RegistryCommit",
            "R3",
            announcer_contract="AnnouncerMinLog",
            announcer_variant="A2",
            use_commitment=True,
        ),
    ]


def registry_payload(target: MeasurementTarget, keys: RecipientKeys) -> bytes:
    """The bytes a target actually registers.

    R3's whole saving lives here: it registers `M ‖ keccak256(ek_view)`, 65
    bytes, and serves the encapsulation key off-chain. The contract is identical
    to R1's — only the payload differs.
    """
    if not target.use_commitment:
        return keys.meta.payload
    scheme = target.scheme
    assert isinstance(scheme, P3Hybrid)
    return scheme.commitment_payload(keys.meta)


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
    receipts: list[dict[str, Any]],
) -> list[GasRow]:
    """Measure one fresh registration and one announcement.

    Appends both raw receipts to `receipts` so nothing the node returned is
    discarded — see `write_receipts`.
    """
    scheme = target.scheme
    seed = f"{run_label}/{scheme.name}/{scheme.param_set}/{sample_id:04d}"
    keys = scheme.keygen(seed.encode())

    registry = w3.eth.contract(
        address=Web3.to_checksum_address(addresses[target.registry_contract]),
        abi=chain.load_abi(target.registry_contract),
    )
    announcer = w3.eth.contract(
        address=Web3.to_checksum_address(addresses[target.announcer_contract]),
        abi=chain.load_abi(target.announcer_contract),
    )

    # A brand-new account, so every storage slot it writes is cold.
    sample_account = chain.new_account()

    payload = registry_payload(target, keys)
    register_call = registry.functions.registerKeys(scheme.scheme_id, payload)
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

    register_tx = register_call.build_transaction({"from": sample_account.address})
    registration = chain.send(w3, sample_account, register_tx)
    receipts.append(registration)
    rows.append(
        _row(
            commit,
            net,
            target,
            scheme,
            "register",
            sample_id,
            seed,
            payload,
            registration,
            now,
            _calldata_of(register_tx),
        )
    )

    announce_tx = announce_call.build_transaction({"from": sample_account.address})
    receipt = chain.send(w3, sample_account, announce_tx)
    receipts.append(receipt)
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
            _calldata_of(announce_tx),
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


def _calldata_of(tx: Mapping[str, Any]) -> bytes:
    """The transaction's data field as raw bytes, for the EIP-7623 floor."""
    data = tx.get("data", b"")
    if isinstance(data, str):
        return bytes.fromhex(data.removeprefix("0x"))
    return bytes(data)


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
    calldata: bytes,
) -> GasRow:
    costs = chain.receipt_costs(receipt, net)
    tokens, floor = chain.calldata_floor(calldata)
    gas_used = costs["gas_used"]
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
        calldata_bytes=len(calldata),
        calldata_tokens=tokens,
        eip7623_floor_gas=floor,
        # Within a few gas of the floor means the floor is what was charged, and
        # execution-side savings would have been invisible.
        floor_bound=gas_used is not None and gas_used <= floor + 50,
        gas_used=gas_used,
        effective_gas_price=costs["effective_gas_price"],
        l1_gas_used=costs["l1_gas_used"],
        l1_fee_wei=costs["l1_fee_wei"],
        l1_gas_price=costs["l1_gas_price"],
        l1_blob_base_fee=costs["l1_blob_base_fee"],
        l1_base_fee_scalar=costs["l1_base_fee_scalar"],
        l1_blob_base_fee_scalar=costs["l1_blob_base_fee_scalar"],
        tx_hash=str(receipt.get("transactionHash", "")),
        timestamp=timestamp,
    )


def run(network: str, samples: int, run_label: str) -> list[GasRow]:
    """Measure the full grid on one network, checkpointing as it goes.

    Results are flushed to disk after every target and again if the run dies.
    A full grid is several hundred sequential transactions on a real network,
    and the funds behind them come from rate-limited faucets — so a crash at
    80% must not throw away the 80% already paid for. Re-running afterwards
    with a fresh `--run-label` tops up what is missing rather than starting
    over.
    """
    w3, net = chain.connect(network)
    addresses = chain.load_deployment(net.chain_id)
    funder = _funder(w3, net)
    commit = git_commit()
    balance = w3.eth.get_balance(funder.address)

    print(f"network {net.name} (chain {net.chain_id}), {samples} samples per target")
    print(f"funder {funder.address} — {balance / 1e18:.4f} ETH")
    for name, address in sorted(addresses.items()):
        print(f"  {name:<18} {address}")
    print()

    rows: list[GasRow] = []
    receipts: list[dict[str, Any]] = []

    def checkpoint() -> None:
        if rows:
            write_csv(rows, network)
            write_receipts(receipts, network)

    try:
        for target in targets():
            scheme = target.scheme
            label = (
                f"{scheme.name}/{scheme.param_set}/"
                f"{target.registry_variant}+{target.announcer_variant}"
            )
            print(f"  {label} ... ", end="", flush=True)
            for sample_id in range(samples):
                rows.extend(
                    _measure_sample(
                        w3, net, target, addresses, funder, sample_id, run_label, commit, receipts
                    )
                )
            checkpoint()
            print(f"done ({len(rows)} rows saved)")
    except (Exception, KeyboardInterrupt) as exc:
        checkpoint()
        spent = (balance - w3.eth.get_balance(funder.address)) / 1e18
        print(f"\n  INTERRUPTED after {len(rows)} rows ({spent:.4f} ETH spent).")
        print(f"  Everything measured so far is saved. Cause: {type(exc).__name__}: {exc}")
        raise

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
            address=Web3.to_checksum_address(addresses[target.announcer_contract]),
            abi=chain.load_abi(target.announcer_contract),
        )
        announcement = scheme.announce(keys.meta)

        per_sample = int(
            registry.functions.registerKeys(
                scheme.scheme_id, registry_payload(target, keys)
            ).estimate_gas({"from": funder.address})
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


def preflight(network: str) -> str:
    """Check everything checkable without sending a transaction.

    Run this before a real measurement. Faucet funds are rate-limited, so the
    failures worth catching are the ones that would otherwise surface halfway
    through a run that has already spent them: a wrong RPC, contracts not
    deployed, a receipt field the node does not return, an unfunded key.
    """
    checks: list[tuple[bool, str]] = []

    try:
        w3, net = chain.connect(network)
        checks.append((True, f"RPC reachable, chain id {net.chain_id} as expected"))
    except ChainError as exc:
        return f"FAIL: {exc}"

    try:
        addresses = chain.load_deployment(net.chain_id)
        missing = {t.registry_contract for t in targets()} | {
            t.announcer_contract for t in targets()
        }
        absent = sorted(missing - set(addresses))
        checks.append(
            (not absent, f"contracts deployed ({len(addresses)} found)")
            if not absent
            else (False, f"contracts NOT deployed: {', '.join(absent)}")
        )
    except ChainError as exc:
        return "\n".join([f"  ok  {m}" for _, m in checks] + [f"FAIL: {exc}"])

    try:
        funder = _funder(w3, net)
        balance = w3.eth.get_balance(funder.address)
        checks.append((balance > 0, f"funder {funder.address} holds {balance / 1e18:.4f} ETH"))
    except ChainError as exc:
        return "\n".join([f"  ok  {m}" for _, m in checks] + [f"FAIL: {exc}"])

    # Gas estimation must work against every deployed contract, or the run will
    # fail on its first sample rather than its last.
    for target in targets():
        scheme = target.scheme
        keys = scheme.keygen(b"preflight")
        registry = w3.eth.contract(
            address=Web3.to_checksum_address(addresses[target.registry_contract]),
            abi=chain.load_abi(target.registry_contract),
        )
        try:
            registry.functions.registerKeys(
                scheme.scheme_id, registry_payload(target, keys)
            ).estimate_gas({"from": funder.address})
            ok, note = True, f"{scheme.name}/{scheme.param_set}/{target.registry_variant} estimates"
        except Exception as exc:
            ok, note = False, f"{target.registry_variant} estimate FAILED: {exc}"
        checks.append((ok, note))

    # The receipt fields the harness reads must actually be present. Checked
    # against a real transaction already on the chain, so nothing is sent.
    latest = w3.eth.get_block("latest", full_transactions=False)
    sample_tx: str | None = None
    for offset in range(30):
        block = w3.eth.get_block(max(0, latest["number"] - offset), full_transactions=False)
        transactions = block["transactions"]
        if transactions:
            first = transactions[0]
            sample_tx = first.hex() if isinstance(first, bytes) else str(first)
            break
    if sample_tx:
        receipt = chain.raw_receipt(w3, sample_tx)
        required = ["gasUsed", "effectiveGasPrice", "blockNumber"]
        if net.is_op_stack:
            required += ["l1Fee", "l1GasUsed", "l1GasPrice"]
        absent_fields = [f for f in required if f not in receipt]
        checks.append(
            (not absent_fields, f"receipt fields present ({', '.join(required)})")
            if not absent_fields
            else (False, f"receipt MISSING fields: {', '.join(absent_fields)}")
        )
    else:
        checks.append((True, "no recent transaction to check receipt fields against (skipped)"))

    lines = [f"preflight — {net.name} (chain {net.chain_id})", ""]
    lines += [f"  {'ok ' if ok else 'FAIL'}  {note}" for ok, note in checks]
    lines.append("")
    if all(ok for ok, _ in checks):
        lines.append("All checks passed. Now run --estimate to price the run, then measure.")
    else:
        lines.append("Fix the failures above before spending anything.")
    return "\n".join(lines)


def write_receipts(receipts: list[dict[str, Any]], network: str, path: Path | None = None) -> Path:
    """Archive every raw receipt, exactly as the node returned it.

    Insurance. A testnet run costs scarce faucet funds, so discovering later
    that some field was needed and not extracted would mean waiting on a faucet
    to measure again. The CSV holds what the analysis uses; this holds
    everything, so any future question can be answered from data already paid
    for.
    """
    path = path or RESULTS_DIR / f"receipts_{network}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        for receipt in receipts:
            handle.write(json.dumps(receipt, sort_keys=True) + "\n")
    return path


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


def _variant_of(row: GasRow) -> str:
    """Which variant a row measures: the registry for a registration, else the
    announcer. Grouping without this would merge R1 with R3 and A1 with A2."""
    return row.registry_variant if row.operation == "register" else row.announcer_variant


def _medians(rows: list[GasRow]) -> dict[tuple[str, str, str, str], list[int]]:
    groups: dict[tuple[str, str, str, str], list[int]] = {}
    for row in rows:
        if row.gas_used is None:
            continue
        key = (row.protocol, row.param_set, row.operation, _variant_of(row))
        groups.setdefault(key, []).append(row.gas_used)
    for values in groups.values():
        values.sort()
    return groups


def summarise(rows: list[GasRow]) -> str:
    """Median and spread per variant — never a lone mean."""
    groups = _medians(rows)

    floor_bound: dict[tuple[str, str, str, str], bool] = {}
    for row in rows:
        key = (row.protocol, row.param_set, row.operation, _variant_of(row))
        floor_bound[key] = floor_bound.get(key, True) and row.floor_bound

    header = (
        f"{'protocol':<12}{'params':<11}{'op':<10}{'variant':<10}"
        f"{'n':>4}{'median':>10}{'min':>10}{'max':>10}{'  floor':<8}"
    )
    lines = [header, "-" * len(header)]
    for key, values in sorted(groups.items()):
        protocol, params, operation, variant = key
        median = values[len(values) // 2]
        # "floor" marks a transaction whose cost is set entirely by its calldata
        # under EIP-7623, so no execution-side saving could reduce it.
        marker = "  <- floor" if floor_bound.get(key) else ""
        lines.append(
            f"{protocol:<12}{params:<11}{operation:<10}{variant:<10}{len(values):>4}"
            f"{median:>10,}{values[0]:>10,}{values[-1]:>10,}{marker}"
        )
    return "\n".join(lines)


#: Intrinsic cost of any transaction. The charter reports Q2 net of this,
#: because it is paid identically by every protocol and would compress the
#: differences under study.
INTRINSIC_TX_GAS = 21_000


def cost_regime(rows: list[GasRow]) -> str:
    """Which cost model governs each variant: the EIP-7623 floor, or execution.

    The announcement side turned out to be floor-bound, which is what made A2's
    log optimisation worthless. The same question has to be asked of every
    registry, because the answer decides whether an optimisation can help at
    all. A variant sitting on the floor cannot be improved by touching its
    execution; one sitting well above it can.

    R2 is the interesting case. It writes no storage, so a naive
    log-versus-storage estimate would put its saving at the whole of R1's
    ~40 cold SSTOREs — but if its 1217 bytes of calldata put it on the floor,
    the saving is bounded by the floor instead and is smaller than that
    estimate suggests.
    """
    groups: dict[tuple[str, str, str, str], list[GasRow]] = {}
    for row in rows:
        groups.setdefault(
            (row.protocol, row.param_set, row.operation, _variant_of(row)), []
        ).append(row)

    header = (
        f"{'protocol':<12}{'params':<11}{'op':<10}{'variant':<10}"
        f"{'gas':>10}{'floor':>10}{'zero B':>8}{'non-zero':>10}  regime"
    )
    lines = [
        "EIP-7623: is each variant bound by its calldata floor, or by execution?",
        "",
        header,
        "-" * len(header),
    ]

    for key, group in sorted(groups.items()):
        protocol, params, operation, variant = key
        measured = sorted(r.gas_used for r in group if r.gas_used is not None)
        if not measured:
            continue
        median = measured[len(measured) // 2]
        floor = sorted(r.eip7623_floor_gas for r in group)[len(group) // 2]
        calldata = sorted(r.calldata_bytes for r in group)[len(group) // 2]
        tokens = sorted(r.calldata_tokens for r in group)[len(group) // 2]
        # tokens = zero + 4*non_zero, and zero + non_zero = calldata bytes.
        non_zero = (tokens - calldata) // 3
        zero = calldata - non_zero

        floor_bound = all(r.floor_bound for r in group)
        regime = "FLOOR-BOUND" if floor_bound else f"execution ({median / floor:.1f}x floor)"
        lines.append(
            f"{protocol:<12}{params:<11}{operation:<10}{variant:<10}"
            f"{median:>10,}{floor:>10,}{zero:>8,}{non_zero:>10,}  {regime}"
        )
    return "\n".join(lines)


def crossover(rows: list[GasRow]) -> str:
    """Q2's first cut: when do cumulative announcements overtake registration?

    Registration is the largest single cost but is paid once; announcements
    recur. The crossover point is where a protocol's recurring cost equals its
    one-off cost, and it is the number the cumulative curves in M6 are built
    around. Reported net of the intrinsic transaction cost, per the charter.
    """
    groups = _medians(rows)
    registrations: dict[tuple[str, str, str], int] = {}
    announcements: dict[tuple[str, str, str], int] = {}

    for (protocol, params, operation, variant), values in groups.items():
        median = values[len(values) // 2]
        target = registrations if operation == "register" else announcements
        target[(protocol, params, variant)] = median

    measured = {
        (row.protocol, row.param_set, row.registry_variant, row.announcer_variant) for row in rows
    }

    header = (
        f"{'protocol':<12}{'params':<11}{'reg':<10}{'ann':<7}"
        f"{'register':>11}{'announce':>10}{'crossover':>11}"
    )
    lines = [
        "(net of the 21,000 gas intrinsic cost; * = composed, not sent directly)",
        "",
        header,
        "-" * len(header),
    ]

    for (protocol, params, reg_variant), reg_gas in sorted(registrations.items()):
        for (ann_protocol, ann_params, ann_variant), ann_gas in sorted(announcements.items()):
            if (ann_protocol, ann_params) != (protocol, params):
                continue
            reg_net = reg_gas - INTRINSIC_TX_GAS
            ann_net = ann_gas - INTRINSIC_TX_GAS
            payments = reg_net / ann_net if ann_net > 0 else float("inf")
            mark = "" if (protocol, params, reg_variant, ann_variant) in measured else "*"
            lines.append(
                f"{protocol:<12}{params:<11}{reg_variant:<10}{ann_variant + mark:<7}"
                f"{reg_net:>11,}{ann_net:>10,}{payments:>10.1f}x"
            )
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
        "--preflight",
        action="store_true",
        help="verify RPC, deployment, funding and receipt fields, then exit. Sends nothing.",
    )
    parser.add_argument(
        "--estimate",
        action="store_true",
        help="project the run's cost against the live network and exit, sending nothing",
    )
    args = parser.parse_args()

    if args.preflight:
        print(preflight(args.network))
        return

    if args.estimate:
        print(estimate_run_cost(args.network, args.samples))
        return

    rows = run(args.network, args.samples, args.run_label)
    print()
    print(summarise(rows))
    print()
    print(cost_regime(rows))
    print()
    print(crossover(rows))
    print()
    # `run` already checkpointed these after every target; writing once more is
    # cheap and keeps the final file authoritative.
    print(f"written: {write_csv(rows, args.network)}")
    print(f"written: {write_run_meta(args.network, args.samples)}")
    print(f"written: {RESULTS_DIR / f'receipts_{args.network}.jsonl'} (raw receipts, archival)")


if __name__ == "__main__":
    main()
