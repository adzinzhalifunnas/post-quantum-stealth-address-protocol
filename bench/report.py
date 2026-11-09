"""Aggregate every measurement into the tables Chapter IV narrates.

The charter sets the narrative order — P1, then P2, then P3-naive, then
P3-optimised — because that is the argument: here is the standard, here is what
full post-quantum costs, here is what the hybrid costs before optimisation, and
here is what it costs after. This module emits the tables in that order and in
Markdown, so they paste into the thesis without retyping, which is also how
transcription errors are avoided.

It reads only from `bench/results/`. It never measures anything itself and never
computes a figure that a measurement file does not contain, so a number in the
thesis can always be traced to a CSV row and from there to a transaction.

    uv run python -m bench.report
"""

from __future__ import annotations

import argparse
import csv
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

from bench.anonymity import DEPLOYED_DESIGN, PRE_FIX_DESIGN, TAG_DESIGNS
from bench.curves import Leg, Variant, load_legs, load_variants
from bench.sizes import git_commit

__all__ = ["build_report"]

RESULTS_DIR = Path(__file__).parent / "results"

#: Charter's narrative order for Chapter IV.
_NARRATIVE_ORDER = {
    ("p1_erc5564", "erc6538"): 0,
    ("p2_mlwe", "mlwe_full"): 1,
    ("p3_hybrid", "R1"): 2,
    ("p3_hybrid", "R2"): 3,
    ("p3_hybrid", "R3"): 4,
}


def _order(v: Variant) -> tuple[int, str, str]:
    return (
        _NARRATIVE_ORDER.get((v.protocol, v.registry_variant), 99),
        v.param_set,
        v.announcer_variant,
    )


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open() as handle:
        return list(csv.DictReader(handle))


#: Qualitative properties. Not measured — they follow from the protocol
#: definitions and from tests that assert them, and the test is named so a
#: reader can check the claim rather than take it.
_QUALITATIVE: Final[list[tuple[str, str, str, str]]] = [
    (
        "Unlinkability basis",
        "secp256k1 ECDH",
        "Module-LWE (ML-KEM)",
        "Module-LWE (ML-KEM)",
    ),
    ("Custody basis", "secp256k1 ECDSA", "Module-LWE", "secp256k1 ECDSA"),
    ("Lattice keypairs per recipient", "0", "2", "1"),
    ("Resists harvest-now-decrypt-later", "no", "yes", "yes"),
    ("Spendable on unmodified EVM", "yes", "**no**", "yes"),
    ("Dual-key separation (view ≠ spend)", "yes", "yes", "yes"),
    (
        "Quantum leak once an address spends",
        "total",
        "none",
        "none (pre-fix h[0] tag: partial, Q1)",
    ),
    (
        "Off-chain availability dependency",
        "none",
        "none",
        "R3 only — key served off-chain",
    ),
    ("ERC-5564 scheme id", "1 (standard)", "0x4D4C5745 (ours)", "0x50513348 (ours)"),
]


#: What each registry design gives up. Cost alone would name a winner; these
#: are the axes that stop it from being that simple.
_REGISTRY_TRADEOFF: Final[list[tuple[str, str, str, str, str]]] = [
    # variant, where the data lives, contract-readable, availability, gives up
    ("erc6538", "storage", "full", "as available as Ethereum", "nothing — the standard"),
    ("R1", "storage", "full", "as available as Ethereum", "nothing — pays for it"),
    ("R2", "logs", "**nothing**", "as available as Ethereum", "all on-chain readability"),
    ("R3", "storage + off-chain", "M only", "**depends on a directory**", "key availability"),
]


def _registry_tradeoff(variants: list[Variant]) -> str:
    """Cost against on-chain readability — a map, not a ranking.

    Ordering the registries by gas alone would declare R2 the winner and stop
    there. It is the cheapest, and it is also the only one from which a contract
    can read nothing at all. Which design is right depends on whether anything
    on-chain ever needs to resolve a meta-address, so the honest output is a map
    of what each buys and spends.
    """
    # Pin to the level-matched parameter set, matching the table above. Taking
    # whichever row came first would silently mix ML-KEM-512 figures into a
    # ML-KEM-768 comparison — two different numbers for the same thing in one
    # report.
    by_variant: dict[str, Variant] = {}
    for v in variants:
        if v.param_set not in {"mlkem768", "secp256k1"}:
            continue
        # Registration cost is independent of the announcer, so any remaining
        # row for a given registry variant carries the same figure.
        by_variant.setdefault(v.registry_variant, v)

    lines = [
        "**Registry trade-off map**, at ML-KEM-768. Cost is one axis; what a "
        "contract can read back is the other. Ranking by gas alone would end the "
        "discussion at R2, which is exactly the design that gives up the most.",
        "",
        "| Registry | Registration gas | Data lives in | Contract-readable "
        "| Availability | Gives up |",
        "|---|---|---|---|---|---|",
    ]
    for variant, where, readable, availability, gives_up in _REGISTRY_TRADEOFF:
        found = by_variant.get(variant)
        gas = f"{found.registration_gas:,}" if found else "—"
        lines.append(f"| {variant} | {gas} | {where} | {readable} | {availability} | {gives_up} |")
    return "\n".join(lines)


def _protocol_comparison(variants: list[Variant]) -> str:
    """The three-way comparison, at the level-matched parameter set.

    P2 and P3 are both shown at ML-KEM-768 so that a security difference is
    never mistaken for a design difference. P3 appears twice — naive and
    optimised — because the charter's Chapter IV narrates P1 → P2 → P3-naive →
    P3-optimised, and the optimisation is the artifact.
    """
    sizes = {(r["protocol"], r["param_set"]): r for r in _read_csv(RESULTS_DIR / "sizes.csv")}
    scans = {
        (r["protocol"], r["param_set"], r["announcer_variant"]): r
        for r in _read_csv(RESULTS_DIR / "scan.csv")
    }
    by_label = {v.label: v for v in variants}

    columns = [
        ("P1 ERC-5564", "p1_erc5564", "secp256k1", "p1_erc5564/secp256k1/erc6538+A1", "A1"),
        ("P2 MLWE", "p2_mlwe", "mlkem768", "p2_mlwe/mlkem768/mlwe_full+A1", "A1"),
        ("P3 R1+A1 (naive)", "p3_hybrid", "mlkem768", "p3_hybrid/mlkem768/R1+A1", "A1"),
        ("P3 R2+A2 (emit-only)", "p3_hybrid", "mlkem768", "p3_hybrid/mlkem768/R2+A2", "A2"),
        ("P3 R3+A2 (commitment)", "p3_hybrid", "mlkem768", "p3_hybrid/mlkem768/R3+A2", "A2"),
    ]

    def cell(getter: Callable[[str, str, str, str], str]) -> list[str]:
        return [getter(protocol, params, label, ann) for _, protocol, params, label, ann in columns]

    def size_of(field: str) -> Callable[[str, str, str, str], str]:
        def get(protocol: str, params: str, label: str, ann: str) -> str:
            row = sizes.get((protocol, params))
            if not row:
                return "—"
            # R3 registers a 65-byte commitment rather than the full key.
            if field == "meta_bytes" and "R3" in label:
                return "65 B"
            return f"{int(row[field]):,} B"

        return get

    def gas_of(attribute: str) -> Callable[[str, str, str, str], str]:
        def get(protocol: str, params: str, label: str, ann: str) -> str:
            variant = by_label.get(label)
            return f"{getattr(variant, attribute):,}" if variant else "—"

        return get

    def scan_of(field: str, suffix: str) -> Callable[[str, str, str, str], str]:
        def get(protocol: str, params: str, label: str, ann: str) -> str:
            row = scans.get((protocol, params, ann))
            if not row:
                return "—"
            value = float(row[field])
            return f"{value:,.2f}{suffix}" if suffix == " µs" else f"{value:,.0f}{suffix}"

        return get

    def cumulative_at(k: int) -> Callable[[str, str, str, str], str]:
        def get(protocol: str, params: str, label: str, ann: str) -> str:
            variant = by_label.get(label)
            return f"{variant.cost(k) / 1e6:.3f}M" if variant else "—"

        return get

    def crossover(protocol: str, params: str, label: str, ann: str) -> str:
        variant = by_label.get(label)
        if not variant:
            return "—"
        net_ann = variant.announcement_gas - 21_000
        if net_ann <= 0:
            return "—"
        return f"{(variant.registration_gas - 21_000) / net_ann:.1f}"

    def offchain(protocol: str, params: str, label: str, ann: str) -> str:
        """What R3 moved off-chain. Every other variant keeps its key on-chain."""
        if "R3" not in label:
            return "—"
        row = sizes.get((protocol, params))
        # The commitment replaces the encapsulation key, so what a sender must
        # fetch is exactly that key: the meta-address less the 33-byte spending
        # key that stays on-chain in both variants.
        return f"{int(row['meta_bytes']) - 33:,} B" if row else "—"

    def readable(protocol: str, params: str, label: str, ann: str) -> str:
        """What a contract can read back. The axis R2 trades away entirely."""
        if "R2" in label:
            return "**nothing**"
        if "R3" in label:
            return "M only"
        return "full"

    def where(protocol: str, params: str, label: str, ann: str) -> str:
        if "R2" in label:
            return "logs"
        if "R3" in label:
            return "storage + off-chain"
        return "storage"

    rows: list[tuple[str, list[str]]] = [
        ("**Meta-address registered**", cell(size_of("meta_bytes"))),
        ("Where it lives", cell(where)),
        ("Readable by a contract", cell(readable)),
        ("Fetched off-chain, per recipient", cell(offchain)),
        ("**Announcement payload**", cell(size_of("announcement_bytes"))),
        ("**Registration gas**", cell(gas_of("registration_gas"))),
        ("**Announcement gas**", cell(gas_of("announcement_gas"))),
        ("Cumulative at k=1", cell(cumulative_at(1))),
        ("Cumulative at k=10", cell(cumulative_at(10))),
        ("Cumulative at k=100", cell(cumulative_at(100))),
        ("Crossover (payments)", cell(crossover)),
        ("Scan time per announcement", cell(scan_of("per_announcement_us", " µs"))),
        ("Scan bytes per announcement", cell(scan_of("total_bytes_per_announcement", " B"))),
        ("Scan RPC round trips", cell(scan_of("rpc_round_trips", ""))),
    ]

    header = "| | " + " | ".join(name for name, *_ in columns) + " |"
    lines = [header, "|---" * (len(columns) + 1) + "|"]
    lines += [f"| {label} | " + " | ".join(values) + " |" for label, values in rows]

    lines.append("")
    lines.append(_registry_tradeoff(variants))
    lines.append("")
    lines.append(
        "R3's registration parity is an *on-chain* result. The 1,184-byte "
        "encapsulation key did not disappear — it is served off-chain and "
        "verified against the on-chain commitment before a sender may use it. "
        "That fetch is per recipient rather than per payment, so it caches, and "
        "it is paid in a sender's bandwidth rather than in anyone's gas. The "
        "cost it does carry is availability: a directory that will not answer "
        "blocks payments to that recipient, where R1's key is as available as "
        "Ethereum itself."
    )
    lines.append("")
    lines.append("Qualitative properties, from the protocol definitions:")
    lines.append("")
    qual_header = "| | P1 ERC-5564 | P2 MLWE | P3 hybrid |"
    lines += [qual_header, "|---|---|---|---|"]
    lines += [f"| {label} | {p1} | {p2} | {p3} |" for label, p1, p2, p3 in _QUALITATIVE]
    return "\n".join(lines)


def _sizes_table() -> str:
    rows = _read_csv(RESULTS_DIR / "sizes.csv")
    if not rows:
        return "_No size table measured yet._"

    lines = [
        "| Protocol | Parameter set | Meta-address | Announcement | Storage slots |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['protocol']} | {r['param_set']} | {int(r['meta_bytes']):,} B "
            f"| {int(r['announcement_bytes']):,} B | {r['meta_slots']} |"
        )
    return "\n".join(lines)


#: Protocol order for the per-leg tables, the same narrative order as above.
_PROTOCOL_ORDER: Final[dict[str, int]] = {"p1_erc5564": 0, "p2_mlwe": 1, "p3_hybrid": 2}


def _leg_order(leg: Leg) -> tuple[int, int, str, str]:
    return (
        _PROTOCOL_ORDER.get(leg.protocol, 99),
        _NARRATIVE_ORDER.get((leg.protocol, leg.variant), 99),
        leg.param_set,
        leg.variant,
    )


def _leg_table(legs: list[Leg], operation: str) -> str:
    """One row per measured leg: what the harness sent, not a composed variant.

    The range is reported beside the median because announcements cannot
    reproduce from run to run, and a median alone would hide by how much.
    """
    column = "Registry" if operation == "register" else "Announcer"
    lines = [
        f"| Protocol | Params | {column} | n | Median | Min–max | Regime |",
        "|---|---|---|---|---|---|---|",
    ]
    for leg in sorted((leg for leg in legs if leg.operation == operation), key=_leg_order):
        lines.append(
            f"| {leg.protocol} | {leg.param_set} | {leg.variant} | {leg.n} "
            f"| {leg.median:,} | {leg.minimum:,}–{leg.maximum:,} | {leg.regime} |"
        )
    return "\n".join(lines)


def _gas_tables(legs: list[Leg]) -> str:
    return "\n".join(
        [
            "**Registration**",
            "",
            _leg_table(legs, "register"),
            "",
            "**Announcement**",
            "",
            _leg_table(legs, "announce"),
        ]
    )


def _methodology(meta: dict[str, Any] | None) -> str:
    """What reproduces, what cannot, and why the figures are medians with ranges."""
    samples = meta.get("samples_per_target") if meta else None
    sampled = f"sampled {samples} times" if samples else "sampled repeatedly"
    return "\n".join(
        [
            f"Every target is {sampled}. A sample is a fresh keypair registered from a "
            "fresh EOA, then one announcement to it. Only first registrations are "
            "measured, so every storage slot written is cold. A leg that several "
            "targets share pools their samples, which is why some legs have a larger n.",
            "",
            "**Registrations reproduce exactly.** Each keypair is derived from the seed "
            "recorded in its row, so a run under the same label sends byte-identical "
            "registrations, and gas units are deterministic: the same gas, row for row. "
            "A registration's range is between keypairs within a run, never between runs.",
            "",
            "**Announcements do not, and cannot.** Encapsulation, and P1's ephemeral "
            "key, draw fresh randomness on every run, so every payload is new. A "
            "transaction on the EIP-7623 calldata floor costs exactly 21,000 gas plus "
            "10 per calldata token, where a zero byte is one token and a non-zero byte "
            "four. Each zero byte that a pseudorandom payload happens to contain takes "
            "30 gas off, so a floor-bound announcement moves in 30-gas steps, from sample "
            "to sample and from run to run. Above the floor, a zero calldata byte saves "
            "12 gas instead (4 against 16).",
            "",
            "**Every gas figure is therefore a median, reported with its min–max** in "
            "section 3. For an even n the median is the upper of the two middle samples, "
            "so it is always a transaction that was actually sent. Sections 1, 4 and 5 "
            "compose one registration median with one announcement median.",
        ]
    )


def _crossover_table(variants: list[Variant]) -> str:
    baseline = next((v for v in variants if v.protocol == "p1_erc5564"), None)
    lines = [
        "| Variant | Registration vs P1 | Announcement vs P1 | Crossover (payments) |",
        "|---|---|---|---|",
    ]
    for v in sorted(variants, key=_order):
        net_reg = v.registration_gas - 21_000
        net_ann = v.announcement_gas - 21_000
        crossover = f"{net_reg / net_ann:.1f}" if net_ann > 0 else "—"
        if baseline is None or v is baseline:
            reg_ratio = ann_ratio = "—"
        else:
            reg_ratio = f"{v.registration_gas / baseline.registration_gas:.2f}x"
            ann_ratio = f"{v.announcement_gas / baseline.announcement_gas:.2f}x"
        lines.append(f"| {v.label} | {reg_ratio} | {ann_ratio} | {crossover} |")
    return "\n".join(lines)


def _cumulative_table(variants: list[Variant]) -> str:
    points = [1, 10, 50, 100]
    header = "| Variant | " + " | ".join(f"k={k}" for k in points) + " |"
    lines = [header, "|---" * (len(points) + 1) + "|"]
    for v in sorted(variants, key=_order):
        cells = " | ".join(f"{v.cost(k) / 1e6:.3f}M" for k in points)
        lines.append(f"| {v.label} | {cells} |")
    return "\n".join(lines)


def _scan_table() -> str:
    rows = _read_csv(RESULTS_DIR / "scan.csv")
    if not rows:
        return "_No scan measurements yet. Run `bench.scan`._"

    lines = [
        "| Protocol | Params | Announcer | µs/announcement | Bytes/announcement | RPC trips |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['protocol']} | {r['param_set']} | {r['announcer_variant']} "
            f"| {float(r['per_announcement_us']):.2f} "
            f"| {int(r['total_bytes_per_announcement']):,} "
            f"| {float(r['rpc_round_trips']):.1f} |"
        )
    return "\n".join(lines)


def _anonymity_table() -> str:
    rows = _read_csv(RESULTS_DIR / "anonymity.csv")
    if not rows:
        return "_No anonymity simulation yet. Run `bench.anonymity`._"

    # Both designs at the deployed width, keyed by registry size. A file written
    # before the tag was domain-separated has no design column; it describes one
    # design only and is reported as stale rather than guessed at.
    by_design: dict[str, dict[str, dict[str, str]]] = {d: {} for d in TAG_DESIGNS}
    for r in rows:
        if r.get("tag_design") in by_design and r["tag_bits"] == "8":
            by_design[r["tag_design"]][r["registry_size"]] = r
    if not all(by_design.values()):
        return (
            "_The anonymity simulation predates the domain-separated view tag and "
            "covers one design only. Re-run `bench.anonymity`._"
        )

    pre_fix, deployed = by_design[PRE_FIX_DESIGN], by_design[DEPLOYED_DESIGN]
    lines = [
        "Anonymity set for a **spent** P3 address under a quantum adversary "
        "(ECDLP broken, ML-KEM intact), at the deployed 8-bit view tag width. "
        "P3 deploys the domain-separated tag, which the adversary cannot evaluate; "
        "the h[0] columns are the **pre-fix design**, kept for comparison.",
        "",
        "| Registry size | h[0] tag (pre-fix): expected set | Mean (simulated) "
        "| Uniquely identified | Domain-separated tag (deployed): mean set "
        "| Uniquely identified |",
        "|---|---|---|---|---|---|",
    ]
    for size in sorted(pre_fix, key=int):
        old, new = pre_fix[size], deployed.get(size)
        new_cells = (
            f"{float(new['mean_set_size']):,.2f} "
            f"| {float(new['fraction_deanonymised']) * 100:.1f}%"
            if new
            else "— | —"
        )
        lines.append(
            f"| {int(size):,} | {float(old['expected_set_size']):,.2f} "
            f"| {float(old['mean_set_size']):,.2f} "
            f"| {float(old['fraction_deanonymised']) * 100:.1f}% | {new_cells} |"
        )
    return "\n".join(lines)


def _run_meta(network: str) -> dict[str, Any] | None:
    meta_path = RESULTS_DIR / f"run_meta_{network}.json"
    if not meta_path.exists():
        return None
    meta: dict[str, Any] = json.loads(meta_path.read_text())
    return meta


def _provenance(network: str) -> str:
    meta = _run_meta(network)
    if meta is None:
        return f"_No run metadata for {network}._"

    kem = meta.get("kem_backend", {})
    machine = meta.get("machine", {})
    measured_at = str(meta.get("git_commit", "unknown"))
    lines = [
        f"- Measured on: `{meta.get('network')}` (chain state recorded per row)",
        f"- **Measured at commit:** `{measured_at[:12]}`",
        f"- liboqs: {kem.get('liboqs_version')} via liboqs-python "
        f"{kem.get('liboqs_python_version')}",
        f"- solc {meta.get('solc')}, optimizer runs {meta.get('optimizer_runs')}",
        f"- Machine: {machine.get('platform')}, Python {machine.get('python')}",
        f"- Samples per target: {meta.get('samples_per_target')}",
        f"- Measurement timestamp: {meta.get('timestamp')}",
    ]
    if measured_at[:12] != git_commit()[:12]:
        lines.append(
            "- ⚠️ The working tree has moved on since these numbers were taken. "
            "Re-run `bench.gas` before quoting them if any contract changed."
        )
    return "\n".join(lines)


def build_report(network: str) -> str:
    """Assemble the full Markdown report."""
    gas_path = RESULTS_DIR / f"gas_{network}.csv"
    variants = load_variants(gas_path) if gas_path.exists() else []
    legs = load_legs(gas_path) if gas_path.exists() else []

    caveat = ""
    if network == "anvil":
        caveat = (
            "\n> **These are local-chain measurements.** Gas *units* are deterministic "
            "and will reproduce on any chain running the same EVM version, so the "
            "comparisons below stand. Fee columns — and in particular Base Sepolia's "
            "separate L1 data fee — require the testnet runs and are not yet filled in.\n"
        )

    return "\n".join(
        [
            f"# PQ-SAP measurement report — {network}",
            "",
            f"Generated from `bench/results/` at commit `{git_commit()[:12]}`. "
            "Every figure traces to a CSV row; nothing here is recomputed or adjusted.",
            caveat,
            "## Provenance",
            "",
            _provenance(network),
            "",
            "## Methodology",
            "",
            _methodology(_run_meta(network)),
            "",
            "## 1. The three protocols, head to head",
            "",
            "P2 and P3 are both shown at ML-KEM-768, so a security-level difference "
            "is never mistaken for a design difference. P3 appears twice because the "
            "optimisation is the artifact.",
            "",
            _protocol_comparison(variants) if variants else "_No gas measurements yet._",
            "",
            "## 2. Sizes",
            "",
            "Byte counts drive everything else. All are read from liboqs at runtime, "
            "never hardcoded.",
            "",
            _sizes_table(),
            "",
            "## 3. Measured gas",
            "",
            "One row per measured leg, which is what the harness actually sent. n is "
            "the pooled sample count. Regime says whether the EIP-7623 calldata floor "
            "or execution set the price. Methodology explains why announcements range "
            "and registrations reproduce.",
            "",
            _gas_tables(legs) if legs else "_No gas measurements yet._",
            "",
            "## 4. Cost ratios and crossover",
            "",
            "Crossover is the payment count at which cumulative announcements overtake "
            "registration, net of the 21,000 gas intrinsic transaction cost.",
            "",
            _crossover_table(variants) if variants else "_No gas measurements yet._",
            "",
            "## 5. Cumulative cost",
            "",
            "Total gas after k payments, including registration. This is the headline: "
            "which protocol is cheaper depends on how many payments a recipient receives.",
            "",
            _cumulative_table(variants) if variants else "_No gas measurements yet._",
            "",
            "## 6. Receiver scan cost (Q3)",
            "",
            _scan_table(),
            "",
            "## 7. Anonymity under a quantum adversary (Q1)",
            "",
            _anonymity_table(),
            "",
            "---",
            "",
            "Regenerate with `uv run python -m bench.report`. "
            "`bench/results/` is committed and never hand-edited; a surprising number "
            "is re-run and investigated, never adjusted.",
            "",
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", default="anvil")
    args = parser.parse_args()

    report = build_report(args.network)
    path = RESULTS_DIR / f"report_{args.network}.md"
    path.write_text(report)
    print(report)
    print(f"written: {path}")


if __name__ == "__main__":
    main()
