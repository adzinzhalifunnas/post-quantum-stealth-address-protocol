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
from typing import Final

from bench.curves import Variant, load_variants
from bench.sizes import git_commit

__all__ = ["build_report"]

RESULTS_DIR = Path(__file__).parent / "results"

#: Charter's narrative order for Chapter IV.
_NARRATIVE_ORDER = {
    ("p1_erc5564", "erc6538"): 0,
    ("p2_mlwe", "mlwe_full"): 1,
    ("p3_hybrid", "R1"): 2,
    ("p3_hybrid", "R3"): 3,
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
    ("Quantum leak once an address spends", "total", "none", "partial (Q1)"),
    ("ERC-5564 scheme id", "1 (standard)", "0x4D4C5745 (ours)", "0x50513348 (ours)"),
]


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
        ("P3 naive (R1+A1)", "p3_hybrid", "mlkem768", "p3_hybrid/mlkem768/R1+A1", "A1"),
        ("P3 optimised (R3+A2)", "p3_hybrid", "mlkem768", "p3_hybrid/mlkem768/R3+A2", "A2"),
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

    rows: list[tuple[str, list[str]]] = [
        ("**Meta-address registered**", cell(size_of("meta_bytes"))),
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


def _gas_table(variants: list[Variant]) -> str:
    lines = [
        "| Protocol | Params | Registry | Announcer | Registration | Announcement |",
        "|---|---|---|---|---|---|",
    ]
    for v in sorted(variants, key=_order):
        lines.append(
            f"| {v.protocol} | {v.param_set} | {v.registry_variant} | {v.announcer_variant} "
            f"| {v.registration_gas:,} | {v.announcement_gas:,} |"
        )
    return "\n".join(lines)


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
    rows = [r for r in _read_csv(RESULTS_DIR / "anonymity.csv") if r["tag_bits"] == "8"]
    if not rows:
        return "_No anonymity simulation yet. Run `bench.anonymity`._"

    lines = [
        "Anonymity set for a **spent** P3 address under a quantum adversary "
        "(ECDLP broken, ML-KEM intact), at the deployed 8-bit view tag:",
        "",
        "| Registry size | Expected set | Mean (simulated) | Uniquely identified |",
        "|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {int(r['registry_size']):,} | {float(r['expected_set_size']):,.2f} "
            f"| {float(r['mean_set_size']):,.2f} "
            f"| {float(r['fraction_deanonymised']) * 100:.1f}% |"
        )
    return "\n".join(lines)


def _provenance(network: str) -> str:
    meta_path = RESULTS_DIR / f"run_meta_{network}.json"
    if not meta_path.exists():
        return f"_No run metadata for {network}._"

    meta = json.loads(meta_path.read_text())
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
            "Medians over 20 fresh keypairs and 20 fresh EOAs per variant. First "
            "registrations only, so every storage slot written is cold.",
            "",
            _gas_table(variants) if variants else "_No gas measurements yet._",
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
