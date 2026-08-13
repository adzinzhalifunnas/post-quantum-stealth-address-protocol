"""Cumulative cost curves — the headline result.

The charter is explicit that per-operation gas is the wrong unit to report.
Registration is the largest single cost but is paid once; announcements are
small but recur. Which protocol is cheaper therefore depends entirely on how
many payments a recipient receives, and the honest way to say that is a curve:

    C(k) = registration + k * announcement

Everything interesting is where those curves cross. Where does the
post-quantum design overtake ERC-5564? Where does the optimised variant overtake
the naive one? At what usage does the bottleneck move from registration to
announcements? Those crossings are the result; a single gas number is not.

Reads `bench/results/gas_*.csv`, so it reports whatever has actually been
measured — anvil today, the testnets once they are run.

    uv run python -m bench.curves
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path

__all__ = ["Variant", "crossing", "cumulative", "load_variants"]

RESULTS_DIR = Path(__file__).parent / "results"

#: Payment counts the curve is tabulated at. Dense early, where the crossings
#: are, and sparse later where the curves are straight lines.
DEFAULT_POINTS = [0, 1, 2, 5, 10, 20, 31, 50, 100, 200, 500, 1000]


@dataclass(frozen=True)
class Variant:
    """One deployable configuration and its two measured costs."""

    protocol: str
    param_set: str
    registry_variant: str
    announcer_variant: str
    registration_gas: int
    announcement_gas: int

    @property
    def label(self) -> str:
        return (
            f"{self.protocol}/{self.param_set}/" f"{self.registry_variant}+{self.announcer_variant}"
        )

    def cost(self, payments: int) -> int:
        """Total gas after `payments` payments, including registration."""
        return self.registration_gas + payments * self.announcement_gas


def load_variants(path: Path) -> list[Variant]:
    """Build every deployable configuration from a measured results file.

    Registration and announcement are independent transactions, so a registry
    variant and an announcer variant compose into a configuration even when the
    harness never sent that exact pair. This takes the median of each measured
    leg and crosses them.
    """
    registrations: dict[tuple[str, str, str], list[int]] = {}
    announcements: dict[tuple[str, str, str], list[int]] = {}

    with path.open() as handle:
        for row in csv.DictReader(handle):
            if not row.get("gas_used"):
                continue
            gas = int(row["gas_used"])
            key_base = (row["protocol"], row["param_set"])
            if row["operation"] == "register":
                registrations.setdefault((*key_base, row["registry_variant"]), []).append(gas)
            else:
                announcements.setdefault((*key_base, row["announcer_variant"]), []).append(gas)

    def median(values: list[int]) -> int:
        values.sort()
        return values[len(values) // 2]

    variants: list[Variant] = []
    for (protocol, params, reg_variant), reg_values in sorted(registrations.items()):
        for (ann_protocol, ann_params, ann_variant), ann_values in sorted(announcements.items()):
            if (ann_protocol, ann_params) != (protocol, params):
                continue
            variants.append(
                Variant(
                    protocol=protocol,
                    param_set=params,
                    registry_variant=reg_variant,
                    announcer_variant=ann_variant,
                    registration_gas=median(reg_values),
                    announcement_gas=median(ann_values),
                )
            )
    return variants


def cumulative(variants: list[Variant], points: list[int]) -> list[dict[str, object]]:
    """Tabulate C(k) for every variant at every payment count."""
    return [
        {
            "variant": v.label,
            "protocol": v.protocol,
            "param_set": v.param_set,
            "registry_variant": v.registry_variant,
            "announcer_variant": v.announcer_variant,
            "payments": k,
            "cumulative_gas": v.cost(k),
        }
        for v in variants
        for k in points
    ]


def crossing(a: Variant, b: Variant) -> float | None:
    """Payments at which `a` becomes more expensive than `b`.

    Returns None when the lines never cross for a non-negative payment count —
    either because `a` is cheaper everywhere, or dearer everywhere.
    """
    d_reg = a.registration_gas - b.registration_gas
    d_ann = a.announcement_gas - b.announcement_gas

    if d_ann == 0:
        return None
    k = -d_reg / d_ann
    return k if k > 0 else None


def _baseline(variants: list[Variant]) -> Variant | None:
    return next((v for v in variants if v.protocol == "p1_erc5564"), None)


def _format_table(variants: list[Variant], points: list[int]) -> str:
    """Cumulative gas in millions — the raw figures are too wide to line up."""
    header = f"{'variant':<34}" + "".join(f"{k:>9}" for k in points)
    lines = [
        "cumulative gas after k payments, in millions",
        "",
        header,
        "-" * len(header),
    ]
    for v in variants:
        lines.append(f"{v.label:<34}" + "".join(f"{v.cost(k) / 1e6:>9.3f}" for k in points))
    return "\n".join(lines)


def _format_crossings(variants: list[Variant]) -> str:
    baseline = _baseline(variants)
    lines = ["where each variant overtakes the ERC-5564 baseline", ""]
    if baseline is None:
        return "\n".join([*lines, "  no P1 baseline in this results file"])

    lines.append(f"baseline: {baseline.label}")
    lines.append(
        f"  registration {baseline.registration_gas:,}, "
        f"announcement {baseline.announcement_gas:,}"
    )
    lines.append("")
    header = f"{'variant':<34}{'reg ratio':>11}{'ann ratio':>11}{'overtakes P1':>15}"
    lines += [header, "-" * len(header)]

    for v in variants:
        if v is baseline or v.protocol == "p1_erc5564":
            continue
        k = crossing(v, baseline)
        if v.registration_gas >= baseline.registration_gas and (
            v.announcement_gas >= baseline.announcement_gas
        ):
            note = "from payment 0"
        elif k is None:
            note = "never"
        elif k < 1:
            # Starts marginally cheaper than P1 and is overtaken by the first
            # payment. Reporting "0.0" would read as though it never led.
            note = "at payment 1"
        else:
            note = f"after {k:.1f}"
        lines.append(
            f"{v.label:<34}"
            f"{v.registration_gas / baseline.registration_gas:>10.2f}x"
            f"{v.announcement_gas / baseline.announcement_gas:>10.2f}x"
            f"{note:>15}"
        )
    return "\n".join(lines)


def _format_internal_crossings(variants: list[Variant]) -> str:
    """Where P3's own variants overtake each other — the optimisation's payoff."""
    by_label = {v.label: v for v in variants}
    pairs = [
        ("p3_hybrid/mlkem768/R1+A1", "p3_hybrid/mlkem768/R3+A2"),
        ("p3_hybrid/mlkem768/R3+A1", "p3_hybrid/mlkem768/R3+A2"),
        ("p3_hybrid/mlkem768/R3+A2", "p3_hybrid/mlkem512/R3+A2"),
        ("p2_mlwe/mlkem768/mlwe_full+A1", "p3_hybrid/mlkem768/R3+A2"),
    ]
    lines = ["savings between P3 variants, and against the post-quantum baseline", ""]
    for worse_label, better_label in pairs:
        worse, better = by_label.get(worse_label), by_label.get(better_label)
        if worse is None or better is None:
            continue
        for k in (1, 10, 100):
            saving = 1 - better.cost(k) / worse.cost(k)
            lines.append(
                f"  at k={k:>3}: {better_label} saves {saving * 100:5.1f}% against {worse_label}"
            )
        lines.append("")
    return "\n".join(lines).rstrip()


def write_csv(rows: list[dict[str, object]], network: str, path: Path | None = None) -> Path:
    path = path or RESULTS_DIR / f"curves_{network}.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return path


def write_figure(variants: list[Variant], network: str, path: Path | None = None) -> Path | None:
    """Plot the curves. Returns None if matplotlib is unavailable."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:  # pragma: no cover - optional dependency
        return None

    path = path or RESULTS_DIR / f"curves_{network}.png"
    payments = list(range(0, 101))

    figure, axes = plt.subplots(figsize=(10, 6.5))
    for v in variants:
        style = "-" if v.protocol == "p3_hybrid" else "--"
        width = 2.0 if v.registry_variant in {"R3", "erc6538"} else 1.2
        axes.plot(
            payments,
            [v.cost(k) / 1e6 for k in payments],
            style,
            linewidth=width,
            label=v.label,
        )

    axes.set_xlabel("payments received")
    axes.set_ylabel("cumulative gas (millions)")
    axes.set_title(f"Cumulative on-chain cost, {network}")
    axes.grid(alpha=0.3)
    axes.legend(fontsize=7, loc="upper left", ncols=2)
    figure.tight_layout()
    figure.savefig(path, dpi=150)
    plt.close(figure)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", default="anvil")
    args = parser.parse_args()

    source = RESULTS_DIR / f"gas_{args.network}.csv"
    if not source.exists():
        raise SystemExit(f"no measurements at {source}. Run bench.gas first.")

    variants = load_variants(source)
    print(_format_table(variants, DEFAULT_POINTS))
    print()
    print(_format_crossings(variants))
    print()
    print(_format_internal_crossings(variants))
    print()
    print(f"written: {write_csv(cumulative(variants, DEFAULT_POINTS), args.network)}")
    figure = write_figure(variants, args.network)
    if figure:
        print(f"written: {figure}")


if __name__ == "__main__":
    main()
