"""Q1 — what a quantum adversary learns from a *spent* P3 stealth address.

This leak is specific to P3 and is not analysed anywhere in the literature, so
the charter asks for an argued analysis plus a numerical simulation of
anonymity-set size, explicitly not a formal proof.

**The threat.** Assume an adversary who has broken ECDLP but not ML-KEM — the
exact position a hybrid design creates, since P3 keeps custody on secp256k1
while moving unlinkability to a lattice. While a stealth address merely
*receives*, the adversary sees only an address, and addresses are hashes: there
is nothing to attack. The moment it *spends*, its ECDSA signature reveals the
full public key P. Now, for every registered meta-address M_j, the adversary can
compute h_j = dlog(P - M_j).

**Why that alone reveals nothing.** Every candidate yields *a* valid discrete
log. h_j exists for all j, so without more information the adversary cannot tell
which M_j actually received the payment. The anonymity set is the entire
registry.

**Why the view tag leaks.** The announcement publishes an 8-bit tag equal to
byte 0 of keccak256(S), and the adversary can compute keccak256 of anything. For
each candidate M_j it derives h_j, and only candidates whose derived tag matches
the published one survive. The true recipient always survives; each other
registrant survives with probability 2^-t. The anonymity set collapses from N to
roughly 1 + (N-1)/2^t.

That is the trade the view tag makes, and it is a trade ERC-5564 also makes —
but for P1 the point is moot, because an adversary who has broken ECDLP can
simply solve the ECDH directly and identify the recipient outright. P3's leak is
therefore *partial* where P1's is total, and P2 has no such leak at all, since
its stealth key is a lattice element with no discrete log to take.

    uv run python -m bench.anonymity
"""

from __future__ import annotations

import argparse
import csv
import random
import statistics
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from bench.sizes import git_commit

__all__ = ["AnonymityRow", "expected_set_size", "run", "simulate"]

RESULTS_DIR = Path(__file__).parent / "results"

#: The view-tag width this protocol actually uses: one byte, per ERC-5564.
DEPLOYED_TAG_BITS = 8

#: Registry sizes to sweep. Ethereum has on the order of 10^8 addresses ever
#: used; a stealth registry realistically sits far below that, so this spans
#: from a niche deployment to an implausibly popular one.
DEFAULT_REGISTRY_SIZES = [100, 1_000, 10_000, 100_000, 1_000_000]

#: Tag widths to compare. 0 is the no-tag baseline, where nothing leaks; 8 is
#: what is deployed; the rest show how sharply the leak worsens with width.
DEFAULT_TAG_BITS = [0, 4, 8, 12, 16]


@dataclass(frozen=True)
class AnonymityRow:
    """Anonymity-set size for one registry size and tag width."""

    git_commit: str
    registry_size: int
    tag_bits: int
    trials: int
    expected_set_size: float
    mean_set_size: float
    median_set_size: float
    p95_set_size: float
    max_set_size: int
    #: Fraction of trials where the recipient was uniquely identified.
    fraction_deanonymised: float


def expected_set_size(registry_size: int, tag_bits: int) -> float:
    """1 + (N-1)/2^t — the true recipient, plus survivors of the tag filter."""
    if registry_size < 1:
        raise ValueError("registry must contain at least the recipient")
    return 1.0 + (registry_size - 1) / float(2**tag_bits)


def simulate(registry_size: int, tag_bits: int, trials: int, seed: int = 20260813) -> AnonymityRow:
    """Draw anonymity-set sizes rather than trusting the closed form.

    Each non-recipient registrant survives the tag filter independently with
    probability 2^-t, because the tag it derives is a keccak256 byte of a value
    it does not control. The number of survivors is therefore Binomial(N-1,
    2^-t), sampled here exactly — not enumerated per registrant, which would be
    hopeless at N = 10^6 — and the closed form is reported alongside as a check.

    Seeded, so the table in the thesis regenerates byte-for-byte.
    """
    rng = random.Random(seed + registry_size * 31 + tag_bits)
    others = registry_size - 1
    survival = 2.0**-tag_bits
    sizes: list[int] = []

    for _ in range(trials):
        # tag_bits == 0 is the no-tag baseline: nothing is filtered, so the
        # anonymity set is the whole registry.
        extra = others if tag_bits == 0 else rng.binomialvariate(others, survival)
        sizes.append(1 + extra)

    sizes.sort()
    return AnonymityRow(
        git_commit=git_commit(),
        registry_size=registry_size,
        tag_bits=tag_bits,
        trials=trials,
        expected_set_size=round(expected_set_size(registry_size, tag_bits), 4),
        mean_set_size=round(statistics.fmean(sizes), 4),
        median_set_size=float(sizes[len(sizes) // 2]),
        p95_set_size=float(sizes[min(len(sizes) - 1, int(len(sizes) * 0.95))]),
        max_set_size=sizes[-1],
        fraction_deanonymised=round(sum(1 for s in sizes if s == 1) / len(sizes), 4),
    )


def run(registry_sizes: list[int], tag_widths: list[int], trials: int) -> list[AnonymityRow]:
    return [simulate(size, bits, trials) for size in registry_sizes for bits in tag_widths]


def write_csv(rows: list[AnonymityRow], path: Path | None = None) -> Path:
    path = path or RESULTS_DIR / "anonymity.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[f.name for f in fields(AnonymityRow)])
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))
    return path


def _format(rows: list[AnonymityRow]) -> str:
    header = (
        f"{'registry N':>11}{'tag bits':>10}{'expected':>13}{'mean':>13}"
        f"{'median':>11}{'p95':>10}{'unique?':>10}"
    )
    lines = [
        "anonymity set for a SPENT P3 address, quantum adversary (ECDLP broken, ML-KEM intact)",
        "",
        header,
        "-" * len(header),
    ]
    for r in rows:
        lines.append(
            f"{r.registry_size:>11,}{r.tag_bits:>10}{r.expected_set_size:>13,.2f}"
            f"{r.mean_set_size:>13,.2f}{r.median_set_size:>11,.0f}{r.p95_set_size:>10,.0f}"
            f"{r.fraction_deanonymised * 100:>9.1f}%"
        )
    return "\n".join(lines)


def _commentary(rows: list[AnonymityRow]) -> str:
    deployed = [r for r in rows if r.tag_bits == DEPLOYED_TAG_BITS]
    lines = [
        "Reading this table.",
        "",
        "  'unique?' is how often the adversary is left with exactly one candidate,",
        "  i.e. full deanonymisation of a spent address.",
        "",
        f"At the deployed {DEPLOYED_TAG_BITS}-bit tag:",
    ]
    for r in deployed:
        lines.append(
            f"  N = {r.registry_size:>9,}  ->  {r.mean_set_size:>8.1f} candidates on average, "
            f"unique in {r.fraction_deanonymised * 100:.1f}% of cases"
        )

    small = next((r for r in deployed if r.registry_size == 100), None)
    large = next((r for r in deployed if r.registry_size == 1_000_000), None)
    lines += [
        "",
        "What this means for the design.",
        "",
        "  The leak is real but bounded, and it scales the right way: it is worst",
        "  for a small registry and negligible for a large one. An 8-bit tag divides",
        "  the anonymity set by 256, so a protocol with few users protects a spent",
        "  address poorly and one with many users protects it well.",
    ]
    if small and large:
        lines.append(
            f"  At N=100 the adversary is often left with a single candidate "
            f"({small.fraction_deanonymised * 100:.0f}% of the time); at N=1,000,000 it faces "
            f"about {large.mean_set_size:.0f}."
        )
    lines += [
        "",
        "  Three scope limits, all of which belong in the thesis text:",
        "",
        "  1. Only SPENT addresses leak. An address that has merely received has",
        "     published no public key, so there is no discrete log to take and the",
        "     anonymity set is untouched. Most stealth addresses in a payment",
        "     workload are unspent at any given time.",
        "  2. This is P3's leak alone. P2 is structurally immune, its stealth key",
        "     being a lattice element with no discrete log. P1 is far worse off, not",
        "     better: an adversary who has broken ECDLP recovers the ECDH secret",
        "     directly and identifies the recipient outright, tag or no tag.",
        "  3. The tag is not optional. Removing it would close this leak entirely,",
        "     at the cost of an elliptic-curve operation on every announcement",
        "     during scanning rather than on one in 256 — see bench/scan.py for what",
        "     that costs. The 8-bit width is inherited from ERC-5564, and this",
        "     analysis quantifies what it buys and what it spends.",
        "",
        "  Argued analysis plus simulation, per the charter's bounded scope. Not a",
        "  formal proof, and it should not be cited as one.",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=2000)
    args = parser.parse_args()

    rows = run(DEFAULT_REGISTRY_SIZES, DEFAULT_TAG_BITS, args.trials)
    print(_format(rows))
    print()
    print(_commentary(rows))
    print()
    print(f"written: {write_csv(rows)}")


if __name__ == "__main__":
    main()
