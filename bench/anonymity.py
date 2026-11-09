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

**Why the pre-fix tag leaked.** P3 originally published an 8-bit view tag equal
to byte 0 of keccak256(S) — the digest h is read from, exactly as ERC-5564 does.
Holding h_j, the adversary therefore had each candidate's tag for free, and only
candidates whose tag matched the published one survived. The true recipient
always survives; each other registrant survives with probability 2^-t. The
anonymity set collapses from N to roughly 1 + (N-1)/2^t.

**Why the deployed tag does not.** P3 now publishes
keccak256("pq-sap/p3/view-tag/v1" || S)[0], with h unchanged. The tag is a
function of S, and the adversary holds h_j = keccak256(S) mod n, never S:
keccak256 does not invert, and S is protected by ML-KEM, which this adversary has
not broken. It cannot evaluate any candidate's tag, so the tag filters nothing
and every registrant remains a candidate. The anonymity set is N, at every tag
width.

The h[0] tag is ERC-5564's rule, so the standard makes the same trade — but for
P1 the point is moot, because an adversary who has broken ECDLP can simply solve
the ECDH directly and identify the recipient outright. P3's leak was therefore
*partial* where P1's is total; with the domain-separated tag P3 has none, and P2
never had one, since its stealth key is a lattice element with no discrete log
to take.

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

__all__ = [
    "DEPLOYED_DESIGN",
    "PRE_FIX_DESIGN",
    "TAG_DESIGNS",
    "AnonymityRow",
    "adversary_can_evaluate_tag",
    "expected_set_size",
    "run",
    "simulate",
]

RESULTS_DIR = Path(__file__).parent / "results"

#: The view-tag width this protocol actually uses: one byte, per ERC-5564.
DEPLOYED_TAG_BITS = 8

#: Registry sizes to sweep. Ethereum has on the order of 10^8 addresses ever
#: used; a stealth registry realistically sits far below that, so this spans
#: from a niche deployment to an implausibly popular one.
DEFAULT_REGISTRY_SIZES = [100, 1_000, 10_000, 100_000, 1_000_000]

#: Tag widths to compare. 0 is the no-tag baseline, where nothing leaks; 8 is
#: what is deployed; the rest show how sharply the pre-fix leak worsens with
#: width. Under the domain-separated design every width gives N, which is itself
#: the finding: width then matters to scan speed only, not to Q1.
DEFAULT_TAG_BITS = [0, 4, 8, 12, 16]

#: The pre-fix design: tag = byte 0 of keccak256(S), the digest h is read from.
#: Still ERC-5564's rule, and still P1's.
PRE_FIX_DESIGN = "h0"
#: What P3 deploys: tag = keccak256("pq-sap/p3/view-tag/v1" || S)[0].
DEPLOYED_DESIGN = "domain_separated"
#: Both, pre-fix first, so its rows keep the positions they had before the fix.
TAG_DESIGNS = [PRE_FIX_DESIGN, DEPLOYED_DESIGN]

_DESIGN_LABELS = {
    PRE_FIX_DESIGN: "h[0] tag (pre-fix)",
    DEPLOYED_DESIGN: "domain-separated tag (deployed)",
}


@dataclass(frozen=True)
class AnonymityRow:
    """Anonymity-set size for one tag design, registry size and tag width."""

    git_commit: str
    tag_design: str
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


def adversary_can_evaluate_tag(tag_design: str) -> bool:
    """Whether A4, holding h_j for every candidate, can compute each one's tag."""
    if tag_design == PRE_FIX_DESIGN:
        # The tag is a byte of the very digest h is read from, so h_j gives it.
        return True
    if tag_design == DEPLOYED_DESIGN:
        # The tag needs S itself. h_j = keccak256(S) mod n does not invert, and
        # S is protected by ML-KEM, which this adversary has not broken.
        return False
    raise ValueError(f"unknown tag design {tag_design!r}")


def expected_set_size(registry_size: int, tag_bits: int, *, tag_design: str) -> float:
    """The true recipient plus everyone the tag filter fails to remove.

    1 + (N-1)/2^t when the adversary can evaluate the tag; N when it cannot.
    """
    if registry_size < 1:
        raise ValueError("registry must contain at least the recipient")
    if not adversary_can_evaluate_tag(tag_design):
        return float(registry_size)
    return 1.0 + (registry_size - 1) / float(2**tag_bits)


def simulate(
    registry_size: int, tag_bits: int, trials: int, *, tag_design: str, seed: int = 20260813
) -> AnonymityRow:
    """Draw anonymity-set sizes rather than trusting the closed form.

    Each non-recipient registrant survives the tag filter independently with
    probability 2^-t, because the tag it derives is a keccak256 byte of a value
    it does not control. The number of survivors is therefore Binomial(N-1,
    2^-t), sampled here exactly — not enumerated per registrant, which would be
    hopeless at N = 10^6 — and the closed form is reported alongside as a check.

    That holds only while the adversary can evaluate the tag. Under the
    domain-separated design it cannot, so nobody is filtered out and every
    trial leaves the whole registry.

    Seeded, so the table in the thesis regenerates byte-for-byte. The seed does
    not depend on the design, and the pre-fix design draws exactly what it drew
    before the deployed one existed, so its rows reproduce the earlier table.
    """
    rng = random.Random(seed + registry_size * 31 + tag_bits)
    others = registry_size - 1
    survival = 2.0**-tag_bits
    filtering = adversary_can_evaluate_tag(tag_design)
    sizes: list[int] = []

    for _ in range(trials):
        # No usable filter — no tag at all, or a tag the adversary cannot
        # evaluate — leaves every other registrant a candidate.
        unfiltered = not filtering or tag_bits == 0
        extra = others if unfiltered else rng.binomialvariate(others, survival)
        sizes.append(1 + extra)

    sizes.sort()
    return AnonymityRow(
        git_commit=git_commit(),
        tag_design=tag_design,
        registry_size=registry_size,
        tag_bits=tag_bits,
        trials=trials,
        expected_set_size=round(
            expected_set_size(registry_size, tag_bits, tag_design=tag_design), 4
        ),
        mean_set_size=round(statistics.fmean(sizes), 4),
        median_set_size=float(sizes[len(sizes) // 2]),
        p95_set_size=float(sizes[min(len(sizes) - 1, int(len(sizes) * 0.95))]),
        max_set_size=sizes[-1],
        fraction_deanonymised=round(sum(1 for s in sizes if s == 1) / len(sizes), 4),
    )


def run(
    registry_sizes: list[int],
    tag_widths: list[int],
    trials: int,
    tag_designs: list[str] = TAG_DESIGNS,
) -> list[AnonymityRow]:
    return [
        simulate(size, bits, trials, tag_design=design)
        for design in tag_designs
        for size in registry_sizes
        for bits in tag_widths
    ]


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
        f"{'tag design':<33}{'registry N':>11}{'tag bits':>10}{'expected':>13}{'mean':>13}"
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
            f"{_DESIGN_LABELS[r.tag_design]:<33}"
            f"{r.registry_size:>11,}{r.tag_bits:>10}{r.expected_set_size:>13,.2f}"
            f"{r.mean_set_size:>13,.2f}{r.median_set_size:>11,.0f}{r.p95_set_size:>10,.0f}"
            f"{r.fraction_deanonymised * 100:>9.1f}%"
        )
    return "\n".join(lines)


def _commentary(rows: list[AnonymityRow]) -> str:
    lines = [
        "Reading this table.",
        "",
        "  'unique?' is how often the adversary is left with exactly one candidate,",
        "  i.e. full deanonymisation of a spent address.",
    ]
    deployed_tag = {
        design: [r for r in rows if r.tag_design == design and r.tag_bits == DEPLOYED_TAG_BITS]
        for design in TAG_DESIGNS
    }
    for design, design_rows in deployed_tag.items():
        lines += ["", f"At the deployed {DEPLOYED_TAG_BITS}-bit width, {_DESIGN_LABELS[design]}:"]
        for r in design_rows:
            lines.append(
                f"  N = {r.registry_size:>9,}  ->  {r.mean_set_size:>10,.1f} candidates on "
                f"average, unique in {r.fraction_deanonymised * 100:.1f}% of cases"
            )

    pre_fix = deployed_tag[PRE_FIX_DESIGN]
    small = next((r for r in pre_fix if r.registry_size == 100), None)
    large = next((r for r in pre_fix if r.registry_size == 1_000_000), None)
    lines += [
        "",
        "What this means for the design.",
        "",
        "  Under the pre-fix h[0] tag the leak was real but bounded, and it scaled",
        "  the right way: worst for a small registry, negligible for a large one. An",
        "  8-bit tag divided the anonymity set by 256.",
    ]
    if small and large:
        lines.append(
            f"  At N=100 the adversary was often left with a single candidate "
            f"({small.fraction_deanonymised * 100:.0f}% of the time); at N=1,000,000 it faced "
            f"about {large.mean_set_size:.0f}."
        )
    lines += [
        "",
        "  Domain separation closes it. The adversary still recovers a candidate h_j",
        "  for every registrant, but the tag is no longer a function of h_j, so it",
        "  filters nothing: the anonymity set is the whole registry at every size and",
        "  every tag width. The tag is still one byte, so announcements are the same",
        "  size, and a scanner still spends one hash per announcement on it.",
        "",
        "  Three scope limits, all of which belong in the thesis text:",
        "",
        "  1. Only SPENT addresses were ever exposed. An address that has merely",
        "     received has published no public key, so there is no discrete log to",
        "     take, under either design.",
        "  2. This was P3's leak alone. P2 is structurally immune, its stealth key",
        "     being a lattice element with no discrete log. P1 keeps the ERC-5564",
        "     h[0] tag and is far worse off regardless: an adversary who has broken",
        "     ECDLP recovers the ECDH secret directly and identifies the recipient",
        "     outright, tag or no tag.",
        "  3. The closure rests on assumptions, not a proof: that ML-KEM keeps S",
        "     from this adversary, and that keccak256 under two domains behaves as",
        "     two independent functions, so h_j says nothing about the tag.",
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
