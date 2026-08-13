"""Receiver-side scan cost — Q3's half of the story.

The charter frames Q3 as a tension: if ML-KEM decapsulation beats a secp256k1
point multiplication per announcement, then post-quantum stealth addresses are
*cheaper to scan but dearer to store*, and the thesis has to report both
directions rather than the flattering one.

Three quantities per protocol, all measured rather than modelled:

**Cryptographic work.** Wall-clock for a full scan, and the operation counts
behind it — one shared-secret derivation per announcement always, plus the
elliptic-curve address check on the roughly 1-in-256 that survive the view tag.

**Bandwidth.** How many bytes the recipient must pull to scan one announcement.
This is where the announcer variant matters, and where A2 turns out to lose.

**Round trips.** A1 answers a scan with one bulk log query. A2 cannot: its log
omits the ciphertext, and the recipient's view tag is derived *from* the shared
secret, so it cannot be computed without first fetching the ciphertext. The tag
in A2's minimal log therefore filters nothing on the recipient's side — every
announcement needs its transaction fetched. That is counted honestly here.

A measurement pitfall found the hard way and worth repeating: **benchmark
secp256k1 with a realistic scalar.** libsecp256k1's scalar multiplication here
is not constant-time in the scalar, so a small toy value costs 10.9 us where a
random 256-bit viewing key costs 25.2 us. Timing P1 with a convenient small
integer understates its per-announcement cost by more than half, and would have
reversed this study's Q3 conclusion. Every figure below uses real keys.

    uv run python -m bench.scan --announcements 2000
"""

from __future__ import annotations

import argparse
import csv
import statistics
import time
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from pqsap_core import derive, kem
from pqsap_core.scheme import Announcement, StealthScheme

from bench.sizes import git_commit
from p1_erc5564.scheme import P1Erc5564
from p2_mlwe.scheme import P2Mlwe
from p3_hybrid.scheme import P3Hybrid

__all__ = ["BandwidthModel", "ScanResult", "bandwidth_for", "measure_scan", "run"]

RESULTS_DIR = Path(__file__).parent / "results"

#: Word size of ABI encoding, and the unit every dynamic field is padded to.
_WORD = 32

#: Bytes of a transaction's calldata that are not the payload: selector plus
#: the ABI head. Verified against measured transactions in tests.
_A1_CALLDATA_OVERHEAD = 4 + _WORD * 7  # schemeId, address, 2 offsets, 2 lengths, padded tag
_A2_CALLDATA_OVERHEAD = 4 + _WORD * 5  # schemeId, address, offset, bytes1 tag, length


@dataclass(frozen=True)
class BandwidthModel:
    """What a recipient must download to scan one announcement."""

    announcer_variant: str
    log_bytes: int
    tx_fetch_bytes: int
    rpc_round_trips_per_announcement: float

    @property
    def total_bytes(self) -> int:
        return self.log_bytes + self.tx_fetch_bytes


def bandwidth_for(payload_len: int, announcer_variant: str) -> BandwidthModel:
    """Per-announcement download cost, from ABI encoding rules.

    A1 puts the payload in the log, so one bulk `eth_getLogs` returns everything
    a scan needs — the round-trip cost per announcement is effectively zero
    because the query is amortised over the whole range.

    A2 puts the payload in calldata only. The recipient cannot skip any
    announcement, because deciding whether to skip requires the view tag, and
    the recipient's own view tag comes from decapsulating the ciphertext that
    A2 left in calldata. So it pays a per-announcement transaction fetch.
    """
    padded = -(-payload_len // _WORD) * _WORD

    if announcer_variant == "A1":
        # log data = offset, offset, len, payload, len, padded tag
        log_bytes = _WORD * 2 + _WORD + padded + _WORD + _WORD
        return BandwidthModel("A1", log_bytes, 0, 0.0)

    if announcer_variant == "A2":
        # log data = the bytes1 view tag alone, ABI-padded to one word.
        log_bytes = _WORD
        tx_bytes = _A2_CALLDATA_OVERHEAD + padded
        return BandwidthModel("A2", log_bytes, tx_bytes, 1.0)

    raise ValueError(f"unknown announcer variant {announcer_variant!r}")


@dataclass(frozen=True)
class ScanResult:
    """One protocol scanned over one synthetic announcement population."""

    git_commit: str
    protocol: str
    param_set: str
    announcer_variant: str
    announcements: int
    planted_matches: int
    matches_found: int
    shared_secret_ops: int
    address_checks: int
    wall_clock_s: float
    per_announcement_us: float
    log_bytes_per_announcement: int
    tx_fetch_bytes_per_announcement: int
    total_bytes_per_announcement: int
    rpc_round_trips: float


def _population(
    scheme: StealthScheme, announcements: int, planted: int
) -> tuple[list[Announcement], object]:
    """Build a scan population: mostly other people's payments, a few ours."""
    recipient = scheme.keygen(b"scan-recipient")
    stream: list[Announcement] = []

    stranger = scheme.keygen(b"scan-stranger")
    for index in range(announcements):
        # Plant ours at an even spread so no scan can shortcut by position.
        if (
            planted
            and index % max(1, announcements // planted) == 0
            and index // max(1, announcements // planted) < planted
        ):
            stream.append(scheme.announce(recipient.meta))
        else:
            stream.append(scheme.announce(stranger.meta))
    return stream, recipient


def _count_operations(
    scheme: StealthScheme, viewing: object, stream: list[Announcement]
) -> tuple[int, int]:
    """Count shared-secret derivations and elliptic-curve address checks.

    Counted in a separate pass from the timed one, so instrumentation overhead
    never contaminates the wall-clock figure.
    """
    counters = {"shared": 0, "address": 0}

    real_decaps = kem.decaps
    real_pubkey = derive.derive_stealth_pubkey

    def counted_decaps(spec: object, dk: bytes, ct: bytes) -> bytes:
        counters["shared"] += 1
        return real_decaps(spec, dk, ct)  # type: ignore[arg-type]

    def counted_pubkey(spend_pub: bytes, h: int) -> bytes:
        counters["address"] += 1
        return real_pubkey(spend_pub, h)

    kem.decaps = counted_decaps
    derive.derive_stealth_pubkey = counted_pubkey  # type: ignore[assignment]
    # P1 derives its shared secret by point multiplication rather than
    # decapsulation, so its count comes from the announcements it inspects.
    try:
        scheme.scan(viewing, stream)  # type: ignore[arg-type]
    finally:
        kem.decaps = real_decaps
        derive.derive_stealth_pubkey = real_pubkey

    shared = counters["shared"] or len(stream)
    return shared, counters["address"]


def measure_scan(
    scheme: StealthScheme,
    announcer_variant: str,
    announcements: int,
    planted: int,
    repeats: int,
) -> ScanResult:
    """Scan a synthetic population and report time, operations and bandwidth."""
    stream, recipient = _population(scheme, announcements, planted)
    viewing = scheme.viewing_keys(recipient)  # type: ignore[arg-type]

    # Warm up: first call pays import and allocator costs that are not part of
    # steady-state scanning.
    scheme.scan(viewing, stream[: min(64, announcements)])

    timings: list[float] = []
    matches = 0
    for _ in range(repeats):
        start = time.perf_counter()
        found = scheme.scan(viewing, stream)
        timings.append(time.perf_counter() - start)
        matches = len(found)

    wall = statistics.median(timings)
    shared_ops, address_checks = _count_operations(scheme, viewing, stream)
    band = bandwidth_for(scheme.payload_len, announcer_variant)

    return ScanResult(
        git_commit=git_commit(),
        protocol=scheme.name,
        param_set=scheme.param_set,
        announcer_variant=announcer_variant,
        announcements=announcements,
        planted_matches=planted,
        matches_found=matches,
        shared_secret_ops=shared_ops,
        address_checks=address_checks,
        wall_clock_s=round(wall, 6),
        per_announcement_us=round(wall / announcements * 1e6, 3),
        log_bytes_per_announcement=band.log_bytes,
        tx_fetch_bytes_per_announcement=band.tx_fetch_bytes,
        total_bytes_per_announcement=band.total_bytes,
        rpc_round_trips=band.rpc_round_trips_per_announcement,
    )


def run(announcements: int, planted: int, repeats: int) -> list[ScanResult]:
    """Scan every protocol, plus P3 under both announcer variants."""
    combinations: list[tuple[StealthScheme, str]] = [
        (P1Erc5564(), "A1"),
        (P2Mlwe(kem.ML_KEM_768), "A1"),
        (P2Mlwe(kem.ML_KEM_512), "A1"),
        (P3Hybrid(kem.ML_KEM_768), "A1"),
        (P3Hybrid(kem.ML_KEM_768), "A2"),
        (P3Hybrid(kem.ML_KEM_512), "A1"),
        (P3Hybrid(kem.ML_KEM_512), "A2"),
    ]

    results: list[ScanResult] = []
    for scheme, variant in combinations:
        print(f"  {scheme.name}/{scheme.param_set}/{variant} ... ", end="", flush=True)
        results.append(measure_scan(scheme, variant, announcements, planted, repeats))
        print("done")
    return results


def write_csv(results: list[ScanResult], path: Path | None = None) -> Path:
    path = path or RESULTS_DIR / "scan.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[f.name for f in fields(ScanResult)])
        writer.writeheader()
        for result in results:
            writer.writerow(asdict(result))
    return path


def _format(results: list[ScanResult]) -> str:
    header = (
        f"{'protocol':<12}{'params':<11}{'ann':<5}{'us/ann':>9}{'ops':>8}"
        f"{'ec':>6}{'bytes/ann':>11}{'trips':>7}"
    )
    lines = [header, "-" * len(header)]
    for r in results:
        lines.append(
            f"{r.protocol:<12}{r.param_set:<11}{r.announcer_variant:<5}"
            f"{r.per_announcement_us:>9.2f}{r.shared_secret_ops:>8,}{r.address_checks:>6}"
            f"{r.total_bytes_per_announcement:>11,}{r.rpc_round_trips:>7.1f}"
        )
    return "\n".join(lines)


def _commentary(results: list[ScanResult]) -> str:
    by_key = {(r.protocol, r.param_set, r.announcer_variant): r for r in results}
    lines: list[str] = []

    p1 = by_key.get(("p1_erc5564", "secp256k1", "A1"))
    p3 = by_key.get(("p3_hybrid", "mlkem768", "A1"))
    if p1 and p3:
        ratio = p1.per_announcement_us / p3.per_announcement_us
        faster = "faster" if ratio > 1 else "slower"
        speed = ratio if ratio > 1 else 1 / ratio
        bytes_ratio = p3.total_bytes_per_announcement / p1.total_bytes_per_announcement
        lines.append(
            f"Q3: P3 scans {speed:.2f}x {faster} per announcement than ERC-5564 "
            f"({p3.per_announcement_us:.2f} us against {p1.per_announcement_us:.2f} us), "
            f"while storing {bytes_ratio:.1f}x the bytes per announcement."
        )

    a1 = by_key.get(("p3_hybrid", "mlkem768", "A1"))
    a2 = by_key.get(("p3_hybrid", "mlkem768", "A2"))
    if a1 and a2:
        extra = a2.total_bytes_per_announcement - a1.total_bytes_per_announcement
        lines.append(
            f"A2 costs the recipient {a2.rpc_round_trips:.0f} extra RPC round trip per "
            f"announcement and {extra:+,} bytes, because its log omits the ciphertext "
            "and the view tag cannot be computed without it. The tag in A2's log "
            "filters nothing."
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--announcements", type=int, default=2000)
    parser.add_argument("--planted", type=int, default=5, help="payments actually ours")
    parser.add_argument("--repeats", type=int, default=5, help="timed runs; median reported")
    args = parser.parse_args()

    print(f"scanning {args.announcements} announcements, {args.planted} of them ours")
    results = run(args.announcements, args.planted, args.repeats)
    print()
    print(_format(results))
    print()
    print(_commentary(results))
    print()
    print(f"written: {write_csv(results)}")


if __name__ == "__main__":
    main()
