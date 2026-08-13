"""Size table for every protocol and parameter set — the input to every cost model.

Byte counts drive the whole cost story: calldata is 16 gas per non-zero byte,
log data 8 gas per byte, and cold storage 20k gas per 32-byte slot, so the table
this module emits predicts most of what `gas.py` later measures. Emitting it
separately means the prediction is recorded before the measurement, and a
disagreement between them is a signal to investigate rather than something to
discover after the fact.

Every number is taken from the scheme objects, which take theirs from liboqs.
Nothing here is a literal.

    uv run python -m bench.sizes
"""

from __future__ import annotations

import csv
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from pqsap_core import kem
from pqsap_core.scheme import StealthScheme

from p1_erc5564.scheme import P1Erc5564
from p2_mlwe.scheme import P2Mlwe
from p3_hybrid.scheme import P3Hybrid

__all__ = ["SizeRow", "all_schemes", "size_rows", "write_csv"]

RESULTS_DIR = Path(__file__).parent / "results"

# EVM cost constants, from the Ethereum yellow paper / EIP-2028.
_GAS_PER_NONZERO_CALLDATA_BYTE = 16
_GAS_PER_ZERO_CALLDATA_BYTE = 4
_GAS_PER_LOG_BYTE = 8
_GAS_PER_COLD_SSTORE = 20_000
_BYTES_PER_SLOT = 32


@dataclass(frozen=True)
class SizeRow:
    """One protocol/parameter-set combination and its predicted cost drivers."""

    protocol: str
    param_set: str
    scheme_id: str
    meta_bytes: int
    announcement_bytes: int
    #: Storage slots a full meta-address occupies, plus one for the length.
    meta_slots: int
    #: Cold SSTORE cost alone, excluding calldata and the 21k intrinsic cost.
    predicted_registration_sstore_gas: int
    #: Calldata plus log cost for one announcement payload, all bytes non-zero.
    predicted_announcement_data_gas: int


def all_schemes() -> list[StealthScheme]:
    """Every protocol and parameter set in the study, in narrative order."""
    return [
        P1Erc5564(),
        P2Mlwe(kem.ML_KEM_768),
        P2Mlwe(kem.ML_KEM_512),
        P3Hybrid(kem.ML_KEM_768),
        P3Hybrid(kem.ML_KEM_512),
    ]


def size_rows() -> list[SizeRow]:
    """Build the size table from the schemes themselves."""
    rows: list[SizeRow] = []
    for scheme in all_schemes():
        slots = -(-scheme.meta_len // _BYTES_PER_SLOT) + 1  # ceil, plus length slot
        # Lattice output is pseudorandom, so roughly 1 byte in 256 is zero. The
        # all-non-zero figure is the honest upper bound for a prediction; the
        # measured value in gas.py will sit just below it.
        announcement_data = scheme.payload_len * (
            _GAS_PER_NONZERO_CALLDATA_BYTE + _GAS_PER_LOG_BYTE
        )
        rows.append(
            SizeRow(
                protocol=scheme.name,
                param_set=scheme.param_set,
                scheme_id=hex(scheme.scheme_id),
                meta_bytes=scheme.meta_len,
                announcement_bytes=scheme.payload_len,
                meta_slots=slots,
                predicted_registration_sstore_gas=slots * _GAS_PER_COLD_SSTORE,
                predicted_announcement_data_gas=announcement_data,
            )
        )
    return rows


def git_commit() -> str:
    """Current commit, recorded in every result file per the charter."""
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=Path(__file__).parent.parent,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):  # pragma: no cover
        return "unknown"


def write_csv(rows: list[SizeRow], path: Path | None = None) -> Path:
    """Write the size table to `bench/results/`. Committed, never hand-edited."""
    path = path or RESULTS_DIR / "sizes.csv"
    path.parent.mkdir(parents=True, exist_ok=True)

    commit = git_commit()
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["git_commit", *asdict(rows[0])])
        writer.writeheader()
        for row in rows:
            writer.writerow({"git_commit": commit, **asdict(row)})
    return path


def _format_table(rows: list[SizeRow]) -> str:
    header = f"{'protocol':<12}{'params':<11}{'meta B':>8}{'ann B':>7}{'slots':>7}"
    header += f"{'reg sstore':>12}{'ann data':>10}"
    lines = [header, "-" * len(header)]
    for r in rows:
        lines.append(
            f"{r.protocol:<12}{r.param_set:<11}{r.meta_bytes:>8}{r.announcement_bytes:>7}"
            f"{r.meta_slots:>7}{r.predicted_registration_sstore_gas:>12,}"
            f"{r.predicted_announcement_data_gas:>10,}"
        )
    return "\n".join(lines)


def main() -> None:
    rows = size_rows()
    print(_format_table(rows))
    print()
    print("Predictions exclude the 21,000 gas intrinsic transaction cost.")
    print(f"written: {write_csv(rows)}")


if __name__ == "__main__":
    main()
