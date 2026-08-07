"""ML-KEM (FIPS 203) access for P2 and P3, through one choke point.

Every lattice operation in this project goes through this module. Centralising
it buys three things the thesis depends on:

**Sizes are read from the library, never trusted to a constant.** Meta-address
and announcement byte counts drive the entire cost story, so a stale literal
would silently corrupt every gas figure. ``KemSpec`` populates its lengths from
liboqs at load time; the tests then assert those against FIPS 203.

**The round-3 substitution hazard is closed.** liboqs ships legacy ``Kyber768``
alongside final ``ML-KEM-768``. They have *identical* key and ciphertext sizes
and produce *different* output, so a one-word slip would yield a plausible,
wrong, and completely undetectable set of results. Loading a spec asserts both
the mechanism name and that liboqs reports ``FIPS203`` as the algorithm version.

**Key generation is reproducible.** liboqs 0.16 exposes derandomised keygen, so
every benchmark sample records the 64-byte seed that produced its keypair and an
examiner can regenerate it exactly. Encapsulation has no such API and stays
randomised — announcement bytes are therefore pinned by digest, not by seed.
"""

from __future__ import annotations

import importlib
import os
from dataclasses import dataclass
from typing import Any, Final

__all__ = [
    "ML_KEM_512",
    "ML_KEM_768",
    "SEED_BYTES",
    "KemBackendUnavailable",
    "KemError",
    "KemSpec",
    "backend_info",
    "decaps",
    "encaps",
    "keygen",
]

#: Length of the derandomised-keygen seed liboqs expects (FIPS 203 d‖z).
SEED_BYTES: Final[int] = 64

#: liboqs' own name for final FIPS 203, as opposed to the round-3 Kyber draft.
_REQUIRED_ALG_VERSION: Final[str] = "FIPS203"

_INSTALL_HINT: Final[str] = (
    "The liboqs shared library could not be loaded. liboqs-python builds it on "
    "first import into ~/_oqs; note that Homebrew's liboqs ships a static "
    "archive only and cannot be used directly. See README.md."
)


class KemError(Exception):
    """A KEM operation was given something the protocol must refuse."""


class KemBackendUnavailable(KemError):
    """liboqs is missing, or does not offer final FIPS 203 ML-KEM."""


def _oqs() -> Any:
    """Import liboqs lazily so a missing library fails with an actionable error."""
    # liboqs-python prints an unconditional faulthandler banner on import unless
    # told otherwise; silence it so benchmark output stays machine-readable.
    os.environ.setdefault("OQS_PYTHON_ENABLE_FAULT_HANDLER", "0")
    try:
        return importlib.import_module("oqs")
    except Exception as exc:  # pragma: no cover - environment failure path
        raise KemBackendUnavailable(f"{_INSTALL_HINT} Underlying error: {exc}") from exc


@dataclass(frozen=True)
class KemSpec:
    """A parameter set, with every length taken from liboqs rather than assumed."""

    name: str
    ek_len: int
    dk_len: int
    ct_len: int
    ss_len: int
    nist_level: int

    @property
    def label(self) -> str:
        """Short identifier for result CSVs, e.g. ``mlkem768``."""
        return self.name.lower().replace("-", "")


def _load_spec(name: str) -> KemSpec:
    oqs = _oqs()
    enabled = oqs.get_enabled_kem_mechanisms()
    if name not in enabled:
        raise KemBackendUnavailable(
            f"{name} is not enabled in this liboqs build. Enabled KEMs: {sorted(enabled)}"
        )
    with oqs.KeyEncapsulation(name) as kem:
        details = kem.details
        version = str(details["version"])
        if version != _REQUIRED_ALG_VERSION:
            # The failure this guards against is silent, so refuse to continue.
            raise KemBackendUnavailable(
                f"{name} reports algorithm version {version!r}, expected "
                f"{_REQUIRED_ALG_VERSION!r}. This build may implement the round-3 "
                "Kyber draft, which shares ML-KEM's sizes but not its output."
            )
        return KemSpec(
            name=name,
            ek_len=int(details["length_public_key"]),
            dk_len=int(details["length_secret_key"]),
            ct_len=int(details["length_ciphertext"]),
            ss_len=int(details["length_shared_secret"]),
            nist_level=int(details["claimed_nist_level"]),
        )


ML_KEM_768: Final[KemSpec] = _load_spec("ML-KEM-768")
ML_KEM_512: Final[KemSpec] = _load_spec("ML-KEM-512")


def keygen(spec: KemSpec, seed: bytes | None = None) -> tuple[bytes, bytes]:
    """Generate an ML-KEM keypair, returning ``(ek, dk)``.

    Args:
        spec: parameter set.
        seed: optional 64-byte seed. Supplying one makes the keypair exactly
            reproducible, which is how benchmark samples stay auditable.
    """
    oqs = _oqs()
    with oqs.KeyEncapsulation(spec.name) as kem:
        if seed is None:
            ek = bytes(kem.generate_keypair())
        else:
            if len(seed) != SEED_BYTES:
                raise KemError(f"seed must be {SEED_BYTES} bytes, got {len(seed)}")
            ek = bytes(kem.generate_keypair_seed(seed))
        dk = bytes(kem.export_secret_key())
    _require_len(ek, spec.ek_len, "encapsulation key")
    _require_len(dk, spec.dk_len, "decapsulation key")
    return ek, dk


def encaps(spec: KemSpec, ek: bytes) -> tuple[bytes, bytes]:
    """Encapsulate to ``ek``, returning ``(ciphertext, shared_secret)``."""
    _require_len(ek, spec.ek_len, "encapsulation key")
    oqs = _oqs()
    with oqs.KeyEncapsulation(spec.name) as kem:
        ct, ss = kem.encap_secret(ek)
    ct, ss = bytes(ct), bytes(ss)
    _require_len(ct, spec.ct_len, "ciphertext")
    _require_len(ss, spec.ss_len, "shared secret")
    return ct, ss


def decaps(spec: KemSpec, dk: bytes, ct: bytes) -> bytes:
    """Decapsulate, returning the shared secret.

    This never signals failure. FIPS 203 specifies *implicit rejection*: a
    ciphertext that was not created for ``dk`` yields pseudorandom bytes instead
    of an error. Callers therefore cannot treat "decapsulation succeeded" as
    evidence of anything — which is precisely why every scheme in this project
    must verify the derived stealth address before accepting a match.
    """
    _require_len(dk, spec.dk_len, "decapsulation key")
    _require_len(ct, spec.ct_len, "ciphertext")
    oqs = _oqs()
    with oqs.KeyEncapsulation(spec.name, dk) as kem:
        ss = bytes(kem.decap_secret(ct))
    _require_len(ss, spec.ss_len, "shared secret")
    return ss


def backend_info() -> dict[str, object]:
    """Provenance of the KEM backend, recorded alongside every benchmark run."""
    oqs = _oqs()
    return {
        "liboqs_version": oqs.oqs_version(),
        "liboqs_python_version": oqs.oqs_python_version(),
        "mechanisms": {
            spec.name: {
                "alg_version": _REQUIRED_ALG_VERSION,
                "nist_level": spec.nist_level,
                "ek_len": spec.ek_len,
                "dk_len": spec.dk_len,
                "ct_len": spec.ct_len,
                "ss_len": spec.ss_len,
            }
            for spec in (ML_KEM_768, ML_KEM_512)
        },
    }


def _require_len(value: bytes, expected: int, what: str) -> None:
    if len(value) != expected:
        raise KemError(f"{what} must be {expected} bytes, got {len(value)}")
