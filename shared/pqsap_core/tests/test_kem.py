"""Tests for the ML-KEM backend.

Two of these are worth more than the rest. ``test_final_mlkem_reported_by_library``
and ``test_cross_backend_interop_with_kyber_py`` together rule out the single
most dangerous silent failure available to this project: liboqs also ships
round-3 ``Kyber768``, which has byte-identical key and ciphertext sizes to
``ML-KEM-768`` and produces different output. Every size assertion in the thesis
would still pass against the wrong algorithm.

``test_implicit_rejection_returns_pseudorandom`` pins the FIPS 203 property that
makes the mandatory address check in every scheme non-optional.
"""

from __future__ import annotations

import pytest

from pqsap_core import kem
from pqsap_core.kem import ML_KEM_512, ML_KEM_768, KemError, KemSpec

SPECS = [ML_KEM_768, ML_KEM_512]


def test_mlkem768_sizes_match_fips203() -> None:
    """Sizes come from liboqs, and are checked against FIPS 203 here."""
    assert (ML_KEM_768.ek_len, ML_KEM_768.ct_len, ML_KEM_768.ss_len) == (1184, 1088, 32)
    assert ML_KEM_768.nist_level == 3


def test_mlkem512_sizes_match_fips203() -> None:
    assert (ML_KEM_512.ek_len, ML_KEM_512.ct_len, ML_KEM_512.ss_len) == (800, 768, 32)
    assert ML_KEM_512.nist_level == 1


def test_final_mlkem_reported_by_library() -> None:
    """Guards against the round-3 Kyber substitution.

    Legacy Kyber is present in this liboqs build, so the guard is not
    theoretical: loading a spec must confirm the algorithm version is FIPS 203.
    """
    import oqs

    enabled = oqs.get_enabled_kem_mechanisms()
    for spec in SPECS:
        assert spec.name in enabled
        with oqs.KeyEncapsulation(spec.name) as k:
            assert k.details["version"] == "FIPS203"


def test_unknown_mechanism_is_refused() -> None:
    with pytest.raises(kem.KemBackendUnavailable):
        kem._load_spec("ML-KEM-9999")


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.name)
def test_roundtrip(spec: KemSpec) -> None:
    ek, dk = kem.keygen(spec)
    assert (len(ek), len(dk)) == (spec.ek_len, spec.dk_len)
    ct, ss_sender = kem.encaps(spec, ek)
    assert len(ct) == spec.ct_len
    assert kem.decaps(spec, dk, ct) == ss_sender


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.name)
def test_seeded_keygen_is_reproducible(spec: KemSpec) -> None:
    """Benchmark samples must be regenerable from the seed recorded in the CSV."""
    seed = bytes(range(kem.SEED_BYTES))
    assert kem.keygen(spec, seed) == kem.keygen(spec, seed)

    other = bytes([1]) + bytes(range(1, kem.SEED_BYTES))
    assert kem.keygen(spec, other)[0] != kem.keygen(spec, seed)[0]


def test_seed_length_is_enforced() -> None:
    with pytest.raises(KemError):
        kem.keygen(ML_KEM_768, b"\x00" * 32)


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.name)
def test_implicit_rejection_returns_pseudorandom(spec: KemSpec) -> None:
    """Decapsulating a foreign ciphertext yields bytes, not an error.

    This is why a passing view tag can never be sufficient evidence of a match.
    """
    _, dk_a = kem.keygen(spec)
    ek_b, _ = kem.keygen(spec)
    ct_for_b, ss_b = kem.encaps(spec, ek_b)

    ss_a = kem.decaps(spec, dk_a, ct_for_b)
    assert len(ss_a) == spec.ss_len
    assert ss_a != ss_b


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.name)
def test_wrong_length_inputs_rejected(spec: KemSpec) -> None:
    ek, dk = kem.keygen(spec)
    ct, _ = kem.encaps(spec, ek)
    with pytest.raises(KemError):
        kem.encaps(spec, ek[:-1])
    with pytest.raises(KemError):
        kem.decaps(spec, dk, ct[:-1])
    with pytest.raises(KemError):
        kem.decaps(spec, dk[:-1], ct)


@pytest.mark.parametrize(
    ("spec", "kyber_name"),
    [(ML_KEM_768, "ML_KEM_768"), (ML_KEM_512, "ML_KEM_512")],
    ids=["ML-KEM-768", "ML-KEM-512"],
)
def test_cross_backend_interop_with_kyber_py(spec: KemSpec, kyber_name: str) -> None:
    """liboqs and an independent pure-Python FIPS 203 implementation must agree.

    Interoperating in both directions is strong evidence that the C backend
    implements final ML-KEM rather than a draft with matching sizes.
    """
    kyber_module = pytest.importorskip("kyber_py.ml_kem")
    reference = getattr(kyber_module, kyber_name)

    # kyber-py generates, liboqs encapsulates, kyber-py decapsulates.
    ek_ref, dk_ref = reference.keygen()
    assert len(ek_ref) == spec.ek_len
    ct, ss_oqs = kem.encaps(spec, ek_ref)
    assert reference.decaps(dk_ref, ct) == ss_oqs

    # liboqs generates, kyber-py encapsulates, liboqs decapsulates.
    ek_oqs, dk_oqs = kem.keygen(spec)
    ss_ref, ct_ref = reference.encaps(ek_oqs)
    assert kem.decaps(spec, dk_oqs, ct_ref) == ss_ref


def test_backend_info_records_provenance() -> None:
    info = kem.backend_info()
    assert info["liboqs_version"]
    mechanisms = info["mechanisms"]
    assert isinstance(mechanisms, dict)
    assert set(mechanisms) == {"ML-KEM-768", "ML-KEM-512"}
