"""Pin P1 to the ERC-5564 reference implementation.

This is the test that makes P1 a legitimate baseline. The comparison the whole
thesis rests on is only meaningful if the ECC protocol we measure is the
standard one, and ERC-5564's prose is not sufficient to reconstruct it: it
specifies neither the hash function nor how the shared secret is serialised
before hashing. Both were recovered from the EIP's own reference notebook, and
these assertions hold us to its executed output.

Failure here means our P1 has drifted from the standard, which would invalidate
every P1-versus-P3 comparison downstream — not merely a broken test.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from coincurve import PublicKey
from pqsap_core import derive
from pqsap_core.scheme import MetaAddress, RecipientKeys

from p1_erc5564.scheme import P1Erc5564

VECTOR_PATH = Path(__file__).parent / "vectors" / "erc5564_reference.json"


@pytest.fixture(scope="module")
def vector() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(VECTOR_PATH.read_text())
    return data


@pytest.fixture(scope="module")
def scheme() -> P1Erc5564:
    return P1Erc5564()


def _meta_from_vector(vector: dict[str, Any]) -> MetaAddress:
    v = vector["vector"]
    payload = derive.pubkey_from_scalar(v["spend_priv"]) + derive.pubkey_from_scalar(v["view_priv"])
    return MetaAddress(P1Erc5564.scheme_id, payload)


def test_provenance_is_recorded(vector: dict[str, Any]) -> None:
    """A thesis artifact must say where it came from."""
    p = vector["provenance"]
    assert p["source_repo"] == "ethereum/ERCs"
    assert p["blob_sha"] and p["last_commit"]


def test_shared_secret_matches_reference(vector: dict[str, Any]) -> None:
    """The ECDH point itself, before any hashing."""
    v = vector["vector"]
    ephemeral = int(v["ephemeral_priv_hex"], 16)
    view_pub = derive.pubkey_from_scalar(v["view_priv"])

    shared = _shared(view_pub, ephemeral)
    assert len(shared) == 64
    assert int.from_bytes(shared[:32], "big") == v["expected_shared_point_x"]
    assert int.from_bytes(shared[32:], "big") == v["expected_shared_point_y"]


def test_view_tag_matches_reference(vector: dict[str, Any]) -> None:
    """Byte 0 of keccak256(x‖y). Wrong serialisation gives a wrong tag here."""
    v = vector["vector"]
    shared = _shared(derive.pubkey_from_scalar(v["view_priv"]), int(v["ephemeral_priv_hex"], 16))
    _, tag = derive.h_scalar_and_tag(shared)
    assert tag == v["expected_view_tag"] == 86


def test_stealth_address_matches_reference(vector: dict[str, Any], scheme: P1Erc5564) -> None:
    """End to end: the sender's announcement must reproduce the published address."""
    v = vector["vector"]
    meta = _meta_from_vector(vector)
    announcement = scheme.announce(meta, ephemeral_priv=int(v["ephemeral_priv_hex"], 16))

    assert derive.to_checksum(announcement.stealth_address) == v["expected_stealth_address"]
    assert announcement.view_tag == v["expected_view_tag"]


def test_recipient_recovers_reference_key(vector: dict[str, Any], scheme: P1Erc5564) -> None:
    """The recipient side must land on the reference's stealth private key."""
    v = vector["vector"]
    meta = _meta_from_vector(vector)
    announcement = scheme.announce(meta, ephemeral_priv=int(v["ephemeral_priv_hex"], 16))

    keys = RecipientKeys(
        meta=meta,
        spend_priv=v["spend_priv"],
        view_secret=int(v["view_priv"]).to_bytes(32, "big"),
    )

    matches = scheme.scan(scheme.viewing_keys(keys), [announcement])
    assert len(matches) == 1

    recovered = scheme.recover_spend_key(keys, matches[0])
    assert recovered == v["expected_stealth_priv"]

    stealth_pub = PublicKey.from_secret(recovered.to_bytes(32, "big")).format(compressed=False)[1:]
    assert int.from_bytes(stealth_pub[:32], "big") == v["expected_stealth_pubkey_x"]
    assert int.from_bytes(stealth_pub[32:], "big") == v["expected_stealth_pubkey_y"]


def test_compressed_serialisation_would_fail(vector: dict[str, Any]) -> None:
    """Guard the choice that ERC-5564's prose leaves open.

    Hashing the compressed point is the obvious alternative reading of the
    spec. It produces a different, non-standard protocol, so this asserts the
    two genuinely differ — if they ever agreed, the vector above would not
    actually be pinning the serialisation.
    """
    v = vector["vector"]
    ephemeral = int(v["ephemeral_priv_hex"], 16)
    point = PublicKey(derive.pubkey_from_scalar(v["view_priv"])).multiply(
        ephemeral.to_bytes(32, "big")
    )

    _, tag_compressed = derive.h_scalar_and_tag(point.format(compressed=True))
    assert tag_compressed != v["expected_view_tag"]


def _shared(pubkey33: bytes, scalar: int) -> bytes:
    return bytes(PublicKey(pubkey33).multiply(scalar.to_bytes(32, "big")).format(False)[1:])
