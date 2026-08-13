"""R3 and A2 — the optimisation variants.

The commitment scheme is the only place in this project where an optimisation
could quietly weaken security rather than merely cost less, so most of these
tests are about the substitution attack the commitment exists to prevent: if a
sender skips the check, whoever serves `ek_view` can hand over their own key and
read every payment.
"""

from __future__ import annotations

import pytest
from pqsap_core import derive, kem
from pqsap_core.derive import DeriveError

from p3_hybrid.scheme import P3Hybrid

SAMPLES = 20


@pytest.fixture(scope="module")
def scheme() -> P3Hybrid:
    return P3Hybrid()


def test_commitment_payload_is_65_bytes(scheme: P3Hybrid) -> None:
    """The parity hypothesis in one assertion: 65 bytes against ERC-6538's 66."""
    keys = scheme.keygen()
    payload = scheme.commitment_payload(keys.meta)

    assert len(payload) == 65
    assert len(payload) < 66  # ERC-6538's own registration
    # Same slot count is what actually drives cost: ceil(65/32) == ceil(66/32).
    assert -(-65 // 32) == -(-66 // 32) == 3


def test_commitment_shrinks_registration_by_19x(scheme: P3Hybrid) -> None:
    keys = scheme.keygen()
    assert len(keys.meta.payload) == 1217
    assert len(scheme.commitment_payload(keys.meta)) == 65
    assert len(keys.meta.payload) / 65 > 18


def test_commitment_binds_the_real_key(scheme: P3Hybrid) -> None:
    keys = scheme.keygen()
    _, ek_view = scheme.split_meta(keys.meta)
    commitment = scheme.commitment_payload(keys.meta)

    assert scheme.verify_commitment(commitment, ek_view)


def test_commitment_rejects_a_substituted_key(scheme: P3Hybrid) -> None:
    """The attack R3 must survive.

    Whoever serves ek_view off-chain is not trusted. Substituting their own key
    would let them decapsulate every payment, so the commitment must reject it.
    """
    victim = scheme.keygen()
    attacker = scheme.keygen()
    commitment = scheme.commitment_payload(victim.meta)
    _, attacker_ek = scheme.split_meta(attacker.meta)

    assert not scheme.verify_commitment(commitment, attacker_ek)
    with pytest.raises(DeriveError, match="does not match"):
        scheme.meta_from_commitment(commitment, attacker_ek)


def test_commitment_rejects_a_single_flipped_bit(scheme: P3Hybrid) -> None:
    keys = scheme.keygen()
    _, ek_view = scheme.split_meta(keys.meta)
    commitment = scheme.commitment_payload(keys.meta)

    tampered = bytearray(ek_view)
    tampered[0] ^= 0x01
    assert not scheme.verify_commitment(commitment, bytes(tampered))


def test_commitment_rejects_wrong_length_key(scheme: P3Hybrid) -> None:
    keys = scheme.keygen()
    commitment = scheme.commitment_payload(keys.meta)
    assert not scheme.verify_commitment(commitment, b"\x00" * 100)


def test_commitment_rejects_malformed_payload(scheme: P3Hybrid) -> None:
    keys = scheme.keygen()
    _, ek_view = scheme.split_meta(keys.meta)
    with pytest.raises(DeriveError, match="65 bytes"):
        scheme.verify_commitment(b"\x00" * 64, ek_view)


def test_r3_roundtrip_matches_r1(scheme: P3Hybrid) -> None:
    """A payment sent via the R3 path must be identical to one sent via R1.

    R3 changes only how the recipient publishes their viewing key. Once the
    sender has verified and reconstructed the meta-address, everything
    downstream — ciphertext, stealth address, view tag — must be unchanged, or
    the optimisation is a different protocol rather than a cheaper encoding.
    """
    keys = scheme.keygen()
    _, ek_view = scheme.split_meta(keys.meta)

    commitment = scheme.commitment_payload(keys.meta)
    reconstructed = scheme.meta_from_commitment(commitment, ek_view)
    assert reconstructed.payload == keys.meta.payload

    announcement = scheme.announce(reconstructed)
    matches = scheme.scan(scheme.viewing_keys(keys), [announcement])
    assert len(matches) == 1

    recovered = scheme.recover_spend_key(keys, matches[0])
    assert derive.eth_address(derive.pubkey_from_scalar(recovered)) == announcement.stealth_address


def test_r3_roundtrip_over_distinct_keypairs(scheme: P3Hybrid) -> None:
    for index in range(SAMPLES):
        keys = scheme.keygen(f"r3-{index}".encode())
        _, ek_view = scheme.split_meta(keys.meta)
        commitment = scheme.commitment_payload(keys.meta)
        assert scheme.meta_from_commitment(commitment, ek_view).payload == keys.meta.payload


def test_commitment_works_at_both_parameter_sets() -> None:
    """R3's payload is 65 bytes regardless of ML-KEM parameter set.

    Worth stating: the commitment is a fixed-width hash, so the registration
    saving grows with the key it replaces rather than shrinking with it.
    """
    for spec in (kem.ML_KEM_768, kem.ML_KEM_512):
        variant = P3Hybrid(spec)
        keys = variant.keygen()
        _, ek_view = variant.split_meta(keys.meta)
        commitment = variant.commitment_payload(keys.meta)

        assert len(commitment) == 65
        assert variant.verify_commitment(commitment, ek_view)


def test_commitment_does_not_leak_the_viewing_key(scheme: P3Hybrid) -> None:
    """The on-chain payload must not contain ek_view in any recoverable form."""
    keys = scheme.keygen()
    _, ek_view = scheme.split_meta(keys.meta)
    commitment = scheme.commitment_payload(keys.meta)

    assert ek_view not in commitment
    assert commitment[33:] == derive.keccak256(ek_view)


def test_a2_announcement_payload_is_unchanged(scheme: P3Hybrid) -> None:
    """A2 changes the log, never the ciphertext.

    The announcement object is identical; only what the contract emits differs.
    That is why announcement *content* costs remain comparable between A1 and
    A2, and the whole measured difference is log data plus the avoided copy.
    """
    keys = scheme.keygen()
    announcement = scheme.announce(keys.meta)

    assert len(announcement.payload) == scheme.payload_len == 1088
    assert 0 <= announcement.view_tag <= 0xFF
    assert len(announcement.stealth_address) == 20
