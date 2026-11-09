"""The M1 spike gate for P3.

Nobody has previously built this construction, so these tests are the evidence
that it works at all — the rest of the project is blocked on them. Three carry
most of the weight:

``test_full_roundtrip_ecrecover`` closes the loop end to end: the sender derives
an address from public material only, the recipient independently re-derives the
same address from viewing keys, recovers its private key, signs, and ecrecover
returns that same address.

``test_colliding_tag_rejected_by_address_check`` is the one that proves the
design rather than the code. It brute-forces an actual view-tag collision on a
foreign ciphertext, confirms the tag filter *passes* it, and confirms the
address check is what rejects it. Without this, a passing test suite would be
consistent with a protocol that accepts roughly 1 in 256 of other people's
payments.

``test_dual_key_separation`` checks the invariant that makes the scheme
regulator-friendly: viewing keys enumerate everything and spend nothing.
"""

from __future__ import annotations

import os

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from pqsap_core import derive, kem, testing
from pqsap_core.derive import SECP256K1_N, DeriveError
from pqsap_core.scheme import Announcement, MetaAddress, ScanMatch

from p3_hybrid.scheme import P3_VIEW_TAG_DOMAIN, P3Hybrid

SAMPLES = 20
TAG_COLLISION_ATTEMPTS = 10_000

#: Written out rather than imported, so the test pins the rule itself and a
#: silent edit to the constant cannot pass unnoticed.
VIEW_TAG_DOMAIN_V1 = b"pq-sap/p3/view-tag/v1"


@pytest.fixture(scope="module")
def scheme() -> P3Hybrid:
    return P3Hybrid()


def test_scheme_id_is_non_standard(scheme: P3Hybrid) -> None:
    """ERC-5564 standardises id 1 for secp256k1; P3 must not claim it."""
    assert scheme.scheme_id != 1
    assert scheme.scheme_id == 0x50513348  # "PQ3H"


def test_sizes_match_charter_and_library(scheme: P3Hybrid) -> None:
    """1217 = 33 + 1184, computed two ways so a FIPS mismatch cannot hide."""
    assert scheme.meta_len == 33 + kem.ML_KEM_768.ek_len == 1217
    assert scheme.payload_len == kem.ML_KEM_768.ct_len == 1088

    keys = scheme.keygen()
    assert len(keys.meta.payload) == 1217
    assert len(scheme.announce(keys.meta).payload) == 1088


def test_mlkem512_variant_sizes() -> None:
    """The parameter sweep reuses the same class; only sizes change."""
    scheme = P3Hybrid(kem.ML_KEM_512)
    assert scheme.meta_len == 33 + 800 == 833
    assert scheme.payload_len == 768
    assert scheme.param_set == "mlkem512"


def test_meta_split_roundtrip(scheme: P3Hybrid) -> None:
    keys = scheme.keygen()
    spend_pub, ek_view = scheme.split_meta(keys.meta)
    assert spend_pub + ek_view == keys.meta.payload
    assert keys.spend_priv is not None
    assert spend_pub == derive.pubkey_from_scalar(keys.spend_priv)
    with pytest.raises(DeriveError):
        scheme.split_meta(MetaAddress(scheme.scheme_id, keys.meta.payload[:-1]))


def test_full_roundtrip_ecrecover(scheme: P3Hybrid) -> None:
    keys = scheme.keygen()
    announcement = scheme.announce(keys.meta)

    # The recipient scans with viewing keys only.
    matches = scheme.scan(scheme.viewing_keys(keys), [announcement])
    assert len(matches) == 1
    assert matches[0].index == 0
    assert matches[0].stealth_address == announcement.stealth_address

    # Recovered key must control exactly the announced address...
    p = scheme.recover_spend_key(keys, matches[0])
    assert derive.eth_address(derive.pubkey_from_scalar(p)) == announcement.stealth_address

    # ...and must actually be able to sign as it.
    message = encode_defunct(text="pq-sap spike")
    signed = Account.sign_message(message, p.to_bytes(32, "big"))
    assert Account.recover_message(message, signature=signed.signature) == derive.to_checksum(
        announcement.stealth_address
    )


def test_roundtrip_over_distinct_keypairs(scheme: P3Hybrid) -> None:
    """Charter requires >= 20 distinct keypairs; payloads must genuinely differ."""
    testing.check_roundtrip(scheme, SAMPLES)


def test_address_derivation_is_shared(scheme: P3Hybrid) -> None:
    testing.check_address_derivation_is_shared(scheme)


def test_announcement_shape(scheme: P3Hybrid) -> None:
    keys = scheme.keygen()
    testing.check_announcement_shape(scheme, scheme.announce(keys.meta))


def test_seeded_keygen_is_reproducible(scheme: P3Hybrid) -> None:
    """A result row's seed must regenerate its keypair byte-for-byte."""
    seed = b"thesis-sample-0001"
    first, second = scheme.keygen(seed), scheme.keygen(seed)
    assert first.meta.payload == second.meta.payload
    assert first.spend_priv == second.spend_priv
    assert first.view_secret == second.view_secret
    assert scheme.keygen(b"thesis-sample-0002").meta.payload != first.meta.payload


def test_scan_ignores_foreign_announcements(scheme: P3Hybrid) -> None:
    """Announcements addressed to other people must not match."""
    testing.check_scan_rejects_foreign(scheme)


def test_scan_finds_ours_among_foreign(scheme: P3Hybrid) -> None:
    keys = scheme.keygen()
    stream: list[Announcement] = [scheme.announce(scheme.keygen().meta) for _ in range(20)]
    ours = scheme.announce(keys.meta)
    stream.insert(7, ours)

    matches = scheme.scan(scheme.viewing_keys(keys), stream)
    assert [m.index for m in matches] == [7]
    assert matches[0].stealth_address == ours.stealth_address


@pytest.mark.slow
def test_colliding_tag_rejected_by_address_check(scheme: P3Hybrid) -> None:
    """The false-positive path, forced rather than assumed.

    FIPS 203 implicit rejection means a foreign ciphertext still decapsulates,
    to pseudorandom bytes. Roughly 1 in 256 of those produce a view tag matching
    the announcement's. This test finds such a case and asserts that the tag
    filter lets it through and the mandatory address check stops it.
    """
    victim = scheme.keygen()
    viewing = scheme.viewing_keys(victim)
    spend_pub, _ = scheme.split_meta(victim.meta)
    stranger = scheme.keygen()

    for _ in range(TAG_COLLISION_ATTEMPTS):
        announcement = scheme.announce(stranger.meta)

        shared = kem.decaps(scheme.spec, viewing.view_secret, announcement.payload)
        tag = derive.domain_separated_view_tag(shared, P3_VIEW_TAG_DOMAIN)
        if tag != announcement.view_tag:
            continue
        h, _ = derive.h_scalar_and_tag(shared)

        # The cheap filter has passed on an announcement that is not ours.
        assert tag == announcement.view_tag

        # The derived address does not match, so the announcement is rejected...
        derived = derive.eth_address(derive.derive_stealth_pubkey(spend_pub, h))
        assert derived != announcement.stealth_address

        # ...and scan agrees, which is the property that matters.
        assert scheme.scan(viewing, [announcement]) == []

        # Had we trusted the tag, this is the worthless key we would have used.
        assert victim.spend_priv is not None
        bogus = derive.derive_stealth_privkey(victim.spend_priv, h)
        assert derive.eth_address(derive.pubkey_from_scalar(bogus)) != announcement.stealth_address
        return

    pytest.fail(
        f"no view-tag collision in {TAG_COLLISION_ATTEMPTS} attempts; "
        "expected roughly one per 256 — the tag rule may be broken"
    )


def test_view_tag_is_byte_0_of_the_domain_separated_digest(scheme: P3Hybrid) -> None:
    """Pin the rule: tag = keccak256("pq-sap/p3/view-tag/v1" ‖ S)[0].

    The recipient recomputes S from the ciphertext, so this checks what the
    sender published against what a scanner must derive, byte for byte.
    """
    assert P3_VIEW_TAG_DOMAIN == VIEW_TAG_DOMAIN_V1
    keys = scheme.keygen()
    for _ in range(SAMPLES):
        announcement = scheme.announce(keys.meta)
        shared = kem.decaps(scheme.spec, keys.view_secret, announcement.payload)
        assert announcement.view_tag == derive.keccak256(VIEW_TAG_DOMAIN_V1 + shared)[0]


def test_h_is_unchanged_by_the_tag_change(scheme: P3Hybrid) -> None:
    """Only the tag moved. h, and therefore every stealth address, is as before."""
    keys = scheme.keygen()
    spend_pub, _ = scheme.split_meta(keys.meta)
    for _ in range(SAMPLES):
        announcement = scheme.announce(keys.meta)
        shared = kem.decaps(scheme.spec, keys.view_secret, announcement.payload)
        h = int.from_bytes(derive.keccak256(shared), "big") % SECP256K1_N

        (match,) = scheme.scan(scheme.viewing_keys(keys), [announcement])
        assert match.tweak == h
        assert derive.eth_address(derive.derive_stealth_pubkey(spend_pub, h)) == (
            announcement.stealth_address
        )


def test_knowing_h_does_not_predict_the_tag(scheme: P3Hybrid) -> None:
    """Q1: the h[0] rule no longer predicts the published tag.

    A quantum adversary recovers h for every candidate from a spent address.
    Under the pre-fix design the true recipient's h[0] equalled the tag every
    time, which is what made the tag a filter. Now it agrees about 1 time in
    256 — chance, the same rate as any stranger — so h carries no tag
    information. 512 trials expect 2 agreements; 20 or more has probability
    below 10^-13 for an independent tag.
    """
    keys = scheme.keygen()
    agreements = 0
    for _ in range(512):
        announcement = scheme.announce(keys.meta)
        (match,) = scheme.scan(scheme.viewing_keys(keys), [announcement])
        assert match.tweak is not None
        if match.tweak.to_bytes(32, "big")[0] == announcement.view_tag:
            agreements += 1
    assert agreements < 20


def test_dual_key_separation(scheme: P3Hybrid) -> None:
    """A holder of viewing keys enumerates every payment and can spend none.

    This is the disclosure property ERC-5564 and Mikić et al. both rely on.
    Anyone 'simplifying' P3 to a single keypair breaks it, so it is asserted
    structurally: ViewingKeys has no field that could carry spend material.
    """
    testing.check_dual_key_separation(scheme)

    # P3-specific: the tweak h is fully known to a viewer, and is still useless
    # without the spending scalar m. Q1 examines the converse — a quantum
    # adversary recovers a candidate h for every registrant from a *spent*
    # address, and because the tag is domain-separated it cannot confirm any.
    keys = scheme.keygen()
    announcement = scheme.announce(keys.meta)
    match = scheme.scan(scheme.viewing_keys(keys), [announcement])[0]
    assert match.tweak is not None
    assert derive.eth_address(derive.pubkey_from_scalar(match.tweak)) != match.stealth_address


def test_recover_rejects_zero_stealth_key(scheme: P3Hybrid) -> None:
    """p == 0 must be refused even though it is vanishingly improbable."""
    keys = scheme.keygen()
    assert keys.spend_priv is not None
    poisoned = ScanMatch(index=0, stealth_address=b"\x00" * 20, tweak=SECP256K1_N - keys.spend_priv)
    with pytest.raises(DeriveError, match="zero"):
        scheme.recover_spend_key(keys, poisoned)


def test_recover_rejects_match_without_tweak(scheme: P3Hybrid) -> None:
    keys = scheme.keygen()
    with pytest.raises(DeriveError):
        scheme.recover_spend_key(keys, ScanMatch(index=0, stealth_address=b"\x00" * 20, tweak=None))


def test_scan_skips_other_schemes_and_bad_lengths(scheme: P3Hybrid) -> None:
    keys = scheme.keygen()
    good = scheme.announce(keys.meta)
    wrong_scheme = Announcement(1, good.payload, good.stealth_address, good.view_tag)
    truncated = Announcement(
        scheme.scheme_id, good.payload[:-1], good.stealth_address, good.view_tag
    )
    assert scheme.scan(scheme.viewing_keys(keys), [wrong_scheme, truncated]) == []


def test_stealth_addresses_are_unlinkable_to_each_other(scheme: P3Hybrid) -> None:
    """Repeated payments to one recipient must land on distinct addresses."""
    keys = scheme.keygen()
    addresses = {scheme.announce(keys.meta).stealth_address for _ in range(SAMPLES)}
    assert len(addresses) == SAMPLES
    meta_address_bytes = derive.eth_address(scheme.split_meta(keys.meta)[0])
    assert meta_address_bytes not in addresses


def test_announcement_payload_is_high_entropy(scheme: P3Hybrid) -> None:
    """Ciphertexts are pseudorandom, so calldata cost is content-dependent.

    Charter pitfall: zero bytes cost 4 gas in calldata against 16 for non-zero,
    so gas varies with payload content and must be sampled, not measured once.
    """
    keys = scheme.keygen()
    payloads = [scheme.announce(keys.meta).payload for _ in range(SAMPLES)]
    zero_fraction = sum(b == 0 for p in payloads for b in p) / sum(len(p) for p in payloads)
    # Expected ~1/256; a wide band still catches an all-zero or constant payload.
    assert 0.0005 < zero_fraction < 0.02


def test_independent_recipients_do_not_collide(scheme: P3Hybrid) -> None:
    """Sanity check on the KEM wiring: A must not decrypt B's payments."""
    alice, bob = scheme.keygen(), scheme.keygen()
    to_bob = [scheme.announce(bob.meta) for _ in range(SAMPLES)]
    assert scheme.scan(scheme.viewing_keys(alice), to_bob) == []
    assert len(scheme.scan(scheme.viewing_keys(bob), to_bob)) == SAMPLES


def test_random_keygen_is_not_deterministic(scheme: P3Hybrid) -> None:
    """Guard against a seeding bug that would silently reuse one keypair."""
    assert scheme.keygen().meta.payload != scheme.keygen().meta.payload
    assert os.urandom(1) is not None
