"""P1 protocol behaviour, beyond the reference-vector pinning.

The shared invariant helpers do most of the work here, deliberately: P1, P2 and
P3 are held to identical properties by identical code, which is what keeps the
three-way comparison honest.
"""

from __future__ import annotations

import pytest
from coincurve import PublicKey
from pqsap_core import derive, testing
from pqsap_core.derive import SECP256K1_N, DeriveError
from pqsap_core.scheme import Announcement, MetaAddress, ScanMatch

from p1_erc5564.scheme import META_ADDRESS_PREFIX, P1Erc5564

SAMPLES = 20
TAG_COLLISION_ATTEMPTS = 10_000


@pytest.fixture(scope="module")
def scheme() -> P1Erc5564:
    return P1Erc5564()


def test_scheme_id_is_the_standard_one(scheme: P1Erc5564) -> None:
    """P1 is the baseline, so it uses the id ERC-5564 actually standardises."""
    assert scheme.scheme_id == 1
    assert scheme.param_set == "secp256k1"


def test_sizes_match_charter(scheme: P1Erc5564) -> None:
    """66-byte meta-address, 33-byte announcement payload."""
    assert scheme.meta_len == 66
    assert scheme.payload_len == 33

    keys = scheme.keygen()
    assert len(keys.meta.payload) == 66
    assert len(scheme.announce(keys.meta).payload) == 33


def test_roundtrip(scheme: P1Erc5564) -> None:
    testing.check_roundtrip(scheme, SAMPLES)


def test_scan_rejects_foreign(scheme: P1Erc5564) -> None:
    testing.check_scan_rejects_foreign(scheme)


def test_dual_key_separation(scheme: P1Erc5564) -> None:
    testing.check_dual_key_separation(scheme)


def test_address_derivation_is_shared(scheme: P1Erc5564) -> None:
    testing.check_address_derivation_is_shared(scheme)


def test_announcement_shape(scheme: P1Erc5564) -> None:
    keys = scheme.keygen()
    testing.check_announcement_shape(scheme, scheme.announce(keys.meta))


def test_full_roundtrip_signs_as_stealth_address(scheme: P1Erc5564) -> None:
    from eth_account import Account
    from eth_account.messages import encode_defunct

    keys = scheme.keygen()
    announcement = scheme.announce(keys.meta)
    matches = scheme.scan(scheme.viewing_keys(keys), [announcement])
    p = scheme.recover_spend_key(keys, matches[0])

    message = encode_defunct(text="erc-5564 baseline")
    signed = Account.sign_message(message, p.to_bytes(32, "big"))
    assert Account.recover_message(message, signature=signed.signature) == derive.to_checksum(
        announcement.stealth_address
    )


def test_seeded_keygen_is_reproducible(scheme: P1Erc5564) -> None:
    first, second = scheme.keygen(b"sample-1"), scheme.keygen(b"sample-1")
    assert first.meta.payload == second.meta.payload
    assert first.spend_priv == second.spend_priv
    assert scheme.keygen(b"sample-2").meta.payload != first.meta.payload


def test_spending_and_viewing_keys_are_independent(scheme: P1Erc5564) -> None:
    """DKSAP's two keys must be genuinely distinct, not one key used twice."""
    keys = scheme.keygen()
    spend_pub, view_pub = scheme.split_meta(keys.meta)
    assert spend_pub != view_pub
    assert keys.spend_priv is not None
    assert keys.spend_priv.to_bytes(32, "big") != keys.view_secret


def test_meta_address_string_roundtrip(scheme: P1Erc5564) -> None:
    """ERC-5564 renders meta-addresses as st:eth:0x…"""
    keys = scheme.keygen()
    text = scheme.format_meta_address(keys.meta)
    assert text.startswith(META_ADDRESS_PREFIX)
    assert scheme.parse_meta_address(text).payload == keys.meta.payload

    with pytest.raises(DeriveError):
        scheme.parse_meta_address("0xdeadbeef")


def test_split_meta_rejects_wrong_length(scheme: P1Erc5564) -> None:
    with pytest.raises(DeriveError):
        scheme.split_meta(MetaAddress(scheme.scheme_id, b"\x02" * 65))


def test_recover_rejects_zero_stealth_key(scheme: P1Erc5564) -> None:
    keys = scheme.keygen()
    assert keys.spend_priv is not None
    poisoned = ScanMatch(index=0, stealth_address=b"\x00" * 20, tweak=SECP256K1_N - keys.spend_priv)
    with pytest.raises(DeriveError, match="zero"):
        scheme.recover_spend_key(keys, poisoned)


def test_scan_survives_malformed_payload(scheme: P1Erc5564) -> None:
    """A hostile or broken announcement must not crash a scan."""
    keys = scheme.keygen()
    good = scheme.announce(keys.meta)
    junk = Announcement(scheme.scheme_id, b"\x02" + b"\xff" * 32, good.stealth_address, 0)
    wrong_len = Announcement(scheme.scheme_id, b"\x02" * 32, good.stealth_address, 0)

    matches = scheme.scan(scheme.viewing_keys(keys), [junk, wrong_len, good])
    assert [m.index for m in matches] == [2]


def test_ephemeral_key_range_is_enforced(scheme: P1Erc5564) -> None:
    keys = scheme.keygen()
    for bad in (0, SECP256K1_N):
        with pytest.raises(DeriveError):
            scheme.announce(keys.meta, ephemeral_priv=bad)


def test_stealth_addresses_are_unlinkable(scheme: P1Erc5564) -> None:
    keys = scheme.keygen()
    addresses = {scheme.announce(keys.meta).stealth_address for _ in range(SAMPLES)}
    assert len(addresses) == SAMPLES


@pytest.mark.slow
def test_colliding_tag_rejected_by_address_check(scheme: P1Erc5564) -> None:
    """P1's view tag is probabilistic too, so it needs the same address check.

    The mechanism differs from P3's — here a foreign announcement yields a
    genuine but unrelated ECDH point rather than implicit-rejection noise — but
    the consequence is identical: about 1 in 256 foreign announcements passes
    the tag, and only re-deriving the address rejects them.
    """
    victim = scheme.keygen()
    viewing = scheme.viewing_keys(victim)
    spend_pub, _ = scheme.split_meta(victim.meta)
    view_priv = int.from_bytes(viewing.view_secret, "big")
    stranger = scheme.keygen()

    for _ in range(TAG_COLLISION_ATTEMPTS):
        announcement = scheme.announce(stranger.meta)

        point = PublicKey(announcement.payload).multiply(view_priv.to_bytes(32, "big"))
        h, tag = derive.h_scalar_and_tag(point.format(compressed=False)[1:])
        if tag != announcement.view_tag:
            continue

        assert derive.eth_address(derive.derive_stealth_pubkey(spend_pub, h)) != (
            announcement.stealth_address
        )
        assert scheme.scan(viewing, [announcement]) == []
        return

    pytest.fail(f"no view-tag collision in {TAG_COLLISION_ATTEMPTS} attempts")
