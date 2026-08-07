"""P2 data-plane tests.

The important one is ``test_recover_raises_not_evm_spendable``: it is the
concrete demonstration that MLWE SAP cannot complete a payment on an unmodified
EVM chain. That is a finding the thesis reports, not a shortcoming of this
implementation — see NOTES.md for the boundary statement.
"""

from __future__ import annotations

import pytest
from pqsap_core import kem, testing
from pqsap_core.derive import DeriveError
from pqsap_core.scheme import MetaAddress, NotEvmSpendable, ScanMatch

from p2_mlwe.scheme import SPEND_KEY_EXTRA, P2Mlwe

SAMPLES = 20


@pytest.fixture(scope="module")
def scheme() -> P2Mlwe:
    return P2Mlwe()


def test_scheme_id_is_non_standard(scheme: P2Mlwe) -> None:
    assert scheme.scheme_id != 1
    assert scheme.scheme_id == 0x4D4C5745  # "MLWE"


def test_level_matched_sizes(scheme: P2Mlwe) -> None:
    """Default is ML-KEM-768, so P2 and P3 are compared at equal security."""
    assert scheme.meta_len == 2 * kem.ML_KEM_768.ek_len == 2368
    assert scheme.payload_len == kem.ML_KEM_768.ct_len == 1088

    keys = scheme.keygen()
    assert len(keys.meta.payload) == 2368
    assert len(scheme.announce(keys.meta).payload) == 1088


def test_paper_faithful_sizes() -> None:
    """The paper's own experiments used Kyber512; NOTES.md records both."""
    paper = P2Mlwe(kem.ML_KEM_512)
    assert paper.meta_len == 2 * 800 == 1600
    assert paper.payload_len == 768
    assert paper.param_set == "mlkem512"


def test_meta_is_twice_p3s_lattice_material(scheme: P2Mlwe) -> None:
    """Two lattice keypairs against P3's one — the source of P3's advantage."""
    from p3_hybrid.scheme import P3Hybrid

    p3 = P3Hybrid()
    assert scheme.meta_len == 2368
    assert p3.meta_len == 1217
    # Announcements are identical, so registration is where P3 wins.
    assert scheme.payload_len == p3.payload_len
    reduction = 1 - p3.meta_len / scheme.meta_len
    assert 0.48 < reduction < 0.49  # the charter's "roughly 49% smaller"


def test_recover_raises_not_evm_spendable(scheme: P2Mlwe) -> None:
    """The finding: MLWE SAP's stealth key cannot sign an EVM transaction.

    p = k + XOF(S) is an element of R_q. No Ethereum account corresponds to it,
    so an end-to-end payment cannot be completed without Ethereum itself
    becoming post-quantum.
    """
    keys = scheme.keygen()
    announcement = scheme.announce(keys.meta)
    matches = scheme.scan(scheme.viewing_keys(keys), [announcement])
    assert len(matches) == 1

    with pytest.raises(NotEvmSpendable, match="lattice element"):
        scheme.recover_spend_key(keys, matches[0])


def test_no_secp256k1_spending_scalar_exists(scheme: P2Mlwe) -> None:
    """Structurally, not just behaviourally: there is no EVM spend key to hold."""
    keys = scheme.keygen()
    assert keys.spend_priv is None
    matches = scheme.scan(scheme.viewing_keys(keys), [scheme.announce(keys.meta)])
    assert matches[0].tweak is None


def test_roundtrip(scheme: P2Mlwe) -> None:
    testing.check_roundtrip(scheme, SAMPLES)


def test_scan_rejects_foreign(scheme: P2Mlwe) -> None:
    testing.check_scan_rejects_foreign(scheme)


def test_dual_key_separation(scheme: P2Mlwe) -> None:
    """Viewing keys carry dk_view only; dk_spend never leaves RecipientKeys."""
    testing.check_dual_key_separation(scheme)

    keys = scheme.keygen()
    viewing = scheme.viewing_keys(keys)
    dk_spend = keys.extra[SPEND_KEY_EXTRA]
    assert viewing.view_secret != dk_spend
    assert dk_spend not in (viewing.view_secret, viewing.meta.payload)


def test_announcement_shape(scheme: P2Mlwe) -> None:
    keys = scheme.keygen()
    testing.check_announcement_shape(scheme, scheme.announce(keys.meta))


def test_stealth_address_standin_is_not_zero(scheme: P2Mlwe) -> None:
    """The stand-in must be pseudorandom, or P2's calldata cost is understated.

    Twenty zero bytes cost 4 gas each against 16 for non-zero, so the zero
    address would make P2 look ~240 gas per announcement cheaper for reasons
    unrelated to its cryptography.
    """
    keys = scheme.keygen()
    addresses = [scheme.announce(keys.meta).stealth_address for _ in range(SAMPLES)]
    assert len(set(addresses)) == SAMPLES
    assert all(a != b"\x00" * 20 for a in addresses)

    zero_fraction = sum(b == 0 for a in addresses for b in a) / (20 * SAMPLES)
    assert zero_fraction < 0.05  # expected ~1/256


def test_two_independent_lattice_keypairs(scheme: P2Mlwe) -> None:
    keys = scheme.keygen()
    ek_spend, ek_view = scheme.split_meta(keys.meta)
    assert ek_spend != ek_view
    assert keys.extra[SPEND_KEY_EXTRA] != keys.view_secret


def test_seeded_keygen_is_reproducible(scheme: P2Mlwe) -> None:
    first, second = scheme.keygen(b"p2-sample-1"), scheme.keygen(b"p2-sample-1")
    assert first.meta.payload == second.meta.payload
    assert first.view_secret == second.view_secret
    assert first.extra[SPEND_KEY_EXTRA] == second.extra[SPEND_KEY_EXTRA]
    assert scheme.keygen(b"p2-sample-2").meta.payload != first.meta.payload


def test_split_meta_rejects_wrong_length(scheme: P2Mlwe) -> None:
    with pytest.raises(DeriveError):
        scheme.split_meta(MetaAddress(scheme.scheme_id, b"\x00" * 100))


def test_scan_skips_other_schemes_and_bad_lengths(scheme: P2Mlwe) -> None:
    from pqsap_core.scheme import Announcement

    keys = scheme.keygen()
    good = scheme.announce(keys.meta)
    assert (
        scheme.scan(
            scheme.viewing_keys(keys),
            [
                Announcement(1, good.payload, good.stealth_address, good.view_tag),
                Announcement(
                    scheme.scheme_id, good.payload[:-1], good.stealth_address, good.view_tag
                ),
            ],
        )
        == []
    )


def test_recover_raises_even_for_a_fabricated_match(scheme: P2Mlwe) -> None:
    """No input can coax an EVM spending key out of this protocol."""
    keys = scheme.keygen()
    with pytest.raises(NotEvmSpendable):
        scheme.recover_spend_key(keys, ScanMatch(index=0, stealth_address=b"\x11" * 20, tweak=42))
