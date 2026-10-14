"""P2 data-plane tests (journal version of Mikić et al., JCST 2026).

The important one is ``test_recover_raises_not_evm_spendable``: it is the
concrete demonstration that MLWE SAP cannot complete a payment on an unmodified
EVM chain. That is a finding the thesis reports, not a shortcoming of this
implementation — see NOTES.md for the boundary statement. The size tests pin
the registered meta-address to the paper's Table 5.
"""

from __future__ import annotations

import pytest
from pqsap_core import kem, testing
from pqsap_core.derive import DeriveError
from pqsap_core.scheme import MetaAddress, NotEvmSpendable, ScanMatch

from p2_mlwe.scheme import (
    DILITHIUM_Q,
    SPEND_KEY_EXTRA,
    SPEND_PK_LEN,
    P2Mlwe,
    unpack_spend_pk,
)

SAMPLES = 20


@pytest.fixture(scope="module")
def scheme() -> P2Mlwe:
    return P2Mlwe()


def test_scheme_id_is_non_standard(scheme: P2Mlwe) -> None:
    assert scheme.scheme_id != 1
    assert scheme.scheme_id == 0x4D4C5745  # "MLWE"


def test_spending_key_is_uncompressed_dilithium_level3() -> None:
    """6 x 256 coefficients at 23 bits: the 4416 bytes the paper reports (§6.5)."""
    assert SPEND_PK_LEN == 6 * 256 * 23 // 8 == 4416


def test_level_matched_sizes_match_table_5(scheme: P2Mlwe) -> None:
    """Default is Kyber768 + Dilithium level 3: 5600 B, as in the paper's Table 5."""
    assert scheme.meta_len == SPEND_PK_LEN + kem.ML_KEM_768.ek_len == 5600
    assert scheme.payload_len == kem.ML_KEM_768.ct_len == 1088

    keys = scheme.keygen()
    assert len(keys.meta.payload) == 5600
    assert len(scheme.announce(keys.meta).payload) == 1088


def test_paper_primary_sizes_match_table_5() -> None:
    """The paper's primary instantiation is Kyber512 + Dilithium level 3: 5216 B."""
    paper = P2Mlwe(kem.ML_KEM_512)
    assert paper.meta_len == SPEND_PK_LEN + 800 == 5216
    assert paper.payload_len == 768
    assert paper.param_set == "mlkem512"


def test_spending_key_coefficients_are_valid(scheme: P2Mlwe) -> None:
    """Every packed coefficient lies in [0, q), so the bytes are a well-formed t."""
    keys = scheme.keygen(b"p2-coeffs")
    spend_pk, _ = scheme.split_meta(keys.meta)
    coeffs = unpack_spend_pk(spend_pk)
    assert len(coeffs) == 6 * 256
    assert all(0 <= c < DILITHIUM_Q for c in coeffs)
    # Pseudorandom content: zero bytes near 1/256, not a flattering all-zero key.
    assert spend_pk.count(0) / len(spend_pk) < 0.02


def test_p3_meta_is_under_a_quarter_of_p2s(scheme: P2Mlwe) -> None:
    """P3 keeps spending on secp256k1, so it carries no 4416-byte Dilithium key."""
    from p3_hybrid.scheme import P3Hybrid

    p3 = P3Hybrid()
    assert scheme.meta_len == 5600
    assert p3.meta_len == 1217
    # Announcements are identical, so registration is where P3 wins.
    assert scheme.payload_len == p3.payload_len
    reduction = 1 - p3.meta_len / scheme.meta_len
    assert 0.78 < reduction < 0.79  # 1 - 1217/5600 ≈ 78.3%


def test_recover_raises_not_evm_spendable(scheme: P2Mlwe) -> None:
    """The finding: MLWE SAP's stealth key cannot sign an EVM transaction.

    The stealth key is a Dilithium-structured lattice key. No Ethereum account
    corresponds to it, and spending needs on-chain Dilithium verification that
    Ethereum lacks without a precompile — as the authors state (§4.7, §5.5).
    """
    keys = scheme.keygen()
    announcement = scheme.announce(keys.meta)
    matches = scheme.scan(scheme.viewing_keys(keys), [announcement])
    assert len(matches) == 1

    with pytest.raises(NotEvmSpendable, match="Dilithium-structured lattice key"):
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
    """Viewing keys carry dk_view only; the spending secret never leaves RecipientKeys."""
    testing.check_dual_key_separation(scheme)

    keys = scheme.keygen()
    viewing = scheme.viewing_keys(keys)
    spend_secret = keys.extra[SPEND_KEY_EXTRA]
    assert viewing.view_secret != spend_secret
    assert spend_secret not in viewing.view_secret
    assert spend_secret not in viewing.meta.payload


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


def test_spending_and_viewing_keys_are_distinct(scheme: P2Mlwe) -> None:
    keys = scheme.keygen()
    spend_pk, ek_view = scheme.split_meta(keys.meta)
    assert len(spend_pk) == SPEND_PK_LEN
    assert len(ek_view) == kem.ML_KEM_768.ek_len
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
