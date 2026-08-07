"""Tests for the shared derivation layer.

Correctness here is load-bearing for all three protocols, so nothing is checked
against a second copy of the same assumption: addresses are cross-checked
against eth-account, and the group order is checked against libsecp256k1's own
behaviour rather than against another literal.
"""

from __future__ import annotations

import os

import pytest
from coincurve import PrivateKey
from eth_account import Account

from pqsap_core import derive
from pqsap_core.derive import SECP256K1_N, DeriveError

SAMPLES = 20


def _random_scalar() -> int:
    return (int.from_bytes(os.urandom(32), "big") % (SECP256K1_N - 1)) + 1


def test_keccak256_empty_string_vector() -> None:
    """Pin the hash function. SHA3-256 and SHA-256 would both silently 'work'."""
    assert (
        derive.keccak256(b"").hex()
        == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )


def test_group_order_matches_libsecp256k1() -> None:
    """n-1 must be a valid key and n must not be, per libsecp256k1 itself."""
    PrivateKey.from_int(SECP256K1_N - 1)
    with pytest.raises(ValueError, match="less than"):
        PrivateKey.from_int(SECP256K1_N)


def test_eth_address_matches_eth_account() -> None:
    for _ in range(SAMPLES):
        scalar = _random_scalar()
        pub = derive.pubkey_from_scalar(scalar)
        expected = Account.from_key(scalar.to_bytes(32, "big")).address
        assert derive.to_checksum(derive.eth_address(pub)) == expected


def test_pub_priv_derivation_commute() -> None:
    """addr((m+h)*G) == addr(M + h*G).

    This identity is why scanning can verify a match from public spending
    material alone, which is what keeps viewing keys unable to spend.
    """
    for _ in range(SAMPLES):
        m, h = _random_scalar(), _random_scalar()
        big_m = derive.pubkey_from_scalar(m)
        p = derive.derive_stealth_privkey(m, h)
        assert derive.eth_address(derive.pubkey_from_scalar(p)) == derive.eth_address(
            derive.derive_stealth_pubkey(big_m, h)
        )


def test_h_scalar_reduces_mod_n() -> None:
    """A digest at or above n must be reduced, not rejected or truncated."""
    for _ in range(200):
        secret = os.urandom(32)
        digest = derive.keccak256(secret)
        h, _ = derive.h_scalar_and_tag(secret)
        assert h == int.from_bytes(digest, "big") % SECP256K1_N
        assert 0 < h < SECP256K1_N


def test_tag_is_first_digest_byte() -> None:
    """Pin the view-tag rule; sender and recipient must agree byte-for-byte."""
    for _ in range(SAMPLES):
        secret = os.urandom(32)
        _, tag = derive.h_scalar_and_tag(secret)
        assert tag == derive.keccak256(secret)[0]
        assert 0 <= tag <= 0xFF


def test_h_zero_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """h == 0 would make P == M, publishing the recipient's own key as the
    stealth address. Vanishingly unlikely, still refused."""
    monkeypatch.setattr(derive, "keccak256", lambda _data: SECP256K1_N.to_bytes(32, "big"))
    with pytest.raises(DeriveError, match="zero"):
        derive.h_scalar_and_tag(b"anything")


def test_stealth_priv_zero_raises() -> None:
    """p == 0 is not a usable key; charter requires an explicit check."""
    m = _random_scalar()
    with pytest.raises(DeriveError, match="zero"):
        derive.derive_stealth_privkey(m, SECP256K1_N - m)


def test_scalar_range_is_enforced() -> None:
    m = _random_scalar()
    big_m = derive.pubkey_from_scalar(m)
    for bad in (0, SECP256K1_N, SECP256K1_N + 1):
        with pytest.raises(DeriveError):
            derive.derive_stealth_pubkey(big_m, bad)
        with pytest.raises(DeriveError):
            derive.derive_stealth_privkey(m, bad)


def test_malformed_pubkey_rejected() -> None:
    with pytest.raises(DeriveError):
        derive.eth_address(b"\x02" * 32)
    with pytest.raises(DeriveError):
        derive.derive_stealth_pubkey(b"\x02" * 34, 1)


def test_to_checksum_rejects_wrong_length() -> None:
    with pytest.raises(DeriveError):
        derive.to_checksum(b"\x00" * 19)
