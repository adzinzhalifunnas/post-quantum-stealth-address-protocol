"""P1 — ERC-5564 / DKSAP on secp256k1, the current standard and our baseline.

This is the protocol post-quantum schemes must be measured against, so it is
implemented to match the standard rather than to be convenient::

    Sender:     r random, R = r*G
                Q = r * M_view
                h, tag = keccak256(Q.x ‖ Q.y)
                P = M_spend + h*G
                announce(R, addr(P), tag)

    Recipient:  Q = m_view * R          (same point, by ECDH)
                h, tag = keccak256(Q.x ‖ Q.y)
                tag must match, then addr(M_spend + h*G) must match
                p = (m_spend + h) mod n

**The shared point is hashed uncompressed, as ``x ‖ y``: 64 bytes, no SEC1
prefix byte.** ERC-5564's prose does not say this — it writes only ``s_h =
h(s)``, naming neither the serialisation nor even the hash function. Getting it
wrong yields a protocol that is self-consistent and silently non-standard, which
for a baseline would be worse than useless. The rule here is taken from the
EIP's own reference implementation (``assets/erc-5564/minimal_poc.ipynb`` in
ethereum/ERCs), and ``tests/test_p1_vectors.py`` pins this implementation to
that notebook's executed output.

Note the deliberate contrast with P3: both hash a shared secret through the same
``pqsap_core.derive`` code, but P1's secret is an elliptic-curve point that a
quantum adversary can recover from ``R`` and ``M_view``, whereas P3's is an
ML-KEM shared secret that stays confidential. Same address derivation, different
security assumption — which is exactly the comparison the thesis makes.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import ClassVar, Final

from coincurve import PublicKey
from pqsap_core import derive
from pqsap_core.derive import DeriveError
from pqsap_core.scheme import (
    Announcement,
    MetaAddress,
    RecipientKeys,
    ScanMatch,
    StealthScheme,
    ViewingKeys,
)

__all__ = ["META_ADDRESS_PREFIX", "P1_SCHEME_ID", "P1Erc5564"]

#: The one scheme id ERC-5564 actually standardises: secp256k1 with view tags.
P1_SCHEME_ID: Final[int] = 1

#: ERC-5564 renders meta-addresses as ``st:eth:0x<spend><view>``.
META_ADDRESS_PREFIX: Final[str] = "st:eth:0x"

_PUBKEY_BYTES: Final[int] = 33
_META_BYTES: Final[int] = 2 * _PUBKEY_BYTES

_KDF_SPEND: Final[bytes] = b"pqsap/p1/spend"
_KDF_VIEW: Final[bytes] = b"pqsap/p1/view"


class P1Erc5564(StealthScheme):
    """ERC-5564 scheme 1: dual-key stealth addresses on secp256k1."""

    scheme_id: ClassVar[int] = P1_SCHEME_ID
    name: ClassVar[str] = "p1_erc5564"

    @property
    def meta_len(self) -> int:
        return _META_BYTES

    @property
    def payload_len(self) -> int:
        return _PUBKEY_BYTES

    @property
    def param_set(self) -> str:
        return "secp256k1"

    def keygen(self, seed: bytes | None = None) -> RecipientKeys:
        if seed is None:
            spend_priv = _random_scalar()
            view_priv = _random_scalar()
        else:
            spend_priv = _scalar_from_seed(_KDF_SPEND, seed)
            view_priv = _scalar_from_seed(_KDF_VIEW, seed)

        payload = derive.pubkey_from_scalar(spend_priv) + derive.pubkey_from_scalar(view_priv)
        return RecipientKeys(
            meta=MetaAddress(self.scheme_id, payload),
            spend_priv=spend_priv,
            view_secret=view_priv.to_bytes(32, "big"),
        )

    def viewing_keys(self, keys: RecipientKeys) -> ViewingKeys:
        return ViewingKeys(meta=keys.meta, view_secret=keys.view_secret)

    def announce(self, meta: MetaAddress, ephemeral_priv: int | None = None) -> Announcement:
        """Produce one announcement.

        Args:
            meta: the recipient's registered meta-address.
            ephemeral_priv: normally ``None`` so a fresh ephemeral key is drawn.
                Supplying one is for reproducing the EIP's published reference
                vector, never for real use — a reused ephemeral key links
                payments to each other.
        """
        spend_pub, view_pub = self.split_meta(meta)
        r = ephemeral_priv if ephemeral_priv is not None else _random_scalar()
        derive._require_scalar_in_range(r, "ephemeral_priv")

        shared_point = _shared_secret(view_pub, r)
        h, tag = derive.h_scalar_and_tag(shared_point)
        stealth_pub = derive.derive_stealth_pubkey(spend_pub, h)

        return Announcement(
            scheme_id=self.scheme_id,
            payload=derive.pubkey_from_scalar(r),
            stealth_address=derive.eth_address(stealth_pub),
            view_tag=tag,
        )

    def scan(self, keys: ViewingKeys, announcements: Sequence[Announcement]) -> list[ScanMatch]:
        spend_pub, _ = self.split_meta(keys.meta)
        view_priv = int.from_bytes(keys.view_secret, "big")
        matches: list[ScanMatch] = []

        for index, ann in enumerate(announcements):
            if ann.scheme_id != self.scheme_id or len(ann.payload) != _PUBKEY_BYTES:
                continue

            try:
                shared_point = _shared_secret(ann.payload, view_priv)
                h, tag = derive.h_scalar_and_tag(shared_point)
            except (DeriveError, ValueError):
                # A malformed ephemeral public key is another party's problem.
                continue

            if tag != ann.view_tag:
                continue

            # Mandatory for the same reason as in P3: the view tag is a
            # one-byte probabilistic filter, not proof of ownership.
            stealth_pub = derive.derive_stealth_pubkey(spend_pub, h)
            if derive.eth_address(stealth_pub) != ann.stealth_address:
                continue

            matches.append(ScanMatch(index=index, stealth_address=ann.stealth_address, tweak=h))

        return matches

    def recover_spend_key(self, keys: RecipientKeys, match: ScanMatch) -> int:
        if keys.spend_priv is None:
            raise DeriveError("recipient keys carry no spending scalar")
        if match.tweak is None:
            raise DeriveError("match carries no tweak; cannot recover a spending key")
        return derive.derive_stealth_privkey(keys.spend_priv, match.tweak)

    def split_meta(self, meta: MetaAddress) -> tuple[bytes, bytes]:
        """Split into ``(M_spend, M_view)``, per ERC-5564's first-half/second-half rule."""
        if len(meta.payload) != _META_BYTES:
            raise DeriveError(f"meta-address must be {_META_BYTES} bytes, got {len(meta.payload)}")
        return meta.payload[:_PUBKEY_BYTES], meta.payload[_PUBKEY_BYTES:]

    def format_meta_address(self, meta: MetaAddress) -> str:
        """Render as ERC-5564's ``st:eth:0x…`` string."""
        self.split_meta(meta)
        return META_ADDRESS_PREFIX + meta.payload.hex()

    def parse_meta_address(self, text: str) -> MetaAddress:
        """Parse ERC-5564's ``st:eth:0x…`` string."""
        if not text.startswith(META_ADDRESS_PREFIX):
            raise DeriveError(f"meta-address must start with {META_ADDRESS_PREFIX!r}")
        payload = bytes.fromhex(text[len(META_ADDRESS_PREFIX) :])
        meta = MetaAddress(self.scheme_id, payload)
        self.split_meta(meta)
        return meta


def _shared_secret(pubkey33: bytes, scalar: int) -> bytes:
    """ECDH shared point, serialised as ``x ‖ y`` (64 bytes).

    Deliberately not ``coincurve``'s ``ecdh()``: that applies SHA-256 to the
    point internally, which is not what ERC-5564 does and would silently produce
    a non-standard baseline.
    """
    derive._require_scalar_in_range(scalar, "scalar")
    point = PublicKey(pubkey33).multiply(scalar.to_bytes(32, "big"))
    # Strip the 0x04 SEC1 prefix; the EIP's reference hashes the bare
    # coordinate pair, not a prefixed encoding.
    return bytes(point.format(compressed=False)[1:])


def _random_scalar() -> int:
    while True:
        candidate = int.from_bytes(os.urandom(32), "big") % derive.SECP256K1_N
        if candidate != 0:
            return candidate


def _scalar_from_seed(domain: bytes, seed: bytes) -> int:
    counter = 0
    while True:
        digest = derive.keccak256(domain + seed + counter.to_bytes(4, "big"))
        candidate = int.from_bytes(digest, "big") % derive.SECP256K1_N
        if candidate != 0:
            return candidate
        counter += 1  # pragma: no cover - probability ~2^-256
