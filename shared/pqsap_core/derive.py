"""Shared stealth-address derivation for every protocol in this study.

P1, P2 and P3 all import this module. That is deliberate and it is the
experiment's fairness guarantee: the three protocols differ in how they agree
on a shared secret, never in how a shared secret becomes an Ethereum address.
A protocol that derived addresses its own way would not be comparable.

Canonical rules, fixed here once and relied on by all three schemes:

* The digest is ``keccak256`` of the shared secret. Not SHA-256, not SHA3-256
  — Ethereum's keccak256, the same primitive the EVM exposes.
* The **view tag** is byte 0 of the raw 32-byte digest, matching ERC-5564.
  P1 and P2 use exactly this rule. P3 is the one exception: its tag comes from
  a separate, domain-separated digest (:func:`domain_separated_view_tag`), so
  the tag reveals nothing about ``h``. See docs/threat-model.md, Q1, for why.
* The **tweak scalar** ``h`` is that same digest read as a big-endian integer
  and reduced mod n — for every protocol, P3 included. Sender and recipient
  derive both values from one digest, so the reduction can never desynchronise
  them.
* ``h == 0`` and ``p == 0`` are rejected. Both are negligible in probability
  and both are checked anyway: ``h == 0`` would give ``P = M``, publishing the
  recipient's own spending key as the stealth address and destroying the
  unlinkability the protocol exists to provide.
"""

from __future__ import annotations

from typing import Final

from coincurve import PrivateKey, PublicKey
from eth_utils.address import to_checksum_address
from eth_utils.crypto import keccak as _keccak

__all__ = [
    "SECP256K1_N",
    "DeriveError",
    "derive_stealth_privkey",
    "derive_stealth_pubkey",
    "domain_separated_view_tag",
    "eth_address",
    "h_scalar_and_tag",
    "keccak256",
    "pubkey_from_scalar",
    "to_checksum",
]

# Order of the secp256k1 group. Hardcoding a constant is a correctness risk, so
# test_derive.py checks it behaviourally against libsecp256k1 rather than
# against another copy of the same literal.
SECP256K1_N: Final[int] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_SCALAR_BYTES: Final[int] = 32
_COMPRESSED_PUBKEY_BYTES: Final[int] = 33
_ADDRESS_BYTES: Final[int] = 20


class DeriveError(Exception):
    """A derivation produced a value the protocol must refuse to use."""


def keccak256(data: bytes) -> bytes:
    """Ethereum's keccak256. Returns 32 bytes."""
    digest: bytes = _keccak(data)
    return digest


def h_scalar_and_tag(shared_secret: bytes) -> tuple[int, int]:
    """Turn a shared secret into the tweak scalar ``h`` and the view tag.

    Both come from a single ``keccak256`` digest: the tag is byte 0, the scalar
    is the whole digest mod n.

    Raises:
        DeriveError: if the digest reduces to zero mod n, which would make the
            stealth address equal the recipient's registered spending key.
    """
    digest = keccak256(shared_secret)
    tag = digest[0]
    h = int.from_bytes(digest, "big") % SECP256K1_N
    if h == 0:
        raise DeriveError("tweak scalar h is zero; stealth address would equal the meta-address")
    return h, tag


def domain_separated_view_tag(shared_secret: bytes, domain: bytes) -> int:
    """View tag from its own digest of the shared secret: ``keccak256(domain ‖ S)[0]``.

    The ERC-5564 tag is a byte of the very digest ``h`` is read from, so anyone
    who learns ``h`` can compute the tag. Once a stealth address spends, a
    quantum adversary learns a candidate ``h_j`` for every registered recipient,
    and the tag then filters those candidates. A tag computed under a separate domain is a function
    of ``S`` alone: knowing ``h = keccak256(S)`` does not give it, because
    keccak256 does not invert and ``S`` is protected by the KEM.

    ``h`` is unaffected; it still comes from :func:`h_scalar_and_tag`.

    Raises:
        DeriveError: if ``domain`` is empty, which would silently reproduce the
            ERC-5564 tag and with it the leak this function exists to close.
    """
    if not domain:
        raise DeriveError("a domain-separated view tag needs a non-empty domain")
    return keccak256(domain + shared_secret)[0]


def derive_stealth_pubkey(spend_pub33: bytes, h: int) -> bytes:
    """Compute ``P = M + h*G`` and return it compressed (33 bytes).

    This is the sender's view and also the recipient's scan-time check: it needs
    only the *public* spending key, which is why scanning never touches spend
    material.
    """
    _require_pubkey(spend_pub33)
    _require_scalar_in_range(h, "h")
    tweaked = PublicKey(spend_pub33).add(h.to_bytes(_SCALAR_BYTES, "big"))
    out: bytes = tweaked.format(compressed=True)
    return out


def derive_stealth_privkey(spend_priv: int, h: int) -> int:
    """Compute the stealth private key ``p = (m + h) mod n``.

    Raises:
        DeriveError: if ``p == 0``. Negligible in probability, mandatory to
            check: zero is not a valid secp256k1 key and controls nothing.
    """
    _require_scalar_in_range(spend_priv, "spend_priv")
    _require_scalar_in_range(h, "h")
    p = (spend_priv + h) % SECP256K1_N
    if p == 0:
        raise DeriveError("stealth private key p is zero")
    return p


def pubkey_from_scalar(scalar: int) -> bytes:
    """Return the compressed public key for a private scalar."""
    _require_scalar_in_range(scalar, "scalar")
    key = PrivateKey.from_int(scalar)
    out: bytes = key.public_key.format(compressed=True)
    return out


def eth_address(pub33: bytes) -> bytes:
    """Ethereum address of a compressed public key: 20 raw bytes, not checksummed."""
    _require_pubkey(pub33)
    uncompressed = PublicKey(pub33).format(compressed=False)
    # Drop the 0x04 SEC1 prefix; the address is the last 20 bytes of the hash
    # of the 64-byte X‖Y coordinate pair.
    return keccak256(uncompressed[1:])[-_ADDRESS_BYTES:]


def to_checksum(addr20: bytes) -> str:
    """EIP-55 checksummed rendering of a 20-byte address."""
    if len(addr20) != _ADDRESS_BYTES:
        raise DeriveError(f"address must be {_ADDRESS_BYTES} bytes, got {len(addr20)}")
    return str(to_checksum_address(addr20))


def _require_pubkey(pub33: bytes) -> None:
    if len(pub33) != _COMPRESSED_PUBKEY_BYTES:
        raise DeriveError(
            f"expected {_COMPRESSED_PUBKEY_BYTES}-byte compressed public key, got {len(pub33)}"
        )


def _require_scalar_in_range(value: int, name: str) -> None:
    if not 0 < value < SECP256K1_N:
        raise DeriveError(f"{name} must be in (0, n); got a value outside the group order")
