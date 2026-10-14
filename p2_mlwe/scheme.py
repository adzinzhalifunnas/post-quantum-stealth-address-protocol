"""P2 — the MLWE SAP data plane (Mikić, Srbakoski, Praška, JCST 2026).

Reference: the peer-reviewed journal version, *Post-quantum stealth address
protocols*, Journal of Cyber Security Technology, published online 2026-01-08,
doi:10.1080/23742917.2025.2611820. The earlier preprint (arXiv:2501.13733) used
two Kyber keypairs; the journal version replaces the spending keypair with a
Dilithium-compatible Module-LWE key. This module follows the journal version.

**This implements their data plane, not their protocol.** The distinction is
deliberate; see ``NOTES.md`` for the full boundary statement. In the journal
construction (§5.4–5.5) the recipient's meta-address is ``MA = (K, V)``:

- ``V`` is a Kyber encapsulation key (the viewing key), and
- ``K`` is a Dilithium-structured public key ``t = A·s + e``. It must stay
  **uncompressed**, because Dilithium's ``Power2Round`` is not additively
  homomorphic and the stealth key is derived by adding to ``t``. At Dilithium's
  NIST level-3 parameters that is 6 × 256 coefficients of 23 bits, i.e.
  **4416 bytes** — the figure the paper reports in §6.5 and Table 5.

The stealth key is ``t' = A·(s + k') + e'`` and the stealth private key has the
structure of a Dilithium private key (§5.5). Spending therefore needs on-chain
Dilithium verification, which Ethereum does not offer without a precompile, and
an address format that Ethereum's ECDSA-bound address scheme does not support —
both stated by the authors themselves (§4.7, §5.5).

What goes on-chain is the registry entry and the announcement, and those need
only correct sizes and encoding:

- ``V`` and the announcement ciphertext are genuine ML-KEM objects from liboqs.
- ``K`` is 1536 coefficients sampled uniformly modulo q = 8380417 and packed at
  23 bits each, exactly the byte layout of an uncompressed ``t``. Under the
  Module-LWE assumption a real ``t = A·s + e`` is indistinguishable from
  uniform, so the byte statistics that drive calldata and storage cost — length
  and zero-byte fraction — are faithful. No Dilithium arithmetic is performed,
  in line with the charter's rule that lattice arithmetic stays out of scope.

Registered sizes therefore reproduce the paper's Table 5 exactly: 5600 bytes
with Kyber768 (level-matched with P3) and 5216 bytes with Kyber512 (the paper's
primary instantiation). Announcements are one Kyber ciphertext, the same size
as P3's, so P3's advantage over P2 lives entirely in registration.

``recover_spend_key`` raises :class:`NotEvmSpendable`. That is the point rather
than a limitation of our implementation: an end-to-end payment cannot complete
on an unmodified Ethereum, as the authors themselves acknowledge.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Sequence
from typing import ClassVar, Final

from pqsap_core import derive, kem
from pqsap_core.derive import DeriveError
from pqsap_core.kem import SEED_BYTES, KemSpec
from pqsap_core.scheme import (
    Announcement,
    MetaAddress,
    NotEvmSpendable,
    RecipientKeys,
    ScanMatch,
    StealthScheme,
    ViewingKeys,
)

__all__ = [
    "DILITHIUM_K",
    "DILITHIUM_N",
    "DILITHIUM_Q",
    "DILITHIUM_T_BITS",
    "P2_SCHEME_ID",
    "SPEND_KEY_EXTRA",
    "SPEND_PK_LEN",
    "P2Mlwe",
    "unpack_spend_pk",
]

#: ASCII "MLWE". Non-standard, like P3's — ERC-5564 registers only id 1.
P2_SCHEME_ID: Final[int] = 0x4D4C5745

#: Dilithium NIST level-3 module rank (rows of ``t``), as used in the journal.
DILITHIUM_K: Final[int] = 6
#: Polynomial degree.
DILITHIUM_N: Final[int] = 256
#: Dilithium modulus q.
DILITHIUM_Q: Final[int] = 8_380_417
#: Bits per uncompressed coefficient of ``t`` (q < 2**23).
DILITHIUM_T_BITS: Final[int] = 23
#: Uncompressed spending public key: 6 · 256 · 23 / 8 = 4416 bytes (journal §6.5).
SPEND_PK_LEN: Final[int] = DILITHIUM_K * DILITHIUM_N * DILITHIUM_T_BITS // 8

#: Key under which the spending-key stand-in secret is carried in ``RecipientKeys.extra``.
SPEND_KEY_EXTRA: Final[str] = "spend_secret_seed"

# The stand-in stealth address is domain-separated from the view tag so the two
# are not trivially derivable from one another. See NOTES.md for why a stand-in
# is used at all rather than the zero address.
_KDF_ADDR: Final[bytes] = b"pqsap/p2/stealth-address-standin"
_KDF_SPEND_SEED: Final[bytes] = b"pqsap/p2/dilithium/spend/"
_KDF_SPEND_PK: Final[bytes] = b"pqsap/p2/dilithium/t/"
_KDF_VIEW_SEED: Final[bytes] = b"pqsap/p2/kem/view/"


class P2Mlwe(StealthScheme):
    """MLWE SAP data plane (journal version): Kyber viewing key, Dilithium-structured spending key.

    The Kyber parameter set is a constructor argument. It defaults to
    ML-KEM-768 so that P2 and P3 are compared at the same NIST level for the
    viewing key; the paper's primary instantiation is Kyber512, which
    ``P2Mlwe(ML_KEM_512)`` reproduces in size terms. The spending key is fixed
    at Dilithium NIST level 3 in both cases, as in the paper's Table 5.
    """

    scheme_id: ClassVar[int] = P2_SCHEME_ID
    name: ClassVar[str] = "p2_mlwe"

    def __init__(self, spec: KemSpec = kem.ML_KEM_768) -> None:
        self.spec = spec

    @property
    def meta_len(self) -> int:
        return SPEND_PK_LEN + self.spec.ek_len

    @property
    def payload_len(self) -> int:
        return self.spec.ct_len

    @property
    def param_set(self) -> str:
        return self.spec.label

    def keygen(self, seed: bytes | None = None) -> RecipientKeys:
        if seed is None:
            spend_seed = os.urandom(32)
            ek_view, dk_view = kem.keygen(self.spec)
        else:
            spend_seed = derive.keccak256(_KDF_SPEND_SEED + seed)
            ek_view, dk_view = kem.keygen(self.spec, _seed_for(_KDF_VIEW_SEED, seed))

        spend_pk = _spend_pk_standin(spend_seed)
        return RecipientKeys(
            # MA = K ‖ V: spending key first, mirroring ERC-5564's ordering.
            meta=MetaAddress(self.scheme_id, spend_pk + ek_view),
            # No secp256k1 spending scalar exists in this protocol, at all.
            spend_priv=None,
            view_secret=dk_view,
            extra={SPEND_KEY_EXTRA: spend_seed},
        )

    def viewing_keys(self, keys: RecipientKeys) -> ViewingKeys:
        """Viewing keys carry dk_view only — never the spending secret."""
        return ViewingKeys(meta=keys.meta, view_secret=keys.view_secret)

    def announce(self, meta: MetaAddress) -> Announcement:
        _, ek_view = self.split_meta(meta)
        ct, shared = kem.encaps(self.spec, ek_view)
        _, tag = derive.h_scalar_and_tag(shared)
        return Announcement(
            scheme_id=self.scheme_id,
            payload=ct,
            stealth_address=_standin_address(shared),
            view_tag=tag,
        )

    def scan(self, keys: ViewingKeys, announcements: Sequence[Announcement]) -> list[ScanMatch]:
        """Decapsulate, filter by view tag, then check the stand-in address.

        In the real protocol the second step recomputes the lattice stealth key
        and compares it — an R_q operation outside this implementation's stated
        boundary. Our stand-in check is a single hash, so measured P2 scan cost
        is a **lower bound** on the real protocol's. NOTES.md records this.
        """
        matches: list[ScanMatch] = []

        for index, ann in enumerate(announcements):
            if ann.scheme_id != self.scheme_id or len(ann.payload) != self.spec.ct_len:
                continue

            # Implicit rejection again: this never fails on a foreign ciphertext.
            shared = kem.decaps(self.spec, keys.view_secret, ann.payload)
            try:
                _, tag = derive.h_scalar_and_tag(shared)
            except DeriveError:
                continue

            if tag != ann.view_tag:
                continue
            if _standin_address(shared) != ann.stealth_address:
                continue

            # tweak is None: there is no EVM tweak to recover, by construction.
            matches.append(ScanMatch(index=index, stealth_address=ann.stealth_address, tweak=None))

        return matches

    def recover_spend_key(self, keys: RecipientKeys, match: ScanMatch) -> int:
        """Always raises. This is the finding, not a gap.

        Mikić et al.'s stealth key is a Dilithium-structured lattice key
        ``t' = A·(s + k') + e'`` and its private key is a Dilithium private key.
        No secp256k1 scalar corresponds to it, so no Ethereum account is
        controlled by it; spending needs on-chain Dilithium verification, which
        the authors state is impractical without a precompile (§4.7, §5.5).
        """
        raise NotEvmSpendable(
            "MLWE SAP's stealth key is a Dilithium-structured lattice key, not a "
            "secp256k1 scalar. It cannot sign an EVM transaction: spending needs "
            "on-chain Dilithium verification (a precompile Ethereum lacks) and a "
            "post-quantum address format."
        )

    def split_meta(self, meta: MetaAddress) -> tuple[bytes, bytes]:
        """Split the registered meta-address into ``(spend_pk, ek_view)``."""
        if len(meta.payload) != self.meta_len:
            raise DeriveError(
                f"meta-address must be {self.meta_len} bytes for {self.spec.name}, "
                f"got {len(meta.payload)}"
            )
        return meta.payload[:SPEND_PK_LEN], meta.payload[SPEND_PK_LEN:]


def _spend_pk_standin(spend_seed: bytes) -> bytes:
    """Uncompressed Dilithium-structured ``t``: 1536 coefficients mod q, 23 bits each.

    Coefficients are rejection-sampled from SHAKE256 three bytes at a time,
    masked to 23 bits and kept when below q — the same sampler shape FIPS 204
    uses for uniform polynomials. They are packed little-endian, 23 bits per
    coefficient, which is the uncompressed layout of ``t``.
    """
    count = DILITHIUM_K * DILITHIUM_N
    coeffs: list[int] = []
    stream = hashlib.shake_256(_KDF_SPEND_PK + spend_seed).digest(3 * count * 2)
    offset = 0
    while len(coeffs) < count:
        if offset + 3 > len(stream):  # astronomically unlikely; extend deterministically
            stream = hashlib.shake_256(_KDF_SPEND_PK + spend_seed).digest(len(stream) * 2)
        value = int.from_bytes(stream[offset : offset + 3], "little") & 0x7FFFFF
        offset += 3
        if value < DILITHIUM_Q:
            coeffs.append(value)

    acc = 0
    for i, c in enumerate(coeffs):
        acc |= c << (DILITHIUM_T_BITS * i)
    packed = acc.to_bytes(SPEND_PK_LEN, "little")
    assert len(packed) == SPEND_PK_LEN
    return packed


def unpack_spend_pk(spend_pk: bytes) -> list[int]:
    """Inverse of the packing in :func:`_spend_pk_standin`, for tests."""
    if len(spend_pk) != SPEND_PK_LEN:
        raise DeriveError(f"spending key must be {SPEND_PK_LEN} bytes, got {len(spend_pk)}")
    acc = int.from_bytes(spend_pk, "little")
    mask = (1 << DILITHIUM_T_BITS) - 1
    return [(acc >> (DILITHIUM_T_BITS * i)) & mask for i in range(DILITHIUM_K * DILITHIUM_N)]


def _standin_address(shared_secret: bytes) -> bytes:
    """Pseudorandom 20-byte stand-in for the stealth address field.

    The shared announcer's ABI has an address argument, and the real protocol
    has no Ethereum address to put there. Passing the zero address would be
    cheaper on purpose — 20 zero calldata bytes at 4 gas each instead of 16 —
    which would silently flatter P2's measured cost by about 240 gas per
    announcement. A pseudorandom value keeps the calldata content statistics
    honest against P1 and P3.
    """
    return derive.keccak256(_KDF_ADDR + shared_secret)[-20:]


def _seed_for(domain: bytes, seed: bytes) -> bytes:
    """Stretch an arbitrary benchmark seed into liboqs' 64-byte keygen seed."""
    material = derive.keccak256(domain + b"0" + seed) + derive.keccak256(domain + b"1" + seed)
    assert len(material) == SEED_BYTES
    return material
