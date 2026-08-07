"""P2 — the MLWE SAP data plane (Mikić, Srbakoski, Praska).

**This implements their data plane, not their protocol.** The distinction is
deliberate and is itself a result; see ``NOTES.md`` for the full boundary
statement. In short: their stealth key is a lattice element,

    P = XOF(ρ_K)·XOF(S) + Decompress_q(t_K, d_t)        p = k + XOF(S)

which is not an Ethereum address and cannot sign an EVM transaction. Computing
it needs full R_q arithmetic with NTT, which liboqs does not expose and which
would consume weeks of the implementation budget — for a value that never goes
on-chain, since the recipient computes it locally. What *does* go on-chain is
the registry entry and the announcement, and those need only correct sizes and
encoding. So we implement exactly that, using real ML-KEM keys, and measure it.

The recipient holds *two* lattice keypairs, one spending and one viewing, which
is what makes P2's meta-address roughly twice P3's: both roles are lattice,
whereas P3 keeps spending on secp256k1. Announcements are the same size in both,
so the whole of P3's advantage lives in registration.

``recover_spend_key`` raises :class:`NotEvmSpendable`. That is the point rather
than a limitation of our implementation: demonstrating concretely that an
end-to-end payment cannot complete on an unmodified Ethereum is better evidence
than quoting the claim.
"""

from __future__ import annotations

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

__all__ = ["P2_SCHEME_ID", "SPEND_KEY_EXTRA", "P2Mlwe"]

#: ASCII "MLWE". Non-standard, like P3's — ERC-5564 registers only id 1.
P2_SCHEME_ID: Final[int] = 0x4D4C5745

#: Key under which the spending decapsulation key is carried in ``RecipientKeys.extra``.
SPEND_KEY_EXTRA: Final[str] = "dk_spend"

# The stand-in stealth address is domain-separated from the view tag so the two
# are not trivially derivable from one another. See NOTES.md for why a stand-in
# is used at all rather than the zero address.
_KDF_ADDR: Final[bytes] = b"pqsap/p2/stealth-address-standin"
_KDF_SPEND_SEED: Final[bytes] = b"pqsap/p2/kem/spend/"
_KDF_VIEW_SEED: Final[bytes] = b"pqsap/p2/kem/view/"


class P2Mlwe(StealthScheme):
    """MLWE SAP data plane: two lattice keypairs, lattice-only custody.

    The parameter set is a constructor argument. It defaults to ML-KEM-768 so
    that P2 and P3 are compared at the same NIST level; the paper's own
    experiments used Kyber512, which ``P2Mlwe(ML_KEM_512)`` reproduces in size
    terms. NOTES.md records both readings.
    """

    scheme_id: ClassVar[int] = P2_SCHEME_ID
    name: ClassVar[str] = "p2_mlwe"

    def __init__(self, spec: KemSpec = kem.ML_KEM_768) -> None:
        self.spec = spec

    @property
    def meta_len(self) -> int:
        return 2 * self.spec.ek_len

    @property
    def payload_len(self) -> int:
        return self.spec.ct_len

    @property
    def param_set(self) -> str:
        return self.spec.label

    def keygen(self, seed: bytes | None = None) -> RecipientKeys:
        if seed is None:
            ek_spend, dk_spend = kem.keygen(self.spec)
            ek_view, dk_view = kem.keygen(self.spec)
        else:
            ek_spend, dk_spend = kem.keygen(self.spec, _seed_for(_KDF_SPEND_SEED, seed))
            ek_view, dk_view = kem.keygen(self.spec, _seed_for(_KDF_VIEW_SEED, seed))

        return RecipientKeys(
            meta=MetaAddress(self.scheme_id, ek_spend + ek_view),
            # No secp256k1 spending scalar exists in this protocol, at all.
            spend_priv=None,
            view_secret=dk_view,
            extra={SPEND_KEY_EXTRA: dk_spend},
        )

    def viewing_keys(self, keys: RecipientKeys) -> ViewingKeys:
        """Viewing keys carry dk_view only — never the spending decapsulation key."""
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

        Mikić et al.'s stealth private key is ``p = k + XOF(S)``, an element of
        R_q. No secp256k1 scalar corresponds to it and no Ethereum account can
        be controlled by it, so a payment under this protocol cannot be
        completed on an unmodified EVM chain.
        """
        raise NotEvmSpendable(
            "MLWE SAP's stealth key is a lattice element (p = k + XOF(S)), not a "
            "secp256k1 scalar. It cannot sign an EVM transaction, so an end-to-end "
            "payment requires Ethereum itself to become post-quantum."
        )

    def split_meta(self, meta: MetaAddress) -> tuple[bytes, bytes]:
        """Split the registered meta-address into ``(ek_spend, ek_view)``."""
        if len(meta.payload) != self.meta_len:
            raise DeriveError(
                f"meta-address must be {self.meta_len} bytes for {self.spec.name}, "
                f"got {len(meta.payload)}"
            )
        return meta.payload[: self.spec.ek_len], meta.payload[self.spec.ek_len :]


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
