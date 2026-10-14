"""The interface all three protocols implement.

One abstract scheme, three implementations, one benchmark harness. Because
``bench/`` talks only to this interface, P1, P2 and P3 are measured by identical
code paths and their numbers stay comparable — a separate harness per protocol
would drift methodologically and quietly invalidate the comparison.

Two design points carry protocol meaning rather than mere convenience:

``ViewingKeys`` holds no spending material at all. The dual-key separation that
both ERC-5564 and Mikić et al. rely on for regulatory disclosure is enforced by
the type, not by a convention: ``scan`` accepts only ``ViewingKeys``, so a
scanner structurally *cannot* reach a spending key. A third party given viewing
keys can enumerate every stealth address belonging to the recipient and spend
from none of them.

``scan`` verifies matches as ``addr(M + h*G)`` rather than ``addr(p*G)``. The
two are the same point — ``p*G = mG + hG`` — but only the first is computable
from public spending material, which is what keeps the separation above honest.
The spending path is exercised separately, in the round-trip tests.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import ClassVar

__all__ = [
    "Announcement",
    "MetaAddress",
    "NotEvmSpendable",
    "RecipientKeys",
    "ScanMatch",
    "StealthScheme",
    "ViewingKeys",
]


class NotEvmSpendable(Exception):
    """This protocol's stealth key cannot sign an Ethereum transaction.

    Raised by P2. Mikić et al.'s stealth key is a lattice element, not a
    secp256k1 scalar, so no EVM account corresponds to it and a payment cannot
    be completed on an unmodified Ethereum. That is the authors' own stated
    position — the exception exists so the thesis can demonstrate the limitation
    concretely instead of merely quoting it.
    """


@dataclass(frozen=True)
class MetaAddress:
    """What a recipient publishes to the registry.

    ``payload`` is the exact byte string that goes on-chain, so its length is
    the registration cost driver: 66 bytes for P1, 5600 for P2 (Kyber768 +
    Dilithium-structured key, Mikić et al. 2026), 1217 for P3 at ML-KEM-768.
    """

    scheme_id: int
    payload: bytes

    def __len__(self) -> int:
        return len(self.payload)


@dataclass(frozen=True)
class Announcement:
    """What a sender publishes per payment.

    ``payload`` is the ephemeral public key (P1) or the KEM ciphertext (P2, P3).
    ``view_tag`` is the ERC-5564 single-byte filter; it is probabilistic, so a
    passing tag is never on its own sufficient to accept a match.
    """

    scheme_id: int
    payload: bytes
    stealth_address: bytes
    view_tag: int


@dataclass(frozen=True)
class RecipientKeys:
    """Everything a recipient holds, including spending material."""

    meta: MetaAddress
    #: secp256k1 spending scalar. ``None`` for P2, which has no EVM spend key.
    spend_priv: int | None
    #: Viewing secret: a secp256k1 scalar's bytes (P1) or an ML-KEM dk (P2, P3).
    view_secret: bytes
    #: Protocol-specific extras, e.g. P2's second decapsulation key.
    extra: Mapping[str, bytes] = field(default_factory=dict)


@dataclass(frozen=True)
class ViewingKeys:
    """Disclosure-safe subset: enough to enumerate, never enough to spend.

    Deliberately has no field that could carry spending material. See the module
    docstring — this type *is* the dual-key separation invariant.
    """

    meta: MetaAddress
    view_secret: bytes


@dataclass(frozen=True)
class ScanMatch:
    """An announcement the recipient has verified as their own."""

    index: int
    stealth_address: bytes
    #: Tweak ``h`` needed to recover the spending key. ``None`` when the
    #: protocol has no EVM-spendable key (P2), where matches are tag-level only.
    tweak: int | None


class StealthScheme(ABC):
    """Abstract stealth address protocol."""

    #: ERC-5564 scheme identifier. 1 is the standardised secp256k1 scheme; the
    #: post-quantum schemes here use unregistered ids and the thesis says so.
    scheme_id: ClassVar[int]
    #: Short name used in result CSVs and figures.
    name: ClassVar[str]

    @property
    @abstractmethod
    def meta_len(self) -> int:
        """Registered meta-address length in bytes."""

    @property
    @abstractmethod
    def payload_len(self) -> int:
        """Per-announcement payload length in bytes."""

    @property
    @abstractmethod
    def param_set(self) -> str:
        """Parameter set label for result rows, e.g. ``mlkem768`` or ``secp256k1``."""

    @abstractmethod
    def keygen(self, seed: bytes | None = None) -> RecipientKeys:
        """Generate a recipient's keys. A seed makes the result reproducible."""

    @abstractmethod
    def viewing_keys(self, keys: RecipientKeys) -> ViewingKeys:
        """Project full keys down to the disclosure-safe viewing subset."""

    @abstractmethod
    def announce(self, meta: MetaAddress) -> Announcement:
        """Sender side: produce one payment's announcement."""

    @abstractmethod
    def scan(self, keys: ViewingKeys, announcements: Sequence[Announcement]) -> list[ScanMatch]:
        """Recipient side: return the announcements that are verifiably ours."""

    @abstractmethod
    def recover_spend_key(self, keys: RecipientKeys, match: ScanMatch) -> int:
        """Recover the stealth address's private key.

        Raises:
            NotEvmSpendable: if the protocol has no EVM-spendable stealth key.
        """
