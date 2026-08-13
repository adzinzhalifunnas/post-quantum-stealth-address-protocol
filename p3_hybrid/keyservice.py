"""R3's off-chain half: publishing and fetching ``ek_view``.

R3 registers a 65-byte commitment on-chain and serves the 1184-byte
encapsulation key somewhere else. That is what buys registration parity with
ERC-5564 — but the bytes did not disappear, they moved, and a cost claim that
ignores where they moved to is incomplete. This module is the moved-to half,
made explicit so it can be reasoned about and measured rather than waved at.

**Transport is deliberately not specified.** An ENS text record, an HTTPS
endpoint, IPFS, a wallet-to-wallet message, a QR code — all work, because the
commitment makes the channel untrusted. What matters is the *shape*: a sender
fetches some bytes from somewhere it does not trust, and refuses them unless
they hash to the value the chain already committed to. ``KeyDirectory`` is that
shape; the two implementations here are a reference and a test double, not a
deployment.

Two failure modes, and only one of them is dangerous:

**Integrity** is protected. A directory that returns the wrong key — through
compromise, substitution or corruption — is caught by
``resolve_meta_address``, which is the only supported way to go from a
commitment to a usable meta-address. There is deliberately no path that skips
the check.

**Availability** is not, and cannot be. A directory that refuses to answer
blocks payments to that recipient. This is a real regression against R1, where
the key is on-chain and as available as Ethereum, and it belongs in the thesis
as a stated cost of the optimisation rather than a footnote.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from pqsap_core.scheme import MetaAddress

from p3_hybrid.scheme import P3Hybrid

__all__ = [
    "FileKeyDirectory",
    "InMemoryKeyDirectory",
    "KeyDirectory",
    "KeyUnavailable",
    "offchain_fetch_bytes",
    "publish_from_keys",
    "resolve_meta_address",
]


class KeyUnavailable(Exception):
    """The directory could not supply a key.

    Distinct from a verification failure on purpose. This one means "try again
    later or ask elsewhere"; a verification failure means "someone is lying to
    you" and must never be retried against the same source.
    """


class KeyDirectory(ABC):
    """Somewhere a recipient's ``ek_view`` can be published and fetched from.

    Untrusted by construction. Implementations may lose, corrupt or lie about
    what they store; the commitment on-chain is what makes that survivable.
    """

    @abstractmethod
    def publish(self, registrant: str, ek_view: bytes) -> None:
        """Make ``ek_view`` retrievable for ``registrant``."""

    @abstractmethod
    def fetch(self, registrant: str) -> bytes:
        """Retrieve a registrant's ``ek_view``.

        Raises:
            KeyUnavailable: if nothing is stored for this registrant.
        """


class InMemoryKeyDirectory(KeyDirectory):
    """Reference implementation. Also the test double for a hostile server."""

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def publish(self, registrant: str, ek_view: bytes) -> None:
        self._keys[registrant.lower()] = bytes(ek_view)

    def fetch(self, registrant: str) -> bytes:
        try:
            return self._keys[registrant.lower()]
        except KeyError:
            raise KeyUnavailable(f"no viewing key published for {registrant}") from None


class FileKeyDirectory(KeyDirectory):
    """A directory that survives a process boundary.

    Included because an in-memory dictionary can hide encoding mistakes that a
    real transport would expose. Keys are stored hex-encoded in one JSON file —
    the simplest thing that genuinely crosses a serialisation boundary.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        loaded: dict[str, str] = json.loads(self.path.read_text())
        return loaded

    def publish(self, registrant: str, ek_view: bytes) -> None:
        keys = self._load()
        keys[registrant.lower()] = ek_view.hex()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(keys, indent=2, sort_keys=True))

    def fetch(self, registrant: str) -> bytes:
        keys = self._load()
        try:
            return bytes.fromhex(keys[registrant.lower()])
        except KeyError:
            raise KeyUnavailable(f"no viewing key published for {registrant}") from None


def publish_from_keys(
    directory: KeyDirectory, registrant: str, scheme: P3Hybrid, meta: MetaAddress
) -> bytes:
    """Recipient side: publish the viewing key that the on-chain commitment covers.

    Returns the published ``ek_view``, so a caller can check it against what it
    registered without splitting the meta-address twice.
    """
    _, ek_view = scheme.split_meta(meta)
    directory.publish(registrant, ek_view)
    return ek_view


def resolve_meta_address(
    scheme: P3Hybrid, registrant: str, commitment: bytes, directory: KeyDirectory
) -> MetaAddress:
    """Sender side: fetch a viewing key and refuse it unless it matches the chain.

    This is the only supported route from an R3 commitment to a meta-address a
    sender may encapsulate to. Fetching and verifying are deliberately one
    operation, because every realistic way to get this wrong involves doing the
    first without the second.

    Args:
        commitment: the 65 bytes read from the registry, ``M ‖ keccak256(ek_view)``.

    Raises:
        KeyUnavailable: the directory had nothing to offer.
        DeriveError: the directory answered, and its answer does not match the
            commitment. Do not retry against this source — encapsulating to that
            key would let whoever served it read the payment.
    """
    ek_view = directory.fetch(registrant)
    return scheme.meta_from_commitment(commitment, ek_view)


def offchain_fetch_bytes(scheme: P3Hybrid) -> int:
    """Bytes a sender must fetch off-chain before it can pay an R3 recipient.

    The honest counterpart to R3's on-chain saving. Registration drops from 1217
    bytes to 65, and this is where the difference went. Two things keep the
    trade favourable and both belong in the analysis: the fetch is per
    *recipient* rather than per payment, so it caches, and it is paid by the
    sender in bandwidth rather than by anyone in gas.
    """
    return scheme.spec.ek_len
