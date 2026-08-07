"""Protocol invariants every scheme in this study must satisfy.

These are properties of the *design*, not of any one implementation, so they
live beside the shared interface and each protocol's test module calls them.
Writing them once means P1, P2 and P3 are held to an identical standard — three
separately hand-written versions would inevitably drift and start testing
different things under the same names.

Not named ``test_*``, so pytest does not collect them directly; a protocol opts
in by calling them. ``pqsap_core`` deliberately imports no protocol package, so
the dependency direction stays one-way.
"""

from __future__ import annotations

from pqsap_core import derive
from pqsap_core.derive import DeriveError
from pqsap_core.scheme import Announcement, RecipientKeys, StealthScheme, ViewingKeys

__all__ = [
    "check_address_derivation_is_shared",
    "check_announcement_shape",
    "check_dual_key_separation",
    "check_roundtrip",
    "check_scan_rejects_foreign",
]


def check_roundtrip(scheme: StealthScheme, samples: int = 20) -> None:
    """A payment must be findable by its recipient and by nobody else.

    Charter requires at least 20 distinct keypairs, and that the payloads
    genuinely differ — gas cost depends on calldata content, so a scheme that
    silently emitted a constant payload would invalidate the measurements.
    """
    metas: set[bytes] = set()
    payloads: set[bytes] = set()

    for _ in range(samples):
        keys = scheme.keygen()
        announcement = scheme.announce(keys.meta)

        matches = scheme.scan(scheme.viewing_keys(keys), [announcement])
        assert len(matches) == 1, f"{scheme.name}: recipient failed to find its own payment"
        assert matches[0].stealth_address == announcement.stealth_address

        metas.add(keys.meta.payload)
        payloads.add(announcement.payload)

    assert len(metas) == samples, f"{scheme.name}: keygen produced duplicate meta-addresses"
    assert len(payloads) == samples, f"{scheme.name}: announce produced duplicate payloads"


def check_scan_rejects_foreign(scheme: StealthScheme, samples: int = 50) -> None:
    """Announcements addressed to other recipients must never match."""
    keys = scheme.keygen()
    foreign = [scheme.announce(scheme.keygen().meta) for _ in range(samples)]
    assert (
        scheme.scan(scheme.viewing_keys(keys), foreign) == []
    ), f"{scheme.name}: scan matched an announcement addressed to someone else"


def check_dual_key_separation(scheme: StealthScheme, samples: int = 5) -> None:
    """Viewing keys must enumerate every payment and spend none of them.

    This is the disclosure property both ERC-5564 and Mikić et al. rely on, and
    the charter requires it of all three protocols. It is checked structurally
    as well as behaviourally: ``ViewingKeys`` has no field able to carry
    spending material, so a scanner cannot reach one even by accident.
    """
    assert set(ViewingKeys.__dataclass_fields__) == {"meta", "view_secret"}

    keys = scheme.keygen()
    viewing = scheme.viewing_keys(keys)
    announcements = [scheme.announce(keys.meta) for _ in range(samples)]

    matches = scheme.scan(viewing, announcements)
    assert [m.index for m in matches] == list(
        range(samples)
    ), f"{scheme.name}: viewing key failed to enumerate all payments"

    viewer_only = RecipientKeys(meta=viewing.meta, spend_priv=None, view_secret=viewing.view_secret)
    try:
        scheme.recover_spend_key(viewer_only, matches[0])
    except Exception as exc:
        assert isinstance(exc, DeriveError), f"{scheme.name}: unexpected error type {type(exc)}"
    else:  # pragma: no cover - a failure here is a protocol break, not a flake
        raise AssertionError(f"{scheme.name}: viewing keys alone produced a spending key")


def check_announcement_shape(scheme: StealthScheme, announcement: Announcement) -> None:
    """Field-level sanity: sizes and ranges the on-chain encoding depends on."""
    assert announcement.scheme_id == scheme.scheme_id
    assert len(announcement.payload) == scheme.payload_len
    assert len(announcement.stealth_address) == 20
    assert 0 <= announcement.view_tag <= 0xFF
    # A zero address would mean 20 zero calldata bytes at 4 gas each instead of
    # 16, quietly flattering this protocol's measured cost.
    assert announcement.stealth_address != b"\x00" * 20


def check_address_derivation_is_shared(scheme: StealthScheme) -> None:
    """Every protocol must derive addresses through the shared code path.

    This is the experiment's fairness guarantee: schemes may differ in how they
    agree a secret, never in how a secret becomes an address.
    """
    keys = scheme.keygen()
    announcement = scheme.announce(keys.meta)
    matches = scheme.scan(scheme.viewing_keys(keys), [announcement])
    assert len(matches) == 1

    tweak = matches[0].tweak
    if tweak is None:
        return  # P2 has no EVM-spendable key; nothing to cross-check.

    spend_pub, _ = scheme.split_meta(keys.meta)  # type: ignore[attr-defined]
    assert derive.eth_address(derive.derive_stealth_pubkey(spend_pub, tweak)) == (
        announcement.stealth_address
    )
