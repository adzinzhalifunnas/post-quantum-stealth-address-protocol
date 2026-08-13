"""R3's off-chain half, end to end.

The commitment is only worth something if the sender actually checks it, so
most of these tests are a hostile directory: one that substitutes a key,
corrupts one, truncates one, or simply refuses. The payment must fail in every
case, and it must fail differently when the directory is merely absent than
when it is lying.

The end-to-end test is the one that matters: publish, register a commitment,
fetch through an untrusted directory, verify, pay, and recover the key — with
the result required to be byte-identical to what R1 would have produced.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pqsap_core import derive, kem
from pqsap_core.derive import DeriveError

from p3_hybrid.keyservice import (
    FileKeyDirectory,
    InMemoryKeyDirectory,
    KeyDirectory,
    KeyUnavailable,
    offchain_fetch_bytes,
    publish_from_keys,
    resolve_meta_address,
)
from p3_hybrid.scheme import P3Hybrid

ALICE = "0xA11CE00000000000000000000000000000000001"
MALLORY = "0x4A110000000000000000000000000000000000FF"


@pytest.fixture(scope="module")
def scheme() -> P3Hybrid:
    return P3Hybrid()


@pytest.fixture(params=["memory", "file"])
def directory(request: pytest.FixtureRequest, tmp_path: Path) -> KeyDirectory:
    """Both implementations must behave identically.

    The file-backed one crosses a serialisation boundary, which is where an
    encoding mistake an in-memory dict would hide shows up.
    """
    if request.param == "memory":
        return InMemoryKeyDirectory()
    return FileKeyDirectory(tmp_path / "keys.json")


class TestHappyPath:
    def test_published_key_survives_the_round_trip(
        self, scheme: P3Hybrid, directory: KeyDirectory
    ) -> None:
        keys = scheme.keygen()
        published = publish_from_keys(directory, ALICE, scheme, keys.meta)
        assert directory.fetch(ALICE) == published
        assert len(published) == kem.ML_KEM_768.ek_len

    def test_resolution_reconstructs_the_full_meta_address(
        self, scheme: P3Hybrid, directory: KeyDirectory
    ) -> None:
        keys = scheme.keygen()
        publish_from_keys(directory, ALICE, scheme, keys.meta)
        commitment = scheme.commitment_payload(keys.meta)

        resolved = resolve_meta_address(scheme, ALICE, commitment, directory)
        assert resolved.payload == keys.meta.payload

    def test_registrant_lookup_is_case_insensitive(
        self, scheme: P3Hybrid, directory: KeyDirectory
    ) -> None:
        """Ethereum addresses appear checksummed and lowercased interchangeably."""
        keys = scheme.keygen()
        publish_from_keys(directory, ALICE.lower(), scheme, keys.meta)
        assert directory.fetch(ALICE.upper())


class TestHostileDirectory:
    """The attack the commitment exists to stop."""

    def test_substituted_key_is_refused(self, scheme: P3Hybrid, directory: KeyDirectory) -> None:
        """A directory that serves its own key must not be able to read payments.

        Without the commitment check this is a total break: the attacker holds
        dk for the key it served, so it decapsulates every announcement.
        """
        victim = scheme.keygen()
        attacker = scheme.keygen()
        commitment = scheme.commitment_payload(victim.meta)

        # The directory lies: Alice's address, Mallory's key.
        publish_from_keys(directory, ALICE, scheme, attacker.meta)

        with pytest.raises(DeriveError, match="does not match"):
            resolve_meta_address(scheme, ALICE, commitment, directory)

    def test_a_sender_who_skips_verification_is_the_one_who_loses(
        self, scheme: P3Hybrid, directory: KeyDirectory
    ) -> None:
        """Demonstrates the consequence, so the requirement is not abstract.

        Encapsulating to a substituted key produces an announcement the attacker
        can decapsulate and the victim cannot find.
        """
        victim = scheme.keygen()
        attacker = scheme.keygen()

        # A careless sender uses the served key without checking it.
        announcement = scheme.announce(attacker.meta)

        assert scheme.scan(scheme.viewing_keys(victim), [announcement]) == []
        assert len(scheme.scan(scheme.viewing_keys(attacker), [announcement])) == 1

    def test_corrupted_key_is_refused(self, scheme: P3Hybrid, directory: KeyDirectory) -> None:
        keys = scheme.keygen()
        commitment = scheme.commitment_payload(keys.meta)
        _, ek_view = scheme.split_meta(keys.meta)

        corrupted = bytearray(ek_view)
        corrupted[500] ^= 0x01
        directory.publish(ALICE, bytes(corrupted))

        with pytest.raises(DeriveError):
            resolve_meta_address(scheme, ALICE, commitment, directory)

    def test_truncated_key_is_refused(self, scheme: P3Hybrid, directory: KeyDirectory) -> None:
        keys = scheme.keygen()
        commitment = scheme.commitment_payload(keys.meta)
        _, ek_view = scheme.split_meta(keys.meta)
        directory.publish(ALICE, ek_view[:-1])

        with pytest.raises(DeriveError):
            resolve_meta_address(scheme, ALICE, commitment, directory)

    def test_another_registrants_key_is_refused(
        self, scheme: P3Hybrid, directory: KeyDirectory
    ) -> None:
        """Serving a real key, just the wrong person's, must also fail."""
        alice, mallory = scheme.keygen(), scheme.keygen()
        publish_from_keys(directory, ALICE, scheme, alice.meta)
        publish_from_keys(directory, MALLORY, scheme, mallory.meta)

        alice_commitment = scheme.commitment_payload(alice.meta)
        with pytest.raises(DeriveError):
            resolve_meta_address(scheme, MALLORY, alice_commitment, directory)


class TestAvailability:
    """Unavailability must be distinguishable from dishonesty."""

    def test_missing_key_raises_key_unavailable(
        self, scheme: P3Hybrid, directory: KeyDirectory
    ) -> None:
        keys = scheme.keygen()
        commitment = scheme.commitment_payload(keys.meta)

        with pytest.raises(KeyUnavailable, match="no viewing key published"):
            resolve_meta_address(scheme, ALICE, commitment, directory)

    def test_unavailability_is_not_a_verification_failure(
        self, scheme: P3Hybrid, directory: KeyDirectory
    ) -> None:
        """Different failures need different responses: retry later, versus
        never trust this source again."""
        keys = scheme.keygen()
        commitment = scheme.commitment_payload(keys.meta)

        with pytest.raises(KeyUnavailable) as absent:
            resolve_meta_address(scheme, ALICE, commitment, directory)
        assert not isinstance(absent.value, DeriveError)


class TestEndToEnd:
    def test_r3_payment_completes_through_an_untrusted_directory(
        self, scheme: P3Hybrid, directory: KeyDirectory
    ) -> None:
        """The whole R3 flow, and it must land exactly where R1 would.

        If these diverged, R3 would be a different protocol rather than a
        cheaper encoding of the same one.
        """
        recipient = scheme.keygen()

        # Recipient publishes off-chain and registers 65 bytes on-chain.
        publish_from_keys(directory, ALICE, scheme, recipient.meta)
        commitment = scheme.commitment_payload(recipient.meta)
        assert len(commitment) == 65

        # Sender resolves through a channel it does not trust, then pays.
        meta = resolve_meta_address(scheme, ALICE, commitment, directory)
        announcement = scheme.announce(meta)

        # Recipient finds it and can spend it.
        matches = scheme.scan(scheme.viewing_keys(recipient), [announcement])
        assert len(matches) == 1
        recovered = scheme.recover_spend_key(recipient, matches[0])
        assert (
            derive.eth_address(derive.pubkey_from_scalar(recovered)) == announcement.stealth_address
        )

    def test_r3_works_at_both_parameter_sets(self, directory: KeyDirectory) -> None:
        for spec in (kem.ML_KEM_768, kem.ML_KEM_512):
            variant = P3Hybrid(spec)
            recipient = variant.keygen()
            publish_from_keys(directory, ALICE, variant, recipient.meta)
            commitment = variant.commitment_payload(recipient.meta)

            meta = resolve_meta_address(variant, ALICE, commitment, directory)
            assert meta.payload == recipient.meta.payload


class TestCostAccounting:
    """R3's on-chain saving has an off-chain counterpart. Both get reported."""

    def test_fetch_size_is_the_encapsulation_key(self, scheme: P3Hybrid) -> None:
        assert offchain_fetch_bytes(scheme) == 1184
        assert offchain_fetch_bytes(P3Hybrid(kem.ML_KEM_512)) == 800

    def test_the_bytes_moved_rather_than_vanished(self, scheme: P3Hybrid) -> None:
        """R1 registers 1217 bytes on-chain; R3 registers 65 and moves 1184.

        Stated as an equation so the parity claim cannot be read as though the
        data disappeared.
        """
        keys = scheme.keygen()
        on_chain_r1 = len(keys.meta.payload)
        on_chain_r3 = len(scheme.commitment_payload(keys.meta))
        off_chain_r3 = offchain_fetch_bytes(scheme)

        assert on_chain_r1 == 1217
        assert on_chain_r3 == 65
        # 33 bytes of spending key stay on-chain in both; the commitment
        # replaces the key with a 32-byte hash of it.
        assert on_chain_r3 + off_chain_r3 == on_chain_r1 + 32

    def test_the_fetch_is_per_recipient_not_per_payment(
        self, scheme: P3Hybrid, directory: KeyDirectory
    ) -> None:
        """Why the trade is favourable: one fetch serves any number of payments.

        A cost model that charged this per payment would badly overstate it.
        """
        recipient = scheme.keygen()
        publish_from_keys(directory, ALICE, scheme, recipient.meta)
        commitment = scheme.commitment_payload(recipient.meta)

        meta = resolve_meta_address(scheme, ALICE, commitment, directory)
        announcements = [scheme.announce(meta) for _ in range(10)]

        assert len({a.payload for a in announcements}) == 10
        assert len(scheme.scan(scheme.viewing_keys(recipient), announcements)) == 10
