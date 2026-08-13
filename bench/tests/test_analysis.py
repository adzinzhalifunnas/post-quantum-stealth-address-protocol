"""Tests for the analysis layer: scan, curves and anonymity.

These modules produce the numbers Chapter IV argues from, so the properties
asserted here are the ones a wrong result would violate — the bandwidth model
matching real transactions, the crossover algebra, and the anonymity formula
agreeing with its own simulation.
"""

from __future__ import annotations

import pytest

from bench import anonymity, curves, scan


class TestBandwidthModel:
    """Pinned against transactions actually measured on chain."""

    def test_a1_log_size_matches_a_measured_transaction(self) -> None:
        """A 1088-byte ciphertext produced exactly 1248 bytes of log data."""
        model = scan.bandwidth_for(1088, "A1")
        assert model.log_bytes == 1248
        assert model.tx_fetch_bytes == 0
        assert model.rpc_round_trips_per_announcement == 0.0

    def test_a2_sizes_match_a_measured_transaction(self) -> None:
        """A2 logged 32 bytes and carried 1252 bytes of calldata."""
        model = scan.bandwidth_for(1088, "A2")
        assert model.log_bytes == 32
        assert model.tx_fetch_bytes == 1252

    def test_a2_costs_a_round_trip_per_announcement(self) -> None:
        """The finding: A2's view tag cannot filter, so nothing can be skipped.

        The recipient's own tag comes from decapsulating the ciphertext, which
        A2 leaves in calldata, so every announcement must be fetched.
        """
        assert scan.bandwidth_for(1088, "A2").rpc_round_trips_per_announcement == 1.0

    def test_a2_downloads_more_than_a1_despite_the_smaller_log(self) -> None:
        a1 = scan.bandwidth_for(1088, "A1")
        a2 = scan.bandwidth_for(1088, "A2")
        assert a2.log_bytes < a1.log_bytes
        assert a2.total_bytes > a1.total_bytes

    def test_p1_downloads_far_less_than_p3(self) -> None:
        assert scan.bandwidth_for(33, "A1").total_bytes < scan.bandwidth_for(1088, "A1").total_bytes

    def test_unknown_variant_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unknown announcer variant"):
            scan.bandwidth_for(1088, "A3")


class TestCurves:
    def _variant(self, registration: int, announcement: int, label: str = "R1") -> curves.Variant:
        return curves.Variant("p3_hybrid", "mlkem768", label, "A1", registration, announcement)

    def test_cost_includes_registration_at_zero_payments(self) -> None:
        v = self._variant(100_000, 50_000)
        assert v.cost(0) == 100_000
        assert v.cost(2) == 200_000

    def test_crossing_where_a_cheap_registration_loses_to_a_cheap_announcement(self) -> None:
        """R3 registers cheaply but announces dearly; P1 does the reverse."""
        expensive_to_announce = self._variant(100_000, 60_000, "R3")
        expensive_to_register = self._variant(900_000, 30_000, "R1")
        k = curves.crossing(expensive_to_announce, expensive_to_register)
        assert k is not None
        # 100k + 60k*k == 900k + 30k*k  ->  k = 800/30
        assert round(k, 2) == round(800_000 / 30_000, 2)

    def test_no_crossing_when_one_variant_dominates(self) -> None:
        better = self._variant(100_000, 30_000)
        worse = self._variant(900_000, 60_000)
        assert curves.crossing(better, worse) is None

    def test_equal_announcements_never_cross(self) -> None:
        assert (
            curves.crossing(self._variant(100_000, 50_000), self._variant(200_000, 50_000)) is None
        )


class TestAnonymity:
    def test_no_tag_leaves_the_whole_registry_anonymous(self) -> None:
        assert anonymity.expected_set_size(1000, 0) == 1000.0

    def test_eight_bit_tag_divides_by_256(self) -> None:
        assert anonymity.expected_set_size(1000, 8) == pytest.approx(1 + 999 / 256)

    def test_recipient_is_always_in_their_own_anonymity_set(self) -> None:
        """The set can never be empty: the true recipient always matches."""
        assert anonymity.expected_set_size(1, 8) == 1.0
        row = anonymity.simulate(1, 8, trials=50)
        assert row.median_set_size == 1

    def test_simulation_agrees_with_the_closed_form(self) -> None:
        """Independent check: if these disagree, one of them is wrong."""
        for size in (100, 1_000, 10_000):
            row = anonymity.simulate(size, 8, trials=3000)
            assert row.mean_set_size == pytest.approx(row.expected_set_size, rel=0.10)

    def test_simulation_is_reproducible(self) -> None:
        """A thesis table must regenerate byte-for-byte."""
        assert anonymity.simulate(1000, 8, trials=200) == anonymity.simulate(1000, 8, trials=200)

    def test_small_registries_are_the_dangerous_case(self) -> None:
        """The leak is worst where there are fewest users to hide among."""
        small = anonymity.simulate(100, 8, trials=2000)
        large = anonymity.simulate(1_000_000, 8, trials=200)
        assert small.fraction_deanonymised > 0.5
        assert large.fraction_deanonymised == 0.0
        assert large.mean_set_size > small.mean_set_size

    def test_wider_tags_leak_more(self) -> None:
        sizes = [anonymity.expected_set_size(10_000, bits) for bits in (0, 4, 8, 12, 16)]
        assert sizes == sorted(sizes, reverse=True)

    def test_empty_registry_is_refused(self) -> None:
        with pytest.raises(ValueError, match="at least the recipient"):
            anonymity.expected_set_size(0, 8)
