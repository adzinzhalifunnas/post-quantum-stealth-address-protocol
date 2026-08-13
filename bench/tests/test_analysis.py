"""Tests for the analysis layer: scan, curves and anonymity.

These modules produce the numbers Chapter IV argues from, so the properties
asserted here are the ones a wrong result would violate — the bandwidth model
matching real transactions, the crossover algebra, and the anonymity formula
agreeing with its own simulation.
"""

from __future__ import annotations

import csv
from pathlib import Path

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


class TestLoadVariants:
    """Reading measured CSVs into the cost model — where a bug would silently
    rewrite the headline."""

    def _write(self, path: Path, rows: list[tuple[str, str, str, str, str, int]]) -> None:
        with path.open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "protocol",
                    "param_set",
                    "operation",
                    "registry_variant",
                    "announcer_variant",
                    "gas_used",
                ]
            )
            writer.writerows(rows)

    def test_composes_the_full_cross_product(self, tmp_path: Path) -> None:
        """Two registry variants and two announcers give four configurations,
        even though only two pairs were ever sent."""
        path = tmp_path / "gas.csv"
        self._write(
            path,
            [
                ("p3_hybrid", "mlkem768", "register", "R1", "A1", 941_744),
                ("p3_hybrid", "mlkem768", "register", "R3", "A2", 115_264),
                ("p3_hybrid", "mlkem768", "announce", "R1", "A1", 67_730),
                ("p3_hybrid", "mlkem768", "announce", "R3", "A2", 67_000),
            ],
        )
        variants = curves.load_variants(path)
        labels = {(v.registry_variant, v.announcer_variant) for v in variants}
        assert labels == {("R1", "A1"), ("R1", "A2"), ("R3", "A1"), ("R3", "A2")}

    def test_takes_the_median_of_each_leg(self, tmp_path: Path) -> None:
        path = tmp_path / "gas.csv"
        self._write(
            path,
            [
                ("p3_hybrid", "mlkem768", "register", "R3", "A2", 95_340),
                ("p3_hybrid", "mlkem768", "register", "R3", "A2", 115_264),
                ("p3_hybrid", "mlkem768", "register", "R3", "A2", 115_264),
                ("p3_hybrid", "mlkem768", "announce", "R3", "A2", 67_000),
            ],
        )
        assert curves.load_variants(path)[0].registration_gas == 115_264

    def test_never_mixes_parameter_sets(self, tmp_path: Path) -> None:
        """768 and 512 are different configurations, not samples of one."""
        path = tmp_path / "gas.csv"
        self._write(
            path,
            [
                ("p3_hybrid", "mlkem768", "register", "R3", "A2", 115_264),
                ("p3_hybrid", "mlkem512", "register", "R3", "A2", 115_264),
                ("p3_hybrid", "mlkem768", "announce", "R3", "A2", 67_000),
                ("p3_hybrid", "mlkem512", "announce", "R3", "A2", 54_200),
            ],
        )
        by_params = {v.param_set: v for v in curves.load_variants(path)}
        assert by_params["mlkem768"].announcement_gas == 67_000
        assert by_params["mlkem512"].announcement_gas == 54_200

    def test_rows_without_gas_are_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "gas.csv"
        self._write(
            path,
            [
                ("p3_hybrid", "mlkem768", "register", "R3", "A2", 115_264),
                ("p3_hybrid", "mlkem768", "announce", "R3", "A2", 67_000),
            ],
        )
        with path.open("a") as handle:
            handle.write("p3_hybrid,mlkem768,register,R3,A2,\n")
        assert curves.load_variants(path)[0].registration_gas == 115_264

    def test_cumulative_tabulates_every_variant_at_every_point(self, tmp_path: Path) -> None:
        path = tmp_path / "gas.csv"
        self._write(
            path,
            [
                ("p3_hybrid", "mlkem768", "register", "R3", "A2", 100_000),
                ("p3_hybrid", "mlkem768", "announce", "R3", "A2", 50_000),
            ],
        )
        rows = curves.cumulative(curves.load_variants(path), [0, 1, 10])
        assert [r["cumulative_gas"] for r in rows] == [100_000, 150_000, 600_000]


class TestMeasureScan:
    """The scan measurement itself, on a small population for speed."""

    def test_finds_exactly_the_planted_payments(self) -> None:
        from p3_hybrid.scheme import P3Hybrid

        result = scan.measure_scan(P3Hybrid(), "A1", announcements=200, planted=3, repeats=1)
        assert result.matches_found == 3
        assert result.announcements == 200

    def test_one_shared_secret_operation_per_announcement(self) -> None:
        """The view tag saves elliptic-curve work, never decapsulation."""
        from p3_hybrid.scheme import P3Hybrid

        result = scan.measure_scan(P3Hybrid(), "A1", announcements=200, planted=2, repeats=1)
        assert result.shared_secret_ops == 200
        # Only ~1/256 survive the tag, plus the planted matches.
        assert result.address_checks < 20

    def test_p2_reports_no_evm_address_checks(self) -> None:
        """P2 has no elliptic-curve step at all — its stealth key is a lattice."""
        from p2_mlwe.scheme import P2Mlwe

        result = scan.measure_scan(P2Mlwe(), "A1", announcements=100, planted=2, repeats=1)
        assert result.address_checks == 0
        assert result.matches_found == 2

    def test_timing_is_positive_and_per_announcement_is_derived(self) -> None:
        from p1_erc5564.scheme import P1Erc5564

        result = scan.measure_scan(P1Erc5564(), "A1", announcements=100, planted=1, repeats=1)
        assert result.wall_clock_s > 0
        assert result.per_announcement_us == pytest.approx(
            result.wall_clock_s / 100 * 1e6, rel=0.01
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
