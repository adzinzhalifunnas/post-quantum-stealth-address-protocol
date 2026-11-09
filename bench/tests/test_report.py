"""Tests for the report builder.

This module assembles the tables Chapter IV is written from, so a bug here puts
wrong numbers in a thesis while every other test still passes. What is asserted
is that figures survive the trip from CSV to Markdown unchanged, that variants
are never conflated, and that missing inputs degrade to an honest "not measured
yet" rather than to a silent zero.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from bench import report

GAS_FIELDS = [
    "protocol",
    "param_set",
    "operation",
    "registry_variant",
    "announcer_variant",
    "gas_used",
]


def _write_gas(directory: Path, rows: list[dict[str, object]]) -> None:
    path = directory / "gas_test.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=GAS_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def _gas_row(
    protocol: str, operation: str, gas: int, reg: str = "R1", ann: str = "A1", params: str = "p"
) -> dict[str, object]:
    return {
        "protocol": protocol,
        "param_set": params,
        "operation": operation,
        "registry_variant": reg,
        "announcer_variant": ann,
        "gas_used": gas,
    }


@pytest.fixture
def results(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(report, "RESULTS_DIR", tmp_path)
    return tmp_path


class TestMissingInputs:
    """A report built before anything is measured must say so, not invent."""

    def test_report_builds_with_no_results_at_all(self, results: Path) -> None:
        text = report.build_report("test")
        assert "No gas measurements yet" in text
        assert "No size table measured yet" in text
        assert "No scan measurements yet" in text
        assert "No anonymity simulation yet" in text

    def test_no_fabricated_zeros(self, results: Path) -> None:
        """An unmeasured quantity must never render as 0."""
        text = report.build_report("test")
        assert "| 0 |" not in text
        assert "0.000M" not in text


class TestGasTables:
    def test_measured_gas_survives_into_the_table(self, results: Path) -> None:
        _write_gas(
            results,
            [
                _gas_row("p1_erc5564", "register", 115_316, reg="erc6538"),
                _gas_row("p1_erc5564", "announce", 28_067, reg="erc6538"),
            ],
        )
        text = report.build_report("test")
        assert "115,316" in text
        assert "28,067" in text

    def test_registry_variants_are_never_conflated(self, results: Path) -> None:
        """R1 and R3 are the comparison; averaging them would erase the result."""
        _write_gas(
            results,
            [
                _gas_row("p3_hybrid", "register", 941_744, reg="R1"),
                _gas_row("p3_hybrid", "register", 115_264, reg="R3"),
                _gas_row("p3_hybrid", "announce", 67_730, ann="A1"),
            ],
        )
        text = report.build_report("test")
        assert "941,744" in text
        assert "115,264" in text
        # A mean of the two would be this, and must not appear anywhere.
        assert "528,504" not in text

    def test_median_is_used_not_mean(self, results: Path) -> None:
        """One cheap outlier must not drag the reported figure down."""
        _write_gas(
            results,
            [
                _gas_row("p3_hybrid", "register", 95_340, reg="R3"),  # the 1-in-256 case
                _gas_row("p3_hybrid", "register", 115_264, reg="R3"),
                _gas_row("p3_hybrid", "register", 115_264, reg="R3"),
                _gas_row("p3_hybrid", "announce", 67_730),
            ],
        )
        text = report.build_report("test")
        assert "115,264" in text
        assert "108,622" not in text  # the mean

    def test_ratios_are_computed_against_the_p1_baseline(self, results: Path) -> None:
        _write_gas(
            results,
            [
                _gas_row("p1_erc5564", "register", 100_000, reg="erc6538"),
                _gas_row("p1_erc5564", "announce", 30_000, reg="erc6538"),
                _gas_row("p3_hybrid", "register", 200_000, reg="R3"),
                _gas_row("p3_hybrid", "announce", 60_000),
            ],
        )
        text = report.build_report("test")
        assert "2.00x" in text  # both registration and announcement double

    def test_cumulative_cost_includes_registration(self, results: Path) -> None:
        _write_gas(
            results,
            [
                _gas_row("p3_hybrid", "register", 1_000_000, reg="R1"),
                _gas_row("p3_hybrid", "announce", 1_000_000),
            ],
        )
        text = report.build_report("test")
        assert "2.000M" in text  # k=1 -> registration + one announcement


class TestOtherSections:
    def test_scan_table_renders_measurements(self, results: Path) -> None:
        with (results / "scan.csv").open("w", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "protocol",
                    "param_set",
                    "announcer_variant",
                    "per_announcement_us",
                    "total_bytes_per_announcement",
                    "rpc_round_trips",
                ],
            )
            writer.writeheader()
            writer.writerow(
                {
                    "protocol": "p3_hybrid",
                    "param_set": "mlkem768",
                    "announcer_variant": "A2",
                    "per_announcement_us": "29.28",
                    "total_bytes_per_announcement": "1284",
                    "rpc_round_trips": "1.0",
                }
            )
        text = report.build_report("test")
        assert "29.28" in text
        assert "1,284" in text

    @staticmethod
    def _write_anonymity(results: Path, rows: list[dict[str, str]]) -> None:
        with (results / "anonymity.csv").open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def _anonymity_row(design: str, bits: str, mean: str, unique: str) -> dict[str, str]:
        return {
            "tag_design": design,
            "registry_size": "100",
            "tag_bits": bits,
            "expected_set_size": mean,
            "mean_set_size": mean,
            "fraction_deanonymised": unique,
        }

    def test_anonymity_section_reports_only_the_deployed_tag(self, results: Path) -> None:
        self._write_anonymity(
            results,
            [
                self._anonymity_row("h0", "8", "1.41", "0.666"),
                self._anonymity_row("h0", "16", "1.0", "0.998"),
                self._anonymity_row("domain_separated", "8", "100.0", "0.0"),
            ],
        )
        text = report.build_report("test")
        assert "66.6%" in text
        assert "99.8%" not in text  # the 16-bit row is not the deployed tag

    def test_anonymity_section_shows_both_designs_and_labels_the_old_one(
        self, results: Path
    ) -> None:
        """The deployed design and the pre-fix one, never one mistaken for the other."""
        self._write_anonymity(
            results,
            [
                self._anonymity_row("h0", "8", "1.41", "0.666"),
                self._anonymity_row("domain_separated", "8", "100.0", "0.0"),
            ],
        )
        section = report.build_report("test").split("(Q1)", 1)[1]
        assert "pre-fix design" in section
        assert "| 100 | 1.41 | 1.41 | 66.6% | 100.00 | 0.0% |" in section

    def test_anonymity_file_from_before_the_fix_is_reported_as_stale(self, results: Path) -> None:
        """A one-design file cannot say which design it measured; never guess."""
        row = self._anonymity_row("h0", "8", "1.41", "0.666")
        del row["tag_design"]
        self._write_anonymity(results, [row])
        text = report.build_report("test")
        assert "predates the domain-separated view tag" in text
        assert "66.6%" not in text

    def test_provenance_warns_when_measurement_predates_the_tree(self, results: Path) -> None:
        """A stale measurement must announce itself, not be quietly quoted."""
        (results / "run_meta_test.json").write_text(
            json.dumps(
                {
                    "network": "test",
                    "git_commit": "0" * 40,
                    "samples_per_target": 20,
                    "kem_backend": {"liboqs_version": "0.16.0"},
                    "machine": {"platform": "x", "python": "3.12"},
                }
            )
        )
        text = report.build_report("test")
        assert "Measured at commit" in text
        assert "working tree has moved on" in text


class TestCaveats:
    def test_local_chain_results_are_labelled_as_such(self, results: Path) -> None:
        """Anvil numbers must never be presented as testnet numbers."""
        assert "local-chain measurements" in report.build_report("anvil")

    def test_testnet_results_carry_no_local_caveat(self, results: Path) -> None:
        assert "local-chain measurements" not in report.build_report("eth_sepolia")

    def test_report_states_its_own_integrity_rule(self, results: Path) -> None:
        text = report.build_report("test")
        assert "never hand-edited" in text
