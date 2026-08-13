"""Every command-line entry point must run to completion and write its output.

Cheap insurance rather than deep verification. A formatting bug in one of these
would surface only after a measurement run, which on a real network means after
the funds are spent — and while the numbers themselves would survive (the gas
harness writes before any of this runs), discovering it then is still a wasted
evening. The behaviour of what they print is asserted elsewhere.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from bench import anonymity, curves, report, scan, sizes


@pytest.fixture
def results(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for module in (sizes, scan, curves, anonymity, report):
        monkeypatch.setattr(module, "RESULTS_DIR", tmp_path)
    return tmp_path


def _measured_gas_csv(directory: Path) -> Path:
    """A minimal but structurally real measurement file."""
    path = directory / "gas_smoke.csv"
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
        writer.writerows(
            [
                ["p1_erc5564", "secp256k1", "register", "erc6538", "A1", 115_316],
                ["p1_erc5564", "secp256k1", "announce", "erc6538", "A1", 28_067],
                ["p3_hybrid", "mlkem768", "register", "R3", "A2", 115_264],
                ["p3_hybrid", "mlkem768", "announce", "R3", "A2", 67_000],
            ]
        )
    return path


def test_sizes_main_writes_its_table(results: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sizes.main()
    assert (results / "sizes.csv").exists()
    assert "p3_hybrid" in capsys.readouterr().out


def test_scan_main_writes_its_measurements(
    results: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A tiny population: this asserts the command runs, not how fast it is.
    monkeypatch.setattr("sys.argv", ["scan", "--announcements", "50", "--repeats", "1"])
    scan.main()
    assert (results / "scan.csv").exists()
    assert "Q3" in capsys.readouterr().out


def test_anonymity_main_writes_its_simulation(
    results: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys.argv", ["anonymity", "--trials", "20"])
    anonymity.main()
    assert (results / "anonymity.csv").exists()
    assert "anonymity set" in capsys.readouterr().out


def test_curves_main_writes_table_and_figure(
    results: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _measured_gas_csv(results)
    monkeypatch.setattr("sys.argv", ["curves", "--network", "smoke"])
    curves.main()

    assert (results / "curves_smoke.csv").exists()
    output = capsys.readouterr().out
    assert "cumulative gas" in output
    assert "overtakes" in output


def test_curves_main_refuses_to_invent_missing_measurements(
    results: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Better to stop than to plot a curve from nothing."""
    monkeypatch.setattr("sys.argv", ["curves", "--network", "never_measured"])
    with pytest.raises(SystemExit, match=r"Run bench\.gas first"):
        curves.main()


def test_report_main_writes_markdown(
    results: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _measured_gas_csv(results)
    monkeypatch.setattr("sys.argv", ["report", "--network", "smoke"])
    report.main()

    path = results / "report_smoke.md"
    assert path.exists()
    text = path.read_text()
    assert "115,316" in text and "115,264" in text
    assert "PQ-SAP measurement report" in capsys.readouterr().out


def test_curves_figure_renders_when_matplotlib_is_available(results: Path) -> None:
    variants = curves.load_variants(_measured_gas_csv(results))
    path = curves.write_figure(variants, "smoke")
    if path is not None:  # optional dependency
        assert path.exists()
        assert path.stat().st_size > 1000
