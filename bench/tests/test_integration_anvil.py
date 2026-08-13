"""End-to-end integration against a live anvil.

Everything else in the suite tests a piece. This tests the pipeline as a unit —
deploy, measure, checkpoint, analyse, report — because the failure that costs
most is the one that only appears when the parts run together, and on a real
network that failure is paid for in rate-limited faucet funds.

It also covers the parts of `chain.py` that unit tests structurally cannot:
`connect`, `send`, `sweep_to`, `load_deployment` and `load_abi` all need a node.

**Crucially it exercises the testnet-only branches** by declaring anvil
non-local. Dynamic per-sample funding and sweep-back only run off a local chain,
so without this they would first execute on Sepolia, with real funds behind
them.

Skipped automatically when no anvil is listening.

    anvil &
    forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 \\
      --broadcast --private-key <anvil key>
    uv run pytest -m chain
"""

from __future__ import annotations

import csv
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from eth_account import Account
from pqsap_core import chain
from pqsap_core.chain import ANVIL_FUNDER_KEY, ChainError
from web3.types import Wei

pytestmark = pytest.mark.chain

ANVIL_RPC = "http://127.0.0.1:8545"


def _anvil_available() -> bool:
    try:
        w3, _ = chain.connect("anvil")
        return bool(w3.is_connected())
    except Exception:
        return False


def _deployed() -> bool:
    try:
        chain.load_deployment(31337)
        return True
    except ChainError:
        return False


needs_anvil = pytest.mark.skipif(
    not _anvil_available(), reason="no anvil listening on 127.0.0.1:8545"
)
needs_deployment = pytest.mark.skipif(
    not (_anvil_available() and _deployed()),
    reason="contracts not deployed to anvil; run script/Deploy.s.sol first",
)


@needs_anvil
class TestChainAccess:
    """The parts of chain.py that need a node."""

    def test_connect_verifies_the_chain_id(self) -> None:
        _, net = chain.connect("anvil")
        assert net.chain_id == 31337

    def test_connect_refuses_a_chain_id_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The guard that stops a misconfigured .env reaching mainnet."""
        monkeypatch.setenv("ETH_SEPOLIA_RPC_URL", ANVIL_RPC)
        with pytest.raises(ChainError, match="never touch a mainnet endpoint"):
            chain.connect("eth_sepolia")

    def test_fresh_accounts_are_distinct_and_empty(self) -> None:
        w3, _ = chain.connect("anvil")
        a, b = chain.new_account(), chain.new_account()
        assert a.address != b.address
        assert w3.eth.get_balance(a.address) == 0

    def test_send_returns_a_raw_receipt(self) -> None:
        w3, _ = chain.connect("anvil")
        funder = Account.from_key(ANVIL_FUNDER_KEY)
        receipt = chain.send(w3, funder, {"to": chain.new_account().address, "value": Wei(10**15)})
        assert int(receipt["status"], 16) == 1
        assert "gasUsed" in receipt

    def test_sweep_returns_funds_and_leaves_only_dust(self) -> None:
        """The mechanism that makes a testnet run affordable."""
        w3, _ = chain.connect("anvil")
        funder = Account.from_key(ANVIL_FUNDER_KEY)
        sample = chain.new_account()

        chain.fund_account(w3, funder, sample.address, 10**16)
        assert w3.eth.get_balance(sample.address) == 10**16

        returned = chain.sweep_to(w3, sample, funder.address)
        assert returned > 0
        # Whatever is left cannot pay for its own transfer, which is the point.
        assert w3.eth.get_balance(sample.address) < 21_000 * chain.gas_price_now(w3)

    def test_sweep_declines_when_the_balance_cannot_cover_itself(self) -> None:
        w3, _ = chain.connect("anvil")
        assert (
            chain.sweep_to(w3, chain.new_account(), Account.from_key(ANVIL_FUNDER_KEY).address) == 0
        )


@needs_deployment
class TestDeployment:
    def test_every_contract_the_grid_needs_is_deployed(self) -> None:
        from bench.gas import targets

        addresses = chain.load_deployment(31337)
        required = {t.registry_contract for t in targets()} | {
            t.announcer_contract for t in targets()
        }
        assert required <= set(addresses)

    def test_abis_load_for_every_deployed_contract(self) -> None:
        for name in chain.load_deployment(31337):
            assert chain.load_abi(name), f"{name} has an empty ABI"

    def test_preflight_passes(self) -> None:
        from bench.gas import preflight

        report = preflight("anvil")
        assert "FAIL" not in report
        assert "All checks passed" in report

    def test_preflight_reports_an_unreachable_network(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The failure path matters as much as the success one."""
        from bench.gas import preflight

        monkeypatch.setenv("ETH_SEPOLIA_RPC_URL", "http://127.0.0.1:1")
        assert "FAIL" in preflight("eth_sepolia")

    def test_estimate_prices_the_run_without_sending_anything(self) -> None:
        """The command that decides whether the faucet balance is enough.

        Untested until now, and it is the first thing anyone runs against a real
        network — a crash here would be discovered while trying to budget.
        """
        from bench.gas import estimate_run_cost

        w3, _ = chain.connect("anvil")
        block_before = w3.eth.block_number

        projection = estimate_run_cost("anvil", samples=20)

        assert "projected cost" in projection
        assert "gas price now" in projection
        assert "TOTAL" in projection
        # Every target must appear, or the projection understates the run.
        for name in ("p1_erc5564", "p2_mlwe", "p3_hybrid"):
            assert name in projection
        # It must reach a verdict on affordability.
        assert "sufficient" in projection or "SHORT by" in projection
        # And it must genuinely have sent nothing.
        assert w3.eth.block_number == block_before

    def test_estimate_totals_are_plausible_against_measured_gas(self) -> None:
        """A projection wildly adrift from the known figures is a bug, not news."""
        from bench.gas import estimate_run_cost

        projection = estimate_run_cost("anvil", samples=20)
        total_line = next(line for line in projection.splitlines() if line.startswith("TOTAL"))
        total_gas = int(total_line.split()[1].replace(",", ""))
        # The measured full grid is ~103M gas; allow generous room either side.
        assert 50_000_000 < total_gas < 200_000_000

    def test_cli_preflight_and_estimate_run_clean(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from bench import gas

        monkeypatch.setattr("sys.argv", ["gas", "--network", "anvil", "--preflight"])
        gas.main()
        assert "All checks passed" in capsys.readouterr().out

        monkeypatch.setattr(
            "sys.argv", ["gas", "--network", "anvil", "--samples", "20", "--estimate"]
        )
        gas.main()
        assert "projected cost" in capsys.readouterr().out


@needs_deployment
class TestFullPipeline:
    """Deploy → measure → checkpoint → analyse → report, through the *testnet*
    code path, with results written to a temporary directory."""

    @pytest.fixture
    def testnet_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
        from bench import curves, gas, report

        # Force the branches that only run off a local chain.
        monkeypatch.setitem(
            chain.NETWORKS, "anvil", replace(chain.NETWORKS["anvil"], is_local=False)
        )
        monkeypatch.setenv("ANVIL_RPC_URL", ANVIL_RPC)
        monkeypatch.setenv("DEPLOYER_PRIVATE_KEY", ANVIL_FUNDER_KEY)
        monkeypatch.setattr(gas, "RESULTS_DIR", tmp_path)
        monkeypatch.setattr(curves, "RESULTS_DIR", tmp_path)
        monkeypatch.setattr(report, "RESULTS_DIR", tmp_path)
        return tmp_path

    def test_pipeline_produces_a_complete_report(self, testnet_path: Path) -> None:
        from bench import curves, gas, report

        _, net = chain.connect("anvil")
        assert not net.is_local, "testnet code path not active"

        rows = gas.run("anvil", samples=1, run_label="integration")

        # Every target, one sample, two operations each. Derived rather than
        # hardcoded, so adding a variant does not silently break the assertion
        # into meaninglessness.
        expected_rows = len(gas.targets()) * 2
        assert len(rows) == expected_rows
        assert all(r.gas_used and r.gas_used > 0 for r in rows)
        assert all(r.tx_hash.startswith("0x") for r in rows)

        # R3 must have registered the 65-byte commitment, not the full key.
        r3 = [r for r in rows if r.registry_variant == "R3" and r.operation == "register"]
        assert r3 and all(r.payload_bytes == 65 for r in r3)

        # Announcements must be recognised as calldata-floor-bound; that finding
        # is what makes A2 nearly worthless, so it must survive the pipeline.
        pq_announcements = [
            r for r in rows if r.operation == "announce" and r.protocol != "p1_erc5564"
        ]
        assert all(r.floor_bound for r in pq_announcements)

        # Checkpointing must have written as it went.
        gas_csv = testnet_path / "gas_anvil.csv"
        receipts = testnet_path / "receipts_anvil.jsonl"
        assert gas_csv.exists() and receipts.exists()
        assert len(receipts.read_text().splitlines()) == expected_rows

        # Raw receipts must be archived verbatim and parseable.
        for line in receipts.read_text().splitlines():
            assert "transactionHash" in json.loads(line)

        # The analysis layer must consume what the harness produced.
        variants = curves.load_variants(gas_csv)
        assert variants
        labels = {(v.registry_variant, v.announcer_variant) for v in variants}
        assert ("R3", "A2") in labels

        gas.write_run_meta("anvil", 1)
        text = report.build_report("anvil")
        assert "No gas measurements yet" not in text
        assert "local-chain measurements" in text

        # Registration figures must survive verbatim from receipt to Markdown.
        # Registry variants are unique across targets, so with one sample each
        # the reported median is that sample.
        #
        # Announcements are deliberately not checked this way: several targets
        # share an announcer variant, so their rows fall into one group and the
        # reported median is one of them rather than all.
        for row in rows:
            if row.operation != "register":
                continue
            assert row.gas_used is not None
            assert f"{row.gas_used:,}" in text, (
                f"{row.protocol}/{row.registry_variant} registration "
                f"{row.gas_used:,} missing from the report"
            )

    def test_a_crash_preserves_everything_already_paid_for(
        self, testnet_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The property that makes a scarce-funds run survivable."""
        from bench import gas

        real = gas._measure_sample
        calls = {"n": 0}

        def failing(*args: Any, **kwargs: Any) -> Any:
            calls["n"] += 1
            if calls["n"] > 2:
                raise RuntimeError("simulated RPC failure")
            return real(*args, **kwargs)

        monkeypatch.setattr(gas, "_measure_sample", failing)

        with pytest.raises(RuntimeError, match="simulated RPC failure"):
            gas.run("anvil", samples=1, run_label="crash")

        rows = list(csv.DictReader((testnet_path / "gas_anvil.csv").open()))
        assert len(rows) == 4, "checkpoint lost data paid for before the failure"
