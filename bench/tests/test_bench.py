"""Tests for the measurement harness itself.

Chain-free: everything here checks the logic that decides what gets measured and
how it is reported. A harness bug corrupts every number in the thesis silently,
so the safety rails — the mainnet guard, the L1/L2 fee separation, the size
table matching the schemes — are worth asserting even though they never touch a
node.
"""

from __future__ import annotations

import pytest
from pqsap_core import chain
from pqsap_core.chain import ChainError, Network

from bench import gas, sizes


def test_size_table_covers_every_scheme() -> None:
    rows = sizes.size_rows()
    assert len(rows) == len(sizes.all_schemes())
    assert {r.protocol for r in rows} == {"p1_erc5564", "p2_mlwe", "p3_hybrid"}


def test_size_table_matches_the_schemes() -> None:
    """The table must be derived, never transcribed."""
    for row, scheme in zip(sizes.size_rows(), sizes.all_schemes(), strict=True):
        assert row.meta_bytes == scheme.meta_len
        assert row.announcement_bytes == scheme.payload_len
        assert row.param_set == scheme.param_set


def test_slot_count_rounds_up_and_includes_length_slot() -> None:
    """1217 bytes is 39 data slots plus one for the length."""
    by_key = {(r.protocol, r.param_set): r for r in sizes.size_rows()}
    assert by_key[("p3_hybrid", "mlkem768")].meta_slots == 40
    assert by_key[("p1_erc5564", "secp256k1")].meta_slots == 4
    assert by_key[("p2_mlwe", "mlkem768")].meta_slots == 75


def test_p2_and_p3_announcements_are_the_same_size() -> None:
    """The premise of the whole comparison: P3's advantage is registration only."""
    by_key = {(r.protocol, r.param_set): r for r in sizes.size_rows()}
    assert (
        by_key[("p2_mlwe", "mlkem768")].announcement_bytes
        == by_key[("p3_hybrid", "mlkem768")].announcement_bytes
    )
    assert by_key[("p3_hybrid", "mlkem768")].meta_bytes < by_key[("p2_mlwe", "mlkem768")].meta_bytes


def test_networks_are_testnets_only() -> None:
    """A mainnet entry here would be a route to broadcasting real value."""
    mainnet_ids = {1, 8453, 10, 137, 42161, 56}
    for net in chain.NETWORKS.values():
        assert net.chain_id not in mainnet_ids


def test_connect_refuses_unknown_networks() -> None:
    with pytest.raises(ChainError, match="unknown network"):
        chain.connect("ethereum_mainnet")


def test_connect_reports_missing_rpc_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ETH_SEPOLIA_RPC_URL", raising=False)
    with pytest.raises(ChainError, match="ETH_SEPOLIA_RPC_URL"):
        chain.connect("eth_sepolia")


def test_receipt_costs_separates_l1_from_l2() -> None:
    """L2 execution gas and L1 data fee are different columns, never summed."""
    receipt = {
        "gasUsed": "0xe6f4",
        "effectiveGasPrice": "0x3b9aca00",
        "blockNumber": "0x10",
        "l1Fee": "0x2386f26fc10000",
        "l1GasUsed": "0x640",
    }

    op_stack = chain.receipt_costs(receipt, Network("base_sepolia", 84532, "X", is_op_stack=True))
    assert op_stack["gas_used"] == 0xE6F4
    assert op_stack["l1_fee_wei"] == 0x2386F26FC10000
    assert op_stack["l1_gas_used"] == 0x640

    # An L1 chain has no such fields, and they must stay null rather than zero —
    # zero would read as "measured and found to be nothing".
    l1 = chain.receipt_costs(receipt, Network("eth_sepolia", 11155111, "X"))
    assert l1["gas_used"] == 0xE6F4
    assert l1["l1_fee_wei"] is None
    assert l1["l1_gas_used"] is None


def test_receipt_costs_tolerates_missing_fields() -> None:
    costs = chain.receipt_costs({}, Network("base_sepolia", 84532, "X", is_op_stack=True))
    assert all(value is None for value in costs.values())


def test_measurement_grid_covers_all_three_protocols() -> None:
    protocols = {t.scheme.name for t in gas.targets()}
    assert protocols == {"p1_erc5564", "p2_mlwe", "p3_hybrid"}


def test_every_target_names_a_real_registry_contract() -> None:
    expected = {"ERC6538Registry", "MLWERegistry", "RegistryFull"}
    assert {t.registry_contract for t in gas.targets()} <= expected


def test_all_targets_share_one_announcer() -> None:
    """The announcer is the control variable; M4 measures no variant of it."""
    assert {t.announcer_variant for t in gas.targets()} == {"A1"}


def _row(protocol: str, operation: str, gas_used: int) -> gas.GasRow:
    return gas.GasRow(
        git_commit="deadbeef",
        network="anvil",
        chain_id=31337,
        block_number=1,
        protocol=protocol,
        operation=operation,
        registry_variant="R1",
        announcer_variant="A1",
        param_set="mlkem768",
        sample_id=0,
        seed="seed",
        payload_bytes=1217,
        payload_keccak="00",
        gas_used=gas_used,
        effective_gas_price=1,
        l1_gas_used=None,
        l1_fee_wei=None,
        tx_hash="0x0",
        timestamp="now",
    )


def test_crossover_is_net_of_the_intrinsic_cost() -> None:
    """121k register against 71k announce is 2.0 payments once 21k is removed."""
    rows = [_row("p3_hybrid", "register", 121_000), _row("p3_hybrid", "announce", 71_000)]
    report = gas.crossover(rows)
    assert "100,000" in report  # registration net of intrinsic
    assert "50,000" in report  # announcement net of intrinsic
    assert "2.0x" in report


def test_summarise_reports_a_distribution_not_a_mean() -> None:
    """The charter requires distributions; a lone average hides content variance."""
    rows = [_row("p3_hybrid", "announce", value) for value in (67_500, 67_700, 67_900)]
    report = gas.summarise(rows)
    assert "67,700" in report  # median
    assert "67,500" in report and "67,900" in report  # min and max
