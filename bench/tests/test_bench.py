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
    """L2 execution gas and L1 data fee are different columns, never summed.

    Field names and shape are copied from a real Base Sepolia receipt fetched
    on 2026-08-13, so this asserts against what the chain actually returns
    rather than against what the OP Stack documentation says it should.
    """
    receipt = {
        "gasUsed": "0x2c108",
        "effectiveGasPrice": "0x5b8d80",
        "blockNumber": "0x2b54679",
        "l1Fee": "0x4cd61a529",
        "l1GasUsed": "0x16da",
        "l1GasPrice": "0x3d69ade2",
        "l1BlobBaseFee": "0x374c6d2",
        "l1BaseFeeScalar": "0x44d",
        "l1BlobBaseFeeScalar": "0xa118b",
    }

    op_stack = chain.receipt_costs(receipt, Network("base_sepolia", 84532, "X", is_op_stack=True))
    assert op_stack["gas_used"] == 0x2C108
    assert op_stack["l1_fee_wei"] == 0x4CD61A529
    assert op_stack["l1_gas_used"] == 0x16DA
    # Captured but not yet used in analysis: a testnet run is expensive enough
    # that recovering a column later would mean measuring again.
    assert op_stack["l1_gas_price"] == 0x3D69ADE2
    assert op_stack["l1_blob_base_fee"] == 0x374C6D2
    assert op_stack["l1_base_fee_scalar"] == 0x44D
    assert op_stack["l1_blob_base_fee_scalar"] == 0xA118B

    # An L1 chain has no such fields, and they must stay null rather than zero —
    # zero would read as "measured and found to be nothing".
    l1 = chain.receipt_costs(receipt, Network("eth_sepolia", 11155111, "X"))
    assert l1["gas_used"] == 0x2C108
    assert l1["l1_fee_wei"] is None
    assert l1["l1_gas_used"] is None
    assert l1["l1_gas_price"] is None


def test_receipt_costs_tolerates_missing_fields() -> None:
    costs = chain.receipt_costs({}, Network("base_sepolia", 84532, "X", is_op_stack=True))
    assert all(value is None for value in costs.values())


def test_measurement_grid_covers_all_three_protocols() -> None:
    protocols = {t.scheme.name for t in gas.targets()}
    assert protocols == {"p1_erc5564", "p2_mlwe", "p3_hybrid"}


def test_every_target_names_a_real_registry_contract() -> None:
    expected = {"ERC6538Registry", "MLWERegistry", "RegistryFull", "RegistryCommit"}
    assert {t.registry_contract for t in gas.targets()} <= expected


def test_only_p3_departs_from_the_shared_announcer() -> None:
    """The shared announcer stays the control variable.

    A2 is an object of study belonging to P3, measured *against* the shared
    announcer. If P1 or P2 ever announced through anything else, the per-payment
    comparison between protocols would stop meaning anything.
    """
    for target in gas.targets():
        if target.scheme.name == "p3_hybrid":
            continue
        assert target.announcer_variant == "A1"
        assert target.announcer_contract == "StealthAnnouncer"

    assert {t.announcer_variant for t in gas.targets()} == {"A1", "A2"}


def test_grid_covers_every_variant_at_least_once() -> None:
    """Registration and announcement are independent, so each variant needs to
    appear once; `crossover` composes the rest of the cross product."""
    registries = {t.registry_variant for t in gas.targets()}
    announcers = {t.announcer_variant for t in gas.targets()}
    assert registries == {"erc6538", "mlwe_full", "R1", "R3"}
    assert announcers == {"A1", "A2"}


def test_r3_registers_the_commitment_not_the_key() -> None:
    """The 65-byte payload is the whole of R3's saving."""
    from p3_hybrid.scheme import P3Hybrid

    r3 = next(t for t in gas.targets() if t.registry_variant == "R3")
    keys = r3.scheme.keygen(b"grid")
    payload = gas.registry_payload(r3, keys)

    assert len(payload) == 65
    assert len(keys.meta.payload) > 800
    # The encapsulation key itself must not reach the chain.
    assert isinstance(r3.scheme, P3Hybrid)
    _, ek_view = r3.scheme.split_meta(keys.meta)
    assert ek_view not in payload


def test_non_commitment_targets_register_the_full_meta() -> None:
    for target in gas.targets():
        if target.use_commitment:
            continue
        keys = target.scheme.keygen(b"grid")
        assert gas.registry_payload(target, keys) == keys.meta.payload


def test_calldata_floor_matches_eip7623() -> None:
    """The floor is 21,000 plus ten gas per token, a token being one zero byte
    or a quarter of a non-zero byte."""
    tokens, floor = chain.calldata_floor(b"\x00" * 10)
    assert tokens == 10
    assert floor == 21_000 + 100

    tokens, floor = chain.calldata_floor(b"\xff" * 10)
    assert tokens == 40
    assert floor == 21_000 + 400

    assert chain.calldata_floor(b"") == (0, 21_000)


def test_floor_dominates_a_large_announcement() -> None:
    """Why A2 cannot help much: a 1088-byte ciphertext puts the transaction on
    the calldata floor, where removing log data saves nothing."""
    _, floor = chain.calldata_floor(b"\xab" * 1088)
    log_data_saving = 1088 * 8  # 8 gas per byte of log data
    assert floor > 21_000 + log_data_saving


def _row(protocol: str, operation: str, gas_used: int, *, variant: str | None = None) -> gas.GasRow:
    return gas.GasRow(
        git_commit="deadbeef",
        network="anvil",
        chain_id=31337,
        block_number=1,
        protocol=protocol,
        operation=operation,
        registry_variant=variant if operation == "register" and variant else "R1",
        announcer_variant=variant if operation == "announce" and variant else "A1",
        param_set="mlkem768",
        sample_id=0,
        seed="seed",
        payload_bytes=1217,
        payload_keccak="00",
        calldata_bytes=1348,
        calldata_tokens=5000,
        eip7623_floor_gas=71_000,
        floor_bound=False,
        gas_used=gas_used,
        effective_gas_price=1,
        l1_gas_used=None,
        l1_fee_wei=None,
        l1_gas_price=None,
        l1_blob_base_fee=None,
        l1_base_fee_scalar=None,
        l1_blob_base_fee_scalar=None,
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


def test_crossover_separates_registry_variants() -> None:
    """R1 and R3 must never be averaged together — they are the comparison."""
    rows = [
        _row("p3_hybrid", "register", 941_744, variant="R1"),
        _row("p3_hybrid", "register", 115_264, variant="R3"),
        _row("p3_hybrid", "announce", 67_730, variant="A1"),
    ]
    report = gas.crossover(rows)
    assert "920,744" in report  # R1 net of intrinsic
    assert "94,264" in report  # R3 net of intrinsic
    # The pair not sent directly is composed and marked as such.
    assert "*" in report


def test_summarise_reports_a_distribution_not_a_mean() -> None:
    """The charter requires distributions; a lone average hides content variance."""
    rows = [_row("p3_hybrid", "announce", value) for value in (67_500, 67_700, 67_900)]
    report = gas.summarise(rows)
    assert "67,700" in report  # median
    assert "67,500" in report and "67,900" in report  # min and max
