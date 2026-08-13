"""Chain access for the benchmark harness — one binding for every network.

Three networks, one code path: a local anvil for validating the harness before
spending anything, then Ethereum Sepolia and Base Sepolia for the authoritative
numbers. Gas *units* are deterministic and will agree across all three; the L1
data fee will not, and that difference is a result rather than noise.

Two things here exist specifically to avoid corrupting measurements.

**Receipts are read raw.** ``eth_getTransactionReceipt`` is called through
``make_request`` and the reply is used as-is, because web3.py's formatters are
built for Ethereum receipts and OP Stack chains return extra fields —
``l1Fee``, ``l1GasUsed`` and friends — that a typed formatter can silently drop.
On Base Sepolia those fields *are* the L2 cost story.

**Nothing may point at a mainnet RPC.** ``connect`` asserts the chain id it
reached is the one asked for and refuses any id not in this module's table. A
misconfigured ``.env`` should fail loudly, not quietly broadcast real value.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.types import RPCEndpoint, TxParams, Wei

__all__ = [
    "NETWORKS",
    "ChainError",
    "Network",
    "calldata_floor",
    "connect",
    "fund_account",
    "gas_price_now",
    "load_deployment",
    "new_account",
    "raw_receipt",
    "receipt_costs",
    "send",
    "sweep_to",
]


class ChainError(Exception):
    """A chain interaction was refused or produced something unusable."""


@dataclass(frozen=True)
class Network:
    """A network this study is allowed to talk to."""

    name: str
    chain_id: int
    rpc_env_var: str
    #: True for OP Stack chains, whose receipts carry L1 data fee fields.
    is_op_stack: bool = False
    #: Local development chains need no funding ceremony and are never
    #: authoritative for thesis numbers.
    is_local: bool = False


#: Every network the harness may reach. Testnets and a local node only — there
#: is deliberately no mainnet entry, and `connect` rejects anything absent here.
NETWORKS: Final[dict[str, Network]] = {
    "anvil": Network("anvil", 31337, "ANVIL_RPC_URL", is_local=True),
    "eth_sepolia": Network("eth_sepolia", 11155111, "ETH_SEPOLIA_RPC_URL"),
    "base_sepolia": Network("base_sepolia", 84532, "BASE_SEPOLIA_RPC_URL", is_op_stack=True),
}

_DEFAULT_ANVIL_RPC: Final[str] = "http://127.0.0.1:8545"
_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

#: anvil's first prefunded development account. Well-known, worthless, and never
#: valid anywhere else — the harness refuses to use it off a local chain.
ANVIL_FUNDER_KEY: Final[str] = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def connect(network: str) -> tuple[Web3, Network]:
    """Connect to a named network and verify we reached the chain we meant to.

    Raises:
        ChainError: if the network is unknown, the RPC URL is missing, the node
            is unreachable, or its chain id is not the expected one.
    """
    if network not in NETWORKS:
        raise ChainError(f"unknown network {network!r}; known: {sorted(NETWORKS)}")
    net = NETWORKS[network]

    rpc_url = os.environ.get(net.rpc_env_var, "")
    if not rpc_url and net.is_local:
        rpc_url = _DEFAULT_ANVIL_RPC
    if not rpc_url:
        raise ChainError(f"{net.rpc_env_var} is not set. Copy .env.example to .env and fill it in.")

    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 60}))
    if not w3.is_connected():
        raise ChainError(f"cannot reach {network} at the configured RPC endpoint")

    actual = w3.eth.chain_id
    if actual != net.chain_id:
        raise ChainError(
            f"connected to chain id {actual} but {network} expects {net.chain_id}. "
            "Check the RPC URL — this study must never touch a mainnet endpoint."
        )
    return w3, net


def new_account() -> LocalAccount:
    """Generate a fresh EOA.

    Every registration sample uses one of these. The charter's pitfall is that a
    first registration writes cold zero-to-non-zero storage at 20k gas per slot
    while an overwrite is far cheaper, so measuring anything but a fresh account
    would understate real-world registration cost.
    """
    account: LocalAccount = Account.create()
    return account


def send(w3: Web3, account: LocalAccount, tx: TxParams) -> dict[str, Any]:
    """Sign, send, and wait for one transaction. Returns the raw receipt.

    Raises:
        ChainError: if the transaction reverted.
    """
    params: TxParams = dict(tx)  # type: ignore[assignment]
    params.setdefault("from", account.address)
    params.setdefault("nonce", w3.eth.get_transaction_count(account.address))
    params.setdefault("chainId", w3.eth.chain_id)
    if "gas" not in params:
        params["gas"] = int(w3.eth.estimate_gas(params) * 12 // 10)
    if "maxFeePerGas" not in params and "gasPrice" not in params:
        priority = int(w3.eth.max_priority_fee)
        base = int(w3.eth.get_block("latest")["baseFeePerGas"])
        params["maxPriorityFeePerGas"] = Wei(priority)
        params["maxFeePerGas"] = Wei(base * 2 + priority)

    signed = account.sign_transaction(cast("dict[str, Any]", params))
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)

    receipt = raw_receipt(w3, tx_hash.hex())
    if int(receipt.get("status", "0x0"), 16) != 1:
        raise ChainError(f"transaction reverted: {tx_hash.hex()}")
    return receipt


def raw_receipt(w3: Web3, tx_hash: str) -> dict[str, Any]:
    """Fetch a receipt as the node returned it, with no formatting applied.

    Deliberately bypasses web3.py's typed formatters. OP Stack chains attach
    ``l1Fee``, ``l1GasUsed`` and related fields that a formatter built for
    Ethereum receipts can drop, and on Base Sepolia those fields carry the
    dominant part of the cost.
    """
    if not tx_hash.startswith("0x"):
        tx_hash = "0x" + tx_hash
    response = w3.provider.make_request(RPCEndpoint("eth_getTransactionReceipt"), [tx_hash])
    result = response.get("result")
    if not result:
        raise ChainError(f"no receipt for {tx_hash}: {response.get('error')}")
    return dict(result)


def receipt_costs(receipt: dict[str, Any], net: Network) -> dict[str, int | None]:
    """Extract the cost columns, keeping L2 execution and L1 data fee separate.

    The charter is explicit that these are different quantities reported in
    different columns: gas units are deterministic and comparable across
    networks, whereas the L1 data fee is the volatile part and is the reason
    Base Sepolia and Ethereum Sepolia will not agree.
    """

    def as_int(key: str) -> int | None:
        value = receipt.get(key)
        if value is None:
            return None
        return int(value, 16) if isinstance(value, str) else int(value)

    costs: dict[str, int | None] = {
        "gas_used": as_int("gasUsed"),
        "effective_gas_price": as_int("effectiveGasPrice"),
        "block_number": as_int("blockNumber"),
        "l1_fee_wei": None,
        "l1_gas_used": None,
        "l1_gas_price": None,
        "l1_blob_base_fee": None,
        "l1_base_fee_scalar": None,
        "l1_blob_base_fee_scalar": None,
    }
    if net.is_op_stack:
        # Verified against a live Base Sepolia receipt on 2026-08-13: all of
        # these are present. The scalars and blob base fee are captured even
        # though nothing currently computes with them, because a testnet run
        # costs scarce faucet funds and re-running to recover a column that was
        # right there the first time would be a waste. They are also what makes
        # an L1 fee explainable rather than merely reported.
        costs["l1_fee_wei"] = as_int("l1Fee")
        costs["l1_gas_used"] = as_int("l1GasUsed")
        costs["l1_gas_price"] = as_int("l1GasPrice")
        costs["l1_blob_base_fee"] = as_int("l1BlobBaseFee")
        costs["l1_base_fee_scalar"] = as_int("l1BaseFeeScalar")
        costs["l1_blob_base_fee_scalar"] = as_int("l1BlobBaseFeeScalar")
    return costs


def fund_account(w3: Web3, funder: LocalAccount, recipient: str, amount_wei: int) -> None:
    """Send native currency from the funder to a fresh sample account."""
    send(w3, funder, {"to": recipient, "value": Wei(amount_wei)})


#: EIP-7623 (Prague / Pectra). A transaction pays at least a floor derived from
#: its calldata alone: every zero byte counts as one token, every non-zero byte
#: as four, and the floor is 21,000 plus ten gas per token. Below that floor,
#: execution gas — including log data — is effectively free.
_STANDARD_TOKEN_COST: Final[int] = 4
_TOTAL_COST_FLOOR_PER_TOKEN: Final[int] = 10


def calldata_floor(data: bytes) -> tuple[int, int]:
    """EIP-7623 token count and floor gas for a transaction's calldata.

    This matters more than it sounds. Announcements in this study are large and
    computationally trivial, so they sit *on* the floor rather than above it —
    which means optimisations that reduce execution gas, such as emitting a
    smaller log, buy nothing at all. Only reducing calldata reduces cost.
    Recording the floor per row is what lets a reader see that from the data
    instead of taking it on trust.

    Returns:
        ``(tokens, floor_gas)``.
    """
    zero_bytes = data.count(0)
    tokens = zero_bytes + (len(data) - zero_bytes) * _STANDARD_TOKEN_COST
    return tokens, 21_000 + tokens * _TOTAL_COST_FLOOR_PER_TOKEN


def gas_price_now(w3: Web3) -> int:
    """Current cost per gas unit, used for budgeting before a run."""
    try:
        base = int(w3.eth.get_block("latest")["baseFeePerGas"])
        return base * 2 + int(w3.eth.max_priority_fee)
    except (KeyError, ValueError):  # pragma: no cover - pre-EIP-1559 nodes
        return int(w3.eth.gas_price)


def sweep_to(w3: Web3, account: LocalAccount, recipient: str) -> int:
    """Return a sample account's remaining balance to the funder.

    Testnet ETH is rationed by faucets, and a run uses a hundred throwaway
    accounts. Without this, every unspent margin is stranded forever in an
    account nothing will ever use again — which is how a benchmark ends up
    needing several ETH it cannot get. Sweeping costs one 21,000-gas transfer
    per sample and recovers the rest.

    Returns:
        Wei returned, or 0 if the balance would not cover its own transfer.
    """
    balance = w3.eth.get_balance(account.address)
    price = gas_price_now(w3)
    priority = min(int(w3.eth.max_priority_fee), price)
    reserved = 21_000 * price
    if balance <= reserved:
        return 0

    # Reserve at the ceiling price rather than the expected price: the transfer
    # must remain affordable even if the base fee rises before it is mined. Any
    # difference is left behind as dust, which is the safe direction to err.
    value = balance - reserved
    send(
        w3,
        account,
        {
            "to": recipient,
            "value": Wei(value),
            "gas": 21_000,
            "maxFeePerGas": Wei(price),
            "maxPriorityFeePerGas": Wei(priority),
        },
    )
    return int(value)


def load_deployment(chain_id: int, script: str = "Deploy.s.sol") -> dict[str, str]:
    """Read deployed contract addresses from Foundry's broadcast artefact.

    Using the broadcast log rather than a hand-maintained address file means
    every measured result traces back to a specific deployment transaction of
    specific bytecode.

    Returns:
        Mapping of contract name to address, most recent deployment winning.
    """
    path = _REPO_ROOT / "broadcast" / script / str(chain_id) / "run-latest.json"
    if not path.exists():
        raise ChainError(
            f"no broadcast artefact at {path}. Deploy first:\n"
            f"  forge script script/{script} --rpc-url <url> --broadcast --private-key <key>"
        )

    data = json.loads(path.read_text())
    addresses: dict[str, str] = {}
    for entry in data.get("transactions", []):
        if entry.get("transactionType") == "CREATE" and entry.get("contractName"):
            addresses[str(entry["contractName"])] = Web3.to_checksum_address(
                entry["contractAddress"]
            )
    if not addresses:
        raise ChainError(f"broadcast artefact at {path} records no contract deployments")
    return addresses


def load_abi(contract: str) -> list[dict[str, Any]]:
    """Load a compiled contract ABI from Foundry's output directory."""
    path = _REPO_ROOT / "out" / f"{contract}.sol" / f"{contract}.json"
    if not path.exists():
        raise ChainError(f"no compiled artefact at {path}. Run `forge build` first.")
    abi: list[dict[str, Any]] = json.loads(path.read_text())["abi"]
    return abi
