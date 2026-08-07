# PQ-SAP — EVM-compatible post-quantum stealth address protocol

Proof-of-concept and measurement harness for a master's thesis (Adzin
Zhalifunnas, BINUS Graduate Program, Master of Computer Science). See
[CLAUDE.md](CLAUDE.md) for the full project charter: positioning against prior
work, settled scope decisions, protocol specifications, and the research
questions this code exists to answer.

Three protocols are implemented against one shared harness so their on-chain
costs are directly comparable:

| | Protocol | Nature | Role |
|---|---|---|---|
| P1 | ERC-5564 / DKSAP | ECC, secp256k1 | current standard |
| P2 | MLWE SAP (Mikić et al.) | full post-quantum | PQ state of the art |
| P3 | Hybrid | PQ unlinkability + ECDSA custody | **the artifact** |

## Setup (macOS)

The repository path contains spaces. Quote it in every shell command.

```bash
brew install liboqs
```

```bash
uv sync
```

`uv` provisions Python 3.12 (pinned in `.python-version`) and installs exact
versions from the committed `uv.lock`. Solidity tooling is Foundry; install it
with `foundryup` if `forge --version` fails.

### Verifying the ML-KEM backend

The single most dangerous silent failure in this project is compiling against
round-3 Kyber instead of final FIPS 203 ML-KEM: the two have identical key and
ciphertext sizes but produce different output. `shared/pqsap_core/kem.py`
asserts the mechanism name at load time, and the test suite cross-checks the
liboqs backend against an independent pure-Python implementation.

```bash
uv run python -c "import pqsap_core.kem as k; print(k.backend_info())"
```

## Running

```bash
uv run pytest
```

```bash
forge build
```

## Layout

- `shared/` — the fairness guarantees. `pqsap_core/` holds the derivation,
  KEM, and scheme interface every protocol imports; `contracts/` holds the
  announcer all three protocols share. Never fork these per protocol.
- `p1_erc5564/`, `p2_mlwe/`, `p3_hybrid/` — one package per protocol, each with
  its Python scheme, its registry contract, and its tests.
- `bench/` — one harness for all three protocols. Results land in
  `bench/results/` as CSV, are committed, and are never hand-edited.
- `docs/` — threat model and architecture.

## Measurement integrity

Benchmark numbers go into a thesis. A surprising result is re-run and
investigated, never adjusted; the protocol design is never tuned to flatter a
benchmark; unknown means unknown. Every result row records the git commit,
chain id, block number, and a digest of the exact bytes measured, so any figure
in the thesis can be traced back to an on-chain transaction.

Deployment targets are Ethereum Sepolia and Base Sepolia. **Testnet only** —
nothing in this repository may be pointed at a mainnet RPC endpoint.
