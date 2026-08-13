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
git clone --recurse-submodules <repo-url>
```

```bash
uv sync
```

`uv` provisions Python 3.12 (pinned in `.python-version`) and installs exact
versions from the committed `uv.lock`. Solidity tooling is Foundry; install it
with `foundryup` if `forge --version` fails.

`--recurse-submodules` matters. forge-std is pinned as a git submodule at
v1.9.7, because Soldeer's registry was returning HTTP 500 when this was set up.
The consequence is a real reproducibility caveat: a GitHub zip archive of this
repository does **not** contain submodule contents, so an examiner who downloads
it rather than cloning it will not be able to run `forge test`. Nothing in the
measured contracts depends on forge-std — it is used only by the test and
deploy scripts — so `forge build` works either way. If Soldeer recovers, moving
the dependency there removes the caveat entirely.

### The liboqs shared library

`liboqs-python` loads liboqs through `ctypes`, so it needs a **shared** library.
Read that sentence carefully before reaching for Homebrew: `brew install liboqs`
installs a static archive (`liboqs.a`) and nothing the Python wrapper can load.

What actually happens on first import is that `liboqs-python` clones and builds
liboqs itself into `~/_oqs`, producing `~/_oqs/lib/liboqs.dylib`. That build
needs `cmake` and a working C toolchain. Verified working here with liboqs
0.16.0 and liboqs-python 0.16.0.

Two provenance notes for reproduction, both recorded in each run's metadata:
the library that gets loaded lives outside this repository, and on this machine
the resulting build links against Homebrew's `openssl@1.1`, which is
end-of-life. Neither affects correctness of the ML-KEM output — the test suite
verifies that independently, see below — but both belong in any description of
the measurement environment.

### Verifying the ML-KEM backend

The single most dangerous silent failure available to this project is running
against round-3 Kyber instead of final FIPS 203 ML-KEM. The two have identical
key and ciphertext sizes and produce different output, so every size assertion
in the thesis would still pass while the results were quietly wrong. This is not
hypothetical: `Kyber768` is enabled in the same liboqs build as `ML-KEM-768`.

Two independent guards. `shared/pqsap_core/kem.py` refuses to load a parameter
set unless liboqs reports its algorithm version as `FIPS203`, and the test suite
interoperates both directions with `kyber-py`, a separate pure-Python FIPS 203
implementation — which is what actually proves the C backend is computing final
ML-KEM rather than something the same shape.

```bash
uv run python -c "import pqsap_core.kem as k; print(k.backend_info())"
```

## Running

The default suite is offline and needs no chain.

```bash
uv run pytest
```

```bash
forge test
```

Chain-dependent tests are marked `chain` and skip themselves when no anvil is
listening. They cover the parts of `chain.py` that need a node, and run the
whole pipeline — deploy, measure, checkpoint, analyse, report — as one unit.
They deliberately declare anvil *non-local*, which forces the branches that
otherwise first execute on a testnet with real funds behind them.

```bash
anvil &
```

```bash
forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

```bash
uv run pytest -m chain
```

Coverage, if you want to see what is not exercised:

```bash
uv run pytest --cov=pqsap_core --cov=p1_erc5564 --cov=p2_mlwe --cov=p3_hybrid --cov=bench --cov-report=term-missing
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
