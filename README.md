# Cost-Efficient Post-Quantum Stealth Address Protocol for Ethereum

Code, measurement harness, and raw data for the paper *"Cost-Efficient
Post-Quantum Stealth Address Protocol for Ethereum"* (Adzin Zhalifunnas and
Richard, Master of Computer Science, BINUS Graduate Program, Bina Nusantara
University) and the accompanying master's thesis.

The proposed protocol delivers the stealth-address shared secret with
ML-KEM-768 (FIPS 203) and keeps stealth keys on secp256k1, so it runs on
unmodified Ethereum: payments are ordinary transactions, with no precompile and
no protocol change. Its commitment registry (R3) stores the spending key plus a
Keccak-256 commitment to the ML-KEM encapsulation key (65 bytes) and serves the
encapsulation key itself off-chain. Design rationale is in [`docs/`](docs/):
architecture, threat model, and findings.

Three protocols are implemented against one shared harness so their on-chain
costs are directly comparable:

| | Protocol | Nature | Role |
|---|---|---|---|
| P1 | ERC-5564 / DKSAP | ECC, secp256k1 | current standard |
| P2 | MLWE SAP (Mikić et al.) | full post-quantum | PQ state of the art |
| P3 | Hybrid | PQ unlinkability + ECDSA custody | **the artifact** |

## Data availability

Every gas figure in the paper comes from [`bench/results/`](bench/results/),
measured at commit `8483324` on a local Anvil node running the Prague rules,
including EIP-7623. These files are committed and never hand-edited.

| File | Contents |
|---|---|
| `gas_anvil.csv` | One row per measured transaction: git commit, chain, block, protocol, operation, variant, seed, payload size and digest, calldata tokens, EIP-7623 floor, gas used, transaction hash |
| `receipts_anvil.jsonl` | Transaction receipts of the measured transactions |
| `run_meta_anvil.json` | Run metadata: commit, network, samples per target, KEM backend with the ML-KEM key and ciphertext sizes, machine, solc version, optimizer runs |
| `sizes.csv` | Meta-address and announcement sizes, storage slots, and predicted storage and data gas per protocol |
| `curves_anvil.csv`, `curves_anvil.png` | Cumulative cost against the number of payments |
| `scan.csv` | Off-chain scanning measurements |
| `anonymity.csv` | View-tag anonymity-set simulation |
| `report_anvil.md` | Generated report: medians, min–max ranges, ratios, break-even points |

The paper reports P1, P2, and P3 with the full registry (R1), the commitment
registry (R3), and the standard ERC-5564 announcer (A1). The repository also
measures two further P3 variants that the paper does not report: an emit-only
registry (R2) and a minimal-log announcer (A2).

To regenerate the results on a local node (see [Running](#running) for starting
Anvil and deploying):

```bash
uv run python -m bench.gas --network anvil --samples 20 --run-label r2
uv run python -m bench.sizes
uv run python -m bench.curves
uv run python -m bench.anonymity
uv run python -m bench.scan --announcements 2000
uv run python -m bench.report
```

Registrations reproduce gas for gas, because each keypair is derived from the
seed recorded in its row. Announcements draw fresh randomness on every run, so
a floor-priced announcement moves in 30-gas steps from run to run; the report
explains why.

## Setup (macOS)

If your checkout path contains spaces, quote it in every shell command.

```bash
git clone --recurse-submodules https://github.com/adzinzhalifunnas/post-quantum-stealth-address-protocol.git
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
- `docs/` — architecture, threat model, findings, and testnet setup.

## Measurement integrity

Benchmark numbers go into a paper and a thesis. A surprising result is re-run
and investigated, never adjusted; the protocol design is never tuned to flatter
a benchmark; unknown means unknown. Every result row records the git commit,
chain id, block number, and a digest of the exact bytes measured, so any figure
in the paper or the thesis can be traced back to the transaction it came from.

## Networks

All results in `bench/results/` and in the paper were measured on a local Anvil
node. Gas units are deterministic, so they reproduce on any EVM running the
same rules; fees, including the separate L1 data fee on layer-2 networks, were
not measured. The harness was also prepared for Ethereum Sepolia and Base
Sepolia (see [`docs/testnet-setup.md`](docs/testnet-setup.md)), but no testnet
results are reported. **Testnet only** — nothing in this repository may be
pointed at a mainnet RPC endpoint.

## Development note

This code was written with the help of Claude Code (Anthropic), an AI coding
assistant, as disclosed in the paper. [`CLAUDE.md`](CLAUDE.md) is the working
brief the assistant was given during development and is kept for transparency.
Parts of it are historical, such as an earlier working title and the testnet
and layer-2 plans. The paper and the thesis are the authoritative description
of the protocol and its results.

## License

MIT; see [`LICENSE`](LICENSE). Two contracts that follow the ERC reference
implementations, `shared/contracts/StealthAnnouncer.sol` and
`p1_erc5564/contracts/ERC6538Registry.sol`, keep their CC0-1.0 SPDX
identifier. forge-std, included as a git submodule, is under its own licenses.

## Citation

If you use this code or data, please cite the paper:

> A. Zhalifunnas and Richard, "Cost-Efficient Post-Quantum Stealth Address
> Protocol for Ethereum," 2026.

Publication details will be added once the paper is published.
