# Testnet setup — what to prepare before measuring

Everything up to this point runs offline or on a local anvil. This document
covers the one step that cannot be automated: obtaining testnet credentials and
funds. It is written to be followed once per network.

**Read the safety rules first.** They are short and the rest of this document
assumes them.

## Safety rules

1. **Create a brand-new wallet for this project.** Never reuse a wallet that has
   ever held mainnet funds, and never import an existing seed phrase. The
   harness broadcasts transactions automatically from this key.
2. **The key goes in `.env`, which is gitignored.** Never commit it, never paste
   it into a chat, an issue, or a thesis appendix. If it leaks, abandon it and
   make a new one — it is worthless, so this costs nothing.
3. **Testnet ETH has no monetary value.** Anyone selling it is running a scam.
   Faucets are free.
4. **Never point an RPC variable at a mainnet endpoint.** `chain.py` checks the
   chain id it actually reached and refuses anything not in its table, so a
   mistake fails loudly rather than spending real money — but do not rely on
   that as your only defence.

## Step 1 — Create the deployer wallet

Any method that produces a private key works. From this repository:

```bash
cast wallet new
```

That prints an address and a private key. Keep the private key for step 4 and
the address for step 3.

This one account does everything: it deploys the four contracts, and it funds
the hundred throwaway accounts that each registration sample uses.

## Step 2 — Get RPC URLs

You need one endpoint per network:

| Network | Chain ID | `.env` variable |
|---|---|---|
| Ethereum Sepolia | 11155111 | `ETH_SEPOLIA_RPC_URL` |
| Base Sepolia | 84532 | `BASE_SEPOLIA_RPC_URL` |

Free options include Alchemy, Infura, and the public endpoints those chains
publish. A free tier is enough: a full run is a few hundred transactions.

Prefer a keyed endpoint over a public one. Public RPCs rate-limit aggressively,
and a run that dies two thirds of the way through wastes the funds already
spent.

## Step 3 — Fund the wallet on **both** networks

This is the slow part. Start it before you need it — faucets are rate-limited
per day, so you may need to come back tomorrow.

**Ethereum Sepolia.** Several faucets exist (Google Cloud's Web3 faucet, Alchemy's,
and others). Most require a sign-in or a mainnet balance to deter abuse, and
daily limits are typically a fraction of an ETH. Check the current limit on the
faucet itself — these change often.

**Base Sepolia.** Two routes:

- A Base Sepolia faucet directly, e.g. via Coinbase Developer Platform.
- Or bridge: get Sepolia ETH first, then send it across the official Base
  Sepolia bridge. Slower, but it turns one faucet into two networks.

### How much do you actually need?

A full run is roughly **103 million gas per network**, measured on anvil against
the real contracts. What that costs depends entirely on the gas price at the
time:

| Gas price | Cost of one full run |
|---|---|
| 0.1 gwei | ~0.010 ETH |
| 1 gwei | ~0.103 ETH |
| 5 gwei | ~0.514 ETH |
| 20 gwei | ~2.06 ETH |

Testnet gas is usually cheap, but Sepolia does spike. **Do not guess** — once
the contracts are deployed, ask the live network:

```bash
uv run python -m bench.gas --network eth_sepolia --samples 20 --estimate
```

That sends nothing. It prices every call against the deployed contracts at the
current gas price, compares the total to your balance, and tells you plainly
whether you are short. Run it again immediately before measuring.

Where the gas goes, if you need to economise: P2 is about 61% of the budget,
because a fully post-quantum meta-address is 2368 bytes and every one of its 75
storage slots is a cold write. P1 is under 3%.

**On stranded funds.** Each sample uses a fresh account, and the harness sweeps
whatever that account did not spend back to the deployer. Without sweeping, a
run would strand its funding in a hundred dead accounts and need several ETH
instead of a fraction of one. Sweeping is automatic on testnets and skipped on
anvil, where it would only add noise.

## Step 4 — Fill in `.env`

```bash
cp .env.example .env
```

Then edit it. `.env` is gitignored; `.env.example` is the committed template and
must never contain real values.

```
ETH_SEPOLIA_RPC_URL=https://...
BASE_SEPOLIA_RPC_URL=https://...
DEPLOYER_PRIVATE_KEY=0x...
```

`ETHERSCAN_API_KEY` and `BASESCAN_API_KEY` are optional and only needed if you
want the deployed contracts verified on the block explorers. Verification is
worth doing for the thesis — it lets an examiner read the exact source that
produced the numbers — but it is not required to measure.

## Step 5 — Deploy

Identical bytecode goes to both networks. Gas units will match; the fees will
not, and that difference is a finding rather than noise.

```bash
forge script script/Deploy.s.sol --rpc-url $ETH_SEPOLIA_RPC_URL --broadcast --private-key $DEPLOYER_PRIVATE_KEY
```

```bash
forge script script/Deploy.s.sol --rpc-url $BASE_SEPOLIA_RPC_URL --broadcast --private-key $DEPLOYER_PRIVATE_KEY
```

Commit the resulting `broadcast/` files. They tie every measured result to the
deployment transaction of specific bytecode, which is what makes a number in the
thesis traceable.

## Step 6 — Preflight, estimate, then measure

Three commands, in order. The first two send nothing.

**Preflight** checks everything that can fail without spending: RPC reachable
and on the right chain, all six contracts deployed, funder holding a balance,
gas estimation working against every target, and — importantly on Base Sepolia —
that the receipt actually carries the `l1Fee` fields the harness reads. It
verifies the last of these against a transaction already on the chain, so it
costs nothing.

```bash
uv run python -m bench.gas --network eth_sepolia --preflight
```

**Estimate** prices the run at the current gas price and says plainly whether
your balance covers it.

```bash
uv run python -m bench.gas --network eth_sepolia --samples 20 --estimate
```

**Measure.** Expect this to take a while — several hundred sequential
transactions, each waiting for a receipt.

```bash
uv run python -m bench.gas --network eth_sepolia --samples 20 --run-label sepolia1
```

```bash
uv run python -m bench.gas --network base_sepolia --samples 20 --run-label basesep1
```

### If the run dies partway through, nothing is lost

Results are flushed to disk after every target and again if the run is
interrupted, so a failure at 80% keeps the 80% already paid for. The harness
prints how many rows survived and how much was spent. Re-run with a **fresh
`--run-label`** to add the missing targets rather than starting over — a
different label means different seeds, so the new samples are genuinely new.

Every raw receipt is also archived to `receipts_<network>.jsonl`, exactly as the
node returned it. That is deliberate insurance: if some later analysis needs a
field the CSV does not carry, it is already there and no second faucet cycle is
needed.

Results land in `bench/results/gas_<network>.csv` alongside a
`run_meta_<network>.json` recording library versions, compiler settings and
machine. All are committed and **never hand-edited**. A surprising number means
re-run and investigate; it never means adjust.

## What to expect, and what would be suspicious

Gas *units* are deterministic. The anvil figures below should reproduce almost
exactly on both testnets — a difference of more than a few hundred gas means
something changed (a different compiler, a different EVM fork, a modified
contract) and is worth chasing before trusting anything else.

| Protocol | Params | Register | Announce |
|---|---|---|---|
| P1 ERC-5564 | secp256k1 | 115,316 | 28,067 |
| P2 MLWE | mlkem768 | 1,745,670 | 67,730 |
| P2 MLWE | mlkem512 | 1,194,672 | 54,900 |
| P3 R1 | mlkem768 | 941,744 | 67,730 |
| P3 R1 | mlkem512 | 666,246 | 54,930 |
| P3 R3 | either | 115,264 | — |

One legitimate outlier to expect rather than be alarmed by: roughly one R3
registration in 256 costs about 20,000 gas *less* than the rest. Its payload's
last byte happens to be zero, so the final storage word is all zeros and
Solidity skips a cold `SSTORE`. Report the median, not the mean.

What will *not* match, and is the reason for measuring on real networks at all:

- **Ethereum Sepolia** charges for calldata inside the gas figure, at the
  prevailing gas price.
- **Base Sepolia** reports a much smaller L2 execution cost plus a separate
  **L1 data fee**, in the `l1Fee` and `l1GasUsed` receipt fields. Those are
  recorded in their own CSV columns and must never be summed with L2 gas.
  Post-Fjord, the L1 fee is derived from a compressed-size estimate — and ML-KEM
  ciphertexts are pseudorandom, so they compress essentially not at all. That is
  a point worth making in the analysis rather than a detail to bury.

## Troubleshooting

**"DEPLOYER_PRIVATE_KEY is not set"** — `.env` is missing or not loaded. The
harness reads the process environment; export the variables or use a loader such
as `direnv`.

**"connected to chain id X but Y expects Z"** — the RPC URL points at the wrong
network. This guard is deliberate; fix the URL rather than the check.

**"no broadcast artefact at ..."** — deploy to that network first (step 5).

**A run dies partway through** — the CSV is written only at the end, so partial
runs produce nothing. Re-run with a fresh `--run-label` so the seeds differ and
the samples are genuinely new. Nothing is corrupted by a failed run; the
registrations it already made simply belong to accounts you will not reuse.

**Transactions stuck pending** — the fee ceiling in `chain.py` is the base fee
doubled plus a priority tip, which is generous but can still be outrun by a
sharp spike. Wait for the network to calm down and re-run.
