# Architecture

How the artifact is put together, and — the part that matters for a comparative
study — which pieces are deliberately shared so that the three protocols stay
comparable.

## The experiment

Three protocols, one harness:

| | Protocol | Nature | Role |
|---|---|---|---|
| P1 | ERC-5564 / DKSAP | ECC, secp256k1 | the current standard |
| P2 | MLWE SAP (Mikić et al.) | full post-quantum | post-quantum state of the art |
| P3 | Hybrid | PQ unlinkability + ECDSA custody | **the artifact** |

The question is on-chain cost, so everything is arranged to ensure that measured
differences are attributable to protocol design and to nothing else.

## What is shared, and why

**`shared/pqsap_core/derive.py` — the fairness guarantee.** All three protocols
turn a shared secret into an Ethereum address through this one module. They
differ in how they *agree* a secret; they must not differ in what they do with
it. A protocol deriving addresses its own way would not be comparable, so the
canonical rules are fixed here once: keccak256, view tag = digest byte 0, tweak
scalar = same digest mod n, and rejection of both `h == 0` and `p == 0`.

**`shared/contracts/StealthAnnouncer.sol` — the control variable.** A faithful
port of ERC-5564's reference announcer, used by all three protocols.
`announce` takes `bytes` and is indifferent to whether it receives 33, 768 or
1088 of them, so any difference in per-payment cost is payload size and content
alone. Never forked per protocol.

**`shared/pqsap_core/testing.py` — one standard, three protocols.** Round trip,
foreign-announcement rejection, dual-key separation, shared address derivation.
Written once and called by each protocol's tests, because three hand-written
versions would drift and start testing different things under the same names.
`shared/contracts/RegistryBehaviour.t.sol` is its Solidity counterpart.

**`bench/` — one harness.** Never a benchmark per protocol. Separate harnesses
drift methodologically and the numbers stop being comparable.

## What differs, and why

Registries differ because they are what the study varies. Each protocol supplies
its own, but every one implements the same `registerKeys(uint256, bytes)` — 
byte-identical to ERC-6538's, with no length validation — so the only thing
differing between measurements is the payload.

| Contract | Protocol | Payload | Bytes |
|---|---|---|---|
| `ERC6538Registry` | P1 | `M_spend ‖ M_view` | 66 |
| `MLWERegistry` | P2 | `K_dilithium ‖ ek_V` | 5600 |
| `RegistryFull` (R1) | P3 | `M ‖ ek_view` | 1217 |
| `RegistryCommit` (R3) | P3 | `M ‖ keccak256(ek_view)` | 65 |

`AnnouncerMinLog` (A2) lives in `p3_hybrid/` rather than `shared/` because it is
an object of study, measured *against* the shared announcer rather than
replacing it.

## Scheme identifiers

| Protocol | Scheme id | Status |
|---|---|---|
| P1 | `1` | standardised by ERC-5564 (secp256k1) |
| P2 | `0x4D4C5745` ("MLWE") | **non-standard**, chosen here |
| P3 | `0x50513348` ("PQ3H") | **non-standard**, chosen here |

ERC-5564 registers only id 1, so the post-quantum schemes necessarily use
unregistered identifiers. This is stated in the methodology rather than glossed:
any real deployment would require standardisation first.

## Package layout

```
shared/
  pqsap_core/          derive, kem, scheme interface, chain access, test helpers
  contracts/           IStealthRegistry, IStealthAnnouncer, StealthAnnouncer
p1_erc5564/            scheme.py, ERC6538Registry.sol, reference vectors
p2_mlwe/               scheme.py, MLWERegistry.sol, NOTES.md (boundary statement)
p3_hybrid/             scheme.py, RegistryFull/RegistryCommit/AnnouncerMinLog, NOTES.md
bench/                 sizes, gas, scan, curves, anonymity, report, results/
docs/                  threat-model.md, architecture.md, testnet-setup.md
```

Underscores rather than hyphens, because `bench/` imports all three protocols
and `p1-erc5564` is not an importable Python identifier. The project installs as
one distribution mapping each directory to an import name, so those imports need
no `sys.path` manipulation. Dependency direction is one-way: protocols import
`pqsap_core`, `pqsap_core` imports no protocol, `bench` imports all.

## The P3 protocol

```
Sender:     (ct, S) = Encaps(ek_view)
            h, tag  = keccak256(S)
            P       = M + h*G
            announce(ct, addr(P), tag)

Recipient:  S      = Decaps(dk_view, ct)
            h, tag = keccak256(S)
            tag must match, then addr(M + h*G) must match
            p = (m + h) mod n
```

**The address check is mandatory.** FIPS 203 uses implicit rejection, so
`Decaps` never fails — a foreign ciphertext returns 32 pseudorandom bytes and
therefore a well-formed-looking tag. Measured over 20,000 foreign announcements,
77 passed the view tag against 78 expected for a uniform 8-bit filter. Every one
of those would have been wrongly accepted on the tag alone.

`scan` verifies as `addr(M + h*G)` rather than `addr(p*G)`. The two are the same
point, but only the first is computable from public spending material, which is
what lets `scan` take `ViewingKeys` and keeps the dual-key separation structural.

## Measurement methodology

Each charter pitfall and the mechanism that handles it:

| Pitfall | Handling |
|---|---|
| Gas units are deterministic; repetition measures nothing | Each sample uses a fresh keypair; payload *content* varies and the distribution is reported |
| First registration ≠ re-registration | Every registration sample uses a brand-new EOA, so all slots are cold |
| L1 data fee is the volatile part | L2 execution gas and L1 data fee are separate CSV columns, never summed |
| Foundry gas is not transaction gas | `forge test` figures are regression aids only; thesis numbers come from real receipts |
| Results must be auditable | Every row records commit, chain, block, seed, and a keccak digest of the exact bytes sent |
| secp256k1 timing depends on scalar size | Scan benchmarks use real 256-bit keys; a toy scalar understates P1 by 2.3× |

Two things are worth knowing before reading any announcement figure:

**EIP-7623 governs announcement cost.** Since Pectra a transaction pays at least
a floor derived from its calldata alone, and post-quantum announcements are
large and computationally trivial, so they sit exactly on that floor. Below it,
execution gas is free — which is why A2's minimal log saves 1.1% rather than the
third a pre-Pectra fee schedule would predict. Every result row records the
calldata token count, the implied floor, and whether the floor bound, so this is
auditable rather than asserted.

**Deployment cost is not comparable across registries.** P1's is a complete
ERC-6538 implementation with EIP-712 and EIP-1271 support; P2's and P3's are
minimal. Registration cost per user is comparable, because `registerKeys` is
byte-identical across all of them.

## Reproducing

```bash
uv run pytest && forge test
```

```bash
anvil &
forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast --private-key <anvil key>
uv run python -m bench.gas --network anvil --samples 20
```

Then `bench.scan`, `bench.curves`, `bench.anonymity`, and `bench.report`.
Testnet measurement needs credentials and funds; see
[testnet-setup.md](testnet-setup.md).
