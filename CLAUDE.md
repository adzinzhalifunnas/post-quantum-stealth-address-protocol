# PQ-SAP — EVM-compatible post-quantum stealth address protocol

Master's thesis PoC (Adzin Zhalifunnas, BINUS Graduate Program; advisor
Dr. Richard; Design Science Research). Thesis prose is Indonesian; code,
comments, commits in English.

Working title: "An EVM-Compatible Post-Quantum Stealth Address Protocol:
On-Chain Cost Optimization on Ethereum Layer 1 and Layer 2." Final title
waits on measurement — decide which lever actually dominates first.

## Positioning (verified Aug 2026 — don't re-litigate, do keep watching)

- Mikić et al., **JCST 2026** (doi 10.1080/23742917.2025.2611820) — the
  version we cite; the preprint arXiv 2501.13733 is superseded. MLWE SAP with
  a Kyber viewing key and a Dilithium-structured spending key. The authors
  state that Ethereum deployment needs a Dilithium verification precompile and
  a PQ address format, since Ethereum addresses are tied to ECDSA (§4.7,
  §5.5). They quantify the on-chain footprint in **bytes only** (§6.5,
  Table 5), never in gas. `0x3327/pq-sap` is Rust-only; their ECC repo ships
  Foundry contracts. The EVM side is genuinely unbuilt.
- Same authors, arXiv 2504.06744 (Apr 2025): Ethereum-friendly hybrid that
  **gives up quantum security** — MLWE for scan speed only. Closest prior
  work; cite and distinguish.
- asanso, ethresear.ch (2023): CSIDH isogeny PQ stealth addresses. Sage
  only, no EVM, different primitive family. Cite as prior art.
- No on-chain gas measurement of any PQ-SAP exists in the literature.

Our point in the design space — quantum-resistant *unlinkability* on
unmodified EVM — is unoccupied. These authors publish every few months.

## Scope decisions (settled; changing any needs advisor sign-off)

- **Unlinkability is PQ; custody stays ECDSA.** Stealth addresses are
  secp256k1 EOAs — same exposure as every Ethereum account today, not a
  regression. Harvest-now-decrypt-later lives in the announcement metadata,
  permanently public and never re-encryptable (ethresear.ch, "Post-Quantum
  Threats to Ethereum Privacy", 2026). No ERC-4337, no on-chain PQ
  signature verification.
- **No EIP-4844 blobs.** Contracts cannot originate transactions, so they
  can never attach one; OP Stack rejects type-3 outright. Blobs appear in
  the thesis as feasibility analysis only.
- **No ML-KEM/Kyber arithmetic in Solidity, ever.** Contracts store bytes,
  hash, emit events. All lattice work is off-chain Python. If a task
  appears to need on-chain lattice math, the design is wrong — say so.

## Three protocols — the spine of the experiment

| | Protocol | Nature | Role |
|---|---|---|---|
| P1 | ERC-5564 / DKSAP | ECC, secp256k1 | current standard |
| P2 | MLWE SAP (Mikić et al.) | full PQ | PQ state of the art |
| P3 | Our hybrid | PQ unlinkability + ECDSA custody | **the artifact** |

Chapter IV narrates P1 → P2 → P3-naive → P3-optimised. Registry and
announcement optimisations are variants *inside* P3, not a separate axis of
equal standing.

Meta-address sizes drive the whole cost story:

| | Composition | Bytes | Announcement |
|---|---|---|---|
| P1 | M_spend ‖ M_view (33+33) | 66 | 33 B ephemeral pubkey |
| P2 | K_dilithium ‖ ek_V (4416+1184) | 5600 | 1088 B ciphertext |
| P3 | M ‖ ek_view (33+1184) | 1217 | 1088 B ciphertext |

P2's spending key is an uncompressed Dilithium-structured key, 4416 bytes at
NIST level 3 (journal §6.5, Table 5). P3 drops it entirely, since spending
stays secp256k1 — roughly **78% smaller before any registry optimisation**. P2 and P3 announcements are
identical in size, so P3's entire advantage lives in registration. That is
why the registry variant is the artifact.

### P2 is data-plane only — this is a result, not a shortcut

Mikić's stealth key (journal §5.4–5.5) is a Dilithium-structured lattice key
`t' = A·(s + k') + e'` whose private key is a Dilithium private key. That is
not an Ethereum address and cannot sign an EVM transaction; the authors
themselves say Ethereum deployment needs a Dilithium precompile and a PQ
address format. End-to-end payment **cannot** be completed for P2, and
demonstrating that concretely is a finding — better evidence than quoting
their claim.

**Do not port their polynomial arithmetic.** liboqs exposes only the KEM
interface; computing their `P` needs full R_q arithmetic with NTT and would
consume weeks. It is unnecessary because `P` never goes on-chain — the
recipient computes it locally. To measure gas you need only correct sizes
and encoding: real Kyber viewing keys from liboqs, a 4416-byte
uncompressed Dilithium-structured spending key, meta-address `K ‖ ek_V`,
announcement of ciphertext + view tag. For off-chain scan performance, cite
their published figures. State this boundary explicitly in the methodology:
we implement their data plane to measure its EVM cost, not the full
protocol. Put it in `p2_mlwe/NOTES.md` too.

## Repo layout

```
pq-sap/
├── CLAUDE.md  foundry.toml  pyproject.toml  .env.example
├── shared/                      # fairness guarantees — never fork these
│   ├── contracts/
│   │   ├── IStealthRegistry.sol
│   │   ├── IStealthAnnouncer.sol
│   │   └── StealthAnnouncer.sol       used by all three protocols
│   └── pqsap_core/
│       ├── scheme.py                  abstract keygen/announce/scan/recover
│       ├── derive.py                  keccak256, p=(m+h) mod n, addr(P)
│       └── chain.py                   web3 bindings, both networks
├── p1_erc5564/
│   ├── contracts/ERC6538Registry.sol  port the reference impl
│   ├── scheme.py  tests/
├── p2_mlwe/
│   ├── contracts/MLWERegistry.sol     5600-byte meta-address
│   ├── scheme.py  tests/  NOTES.md
├── p3_hybrid/
│   ├── contracts/
│   │   ├── RegistryFull.sol           R1 naive
│   │   ├── RegistryEvent.sol          R2 — emit-only, no storage
│   │   ├── RegistryCommit.sol         R3 — the optimisation
│   │   └── AnnouncerMinLog.sol        A2 — recurring-cost optimisation
│   ├── scheme.py  tests/
├── bench/                       # ONE harness for all three
│   ├── sizes.py  gas.py  scan.py
│   ├── curves.py                      cumulative curves — the headline
│   ├── anonymity.py  report.py  results/
└── docs/threat-model.md  architecture.md
```

Underscores, not hyphens — `p1-erc5564` is not an importable Python
identifier and `bench/` must import all three schemes.

**What must stay shared, and why.** Every protocol imports `derive.py` and
implements `scheme.py`; that is what forces identical address derivation.
`StealthAnnouncer` is shared because `announce()` takes `bytes` and does
not care whether the payload is 33, 768, or 1088 bytes — it is the control
variable. Registries differ because they are what we study.
`AnnouncerMinLog` lives inside P3 because it is itself an object of study,
measured against the shared announcer. **Never give a protocol its own
benchmark harness** — separate harnesses drift methodologically and the
numbers stop being comparable.

Foundry needs `src = "."`, `test = "."` to compile across folders. If that
gets slow later, split into per-protocol profiles.

## P3 — implement exactly this

Recipient holds secp256k1 spending pair (m, M = mG) and an ML-KEM pair
(dk_view, ek_view).

    Sender:     (ct, S) = Encaps(ek_view)
                h = keccak256(S);  P = M + h*G
                tag = keccak256("pq-sap/p3/view-tag/v1" ‖ S)[0]
                announce(ct, addr(P), tag)

    Recipient:  for each announcement:
                  S_i = Decaps(dk_view, ct_i)      # never fails, see below
                  if keccak256("pq-sap/p3/view-tag/v1" ‖ S_i)[0] != tag_i: continue
                  h_i = keccak256(S_i)
                  p = (m + h_i) mod n
                  if addr(p*G) != announced_addr: continue   # MANDATORY
                  -> match

**The view tag is domain-separated from h — P3 only.** An earlier revision
used `tag = h[0]`, ERC-5564's rule. That is exactly the Q1 leak: a quantum
adversary who takes `h_j = dlog(P − M_j)` from a spent address can evaluate
`h_j[0]` for every registrant and filter the anonymity set to ~N/256. A tag
hashed from `S` under its own domain cannot be evaluated from `h_j`, so the
anonymity set stays N. `h`, `P` and the one-byte tag size are unchanged, and
scanning still costs one hash per announcement. P1 keeps the ERC-5564 rule
(tag = byte 0 of the h digest); P2 is unchanged. `derive.h_scalar_and_tag` is
untouched; the P3 tag comes from `derive.domain_separated_view_tag`. Analysis
and both designs' numbers: `docs/threat-model.md`, Q1.

**The final address check is not optional.** FIPS 203 uses implicit
rejection: Decaps never errors — on a foreign ciphertext it returns 32
pseudorandom bytes. The view tag is therefore the only prior filter and it
is probabilistic: ~1 in 256 of other people's announcements passes, and the
p derived from those is a garbage key controlling nothing.

Reject p == 0 (negligible, still check). keccak256, not SHA-256. Pick and
document an unused ERC-5564 schemeId (1 is secp256k1); note in the thesis
that the id is non-standard.

**Invariant that must hold and must be tested** (applies to P1, P2, P3): a
third party holding the viewing key alone can enumerate every stealth
address but cannot spend from any. This dual-key separation is the
regulatory feature both ERC-5564 and Mikić et al. emphasise. Anyone
"simplifying" to a single keypair breaks it.

## P3 optimisation variants

**Registry (paid once).** Three variants, and the finding is a trade-off map
across cost and on-chain readability rather than a single winner.

R1 stores the full 1217-byte meta-address (~40 slots). R2 emits it as an event
and stores nothing. R3 stores M plus `keccak256(ek_view)` (~4 slots), with
ek_view served off-chain and verified against the commitment.

**R2 was dropped from an earlier revision of this charter during scope trimming.
That was a mistake and it is restored here.** It is the obvious alternative an
examiner raises, and R3's claim of ERC-5564 parity is not defensible without a
measured intermediate. It also turns out to be the cheapest of the three, so
omitting it would have meant reporting a winner that had not been raced.

What each gives up, measured:

| | Registration | Readable by a contract | Availability |
|---|---|---|---|
| R1 | 941,744 | full meta-address | as available as Ethereum |
| **R2** | **71,170** | **nothing** | as available as Ethereum |
| R3 | 115,264 | M only | depends on an off-chain directory |
| P1 ERC-6538 | 115,316 | full meta-address | as available as Ethereum |

Two results worth carrying into the write-up. **Storing 65 bytes costs more
than emitting 1217**, because cold `SSTORE` dominates and R2 performs none.
And R2 lands exactly on its EIP-7623 calldata floor, so it is the cheapest any
registration of that payload can be — while R1, R3 and ERC-6538 all sit well
above their floors, in the execution-bound regime where storage is the cost.

Note the hypothesis worth testing first: P1 registration is also ~4 slots
(66 bytes). **If R3 lands at parity with ERC-5564 registration, the
registration penalty for post-quantum unlinkability disappears entirely** —
and the remaining cost gap is purely the announcement. That would make
axis 2 the headline lever, not axis 1.

**Announcement (paid every payment).** ERC-5564 pays for the payload twice:
16 gas/byte as calldata *and* 8 gas/byte as log data.

- A1 = shared `StealthAnnouncer`, ERC-5564 standard.
- A2 = `AnnouncerMinLog`: full payload in calldata, **minimal log** (stealth
  address + tag only). Indexers still work — the small log says which
  transaction to fetch, the recipient reads ct from its input. Expect
  roughly a third off the recurring cost; measure the added scan complexity
  honestly.

Cross both with the **ML-KEM parameter set**: ML-KEM-512 ciphertext ~768 B
against ~1088 B for ML-KEM-768 (verify against FIPS 203) — around 29%
cheaper per announcement, trading NIST category 3 for category 1. Explicit
security-vs-cost trade-off; belongs in the results. Do not attempt
compression: Kyber ciphertexts are pseudorandom and incompressible.

## Open questions — quantify, don't assume

**Q1 — view tag leaks under a quantum adversary. Closed by domain
separation; the pre-fix analysis stays as the comparison.** Once a P3
stealth address *spends*, its ECDSA signature reveals P. A quantum
adversary (ECDLP broken, ML-KEM intact) computes h_j = dlog(P − M_j) for
every registered M_j. Every candidate yields *a* valid dlog, so with no view
tag they learn nothing. Under the **pre-fix design**, tag = h[0], the
adversary can evaluate every candidate's tag, and a t-bit tag filters to
~1 + (N−1)/2^t: at N = 100 and 8 bits, 66.6% of spent addresses are
uniquely identified (`bench/results/anonymity.csv`). **The deployed tag
closes it:** keccak256("pq-sap/p3/view-tag/v1" ‖ S)[0] is a function of S
alone, which the adversary never holds, so the anonymity set stays N.
Unspent addresses were always fully unlinkable. The leak was specific to
P3 — P2 does not have it, since its stealth key is also lattice.
Unanalysed in the literature. **Bounded scope:** argued analysis plus a
simple numerical simulation of anonymity-set size, under both designs. Not
a formal proof — that would eat the implementation budget. Numbers and
qualifications: `docs/threat-model.md`, Q1.

**Q2 — where does cost live, and when does it move?** Registration is the
largest single cost but announcements recur. Excluding the 21k base tx:
R1 ~800k once against ~26k per payment (A1, ML-KEM-768) — cumulative
announcements overtake R1 after roughly 31 payments, and overtake R3 almost
immediately. **Report cumulative cost curves against payment count, not
per-operation gas.** That curve is the result: where the design wins, where
it doesn't, where the bottleneck migrates.

**Q3 — scan speed against storage cost.** Mikić et al. (journal §6.2) found
MLWE SAP about 67% faster to scan than ECPDKSAP (the Curvy protocol), with
Kyber512 + Dilithium. If ML-KEM decapsulation really beats secp256k1
ECDH per announcement, PQ is *cheaper to scan but dearer to store*. Measure
both directions; that tension is the headline finding.

Be prepared for the honest conclusion: even fully optimised, P3
announcements may stay an order of magnitude above P1, making the protocol
viable on L2 but not L1. Legitimate and publishable. Do not tune the design
to avoid it.

## Measurement pitfalls — these corrupt results silently

- **Gas units are deterministic.** Repeating an identical call 20 times
  measures nothing. Vary the *seed*: lattice outputs are pseudorandom and
  zero bytes cost 4 gas in calldata against 16 for non-zero, so payload
  content genuinely shifts cost. Sample ≥20 distinct keypairs and report
  the distribution.
- **First registration ≠ re-registration.** Cold zero→non-zero SSTORE is
  20k; overwriting a warm non-zero slot is far less. Always measure fresh
  registrations on fresh addresses and say so.
- **L1 data fee is the volatile part, not gas units.** Medians apply to the
  fee. Report L2 execution gas and L1 data fee as separate columns.
- **Stealth addresses start empty.** They need funding before spending, and
  the funding path can itself create linkage — a known ERC-5564 limitation.
  Document it; don't solve it. In tests verify signing via ecrecover rather
  than broadcasting.

## Stack and targets

Foundry, not Hardhat. Python 3.11+; Kyber/ML-KEM via liboqs-python
(pinned) or pqcrypto; coincurve for secp256k1; web3.py. Deploy identical
bytecode to **both** Ethereum Sepolia and Base Sepolia: gas units will
match, L1 data fee will not — that difference is a finding, not noise.
Testnet only; never broadcast to a mainnet RPC. Secrets in .env
(gitignored), .env.example committed. Solidity: NatSpec on externals,
custom errors. Python: typed, ruff + black, pytest.

## Order of work — risk first

1. **`shared/pqsap_core` + P3 round-trip spike, pure Python, no chain.**
   Encaps → S → valid secp256k1 key; recipient independently derives the
   same address, signs a message, ecrecover returns that address. Include
   the false-positive path: feed a foreign ciphertext whose tag collides
   and confirm the address check rejects it. Nobody has built this —
   nothing else starts until it passes.
2. P1 scheme against published ERC-5564 test vectors.
3. P2 data plane — sizes and encoding only, per the boundary above.
4. Registries + shared announcer → deploy → measure. Test Q2.
5. R3, A2, then the ML-KEM-512/768 sweep.
6. Full harness across both networks; cumulative cost curves.

## Integrity — these numbers go in a thesis

Every run emits CSV: git commit, chain id, block number, protocol, variant,
parameter set, seed, payload bytes, gas used, L1 fee, timestamp.
`bench/results/` is committed and never hand-edited; a surprising number
means re-run and investigate, never adjust. Measure receiver scan cost too
— decapsulation count, wall-clock, bandwidth. Verify all sizes against
FIPS 203 rather than trusting figures in this file; several estimates here
were derived from first principles and have already needed correction.
Never invent a number, a gas estimate, or a citation; unknown means say
unknown. Fabricated numbers in a thesis are academic misconduct. Never
change the protocol design to flatter a benchmark.
