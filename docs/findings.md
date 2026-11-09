# Findings so far

Consolidated from `bench/results/`, `p2_mlwe/NOTES.md` and `p3_hybrid/NOTES.md`.

**Status of these numbers.** Gas *units* are deterministic and were measured on
a local anvil running the same EVM version as the target testnets, so every
comparison below stands. What is not yet measured is the fee side — in
particular Base Sepolia's separate L1 data fee, which is the whole point of
deploying to both networks. Nothing here should be written up as an L1-versus-L2
result until that run happens.

Organised around what the charter expected, because the useful finding is
usually the gap.

---

## 1. The headline: registration is solved, and cheaply

Three registry designs, and the result is a **trade-off map rather than a
winner**.

| Registration | Payload | Gas | vs P1 | Readable by a contract |
|---|---|---|---|---|
| **P3 R2, emit-only** | 1217 B | **71,170** | **0.62×** | **nothing** |
| P1, ERC-6538 reference | 66 B | 115,316 | — | full |
| P3 R3, commitment | 65 B | 115,264 | 1.00× | M only |
| P3 R1, full meta-address | 1217 B | 941,744 | 8.17× | full |
| P2, MLWE SAP, Kyber512 | 5216 B | 3,788,933 | 32.86× | full |
| P2, MLWE SAP, Kyber768 | 5600 B | 4,064,437 | 35.25× | full |

P3 rows are at ML-KEM-768; R3 costs the same at both sets. P2 is the journal
construction (JCST 2026, Table 5): a 4416-byte Dilithium-structured spending key
alongside the Kyber viewing key, measured at both parameter sets. Gas and ratios
from `bench/results/report_anvil.md`, sections 3 and 4.

**Storing 65 bytes costs more than emitting 1217.** R3 registers nineteen times
fewer bytes than R2 and still costs 62% more, because cold `SSTORE` is 20,000
gas per slot and R2 performs none at all. Byte counts predict calldata cost;
they do not predict registration cost, and at these sizes storage dominates.

R2 lands **exactly on its EIP-7623 calldata floor** — 71,170 measured against a
71,170 floor. That makes it not merely cheapest but *optimal*: no registration
carrying that payload can cost less. R1, R3 and ERC-6538 all sit well above
their floors, in the execution-bound regime where storage is the cost.

What R2 gives up is total: **no contract can read a meta-address registered this
way.** For stealth addresses the reader is an off-chain sender, so the trade may
be cheap — but a paymaster, router, or any contract paying a stealth address
could not build on it. R3 keeps M readable for 62% more; R1 keeps everything
readable for 13×.

R2 was omitted from an earlier revision of the charter during scope trimming and
has been restored. Without it, R3's parity claim would have been reported as the
best available result when a cheaper design existed unmeasured.

The charter posed this as a hypothesis worth testing first: *if R3 lands at
parity with ERC-5564 registration, the registration penalty for post-quantum
unlinkability disappears entirely.* It does. R3 is 52 gas cheaper, because 65
bytes is one byte less than 66 and both occupy the same four storage slots.

Two consequences the charter did not anticipate:

**R3's cost is independent of the ML-KEM parameter set.** 115,264 gas at both
768 and 512, because a keccak commitment is 32 bytes regardless of what it
commits to. The security-versus-cost trade-off vanishes from registration
entirely — it survives only in the announcement.

**R3 needs no new contract.** `RegistryCommit` is byte-identical to
`RegistryFull`; the entire saving is in what the client chooses to register. Any
existing ERC-6538 deployment could serve R3 today without redeployment. That is
a deployability result, not merely a cost one, and it is arguably the most
practically useful thing in the study.

**The parity is an on-chain result, and must be stated as one.** The 1184-byte
encapsulation key did not disappear; it is served off-chain and verified against
the commitment before a sender may use it.

| | Registered on-chain | Fetched off-chain |
|---|---|---|
| R1 | 1217 B | — |
| R3 | 65 B | 1184 B, **per recipient** |

The trade stays favourable for three reasons worth stating together: the fetch
is per recipient rather than per payment so it caches; it is paid in a sender's
bandwidth rather than anyone's gas, against 826,480 gas saved permanently; and a
sender already reads the chain for a meta-address, so R3 adds a round trip
rather than a new class of work.

What it genuinely costs is **availability** — a directory that will not answer
blocks payments to that recipient, where R1's key is as available as Ethereum.
Integrity is fully protected by the commitment; a sender who skips the check is
the one who loses, and `test_a_sender_who_skips_verification_is_the_one_who_loses`
demonstrates exactly how.

---

## 2. The charter's announcement optimisation is refuted

**A2 saves 1.1%, not the predicted third — and EIP-7623 is why.**

The charter reasons that ERC-5564 pays for the payload twice: 16 gas/byte as
calldata and 8 gas/byte as log data, so removing the log should take roughly a
third off the recurring cost. **That was true before Pectra.**

EIP-7623 floors a transaction at 21,000 gas plus 10 gas per calldata token. A
post-quantum announcement is large and computationally trivial, so it sits
exactly on that floor:

| | Calldata tokens | EIP-7623 floor | Actual gas |
|---|---|---|---|
| A1 shared announcer | 4,673 | 67,730 | 67,730 |
| A2 minimal log | 4,600 | 67,000 | 67,000 |

Exact match. Below the floor, execution gas is free, so the ~9,984 gas of log
data A2 removes buys **nothing at all**. The 730 gas it does save decomposes
exactly to 73 fewer calldata tokens — an ABI artifact, since a `bytes1` view tag
needs no offset and length words. Not one gas of it comes from the log.

Every post-quantum announcement measured is floor-bound, at both parameter sets
under both announcers. P1's 33-byte announcement is not, which is why the
charter's model still describes ERC-5564 correctly and stops describing P3.

**This dates the literature.** Any pre-Pectra analysis of stealth-address costs
— including the charter's own model — is working from a fee schedule that no
longer applies. Worth stating explicitly, since it is a contribution in itself.

**What follows for the design.** Calldata size is the only remaining lever on
announcement cost. That makes the ML-KEM parameter set the decision that
matters: 768 → 512 saves 19% where A2 saves 1.1%.

---

## 3. A2 loses on the receiver side too, structurally

A2's minimal log carries the view tag but not the ciphertext. The recipient's
own tag is derived *from* the shared secret, which requires that ciphertext. So
**the tag in A2's log filters nothing** — every announcement must have its
transaction fetched regardless.

Measured: A2 costs one extra RPC round trip per announcement and more total
bytes than A1 (1,284 against 1,248), in exchange for 1.1% gas.

A2 stays in the thesis as a **measured negative result**: a well-motivated
optimisation, correctly implemented, that a protocol change outside this work
rendered pointless. Reporting that is more useful than quietly dropping it. It
retains one non-gas benefit worth a sentence — a 32-byte log against a
1,248-byte one is far less data for indexers and archive nodes to store.

---

## 4. The announcement penalty is much smaller than feared

The charter prepares for the honest possibility that *even fully optimised, P3
announcements may stay an order of magnitude above P1, making the protocol
viable on L2 but not L1.*

Measured, the gap is **2.39× on total transaction cost**, or 6.6× net of the
21,000 gas intrinsic cost. Not an order of magnitude in either framing.

The reason is instructive: byte ratios badly overstate gas ratios at these
sizes, because fixed costs dominate. P3's announcement payload is 33× P1's and
costs 2.4× the gas. Any cost argument made from byte counts alone will be wrong
in this direction.

Whether 2.4× is acceptable on L1 is a deployment judgement the fee measurements
will inform, but the framing has shifted from "probably L2-only" to "plausibly
viable on both".

---

## 5. The bottleneck moved

Payments before cumulative announcements overtake registration, net of intrinsic
cost:

| Variant | Register | Announce | Crossover |
|---|---|---|---|
| P1 ERC-5564 | 94,316 | 7,067 | 13.3 |
| P3 R1 + A1 (768) | 920,744 | 46,730 | 19.7 |
| **P3 R3 + A2 (768)** | **94,264** | **46,000** | **2.0** |
| P3 R3 + A2 (512) | 94,264 | 33,200 | 2.8 |

Under R1 a recipient pays a large one-off cost that announcements only overtake
after twenty payments. Under R3 the one-off cost is an ordinary ERC-5564
registration and announcements dominate after two.

**The cost of post-quantum unlinkability is now almost entirely recurring.**
That is the sentence the results chapter builds to, and it reframes what future
optimisation work should target.

Against the post-quantum state of the art, P2 at Kyber768, P3 R3+A2's
cumulative cost is 0.182M gas against 4.132M after one payment, 0.785M against
4.741M after ten, and 6.815M against 10.834M after a hundred
(`bench/results/report_anvil.md`, sections 1 and 5).

---

## 6. Q3 — cheaper to scan, dearer to store, but narrowly

| Protocol | Params | µs/announcement | Bytes/announcement |
|---|---|---|---|
| P1 ERC-5564 | secp256k1 | 30.71 | 224 |
| P3 hybrid | mlkem768 | 29.28 | 1,248 |
| P3 hybrid | mlkem512 | 23.31 | 928 |

The tension the charter predicted is real: P3 scans 1.05× faster while storing
5.6× the bytes. At ML-KEM-512 it is 1.35× faster.

**But the margin is far narrower than Mikić et al.'s "about 67%" (journal
§6.2), and the baselines differ.** Their figure is against ECPDKSAP, which is pairing-based and much
slower than the plain secp256k1 ECDH that ERC-5564 actually uses. The two
numbers are not comparable and should not be presented as though they were.

---

## 7. Q1 — the view-tag leak, quantified and closed

A quantum adversary with ECDLP broken and ML-KEM intact, against a **spent** P3
address. Under the **pre-fix design**, where P3's tag was ERC-5564's `h[0]`, the
anonymity set was 1 + Binomial(N−1, 2⁻⁸). P3 now domain-separates its tag —
`keccak256("pq-sap/p3/view-tag/v1" ‖ S)[0]`, with `h` unchanged — and the
adversary, who holds `h_j` but never `S`, cannot evaluate it:

| Registry size | h[0] tag (pre-fix): mean set | Uniquely identified | Domain-separated (deployed): set | Uniquely identified |
|---|---|---|---|---|
| 100 | 1.4 | **66.6%** | 100 | 0.0% |
| 1,000 | 4.9 | 1.8% | 1,000 | 0.0% |
| 10,000 | 39.9 | 0.0% | 10,000 | 0.0% |
| 1,000,000 | 3,906 | 0.0% | 1,000,000 | 0.0% |

For the pre-fix design, simulation agrees with the closed form within 10% at
every size, each checking the other.

The pre-fix leak scaled the right way: **dangerous precisely for a small
deployment**, negligible for a large one. Domain separation closes it at every
size without dropping the tag — the earlier mitigation, which would have cost an
elliptic-curve operation on every announcement during scanning rather than one
in 256. Only spent addresses were ever exposed, and P1 is unaffected and still
worse off, being fully broken against the same adversary. Argued analysis plus
simulation, not a proof; see `docs/threat-model.md`, Q1.

---

## 8. What we corrected in the charter

Recorded rather than silently applied, since the charter marks these settled and
changing them needs advisor sign-off. All four are in `p2_mlwe/NOTES.md`.

**Superseded by the journal version (2026-10-14).** The thesis now cites the
peer-reviewed journal version (JCST 2026, doi 10.1080/23742917.2025.2611820),
not the preprint. Consequences:

- **P2's construction changed.** The journal's spending key is an uncompressed
  Dilithium-structured key (4416 B), so the meta-address is 5600 B at Kyber768
  and 5216 B at Kyber512 (Table 5), not the preprint's 2368/1600. `p2_mlwe` now
  implements this, and every P2 figure in this document is measured on it:
  registration costs 4,064,437 gas at Kyber768 and 3,788,933 at Kyber512
  (`bench/results/report_anvil.md`, section 3).
- **P2's parameter set.** The paper's primary instantiation is Kyber512 with
  Dilithium level 3. Both Kyber512 and Kyber768 are measured.
- **The 67% figure.** The journal reports "approximately 67%" against
  ECPDKSAP, which its §6.2 identifies as the Curvy protocol. Resolved.
- **"Not Ethereum-friendly."** That sentence is in the preprint (§6.2) — an
  earlier note here wrongly said it was absent — but it does not appear in the
  journal. Cite the journal's statements on the Dilithium precompile and the
  ECDSA-bound address scheme (§4.7, §5.5) instead.

**The ~31-payment crossover estimate.** Measured at 19.7 for R1+A1, because the
charter's ~26k per announcement counted calldata and log bytes only, omitting
memory expansion, log topics and ABI framing.

---

## 9. Methodological findings worth reporting

These belong in the methodology chapter, not buried in code comments. Each one
would have corrupted a result silently.

**secp256k1 timing depends on scalar size.** libsecp256k1's scalar
multiplication here is not constant-time in the scalar: a convenient small
integer costs 10.9 µs where a random 256-bit viewing key costs 25.2 µs.
Benchmarking P1 with a toy scalar understates it by more than half and would
have **inverted the Q3 conclusion**.

**Content-dependent gas is real, not theoretical.** One R3 registration in
twenty came in 20,000 gas cheaper — its payload's last byte was zero, so the
final storage word was all zeros and Solidity skipped a cold `SSTORE`.
Probability 1/256. This is the charter's pitfall made concrete and the argument
for both of its rules at once: sample at least twenty distinct keypairs, and
report the median rather than the mean.

**The round-3 Kyber substitution hazard is live.** This liboqs build genuinely
offers `Kyber768` alongside `ML-KEM-768` — identical sizes, different output. A
one-word slip would have produced plausible, wrong, undetectable results. Closed
by asserting liboqs reports `FIPS203` and by interoperating with an independent
pure-Python implementation in both directions.

**FIPS 203 implicit rejection, measured.** Under the **pre-fix** `h[0]` tag, 77
of 20,000 foreign announcements passed the view tag against 78 expected for a
uniform 8-bit filter. That count came from an inline script during the P3 spike
(2026-08-07) that was never committed, so it cannot be re-run as it stood. Under
the deployed domain-separated tag, `bench.scan` counts 30 of 7,980 foreign
announcements passing against 31.2 expected: its four P3 configurations make 12,
13, 10 and 15 address checks, five of each for the planted payments
(`bench/results/scan.csv`, measured at 84e512b). Every one of them would have
been wrongly accepted on the tag alone. Direct evidence that the mandatory
address check is load-bearing rather than defensive.

**ML-KEM key generation is reproducible.** liboqs 0.16 exposes derandomised
keygen, so every benchmark keypair regenerates exactly from the seed recorded in
its result row. Encapsulation is not seeded, which is why announcement bytes are
pinned by digest instead.

---

## 10. What is genuinely new

For the contribution section, stated conservatively:

1. **The first on-chain gas measurement of any post-quantum stealth address
   protocol.** The charter's positioning review found none in the literature.
2. **EIP-7623's effect on post-quantum stealth-address economics.** Announcements
   are calldata-floor-bound, which invalidates log-minimisation as a lever and
   dates every pre-Pectra cost model.
3. **A commitment-based registry reaching parity with ERC-5564**, requiring no
   contract change.
4. **A quantified analysis of the view-tag leak** against a quantum adversary for
   a hybrid construction, and a domain-separated tag that closes it without
   changing the announcement size or the scan's hash count — argued analysis
   plus simulation, explicitly not a formal proof.
5. **A concrete demonstration that MLWE SAP cannot complete an EVM payment**,
   rather than a citation of the claim.

---

## Still open

- **Fee measurements on both testnets.** Everything above is gas units. The L1
  data fee on Base Sepolia, and how post-Fjord compression treats pseudorandom
  ciphertexts, is unmeasured.
- **The four charter corrections**, pending advisor sign-off.
- **Scan comparison against Mikić's published figures**, which needs their
  parameter set and tag width confirmed first.
