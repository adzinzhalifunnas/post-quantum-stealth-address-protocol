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

## 1. The headline: registration is solved

**R3 reaches parity with ERC-5564, and marginally beats it.**

| Registration | Payload | Gas | vs P1 |
|---|---|---|---|
| P1, ERC-6538 reference | 66 B | 115,316 | — |
| **P3 R3, commitment** | **65 B** | **115,264** | **1.00×** |
| P3 R1, full meta-address | 1217 B | 941,744 | 8.17× |
| P2, two lattice keys | 2368 B | 1,745,670 | 15.14× |

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

The price is one added assumption: `ek_view` is served off-chain and the sender
must verify it against the on-chain commitment before encapsulating. Skipping
that check lets whoever serves the key substitute their own and read every
payment.

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

Against the post-quantum state of the art, P3 R3+A2 saves 89.9% at one payment
and 20.0% at a hundred.

---

## 6. Q3 — cheaper to scan, dearer to store, but narrowly

| Protocol | Params | µs/announcement | Bytes/announcement |
|---|---|---|---|
| P1 ERC-5564 | secp256k1 | 30.71 | 224 |
| P3 hybrid | mlkem768 | 29.28 | 1,248 |
| P3 hybrid | mlkem512 | 23.31 | 928 |

The tension the charter predicted is real: P3 scans 1.05× faster while storing
5.6× the bytes. At ML-KEM-512 it is 1.35× faster.

**But the margin is far narrower than Mikić et al.'s 66.8%, and the baselines
differ.** Their figure is against ECPDKSAP, which is pairing-based and much
slower than the plain secp256k1 ECDH that ERC-5564 actually uses. The two
numbers are not comparable and should not be presented as though they were.

---

## 7. Q1 — the view-tag leak, quantified

A quantum adversary with ECDLP broken and ML-KEM intact, against a **spent** P3
address. Anonymity set = 1 + Binomial(N−1, 2⁻⁸):

| Registry size | Mean set | Uniquely identified |
|---|---|---|
| 100 | 1.4 | **66.6%** |
| 1,000 | 4.9 | 1.8% |
| 10,000 | 39.9 | 0.0% |
| 1,000,000 | 3,906 | 0.0% |

Simulation agrees with the closed form within 10% at every size, each checking
the other.

The leak scales the right way: **dangerous precisely for a small deployment**,
negligible for a large one. Three qualifications belong with any statement of
it — only spent addresses leak; P1 is worse off, not better, being fully broken
against the same adversary; and removing the tag closes the leak at the cost of
an elliptic-curve operation on every announcement rather than one in 256.

---

## 8. What we corrected in the charter

Recorded rather than silently applied, since the charter marks these settled and
changing them needs advisor sign-off. All four are in `p2_mlwe/NOTES.md`.

**P2's parameter set.** The paper's own experiments use Kyber512 (NIST level 1),
not the ML-KEM-768 the charter assumes. Both are now measured: 768 for a
level-matched comparison against P3, 512 to reproduce the published protocol.
Comparing P2 at level 1 against P3 at level 3 would attribute a security
difference to a design difference.

**The 66.8% attribution.** The abstract credits it to ECPDKSAP; the charter
credits it to Curvy. Unresolved — do not cite until checked against the paper's
own definitions.

**The "not Ethereum-friendly" claim.** Does not appear in arXiv:2501.13733. May
belong to the companion paper arXiv:2504.06744. Locate the exact sentence before
citing.

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

**FIPS 203 implicit rejection, measured.** Over 20,000 foreign announcements, 77
passed the view tag against 78 expected for a uniform 8-bit filter. All 77 would
have been wrongly accepted on the tag alone. Direct evidence that the mandatory
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
   a hybrid construction — argued analysis plus simulation, explicitly not a
   formal proof.
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
