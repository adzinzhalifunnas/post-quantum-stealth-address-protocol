# P3 — measured results for the optimisation variants

Figures from `bench/results/gas_anvil.csv`, 20 fresh keypairs and 20 fresh EOAs
per variant. Gas units are deterministic, so these reproduce on any chain
running the same EVM version; only the fee columns await the testnets.

## R3 reaches parity with ERC-5564, and slightly beats it

The charter's hypothesis was that if R3 lands at parity with ERC-5564
registration, the registration penalty for post-quantum unlinkability
disappears. **It does.**

| Registration | Payload | Gas |
|---|---|---|
| P1, ERC-6538 reference | 66 B | 115,316 |
| **P3 R3, commitment** | **65 B** | **115,264** |
| P3 R1, full meta-address | 1217 B | 941,744 |
| P2, two lattice keys | 2368 B | 1,745,670 |

R3 is 52 gas *cheaper* than an ordinary ERC-5564 registration — not
approximately equal, marginally better, because 65 bytes is one byte less than
66. Registering a post-quantum viewing key costs what registering an ECC one
costs. Against R1 the saving is 87.7%.

Two further points worth making in the thesis:

**R3's cost is independent of the ML-KEM parameter set.** 115,264 gas at both
ML-KEM-768 and ML-KEM-512, because a keccak commitment is 32 bytes regardless of
what it commits to. The security-versus-cost trade-off that the parameter sweep
exists to explore simply vanishes from registration.

**R3 needs no new contract.** `RegistryCommit` is byte-identical to
`RegistryFull`; the entire saving is in what the client chooses to register. Any
existing ERC-6538 deployment could serve R3 today without redeployment. That is
a deployability result, not merely a cost one.

### An outlier that justifies the sampling rule

One R3 sample in twenty registered for 95,340 gas instead of 115,264 — almost
exactly one cold `SSTORE` less. It is not noise, and it is not an error.

R3's payload is 65 bytes, so Solidity stores it as a length slot plus three data
words, the third holding a single meaningful byte and 31 bytes of zero padding.
When that byte is itself zero the whole word is zero, Solidity writes zero to an
already-zero slot, and the 20,000-gas cold write never happens. Byte 64 is the
last byte of `keccak256(ek_view)`, so this occurs with probability 1/256 —
consistent with seeing it once in twenty samples.

This is the charter's "payload content genuinely shifts cost" pitfall made
concrete, and it is the argument for its two rules in one observation: sample at
least twenty distinct keypairs, and report the median rather than the mean. A
single measurement had a 1-in-256 chance of reporting a registration cost 17%
below the truth, and a mean over twenty would have been dragged 1,000 gas low by
this one draw.

The security cost is one added assumption: `ek_view` is served off-chain and the
sender must verify it against the on-chain commitment before encapsulating.
`P3Hybrid.verify_commitment` does this, and `test_commitment_rejects_a_substituted_key`
demonstrates what happens to a sender who skips it — whoever serves the key
could otherwise substitute their own and read every payment.

## A2 does almost nothing, and the reason is EIP-7623

The charter expects A2 — full ciphertext in calldata, minimal log — to take
"roughly a third off the recurring cost", reasoning that ERC-5564 pays for the
payload twice, at 16 gas/byte as calldata and 8 gas/byte as log data.

Measured, A2 saves **730 gas of 67,730: 1.1%.**

That reasoning was correct before Pectra. **EIP-7623 changed it.** A transaction
now pays at least a floor set by its calldata alone — one token per zero byte,
four per non-zero byte, 21,000 gas plus 10 gas per token — and below that floor,
execution gas is effectively free. Post-quantum announcements are large and
computationally trivial, so they sit exactly on that floor:

| | Calldata tokens | EIP-7623 floor | Actual gas |
|---|---|---|---|
| A1 shared announcer | 4,673 | 67,730 | 67,730 |
| A2 minimal log | 4,600 | 67,000 | 67,000 |

The match is exact, and the 730-gas difference decomposes exactly too: 73 fewer
tokens × 10 gas. **None of it comes from removing the log.** The ~9,984 gas of
log data A2 eliminates is absorbed entirely by the floor. A2's saving is an ABI
artifact — a `bytes1` view tag needs no offset and length words, unlike ERC-5564's
dynamic `bytes` metadata — and would be obtained just as well by keeping the log
and tightening the signature.

Every post-quantum announcement measured here is floor-bound, at both parameter
sets and under both announcers. P1's 33-byte announcement is not: at 28,067 gas
it sits above its own floor, which is why the charter's model still describes
ERC-5564 correctly and stops describing P3.

### What follows for the design

**Calldata is the only lever on announcement cost.** Anything that reduces
execution gas — smaller logs, cheaper storage, tighter code — is invisible while
the floor binds. This reframes the recurring-cost story entirely:

- The ML-KEM parameter set is the real lever. 768 → 512 takes an announcement
  from 67,730 to 54,930, a 19% saving, against A2's 1.1%. That is a genuine
  security-versus-cost trade-off, NIST category 3 against category 1, and it is
  now the only announcement-side decision that matters.
- Compression is not an option and never was: Kyber ciphertexts are
  pseudorandom and incompressible. Post-Fjord L2 L1-fee estimation compresses
  too, and gets nothing, so the same conclusion holds on L2.

**A2 should stay in the thesis as a measured negative result.** It is a
well-motivated optimisation, correctly implemented, that a protocol change
outside this work rendered nearly pointless. Reporting that is more useful than
quietly dropping it, and it dates the result: anyone reading pre-Pectra
literature on stealth-address costs — including the charter's own model — is
working from a fee schedule that no longer applies.

A2 does retain a non-gas benefit worth one sentence: a 32-byte log instead of a
1,248-byte one is roughly 39× less data for every indexer and archive node to
store and serve. That is real infrastructure cost, just not gas.

## Crossover, and where the bottleneck moved

Net of the 21,000 gas intrinsic cost, payments before cumulative announcements
overtake registration:

| Variant | Register | Announce | Crossover |
|---|---|---|---|
| P1 ERC-5564 | 94,316 | 7,067 | 13.3 |
| P3 R1 + A1 (768) | 920,744 | 46,730 | 19.7 |
| **P3 R3 + A2 (768)** | **94,264** | **46,000** | **2.0** |
| P3 R3 + A2 (512) | 94,264 | 33,200 | 2.8 |

R3 moves the bottleneck decisively. Under R1 a recipient pays a large one-off
cost and announcements only overtake it after twenty payments; under R3 the
one-off cost is an ordinary ERC-5564 registration and announcements dominate
after two. **The cost of post-quantum unlinkability is now almost entirely
recurring**, which is the honest headline: registration is solved, and what
remains is a per-payment premium of roughly 6.5× over ERC-5564 net of intrinsic
cost, or 2.4× on total transaction cost.

Whether that premium is acceptable is a deployment question the L1-versus-L2
measurements will inform, and it is where the remaining work should go.
