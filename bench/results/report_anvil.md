# PQ-SAP measurement report — anvil

Generated from `bench/results/` at commit `b3dad62fcd22`. Every figure traces to a CSV row; nothing here is recomputed or adjusted.

> **These are local-chain measurements.** Gas *units* are deterministic and will reproduce on any chain running the same EVM version, so the comparisons below stand. Fee columns — and in particular Base Sepolia's separate L1 data fee — require the testnet runs and are not yet filled in.

## Provenance

- Measured on: `anvil` (chain state recorded per row)
- **Measured at commit:** `8483324d024b`
- liboqs: 0.16.0 via liboqs-python 0.16.0
- solc 0.8.28, optimizer runs 200
- Machine: macOS-26.5.2-arm64-arm-64bit, Python 3.12.11
- Samples per target: 20
- Measurement timestamp: 2026-11-09T13:11:53.909848+00:00
- ⚠️ The working tree has moved on since these numbers were taken. Re-run `bench.gas` before quoting them if any contract changed.

## 1. The three protocols, head to head

P2 and P3 are both shown at ML-KEM-768, so a security-level difference is never mistaken for a design difference. P3 appears twice because the optimisation is the artifact.

| | P1 ERC-5564 | P2 MLWE | P3 R1+A1 (naive) | P3 R2+A2 (emit-only) | P3 R3+A2 (commitment) |
|---|---|---|---|---|---|
| **Meta-address registered** | 66 B | 5,600 B | 1,217 B | 1,217 B | 65 B |
| Where it lives | storage | storage | storage | logs | storage + off-chain |
| Readable by a contract | full | full | full | **nothing** | M only |
| Fetched off-chain, per recipient | — | — | — | — | 1,184 B |
| **Announcement payload** | 33 B | 1,088 B | 1,088 B | 1,088 B | 1,088 B |
| **Registration gas** | 115,316 | 4,064,437 | 941,744 | 71,170 | 115,264 |
| **Announcement gas** | 28,067 | 67,700 | 67,760 | 67,000 | 67,000 |
| Cumulative at k=1 | 0.143M | 4.132M | 1.010M | 0.138M | 0.182M |
| Cumulative at k=10 | 0.396M | 4.741M | 1.619M | 0.741M | 0.785M |
| Cumulative at k=100 | 2.922M | 10.834M | 7.718M | 6.771M | 6.815M |
| Crossover (payments) | 13.3 | 86.6 | 19.7 | 1.1 | 2.0 |
| Scan time per announcement | 30.71 µs | 28.23 µs | 29.28 µs | 28.20 µs | 28.20 µs |
| Scan bytes per announcement | 224 B | 1,248 B | 1,248 B | 1,284 B | 1,284 B |
| Scan RPC round trips | 0 | 0 | 0 | 1 | 1 |

**Registry trade-off map**, at ML-KEM-768. Cost is one axis; what a contract can read back is the other. Ranking by gas alone would end the discussion at R2, which is exactly the design that gives up the most.

| Registry | Registration gas | Data lives in | Contract-readable | Availability | Gives up |
|---|---|---|---|---|---|
| erc6538 | 115,316 | storage | full | as available as Ethereum | nothing — the standard |
| R1 | 941,744 | storage | full | as available as Ethereum | nothing — pays for it |
| R2 | 71,170 | logs | **nothing** | as available as Ethereum | all on-chain readability |
| R3 | 115,264 | storage + off-chain | M only | **depends on a directory** | key availability |

R3's registration parity is an *on-chain* result. The 1,184-byte encapsulation key did not disappear — it is served off-chain and verified against the on-chain commitment before a sender may use it. That fetch is per recipient rather than per payment, so it caches, and it is paid in a sender's bandwidth rather than in anyone's gas. The cost it does carry is availability: a directory that will not answer blocks payments to that recipient, where R1's key is as available as Ethereum itself.

Qualitative properties, from the protocol definitions:

| | P1 ERC-5564 | P2 MLWE | P3 hybrid |
|---|---|---|---|
| Unlinkability basis | secp256k1 ECDH | Module-LWE (ML-KEM) | Module-LWE (ML-KEM) |
| Custody basis | secp256k1 ECDSA | Module-LWE | secp256k1 ECDSA |
| Lattice keypairs per recipient | 0 | 2 | 1 |
| Resists harvest-now-decrypt-later | no | yes | yes |
| Spendable on unmodified EVM | yes | **no** | yes |
| Dual-key separation (view ≠ spend) | yes | yes | yes |
| Quantum leak once an address spends | total | none | none (pre-fix h[0] tag: partial, Q1) |
| Off-chain availability dependency | none | none | R3 only — key served off-chain |
| ERC-5564 scheme id | 1 (standard) | 0x4D4C5745 (ours) | 0x50513348 (ours) |

## 2. Sizes

Byte counts drive everything else. All are read from liboqs at runtime, never hardcoded.

| Protocol | Parameter set | Meta-address | Announcement | Storage slots |
|---|---|---|---|---|
| p1_erc5564 | secp256k1 | 66 B | 33 B | 4 |
| p2_mlwe | mlkem768 | 5,600 B | 1,088 B | 176 |
| p2_mlwe | mlkem512 | 5,216 B | 768 B | 164 |
| p3_hybrid | mlkem768 | 1,217 B | 1,088 B | 40 |
| p3_hybrid | mlkem512 | 833 B | 768 B | 28 |

## 3. Measured gas

Medians over 20 fresh keypairs and 20 fresh EOAs per variant. First registrations only, so every storage slot written is cold.

| Protocol | Params | Registry | Announcer | Registration | Announcement |
|---|---|---|---|---|---|
| p1_erc5564 | secp256k1 | erc6538 | A1 | 115,316 | 28,067 |
| p2_mlwe | mlkem512 | mlwe_full | A1 | 3,788,933 | 54,960 |
| p2_mlwe | mlkem768 | mlwe_full | A1 | 4,064,437 | 67,700 |
| p3_hybrid | mlkem512 | R1 | A1 | 666,234 | 54,900 |
| p3_hybrid | mlkem512 | R1 | A2 | 666,234 | 54,230 |
| p3_hybrid | mlkem768 | R1 | A1 | 941,744 | 67,760 |
| p3_hybrid | mlkem768 | R1 | A2 | 941,744 | 67,000 |
| p3_hybrid | mlkem512 | R2 | A1 | 55,810 | 54,900 |
| p3_hybrid | mlkem512 | R2 | A2 | 55,810 | 54,230 |
| p3_hybrid | mlkem768 | R2 | A1 | 71,170 | 67,760 |
| p3_hybrid | mlkem768 | R2 | A2 | 71,170 | 67,000 |
| p3_hybrid | mlkem512 | R3 | A1 | 115,264 | 54,900 |
| p3_hybrid | mlkem512 | R3 | A2 | 115,264 | 54,230 |
| p3_hybrid | mlkem768 | R3 | A1 | 115,264 | 67,760 |
| p3_hybrid | mlkem768 | R3 | A2 | 115,264 | 67,000 |

## 4. Cost ratios and crossover

Crossover is the payment count at which cumulative announcements overtake registration, net of the 21,000 gas intrinsic transaction cost.

| Variant | Registration vs P1 | Announcement vs P1 | Crossover (payments) |
|---|---|---|---|
| p1_erc5564/secp256k1/erc6538+A1 | — | — | 13.3 |
| p2_mlwe/mlkem512/mlwe_full+A1 | 32.86x | 1.96x | 111.0 |
| p2_mlwe/mlkem768/mlwe_full+A1 | 35.25x | 2.41x | 86.6 |
| p3_hybrid/mlkem512/R1+A1 | 5.78x | 1.96x | 19.0 |
| p3_hybrid/mlkem512/R1+A2 | 5.78x | 1.93x | 19.4 |
| p3_hybrid/mlkem768/R1+A1 | 8.17x | 2.41x | 19.7 |
| p3_hybrid/mlkem768/R1+A2 | 8.17x | 2.39x | 20.0 |
| p3_hybrid/mlkem512/R2+A1 | 0.48x | 1.96x | 1.0 |
| p3_hybrid/mlkem512/R2+A2 | 0.48x | 1.93x | 1.0 |
| p3_hybrid/mlkem768/R2+A1 | 0.62x | 2.41x | 1.1 |
| p3_hybrid/mlkem768/R2+A2 | 0.62x | 2.39x | 1.1 |
| p3_hybrid/mlkem512/R3+A1 | 1.00x | 1.96x | 2.8 |
| p3_hybrid/mlkem512/R3+A2 | 1.00x | 1.93x | 2.8 |
| p3_hybrid/mlkem768/R3+A1 | 1.00x | 2.41x | 2.0 |
| p3_hybrid/mlkem768/R3+A2 | 1.00x | 2.39x | 2.0 |

## 5. Cumulative cost

Total gas after k payments, including registration. This is the headline: which protocol is cheaper depends on how many payments a recipient receives.

| Variant | k=1 | k=10 | k=50 | k=100 |
|---|---|---|---|---|
| p1_erc5564/secp256k1/erc6538+A1 | 0.143M | 0.396M | 1.519M | 2.922M |
| p2_mlwe/mlkem512/mlwe_full+A1 | 3.844M | 4.339M | 6.537M | 9.285M |
| p2_mlwe/mlkem768/mlwe_full+A1 | 4.132M | 4.741M | 7.449M | 10.834M |
| p3_hybrid/mlkem512/R1+A1 | 0.721M | 1.215M | 3.411M | 6.156M |
| p3_hybrid/mlkem512/R1+A2 | 0.720M | 1.209M | 3.378M | 6.089M |
| p3_hybrid/mlkem768/R1+A1 | 1.010M | 1.619M | 4.330M | 7.718M |
| p3_hybrid/mlkem768/R1+A2 | 1.009M | 1.612M | 4.292M | 7.642M |
| p3_hybrid/mlkem512/R2+A1 | 0.111M | 0.605M | 2.801M | 5.546M |
| p3_hybrid/mlkem512/R2+A2 | 0.110M | 0.598M | 2.767M | 5.479M |
| p3_hybrid/mlkem768/R2+A1 | 0.139M | 0.749M | 3.459M | 6.847M |
| p3_hybrid/mlkem768/R2+A2 | 0.138M | 0.741M | 3.421M | 6.771M |
| p3_hybrid/mlkem512/R3+A1 | 0.170M | 0.664M | 2.860M | 5.605M |
| p3_hybrid/mlkem512/R3+A2 | 0.169M | 0.658M | 2.827M | 5.538M |
| p3_hybrid/mlkem768/R3+A1 | 0.183M | 0.793M | 3.503M | 6.891M |
| p3_hybrid/mlkem768/R3+A2 | 0.182M | 0.785M | 3.465M | 6.815M |

## 6. Receiver scan cost (Q3)

| Protocol | Params | Announcer | µs/announcement | Bytes/announcement | RPC trips |
|---|---|---|---|---|---|
| p1_erc5564 | secp256k1 | A1 | 30.71 | 224 | 0.0 |
| p2_mlwe | mlkem768 | A1 | 28.23 | 1,248 | 0.0 |
| p2_mlwe | mlkem512 | A1 | 21.91 | 928 | 0.0 |
| p3_hybrid | mlkem768 | A1 | 29.28 | 1,248 | 0.0 |
| p3_hybrid | mlkem768 | A2 | 28.20 | 1,284 | 1.0 |
| p3_hybrid | mlkem512 | A1 | 23.31 | 928 | 0.0 |
| p3_hybrid | mlkem512 | A2 | 22.11 | 964 | 1.0 |

## 7. Anonymity under a quantum adversary (Q1)

Anonymity set for a **spent** P3 address under a quantum adversary (ECDLP broken, ML-KEM intact), at the deployed 8-bit view tag width. P3 deploys the domain-separated tag, which the adversary cannot evaluate; the h[0] columns are the **pre-fix design**, kept for comparison.

| Registry size | h[0] tag (pre-fix): expected set | Mean (simulated) | Uniquely identified | Domain-separated tag (deployed): mean set | Uniquely identified |
|---|---|---|---|---|---|
| 100 | 1.39 | 1.41 | 66.6% | 100.00 | 0.0% |
| 1,000 | 4.90 | 4.90 | 1.8% | 1,000.00 | 0.0% |
| 10,000 | 40.06 | 39.92 | 0.0% | 10,000.00 | 0.0% |
| 100,000 | 391.62 | 391.27 | 0.0% | 100,000.00 | 0.0% |
| 1,000,000 | 3,907.25 | 3,906.29 | 0.0% | 1,000,000.00 | 0.0% |

---

Regenerate with `uv run python -m bench.report`. `bench/results/` is committed and never hand-edited; a surprising number is re-run and investigated, never adjusted.
