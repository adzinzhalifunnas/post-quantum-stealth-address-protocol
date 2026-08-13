# PQ-SAP measurement report — anvil

Generated from `bench/results/` at commit `baed80940fe7`. Every figure traces to a CSV row; nothing here is recomputed or adjusted.

> **These are local-chain measurements.** Gas *units* are deterministic and will reproduce on any chain running the same EVM version, so the comparisons below stand. Fee columns — and in particular Base Sepolia's separate L1 data fee — require the testnet runs and are not yet filled in.

## Provenance

- Measured on: `anvil` (chain state recorded per row)
- **Measured at commit:** `d6f8e309ed05`
- liboqs: 0.16.0 via liboqs-python 0.16.0
- solc 0.8.28, optimizer runs 200
- Machine: macOS-26.5.2-arm64-arm-64bit, Python 3.12.11
- Samples per target: 20
- Measurement timestamp: 2026-08-13T16:12:46.250399+00:00
- ⚠️ The working tree has moved on since these numbers were taken. Re-run `bench.gas` before quoting them if any contract changed.

## 1. The three protocols, head to head

P2 and P3 are both shown at ML-KEM-768, so a security-level difference is never mistaken for a design difference. P3 appears twice because the optimisation is the artifact.

| | P1 ERC-5564 | P2 MLWE | P3 naive (R1+A1) | P3 optimised (R3+A2) |
|---|---|---|---|---|
| **Meta-address registered** | 66 B | 2,368 B | 1,217 B | 65 B |
| **Announcement payload** | 33 B | 1,088 B | 1,088 B | 1,088 B |
| **Registration gas** | 115,316 | 1,745,658 | 941,744 | 115,264 |
| **Announcement gas** | 28,067 | 67,730 | 67,700 | 66,970 |
| Cumulative at k=1 | 0.143M | 1.813M | 1.009M | 0.182M |
| Cumulative at k=10 | 0.396M | 2.423M | 1.619M | 0.785M |
| Cumulative at k=100 | 2.922M | 8.519M | 7.712M | 6.812M |
| Crossover (payments) | 13.3 | 36.9 | 19.7 | 2.1 |
| Scan time per announcement | 30.71 µs | 28.23 µs | 29.28 µs | 28.20 µs |
| Scan bytes per announcement | 224 B | 1,248 B | 1,248 B | 1,284 B |
| Scan RPC round trips | 0 | 0 | 0 | 1 |

Qualitative properties, from the protocol definitions:

| | P1 ERC-5564 | P2 MLWE | P3 hybrid |
|---|---|---|---|
| Unlinkability basis | secp256k1 ECDH | Module-LWE (ML-KEM) | Module-LWE (ML-KEM) |
| Custody basis | secp256k1 ECDSA | Module-LWE | secp256k1 ECDSA |
| Lattice keypairs per recipient | 0 | 2 | 1 |
| Resists harvest-now-decrypt-later | no | yes | yes |
| Spendable on unmodified EVM | yes | **no** | yes |
| Dual-key separation (view ≠ spend) | yes | yes | yes |
| Quantum leak once an address spends | total | none | partial (Q1) |
| ERC-5564 scheme id | 1 (standard) | 0x4D4C5745 (ours) | 0x50513348 (ours) |

## 2. Sizes

Byte counts drive everything else. All are read from liboqs at runtime, never hardcoded.

| Protocol | Parameter set | Meta-address | Announcement | Storage slots |
|---|---|---|---|---|
| p1_erc5564 | secp256k1 | 66 B | 33 B | 4 |
| p2_mlwe | mlkem768 | 2,368 B | 1,088 B | 75 |
| p2_mlwe | mlkem512 | 1,600 B | 768 B | 51 |
| p3_hybrid | mlkem768 | 1,217 B | 1,088 B | 40 |
| p3_hybrid | mlkem512 | 833 B | 768 B | 28 |

## 3. Measured gas

Medians over 20 fresh keypairs and 20 fresh EOAs per variant. First registrations only, so every storage slot written is cold.

| Protocol | Params | Registry | Announcer | Registration | Announcement |
|---|---|---|---|---|---|
| p1_erc5564 | secp256k1 | erc6538 | A1 | 115,316 | 28,067 |
| p2_mlwe | mlkem512 | mlwe_full | A1 | 1,194,672 | 54,930 |
| p2_mlwe | mlkem768 | mlwe_full | A1 | 1,745,658 | 67,730 |
| p3_hybrid | mlkem512 | R1 | A1 | 666,246 | 54,930 |
| p3_hybrid | mlkem512 | R1 | A2 | 666,246 | 54,200 |
| p3_hybrid | mlkem768 | R1 | A1 | 941,744 | 67,700 |
| p3_hybrid | mlkem768 | R1 | A2 | 941,744 | 66,970 |
| p3_hybrid | mlkem512 | R3 | A1 | 115,264 | 54,930 |
| p3_hybrid | mlkem512 | R3 | A2 | 115,264 | 54,200 |
| p3_hybrid | mlkem768 | R3 | A1 | 115,264 | 67,700 |
| p3_hybrid | mlkem768 | R3 | A2 | 115,264 | 66,970 |

## 4. Cost ratios and crossover

Crossover is the payment count at which cumulative announcements overtake registration, net of the 21,000 gas intrinsic transaction cost.

| Variant | Registration vs P1 | Announcement vs P1 | Crossover (payments) |
|---|---|---|---|
| p1_erc5564/secp256k1/erc6538+A1 | — | — | 13.3 |
| p2_mlwe/mlkem512/mlwe_full+A1 | 10.36x | 1.96x | 34.6 |
| p2_mlwe/mlkem768/mlwe_full+A1 | 15.14x | 2.41x | 36.9 |
| p3_hybrid/mlkem512/R1+A1 | 5.78x | 1.96x | 19.0 |
| p3_hybrid/mlkem512/R1+A2 | 5.78x | 1.93x | 19.4 |
| p3_hybrid/mlkem768/R1+A1 | 8.17x | 2.41x | 19.7 |
| p3_hybrid/mlkem768/R1+A2 | 8.17x | 2.39x | 20.0 |
| p3_hybrid/mlkem512/R3+A1 | 1.00x | 1.96x | 2.8 |
| p3_hybrid/mlkem512/R3+A2 | 1.00x | 1.93x | 2.8 |
| p3_hybrid/mlkem768/R3+A1 | 1.00x | 2.41x | 2.0 |
| p3_hybrid/mlkem768/R3+A2 | 1.00x | 2.39x | 2.1 |

## 5. Cumulative cost

Total gas after k payments, including registration. This is the headline: which protocol is cheaper depends on how many payments a recipient receives.

| Variant | k=1 | k=10 | k=50 | k=100 |
|---|---|---|---|---|
| p1_erc5564/secp256k1/erc6538+A1 | 0.143M | 0.396M | 1.519M | 2.922M |
| p2_mlwe/mlkem512/mlwe_full+A1 | 1.250M | 1.744M | 3.941M | 6.688M |
| p2_mlwe/mlkem768/mlwe_full+A1 | 1.813M | 2.423M | 5.132M | 8.519M |
| p3_hybrid/mlkem512/R1+A1 | 0.721M | 1.216M | 3.413M | 6.159M |
| p3_hybrid/mlkem512/R1+A2 | 0.720M | 1.208M | 3.376M | 6.086M |
| p3_hybrid/mlkem768/R1+A1 | 1.009M | 1.619M | 4.327M | 7.712M |
| p3_hybrid/mlkem768/R1+A2 | 1.009M | 1.611M | 4.290M | 7.639M |
| p3_hybrid/mlkem512/R3+A1 | 0.170M | 0.665M | 2.862M | 5.608M |
| p3_hybrid/mlkem512/R3+A2 | 0.169M | 0.657M | 2.825M | 5.535M |
| p3_hybrid/mlkem768/R3+A1 | 0.183M | 0.792M | 3.500M | 6.885M |
| p3_hybrid/mlkem768/R3+A2 | 0.182M | 0.785M | 3.464M | 6.812M |

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

Anonymity set for a **spent** P3 address under a quantum adversary (ECDLP broken, ML-KEM intact), at the deployed 8-bit view tag:

| Registry size | Expected set | Mean (simulated) | Uniquely identified |
|---|---|---|---|
| 100 | 1.39 | 1.41 | 66.6% |
| 1,000 | 4.90 | 4.90 | 1.8% |
| 10,000 | 40.06 | 39.92 | 0.0% |
| 100,000 | 391.62 | 391.27 | 0.0% |
| 1,000,000 | 3,907.25 | 3,906.29 | 0.0% |

---

Regenerate with `uv run python -m bench.report`. `bench/results/` is committed and never hand-edited; a surprising number is re-run and investigated, never adjusted.
