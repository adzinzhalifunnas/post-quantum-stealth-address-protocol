# PQ-SAP measurement report — anvil

Generated from `bench/results/` at commit `0844a6792d2e`. Every figure traces to a CSV row; nothing here is recomputed or adjusted.

> **These are local-chain measurements.** Gas *units* are deterministic and will reproduce on any chain running the same EVM version, so the comparisons below stand. Fee columns — and in particular Base Sepolia's separate L1 data fee — require the testnet runs and are not yet filled in.

## Provenance

- Measured on: `anvil` (chain state recorded per row)
- **Measured at commit:** `68da1f17d3dc`
- liboqs: 0.16.0 via liboqs-python 0.16.0
- solc 0.8.28, optimizer runs 200
- Machine: macOS-26.5.2-arm64-arm-64bit, Python 3.12.11
- Samples per target: 20
- Measurement timestamp: 2026-08-13T15:17:57.033087+00:00
- ⚠️ The working tree has moved on since these numbers were taken. Re-run `bench.gas` before quoting them if any contract changed.

## 1. Sizes

Byte counts drive everything else. All are read from liboqs at runtime, never hardcoded.

| Protocol | Parameter set | Meta-address | Announcement | Storage slots |
|---|---|---|---|---|
| p1_erc5564 | secp256k1 | 66 B | 33 B | 4 |
| p2_mlwe | mlkem768 | 2,368 B | 1,088 B | 75 |
| p2_mlwe | mlkem512 | 1,600 B | 768 B | 51 |
| p3_hybrid | mlkem768 | 1,217 B | 1,088 B | 40 |
| p3_hybrid | mlkem512 | 833 B | 768 B | 28 |

## 2. Measured gas

Medians over 20 fresh keypairs and 20 fresh EOAs per variant. First registrations only, so every storage slot written is cold.

| Protocol | Params | Registry | Announcer | Registration | Announcement |
|---|---|---|---|---|---|
| p1_erc5564 | secp256k1 | erc6538 | A1 | 115,316 | 28,067 |
| p2_mlwe | mlkem512 | mlwe_full | A1 | 1,194,672 | 54,930 |
| p2_mlwe | mlkem768 | mlwe_full | A1 | 1,745,670 | 67,730 |
| p3_hybrid | mlkem512 | R1 | A1 | 666,258 | 54,930 |
| p3_hybrid | mlkem512 | R1 | A2 | 666,258 | 54,200 |
| p3_hybrid | mlkem768 | R1 | A1 | 941,744 | 67,730 |
| p3_hybrid | mlkem768 | R1 | A2 | 941,744 | 67,000 |
| p3_hybrid | mlkem512 | R3 | A1 | 115,264 | 54,930 |
| p3_hybrid | mlkem512 | R3 | A2 | 115,264 | 54,200 |
| p3_hybrid | mlkem768 | R3 | A1 | 115,264 | 67,730 |
| p3_hybrid | mlkem768 | R3 | A2 | 115,264 | 67,000 |

## 3. Cost ratios and crossover

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
| p3_hybrid/mlkem768/R3+A2 | 1.00x | 2.39x | 2.0 |

## 4. Cumulative cost

Total gas after k payments, including registration. This is the headline: which protocol is cheaper depends on how many payments a recipient receives.

| Variant | k=1 | k=10 | k=50 | k=100 |
|---|---|---|---|---|
| p1_erc5564/secp256k1/erc6538+A1 | 0.143M | 0.396M | 1.519M | 2.922M |
| p2_mlwe/mlkem512/mlwe_full+A1 | 1.250M | 1.744M | 3.941M | 6.688M |
| p2_mlwe/mlkem768/mlwe_full+A1 | 1.813M | 2.423M | 5.132M | 8.519M |
| p3_hybrid/mlkem512/R1+A1 | 0.721M | 1.216M | 3.413M | 6.159M |
| p3_hybrid/mlkem512/R1+A2 | 0.720M | 1.208M | 3.376M | 6.086M |
| p3_hybrid/mlkem768/R1+A1 | 1.009M | 1.619M | 4.328M | 7.715M |
| p3_hybrid/mlkem768/R1+A2 | 1.009M | 1.612M | 4.292M | 7.642M |
| p3_hybrid/mlkem512/R3+A1 | 0.170M | 0.665M | 2.862M | 5.608M |
| p3_hybrid/mlkem512/R3+A2 | 0.169M | 0.657M | 2.825M | 5.535M |
| p3_hybrid/mlkem768/R3+A1 | 0.183M | 0.793M | 3.502M | 6.888M |
| p3_hybrid/mlkem768/R3+A2 | 0.182M | 0.785M | 3.465M | 6.815M |

## 5. Receiver scan cost (Q3)

| Protocol | Params | Announcer | µs/announcement | Bytes/announcement | RPC trips |
|---|---|---|---|---|---|
| p1_erc5564 | secp256k1 | A1 | 30.71 | 224 | 0.0 |
| p2_mlwe | mlkem768 | A1 | 28.23 | 1,248 | 0.0 |
| p2_mlwe | mlkem512 | A1 | 21.91 | 928 | 0.0 |
| p3_hybrid | mlkem768 | A1 | 29.28 | 1,248 | 0.0 |
| p3_hybrid | mlkem768 | A2 | 28.20 | 1,284 | 1.0 |
| p3_hybrid | mlkem512 | A1 | 23.31 | 928 | 0.0 |
| p3_hybrid | mlkem512 | A2 | 22.11 | 964 | 1.0 |

## 6. Anonymity under a quantum adversary (Q1)

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
