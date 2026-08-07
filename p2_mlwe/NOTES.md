# P2 — implementation boundary and open questions

Reference: Marija Mikić, Mihajlo Srbakoski, Strahinja Praska, *Post-Quantum
Stealth Address Protocols*, arXiv:2501.13733. Retrieved 2026-08-07 from
<https://arxiv.org/abs/2501.13733> and the HTML full text at
<https://arxiv.org/html/2501.13733v1>.

## The boundary — state this explicitly in the methodology chapter

**We implement the MLWE SAP data plane in order to measure its EVM cost. We do
not implement the full protocol.** Everything below follows from that sentence,
and it should appear in the thesis in roughly that form.

What is real here:

- Genuine ML-KEM keypairs and ciphertexts from liboqs, so every byte count and
  every calldata content statistic is authentic.
- Two lattice keypairs per recipient — spending and viewing — exactly as the
  paper specifies, giving the meta-address `M = (K, V)`.
- Real decapsulation on the scan path, so decapsulation counts and per-item
  timings are measured rather than modelled.

What is deliberately absent:

- The stealth key itself. The paper defines

      P = XOF(ρ_K) · XOF(S) + Decompress_q(t_K, d_t)          p = k + XOF(S)

  which requires full R_q arithmetic with NTT. liboqs exposes only the KEM
  interface, so computing `P` would mean porting their polynomial arithmetic —
  weeks of work for a value that **never goes on-chain**, since the recipient
  computes it locally. Nothing we measure depends on it.
- Their view-tag hash. See the deviation below.
- Any spendable EVM account. `recover_spend_key` raises `NotEvmSpendable`.

## Why P2 cannot complete a payment, and why that is a result

`p = k + XOF(S)` is an element of R_q. No secp256k1 scalar corresponds to it, so
no Ethereum account is controlled by it and no EVM transaction can be signed for
the stealth address. An end-to-end payment under this protocol requires Ethereum
itself to become post-quantum.

`tests/test_p2_scheme.py::test_recover_raises_not_evm_spendable` asserts this.
Demonstrating the limitation concretely is stronger evidence than quoting a
claim about it, and it is the reason P2 appears in the comparison at all: it
establishes what the post-quantum state of the art costs *and* what it cannot
do, which together motivate P3.

## Documented deviations

**Hash function for the view tag.** The paper uses SHA-256; we use keccak256,
via the shared `pqsap_core.derive`. Both produce a one-byte tag from the shared
secret, so the on-chain payload is byte-identical in size and statistically
identical in content — the deviation cannot affect any gas figure. Using the
shared derivation instead keeps P1, P2 and P3 on one code path, which is the
fairness guarantee the whole comparison rests on. Off-chain scan timings differ
by one hash of 32 bytes per announcement, which is negligible against a
decapsulation but should be stated when reporting Q3.

**Stealth-address field stand-in.** The shared announcer's ABI has an `address`
argument and the real protocol has no Ethereum address to supply. We pass
`keccak256("pqsap/p2/stealth-address-standin" ‖ S)[-20:]`.

The alternative — passing the zero address — would be *cheaper on purpose*:
twenty zero calldata bytes cost 4 gas each against 16 for non-zero, so P2 would
appear roughly 240 gas per announcement cheaper than P1 and P3 for a reason that
has nothing to do with its cryptography. A pseudorandom stand-in keeps the
comparison honest. When reporting P2's announcement cost, note that a native
MLWE SAP deployment would not carry this field at all, and that omitting it
would save on the order of 320 gas of calldata per announcement (20 bytes × 16
gas) plus the corresponding log data — quantify this from the measured figures
rather than from this estimate.

**Scan verification.** Our `scan` filters by view tag and then checks the
stand-in address, which is a single hash. The real protocol's second step
recomputes the lattice stealth key and compares it — an R_q operation we do not
implement. **Measured P2 scan cost is therefore a lower bound on the real
protocol's**, and Q3 must say so. The decapsulation count, which dominates, is
exact.

## Parameter set — a decision the charter should be updated on

The charter assumes P2 uses ML-KEM-768, giving a 2368-byte meta-address. The
paper's own experiments use **Kyber512**: "All three algorithms (Kyber512,
NewHope512, Frodo640) have the same security level, which corresponds
approximately to AES128" — that is NIST level 1, not level 3.

Both readings are defensible and they answer different questions, so `P2Mlwe`
takes the parameter set as a constructor argument and we measure both:

| Reading | Parameter set | Meta-address | Announcement | Answers |
|---|---|---|---|---|
| Level-matched (default) | ML-KEM-768 | 2368 B | 1088 B | What does P3's design save at equal security? |
| Paper-faithful | ML-KEM-512 | 1600 B | 768 B | What does the published protocol actually cost on-chain? |

The level-matched run is the one that belongs in the headline P1/P2/P3
comparison, because comparing P2 at level 1 against P3 at level 3 would
attribute a security difference to a design difference. The paper-faithful run
belongs alongside it so the reproduction is honest. Note that the charter's
"49% smaller before any registry optimisation" figure is a level-matched claim
and holds only for the 768 row.

## Items to verify before the thesis cites them

- **The 66.8% scan-time figure.** The abstract states MLWE SAP "outperforms
  ECPDKSAP by approximately 66.8% in the scan time of the ephemeral public key
  registry". The charter attributes this figure to a comparison against
  **Curvy**. ECPDKSAP and Curvy are not obviously the same protocol, and one
  automated reading of the full text conflated them. Resolve this against the
  paper's own definitions before citing, and do not repeat the charter's
  wording until it is confirmed. Unknown means unknown.
- **The "not Ethereum-friendly" attribution.** The charter says the authors
  state their protocol is not Ethereum-friendly. The full text of 2501.13733
  does not appear to make that claim directly; it observes that Curvy is
  compatible with Ethereum without claiming the same for MLWE SAP. The explicit
  statement may belong to the companion paper, arXiv:2504.06744. Locate the
  exact sentence and cite the paper it actually appears in.
- **View-tag width.** The paper uses one byte, and notes a larger tag trades
  registry size for scan speed. Our one-byte tag matches. Confirm whether their
  reported timings use the one-byte variant before comparing against them.
- **Their exact registry entry encoding.** We assume `ek_K ‖ ek_V` with no
  framing overhead, which is the most favourable reading for P2. If the paper
  specifies additional fields, P2's registration cost rises and the comparison
  moves further in P3's favour — so this assumption is conservative, but it
  should still be checked.
