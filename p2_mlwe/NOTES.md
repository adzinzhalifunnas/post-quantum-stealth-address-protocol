# P2 — implementation boundary

Reference (peer-reviewed, the version cited in the thesis): Marija Mikić,
Mihajlo Srbakoski, Strahinja Praška, *Post-quantum stealth address protocols*,
Journal of Cyber Security Technology, published online 2026-01-08,
doi:10.1080/23742917.2025.2611820. Received 2025-07-21, accepted 2025-12-22.

The preprint (arXiv:2501.13733, January 2025) is superseded and is **not** the
reference for anything in this module. It differs materially: there the
spending key was a second Kyber key and the meta-address `ek_K ‖ ek_V` was 2368
bytes at Kyber768; in the journal version the spending key is a
Dilithium-structured Module-LWE key and the meta-address is 5600 bytes. Gas
figures measured before this change (P2 registration 1,745,670 gas at 2368 B)
belong to the preprint construction and must not be cited for the journal
version.

## The boundary — state this explicitly in the methodology chapter

**We implement the MLWE SAP data plane in order to measure its EVM cost. We do
not implement the full protocol.** Everything below follows from that sentence,
and it should appear in the thesis in roughly that form.

What is real here:

- Genuine Kyber (ML-KEM) viewing keys and ciphertexts from liboqs, so the
  viewing-key and announcement bytes are authentic.
- The meta-address layout of the journal version, `MA = K ‖ V` (§5.4–5.5):
  - `K`, the spending key, is a Dilithium-structured `t = A·s + e` kept
    **uncompressed**, because `Power2Round` is not additively homomorphic and
    the stealth key is derived by adding to `t`. At Dilithium NIST level 3 that
    is 6 × 256 coefficients × 23 bits = **4416 bytes** (§6.5).
  - `V` is a Kyber encapsulation key: 1184 bytes at Kyber768, 800 at Kyber512.
- Real decapsulation on the scan path, so decapsulation counts and per-item
  timings are measured rather than modelled.

What is a faithful stand-in:

- The bytes of `K`. We rejection-sample 1536 coefficients uniformly modulo
  q = 8380417 from SHAKE256 and pack them at 23 bits each, the uncompressed
  layout of `t`. Under the Module-LWE assumption a real `t = A·s + e` is
  indistinguishable from uniform, so length and byte statistics — the only
  properties that drive storage and calldata cost — are faithful. No Dilithium
  arithmetic is performed.

What is deliberately absent:

- The stealth key `t' = A·(s + k') + e'` and its Dilithium private key. They
  need full R_q arithmetic, never go on-chain (the recipient computes them
  locally), and nothing we measure depends on them.
- Their view-tag hash. See the deviation below.
- Any spendable EVM account. `recover_spend_key` raises `NotEvmSpendable`.

## Why P2 cannot complete a payment on Ethereum today

The stealth private key has the structure of a Dilithium private key (§5.5,
step 5), so spending requires on-chain Dilithium verification. The authors
state that in current Ethereum environments Dilithium verification is expensive
without a dedicated precompile, that experimental on-chain verification incurs
"extremely high gas costs, making it unsuitable for practical use", and that
Ethereum's current address scheme is tied to ECDSA (§4.7, §5.5). An end-to-end
payment therefore waits on protocol-level changes to Ethereum.

`tests/test_p2_scheme.py::test_recover_raises_not_evm_spendable` asserts this.

## Documented deviations

**Hash function for the view tag.** The paper computes the tag from a hash of
the shared secret (SHA-256 given as an example); we use keccak256 via the shared
`pqsap_core.derive`. Both produce a one-byte tag, so the on-chain payload is
identical in size and statistically identical in content — the deviation cannot
affect any gas figure. Off-chain scan timings differ by one 32-byte hash per
announcement, negligible against a decapsulation.

**Stealth-address field stand-in.** The shared announcer's ABI has an `address`
argument and the real protocol has no Ethereum address to supply. We pass
`keccak256("pqsap/p2/stealth-address-standin" ‖ S)[-20:]`. Passing the zero
address would make P2 look roughly 240 gas per announcement cheaper for a reason
unrelated to its cryptography (20 zero calldata bytes at 4 gas instead of 16).

**Scan verification.** Our `scan` filters by view tag and then checks the
stand-in address, a single hash. The real protocol recomputes the lattice
stealth key — an R_q operation we do not implement. **Measured P2 scan cost is
therefore a lower bound on the real protocol's.** The decapsulation count, which
dominates, is exact.

## Parameter set

The paper's primary instantiation is **Kyber512** (§6.1), always combined with
Dilithium at NIST level 3 for the spending key (§6.2, Table 5). `P2Mlwe` takes
the Kyber parameter set as a constructor argument and we measure both readings:

| Reading | Viewing key | Spending key | Meta-address | Announcement | Answers |
|---|---|---|---|---|---|
| Level-matched (default) | Kyber768 | Dilithium L3, 4416 B | 5600 B | 1088 B | What does P3 save at equal viewing-key security? |
| Paper primary | Kyber512 | Dilithium L3, 4416 B | 5216 B | 768 B | What does the published instantiation cost on-chain? |

Both meta-address sizes reproduce the paper's Table 5 exactly. The
level-matched run belongs in the headline comparison; the paper-primary run
belongs alongside it so the reproduction is honest.

## Points resolved against the journal version

- **Scan-time figure.** The journal reports "approximately 67%" improvement for
  80,000 announcements against ECPDKSAP, which §6.2 identifies as the Curvy
  protocol (Protocol 3 of their earlier paper), with Kyber512 + Dilithium and a
  1-byte view tag. Cite it as "about 67%", not 66.8% (the preprint's figure).
- **Ethereum compatibility.** The phrase "not Ethereum-friendly" is from the
  preprint and does not appear in the journal. Cite the journal's own statements
  about the Dilithium precompile and ECDSA-bound addresses instead (§4.7, §5.5).
- **View-tag width.** One byte by default (§4.2), as here.
- **Registry entry encoding.** Table 5 sizes are the raw concatenation of the
  two keys with no framing, which is what we register.
- **Note for citing:** the paper calls the level-3 parameter set "Dilithium2
  (NIST security level 3)" in §5.4; in the Dilithium specification Dilithium2 is
  level 2 and Dilithium3 is level 3. The sizes in Table 5 correspond to level 3
  (k = 6), which is what we implement.
