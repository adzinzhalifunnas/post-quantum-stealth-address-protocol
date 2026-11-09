# Threat model

What each protocol in this study protects, against whom, and — more usefully —
what it does not protect. Written to be argued from rather than quoted: several
entries record limitations the design does not solve and does not claim to.

## The asset

**Unlinkability of payments to a recipient.** Not confidentiality of amounts,
not anonymity of senders, not censorship resistance. A stealth address protocol
succeeds if an observer holding the chain and every registered meta-address
cannot tell which payments went to whom.

Custody — control of received funds — is a separate asset, and this design
deliberately does not make it post-quantum. See "Custody is not in scope" below.

## Adversaries

**A1 — Classical chain observer.** Sees every transaction, every log, every
registered meta-address. No secret keys. This is the everyday adversary and the
one all three protocols are designed against.

**A2 — Classical observer with the recipient's viewing key.** The disclosure
case: a regulator, an auditor, an accountant. Must be able to enumerate every
payment to the recipient and must not be able to spend any of them. This is the
dual-key separation both ERC-5564 and Mikić et al. emphasise, and it is enforced
here by type rather than by convention — `ViewingKeys` has no field capable of
carrying spending material, so `scan` structurally cannot reach one.

**A3 — Harvest-now, decrypt-later.** Records the chain today and attacks it
after a cryptographically relevant quantum computer exists. This adversary is
the reason the project exists. Announcement metadata is permanently public and
can never be re-encrypted, so any linkage recoverable from it in 2040 is
recoverable from data already published in 2026.

**A4 — Quantum adversary, ECDLP broken, ML-KEM intact.** The position a hybrid
design creates. Can take discrete logs on secp256k1 at will; cannot break
lattice assumptions. This is the adversary Q1 analyses.

**A5 — Malicious key server.** Specific to P3's R3 variant, which serves
`ek_view` off-chain. Can return any bytes it likes when asked for a recipient's
viewing key.

## What each protocol gives

| | A1 classical | A3 harvest-now | A4 quantum, unspent | A4 quantum, spent |
|---|---|---|---|---|
| P1 ERC-5564 | unlinkable | **broken later** | broken | broken |
| P2 MLWE | unlinkable | unlinkable | unlinkable | unlinkable |
| P3 hybrid | unlinkable | unlinkable | unlinkable | unlinkable (pre-fix h[0] tag: **partial leak**) |

**P1 fails against A3 and A4.** Its shared secret is an ECDH product of two
published values, `R` and `M_view`. An adversary who can take discrete logs
recovers it directly and identifies the recipient outright. Everything ERC-5564
publishes today is decryptable by A4 tomorrow — which is the harvest-now problem
in its purest form.

**P2 resists all of them**, and cannot complete a payment on Ethereum. Its
stealth key is a lattice element, so no EVM account corresponds to it. That is
demonstrated concretely by `NotEvmSpendable`, not merely asserted; see
`p2_mlwe/NOTES.md`.

**P3 resists A1, A3, and A4, spent or unspent.** Before its view tag was
domain-separated it leaked partially once an address spent. That leak is Q1,
quantified below for both designs.

## Q1 — the view tag on spent P3 addresses

While a P3 stealth address only receives, the chain shows an address, and
addresses are hashes: A4 has nothing to take a discrete log of. When it spends,
its ECDSA signature reveals the public key `P`, and A4 can compute
`h_j = dlog(P − M_j)` for every registered `M_j`.

On its own that reveals nothing, because *every* candidate yields a valid
discrete log. Whether anything leaks depends entirely on whether `h_j` lets A4
check a candidate against the announcement — and the only candidate-specific
value an announcement publishes is the view tag.

**Pre-fix design: `tag = h[0]`.** P3 originally took its tag from byte 0 of
`keccak256(S)`, the same digest `h` is read from, as ERC-5564 does. Holding
`h_j`, A4 had every candidate's tag for free and kept only those matching the
published one. The true recipient always survives; each other registrant
survives with probability 2⁻ᵗ, leaving about 1 + (N−1)/2ᵗ.

**Deployed design: `tag = keccak256("pq-sap/p3/view-tag/v1" ‖ S)[0]`.** `h` is
unchanged. The tag is now a function of `S`, not of `h`. A4 holds
`h_j = keccak256(S) mod n`, which does not invert, and `S` itself is protected by
ML-KEM, which A4 has not broken. A4 cannot evaluate any candidate's tag, so the
tag filters nothing and the anonymity set is the whole registry — at every
registry size and every tag width.

Simulated in `bench/anonymity.py`, at the deployed 8-bit tag width:

| Registry size | h[0] tag (pre-fix): mean set | Uniquely identified | Domain-separated (deployed): set | Uniquely identified |
|---|---|---|---|---|
| 100 | 1.4 | 66.6% | 100 | 0.0% |
| 1,000 | 4.9 | 1.8% | 1,000 | 0.0% |
| 10,000 | 39.9 | 0.0% | 10,000 | 0.0% |
| 1,000,000 | 3,906 | 0.0% | 1,000,000 | 0.0% |

The pre-fix leak was real, bounded, and scaled the right way — worst for a small
registry, negligible for a large one. The fix removes it at every size. It costs
nothing in announcement size, since the tag is still one byte, and nothing in
scanning: a recipient still spends one hash per announcement on the tag, and
computes `h` only for the roughly 1 in 256 that pass.

Four qualifications belong beside any statement of it:

1. **Only spent addresses were ever exposed.** In a payment workload most
   stealth addresses are unspent at any moment, and those were untouched under
   either design.
2. **P1 is worse off, and unchanged.** It keeps the ERC-5564 `h[0]` tag, as the
   standard requires, and against A4 it is fully broken regardless of the tag:
   the ECDH secret falls to a discrete log.
3. **P3's tag rule now deviates from ERC-5564's.** The standard specifies the
   tag only for scheme id 1, and P3's id is non-standard already, but any
   implementation must use P3's rule or it will find no payments.
4. **The closure rests on assumptions.** That ML-KEM keeps `S` from A4, and that
   keccak256 under two domains behaves as two independent functions, so `h_j`
   says nothing about the tag. The earlier mitigation — dropping the tag, at the
   cost of an elliptic-curve operation on every announcement during scanning —
   is no longer needed.

This is argued analysis plus simulation, per the charter's bounded scope. It is
not a formal proof and must not be cited as one.

## R3's added assumption

R3 registers `M ‖ keccak256(ek_view)` and serves `ek_view` off-chain, which
introduces A5. A sender who fetches a viewing key and encapsulates to it without
checking would encapsulate to whatever the server chose — and the server could
then decapsulate every payment.

The commitment closes this: `P3Hybrid.verify_commitment` hashes the served key
and compares against the on-chain value, and
`test_commitment_rejects_a_substituted_key` demonstrates the attack it prevents.
The residual requirement is availability, not integrity — a server that refuses
to serve blocks payments, but cannot redirect or read them.

## Custody is not in scope, and this is deliberate

P3 stealth addresses are ordinary secp256k1 EOAs. Against A4 their funds are
spendable by the adversary — exactly as every Ethereum account's are today.

This is not a weakness introduced by the design; it is the status quo of the
chain the design runs on. Making custody post-quantum would require Ethereum
itself to support post-quantum signatures, which is precisely the dependency P2
demonstrates and this work avoids. The claim made here is narrow and should stay
narrow: **unlinkability is post-quantum; custody is as post-quantum as
Ethereum**.

The reason unlinkability is worth protecting separately is A3. Announcement
metadata is public forever and cannot be re-encrypted, so linkage must be
protected *now*. A signature, by contrast, only needs to resist attack while the
key holds funds, and can be migrated when the chain migrates.

## Known limitations, unsolved

**Funding linkage.** A fresh stealth address holds no ETH and cannot pay for its
own first transaction. Whatever funds it can be correlated with it. This is a
known ERC-5564 limitation, is not specific to post-quantum constructions, and is
documented rather than solved. Tests verify signing via `ecrecover` rather than
broadcasting, so the harness never depends on funding a stealth address.

**Sender anonymity.** The announcer records `msg.sender`. Senders are not
anonymous and were never intended to be.

**Amount confidentiality.** Transfer values are public. Out of scope.

**Timing and graph analysis.** An adversary correlating announcement times with
off-chain events may link payments without breaking any cryptography. No stealth
address scheme addresses this.

**Registry membership.** Registering a meta-address is public and marks an
account as a stealth-address user. Unlinkability is *within* the registry, never
membership privacy.

**Non-standard scheme identifiers.** P2 and P3 use unregistered ERC-5564 scheme
ids (`0x4D4C5745`, `0x50513348`). Any deployment would need these standardised;
until then, wallet interoperability cannot be assumed.
