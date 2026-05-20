# M5 — key technical decisions

A record of the non-obvious calls made during the M5 (PQ signing +
QVM minimal decoder) implementation. Each entry: **what**, **why**,
**alternatives considered**. Decisions resolved by the RFC are not
repeated — see `server-wallet-rfc.md` §10. M1/M2 decisions live in
`m1-decisions.md`; M3 in `m3-decisions.md`; M4 in `m4-decisions.md`.

Generated alongside the `feat/m5-pq-qvm` branch (2026-05-21).

---

## D38 — ML-DSA crate: `ml-dsa` (RustCrypto), not `pqcrypto-dilithium` / `pqcrypto-mldsa`

**What:** The `ml-dsa` crate from the RustCrypto signatures workspace
(v0.1.0, pure-Rust, FIPS 204 final compliant) supplies the ML-DSA-44 /
ML-DSA-65 / ML-DSA-87 primitives. Pinned in `[workspace.dependencies]`
with `default-features = false` plus `alloc, rand_core, zeroize`.

**Why:**
- **Pure Rust.** The RFC §1.5 line explicitly forbids `oqs-rs` (liboqs
  C FFI) for the reproducible-EIF story. `pqcrypto-dilithium` /
  `pqcrypto-mldsa` wrap the NIST PQClean C reference implementation —
  better-audited but still FFI; would compromise the
  `#![forbid(unsafe_code)]` posture across the workspace.
- **RustCrypto pedigree.** Same maintainer team as `k256` /
  `ed25519-dalek` (already in the dep graph). One vendor relationship
  to manage; auditors recognise the project.
- **FIPS 204 final naming.** Crate is named `ml-dsa` (post-Dilithium
  rebrand) and tracks the August 2024 FIPS 204 release, not the older
  CRYSTALS-Dilithium reference. Tests in the crate include the FIPS
  validation vectors.
- **`zeroize` integration.** With the `zeroize` feature, `SigningKey`
  drops zero the expanded key + seed via `ZeroizeOnDrop`. Matches the
  `SecretBytes` lifecycle the rest of the workspace already follows.

**Alternatives considered:**

- `pqcrypto-mldsa` v0.1.x. Rejected — C FFI to PQClean ref impl
  conflicts with `#![forbid(unsafe_code)]` and complicates the
  reproducible Nitro EIF build.
- `dilithium-rs` v0.2.0. Rejected — pre-FIPS 204, single-author, less
  audit surface.
- `lib-q-ml-dsa` / `threshold-ml-dsa`. Rejected — narrower or
  experimental.

**Caveat:** `ml-dsa` v0.1.0 is itself recent. We pin v0.1 explicitly and
revisit in M6 when the crate hits v1.0 or when a third-party audit
publishes.

---

## D39 — ML-DSA secret is the 32-byte FIPS 204 seed `xi`, not the expanded key

**What:** `SecretBytes` for ML-DSA carries the 32-byte seed produced by
FIPS 204 Algorithm 6 (`ML-DSA.KeyGen_internal`). The expanded signing
key (~2.4 kB for ML-DSA-44, ~4.9 kB for ML-DSA-87) is regenerated from
the seed inside the enclave at each `sign()` call.

**Why:**
- **SSS chunking parity.** The existing `qfc-sss::shamir` layer chunks
  at 31 bytes / scalar. The 32-byte seed produces the same number of
  chunks as ed25519 / secp256k1 (two — header + 32-byte chunk plus
  padding). Sharing the expanded key would multiply the share blob size
  by ~75x for ML-DSA-44 and ~150x for ML-DSA-87, swelling KMS
  envelopes, audit lines, and recovery procedures for no security
  benefit (the expanded key is deterministically recoverable from the
  seed).
- **Forwards-compat with hardware backends.** Hardware-backed ML-DSA
  implementations (future M6+) typically take the seed; reconstructing
  the expanded key in software keeps the seed-only contract intact.
- **CPU vs space trade.** Expanding the key adds ~1–2 ms per sign
  (negligible inside the larger sign flow; the enclave round-trip
  dwarfs it). Reducing share material by ~75–150x is the better trade.

The seed is itself wrapped in `SecretBytes` so the auto-zeroize +
constant-time-compare invariants apply to it just like ed25519 keys.

**Alternatives considered:**

- Carry the expanded key as the secret. Rejected — see space cost
  above; also makes wire-level interoperability with a future hardware
  ML-DSA backend harder (those backends speak seed).
- Carry both, sign from expanded. Rejected — two sources of truth.

---

## D40 — `HashAlg::None` is the only accepted hash alg for ML-DSA signing

**What:** All three ML-DSA signers (`MlDsa44Signer`, `MlDsa65Signer`,
`MlDsa87Signer`) reject any `HashAlg` other than `None` with
`SignerError::UnsupportedHash`. Both `sign()` and `verify()` enforce.

**Why:**
- **FIPS 204 internalises the hash.** The construction in §6.2 computes
  `μ = H(BytesToBits(tr) || M', 64)` inside ML-DSA; the caller does not
  pre-hash. Exposing a `HashAlg::Sha256` knob would either be silently
  ignored (caller-confusing) or invoke a different non-standard
  variant (HashML-DSA / §6.3, also called the "pre-hash" mode) — which
  is a *distinct scheme* with a separate domain-separator and OID.
- **No accidental Ethereum-style misuse.** secp256k1 callers reach for
  `HashAlg::Keccak256` reflexively; making ML-DSA reject it loudly
  catches "we copied the secp256k1 sign call" mistakes at type-error
  time.

If callers eventually need HashML-DSA (FIPS 204 §6.3), it lands as a
**separate** `SigningScheme::MlDsa{44,65,87}Prehash` variant, not as a
new `HashAlg` argument. This keeps "one scheme = one wire signature
shape" as a workspace-wide invariant.

**Alternatives considered:**

- Silently accept any `HashAlg` and ignore it. Rejected — caller
  confusion; security audits flag.
- Map `HashAlg::Sha256` to HashML-DSA. Rejected — silent semantic
  switch on what is meant to be a benign pre-hash hint.

---

## D41 — QVM decoder declares a local `QvmTxEnvelope` mirror, not a `qfc-core` dep

**What:** `qfc-policy::decoders::qvm` defines a private
`QvmTxEnvelope` struct that hand-walks the borsh layout
`tx_type:u8 || chain_id:u64 || to:Vec<u8> || value:Vec<u8> || gas_limit:u64 || data:Vec<u8>`
mirroring the wire shape `qfc-core::TransactionType` emits today.
Trailing bytes after `data` are tolerated.

**Why:**
- **No `qfc-core` workspace dep.** The retro (m1-m2 §3.6) explicitly
  documents that this repo carries zero `qfc-core` dependency for
  audit-surface reasons. M5 is not the milestone that breaks that.
- **Forward-compat.** If `qfc-core` adds fields to `Transaction` (e.g.
  a `nonce`, `priority_fee`), the existing four fields the policy
  engine reads stay correct. Trailing bytes are accepted (and dropped)
  rather than rejected.
- **`#[derive(BorshDeserialize)]` is too strict.** The macro version
  errors on un-consumed input, which would lock us to the exact
  upstream schema version. Hand-walking the borsh primitives keeps the
  decoder loose.
- **Unknown tx-type discriminants preserved.** New `TransactionType`
  variants (a future `QvmCall` discriminant from M6) surface as
  `QvmTxType::Other(d)` so policy still sees the envelope fields and
  the operator can decide.

**Alternatives considered:**

- Inline a copy of the `TransactionType` enum + a stub `Transaction`
  struct with `#[derive(BorshSerialize, BorshDeserialize)]`. Rejected —
  tight coupling to the upstream schema; first new upstream field
  breaks decode here.
- Add `qfc-core` as an optional `[features]` dep gated on `qfc-core`.
  Rejected — same retro reasoning; the workspace boundary stays
  zero-`qfc-core`.

**Caveat:** the policy engine only reads `chain_id`, `to`, `value`,
`gas_limit` from QVM transactions. Method-level / argument-level QVM
policy is deferred to M6 (RFC §10 #5) when `qfc-core` lands a
first-class `QvmCall` tx variant.

---

## D42 — Wallet migration tool deferred to a separate post-M5 deliverable

**What:** The "re-shard ed25519/secp256k1 wallet under ML-DSA scheme"
tool listed in RFC §7 M5 ships is **explicitly scoped out** of the
`feat/m5-pq-qvm` branch. It will live in `tools/wallet-migrate` (a
separate post-M5 deliverable).

**Why:** Migration is a *customer-facing flow*, not a crypto primitive:
- The migrated wallet has a **different address** (RFC §3.1 D4 — PQ
  wallets carry `qfc_address = None`). Customers must approve the
  address change before any on-chain balance moves.
- An **operator approval flow** is required so the operator can
  authorise the new wallet under the existing approver set before the
  cutover.
- The actual cutover is a **multi-step ceremony** (drain old wallet,
  fund new wallet, retire old shares with a delay window) — not a
  single CLI invocation.
- The UX surface (operator console, customer notification, audit
  trail) overlaps with M2 HTTP / M4 quorum but is its own surface.

Mixing the customer-facing migration UX into the M5 PR would conflate
PQ-signing readiness (a crypto deliverable) with operational ceremony
(a UX deliverable). Splitting keeps each PR reviewable.

**Alternatives considered:**

- Ship a half-baked CLI that re-shards but no approval flow.
  Rejected — risk of operators using it in production without the
  customer-facing pieces.
- Move it to M6. Rejected — M6 is already loaded with full QVM
  method-level decoder + cross-TEE quorum.

---

## D43 — Cross-TEE quorum lands as a design doc only

**What:** `docs/design/cross-tee-quorum.md` documents the wire shape
and threat model. Implementation is deferred to M6 or later.

**Why:** Per RFC §7 M5 bullet "Cross-TEE quorum design doc
(implementation may be M6)". The hard part is not the data layout — it
is acquiring SGX + TDX backends, wiring their attestation verifiers,
and procuring the (likely co-located but mutually independent)
hardware to host them. The design doc captures the wallet-side schema
change (`Vec<TeeBackendConstraint>`), the verifier composition rule,
and the KMS implications so the implementation PR has an unambiguous
target.

**Alternatives considered:**

- Ship a stub `TeeBackendConstraint` enum. Rejected — no real
  implementation pulls it; the design doc gets the same result with
  less code churn.

---

## D44 — `mock.rs` `generate_wallet` PQ branch emits a 32-byte seed (not 64)

**What:** `MockEnclave::generate_wallet` for an ML-DSA scheme allocates
a 32-byte seed (the FIPS 204 `xi`). The classical-curve path still
allocates 64 bytes (the BIP39-style seed needed for downstream HD
derivation).

**Why:** Storing 64 bytes for an ML-DSA wallet doubles the SSS chunk
count for no benefit — the extra 32 bytes would be padding that the
signer immediately throws away. The split is gated on
`scheme.is_post_quantum()`, which keeps the share-store wire shape
consistent between the orchestrator and a future hardware backend (the
hardware speaks "give me 32 bytes of seed").

**Alternatives considered:**

- Keep a uniform 64-byte allocation. Rejected — wastes space and emits
  an extra SSS chunk per PQ wallet.

---

## D45 — `signer_for_scheme` and `dispatch_signer` stay `Result`-shaped

**What:** Both factories still return `Result<_, SignerError>` even
though every `SigningScheme` variant now has a working impl. M5 does
not collapse the `Result` to an infallible function.

**Why:** Future schemes (SLH-DSA, Falcon, BBS+) may land in
`SigningScheme` before they have a working backend (mirroring how
ML-DSA was declared in M1 but only implemented now). Keeping the
`Result` return shape avoids the trait churn of adding-and-removing it
each milestone.

The previous `SignerError::NotImplemented` variant stays in the error
enum for the same reason. M5 docs the schemes that currently always
succeed; the M1 unit test `pq_schemes_report_not_implemented` was
updated to `pq_schemes_now_dispatch_to_real_signers` to pin the new
shape.

**Alternatives considered:**

- Drop the `Result`, collapse to `pub fn signer_for_scheme(scheme) ->
  Box<dyn Signer>`. Rejected — every future PQ scheme would re-add it,
  churning every call site.
