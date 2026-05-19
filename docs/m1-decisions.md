# M1 — key technical decisions

A record of the non-obvious calls made during M1 implementation. Each entry: **what** was decided, **why**, and **what the alternatives were**. Decisions that boiled down to the RFC are not repeated here — see `server-wallet-rfc.md` §10 for those.

Generated alongside M1 PRs #1–#6 (2026-05-19).

---

## D1 — Add a 7th internal crate `qfc-wallet-types`

**What:** The workspace ships a 7th crate, `qfc-wallet-types`, for shared identifier newtypes, scheme/hash enums, `HdPath` parser, and the redacting `SecretBytes` wrapper.

**Why:** Cross-crate types (`WalletId`, `RequestId`, `ShareId`, `SigningScheme`, etc.) are needed by every other crate in the workspace. Putting them in any single service crate creates dependency cycles (e.g. `qfc-enclave` ↔ `qfc-sss`). Mirroring the pattern `qfc-core` already uses with its own `qfc-types` keeps this consistent across the QFC ecosystem.

**Alternatives considered:**
- Put shared types in `qfc-enclave` since it's the deepest crate. Rejected — `qfc-enclave` needs `EncryptedShare` from `qfc-sss`, creating a cycle.
- Put them in `qfc-server-wallet` (top-level). Rejected — subordinate crates would have to depend "up", inverting the workspace shape.
- Use generic type parameters in each crate. Rejected — destroys ergonomics; the cross-crate types are stable enough to be concrete.

**Note:** RFC §1.3 explicitly argued for six crates as "the smallest split that gives meaningful seams". The 7th crate is internal-only (`publish = false`), and its raison d'être is *types*, not *seams* — so the §1.3 reasoning still holds. Will fold a one-line acknowledgement into the next RFC revision.

---

## D2 — `SecretBytes` exposes inner bytes through an explicit `.expose()` method

**What:** `SecretBytes` wraps `Zeroizing<Vec<u8>>` with constant-time `Eq` and a redacting `Debug`/`Display`. The only way to read the underlying bytes is `secret.expose()`.

**Why:** Audits and code reviews can grep for `\.expose\(` to enumerate every site where secret material is exposed. Naming the accessor `as_ref` or `as_slice` would hide secret access behind the standard trait surface, making the audit much harder.

**Alternatives considered:**
- `Deref<Target = [u8]>`. Rejected — exposes secrets implicitly.
- `AsRef<[u8]>`. Rejected — same problem.
- No accessor (callers pass `SecretBytes` only). Rejected — the underlying crypto libraries need `&[u8]`.

---

## D3 — SSS chunks at 31 bytes, not 32

**What:** `qfc-sss::shamir` chunks the secret into 31-byte blocks, pads each chunk to 32 bytes with a leading `0x00`, then splits each padded chunk as a `k256::Scalar`.

**Why:** A random 32-byte block exceeds the secp256k1 scalar order (`n ≈ 2^256 - 2^128 - …`) with probability ≈ 2⁻¹²⁸. That is small in absolute terms but enables a rejection-sampling branch that would have to be tested for distribution. 31-byte chunks + leading zero means every input is strictly less than `n`, no rejection sampling, no carry-over branch.

**Alternatives considered:**
- 32-byte chunks with a rejection loop. Rejected — adds an attacker-visible non-constant-time branch.
- Switch field to a >256-bit prime (e.g. P-384). Rejected — heavier deps for no benefit.
- Use a byte-level SSS over GF(2⁸). Rejected — `vsss-rs` doesn't expose this, and we'd need our own primitive.

---

## D4 — Recoverable secp256k1 verify double-checks `v`

**What:** `Secp256k1RecoverableSigner::verify` first checks `ecdsa.verify(pk, msg, (r,s))`, then recovers the pubkey from `(digest, sig, v)` and compares it to the supplied pubkey.

**Why:** A signature `(r, s)` that verifies under `pk` *and* a maliciously-chosen `v` that recovers to a different pubkey is a class of bug that has shipped in production wallets. Costs one extra scalar multiplication per verify; that's cheap insurance.

**Alternatives considered:**
- Trust `v` as opaque metadata. Rejected — defeats the purpose of binding recovery into the signature.
- Skip the underlying `(r, s)` verification and only check recovery. Rejected — recovery alone doesn't validate the curve operation.

---

## D5 — SLIP-0010 ed25519 derivation is hand-rolled

**What:** `qfc-enclave::derivation::derive_ed25519_slip10` is an in-tree implementation of SLIP-0010 — about 50 lines of HMAC-SHA512 with `"ed25519 seed"` as the master key.

**Why:** SLIP-0010 ed25519 only supports *hardened* derivation, so the math is much simpler than BIP32's chain-of-public-key derivation. Pulling in a single-purpose crate like `ed25519-hd-key` would add an unmaintained dep for code that fits in one screen. Test vectors from SLIP-0010 spec pin the implementation.

**Alternatives considered:**
- `ed25519-hd-key` (or similar). Rejected — last activity > 12 months on most candidates as of M1.
- Roll in a generic `slip10` crate. Rejected — same concern, broader surface.

---

## D6 — `LocalFsShareStore` takes a raw 32-byte key, not a passphrase

**What:** `LocalFsShareStore::new(root, key: [u8; 32])`. The store does *not* derive the key from a passphrase or load it from a file.

**Why:** Key derivation is an operator-startup concern. RFC §2.2 mentions an age-encrypted file unlocked at server start; that belongs in the orchestrator's bootstrap, not in the store layer. Keeping the store interface narrow lets it compose with `age`, `argon2`, `scrypt`, AWS KMS, or any other key source without rewriting the AEAD logic.

**Alternatives considered:**
- Take a passphrase + KDF inside the constructor. Rejected — pins the KDF choice; bakes it into every store integration.
- Take an `age::Identity`. Rejected — couples the store to one ecosystem.

---

## D7 — Atomic write: tempfile + `sync_all` + `rename`

**What:** `LocalFsShareStore::put` writes to `<file>.bin.tmp`, calls `sync_all`, then `rename`s into place.

**Why:** `rename` is atomic on the same filesystem; `sync_all` makes the data durable before the rename publishes it. Without `sync_all`, a crash between the write and the `rename` could publish a torn file.

**Alternatives considered:**
- Direct write + `sync_all`. Rejected — leaves a partially-written file visible to concurrent readers during the window.
- Write-ahead log + replay. Rejected — overkill for a single-share atomic publish.

---

## D8 — `MockEnclave::new()` is fail-closed via env var

**What:** Constructing a `MockEnclave` for production use requires `QFC_ALLOW_MOCK_ENCLAVE=yes-i-know`. Tests use `MockEnclave::new_for_testing()` / `new_for_testing_with_seed(seed)`, which bypass the env var.

**Why:** "Forgot to swap mock for real" has been a recurring shipping bug in custody systems. Two-pronged defense: (a) the env var means a default-configured deployment can't accidentally use the mock, (b) the explicit `_for_testing` suffix on alternative constructors makes audit grep trivial.

**Alternatives considered:**
- `#[cfg(test)]` gating. Rejected — would prevent integration tests in other crates from using the mock.
- Build-time feature flag. Rejected — same problem.
- Just a doc comment. Rejected — too weak.

---

## D9 — Env-gate is a pure helper, no `unsafe { env::set_var }` in tests

**What:** `MockEnclave::env_gate_open(env_value: Option<&str>) -> bool` is exposed as a `pub(crate)` helper; tests call it with synthetic `env_value`s instead of mutating the process env.

**Why:** Rust edition-2024 makes `std::env::set_var` `unsafe` (the variable mutation is process-global and not safe across threads). The workspace has `#![forbid(unsafe_code)]` on every crate. Refactoring the gate logic into a pure helper sidesteps the issue cleanly — better than adding `serial_test` or relaxing `forbid` for the test module.

**Alternatives considered:**
- Add `serial_test` and gate the env-mutating test behind a global lock. Rejected — adds a dep, and the test is still flaky under high parallelism.
- Move from `forbid` to `deny` so we can `allow` locally. Rejected — `forbid` is stronger and we want to keep it.
- Skip the test entirely. Rejected — the fail-closed property is load-bearing.

---

## D10 — Hybrid policy decision (RFC §2.1 decision #2): enforced as additive trait shape

**What:** The M1 `Enclave::sign_in_enclave` signature does **not** include `policy_decision` or `approvals`. P5's `WalletService::sign` flow collects the policy decision and approvals at the orchestrator level and trusts the enclave to perform only the cryptographic operations.

**Why:** RFC §2.1's hybrid scheme requires both signed-decision verification *and* enclave-side invariant re-checks. The invariants need typed access to `wallet.max_value_cap`, `wallet.contract_allowlist`, etc., which the M1 `Wallet` doesn't yet carry. Deferring the enclave-side hooks to P5/M2 as **additive fields on the existing trait** means M1 ships without them, and adding them later is a minor version bump rather than a breaking change to the trait shape.

**Alternatives considered:**
- Ship empty stub fields in M1 just to lock the shape. Rejected — additive fields are equivalent and cleaner.
- Ship the full hybrid now. Rejected — would expand M1 scope past what RFC §7 budgeted.

---

## D11 — Attestation `raw_payload` preserves the exact bytes signed

**What:** `AttestationDoc` carries both a parsed `payload` field and a `raw_payload: Vec<u8>` field. `verify()` validates the signature over `raw_payload`, then asserts that re-parsing `raw_payload` matches the `payload` field.

**Why:** Serde JSON output is not strictly canonical (Rust's serde-json sorts BTreeMap keys but doesn't re-canonicalize numbers, etc.). If a verifier re-serialized `payload` to check the signature, even an innocuous formatting difference would break verification. Carrying the exact issued bytes eliminates that risk.

**Alternatives considered:**
- Use a strictly canonical encoding (e.g. CBOR or `serde_canonical_json`). Rejected — adds a dep with limited audit history; carrying the bytes is simpler.
- Recompute signing payload from `payload`. Rejected — fragile.

---

## D12 — Audit chain hashes `(preimage ‖ signature)`, not just `preimage`

**What:** `FileAuditSink` advances the chain head as `next_prev_hash = SHA256(preimage ‖ signature)`.

**Why:** Including the signature in the chain hash means that a tamperer who modifies *only* the signature still breaks the chain at the *next* event. Cheap protection against a niche but plausible class of audit-log forgery.

**Alternatives considered:**
- Hash just the preimage. Rejected — signature-only tampering is detectable on that event but not propagated.
- Hash the full JSON line. Rejected — couples chain integrity to JSON output formatting.

---

## D13 — Audit kind tagged by stable `u8`, not by debug-name

**What:** `audit::kind_byte(AuditKind) -> u8` returns a stable single-byte tag used in the signing preimage. The byte assignments are fixed (1..15 in declaration order).

**Why:** Using debug-name strings in the preimage would make any rename a silent breaking change to the chain. The `u8` tag is explicit, fits in one byte, and renumbering becomes a visible breaking change to anyone replaying old logs.

**Alternatives considered:**
- `format!("{kind:?}")`. Rejected — chain integrity tied to debug formatting.
- Hash the serde-string form. Rejected — same problem with rename safety.

---

## D14 — Policy precedence is non-configurable

**What:** `StaticAllowDenyPolicy::evaluate` runs checks in a fixed order: wallet-inactive → chain-deny → chain-allow → requester-deny → requester-allow → default. Operators configure list *contents* but not *order*.

**Why:** Privy and Fireblocks postmortems repeatedly involve allow-list-before-deny-list misorderings. Removing configurable order entirely makes the policy easier to audit and impossible to mis-stack.

**Alternatives considered:**
- Configurable order. Rejected — see above.
- DSL with rule-level priority annotations. Rejected — that's M2 territory; M1 stays fixed.

---

## D15 — Quorum reuses `qfc-enclave::Signer` for approval verification

**What:** `SignedApproval::verify` dispatches via `qfc-enclave::dispatch_signer` rather than re-implementing curve verification.

**Why:** Approval signatures are ordinary curve signatures (ed25519 / secp256k1) over a canonical preimage. There is no reason for `qfc-quorum` to maintain a parallel verify implementation. The added workspace edge (`qfc-quorum → qfc-enclave`) is acceptable because the enclave crate is already audited as the project's source of truth for signature operations.

**Alternatives considered:**
- Independent verify code in `qfc-quorum`. Rejected — duplicate crypto code is a maintenance liability.
- Pass a `Signer` instance into each verify call. Rejected — strictly more verbose with no flexibility benefit.

---

## D16 — Approver identity carries `public_key` and `scheme` on every variant

**What:** Each `ApproverIdentity` variant — `Chain`, `External`, `Hardware`, `NestedWallet` — exposes `public_key()` and `scheme()`. Even `Chain` variant carries an explicit pubkey rather than re-deriving from the address.

**Why:** Verification logic is uniform across variants. Approvals don't need to know whether they came from a chain account or an external key; they just need the bytes. Carrying the pubkey per identity also future-proofs against curve heterogeneity (a nested wallet on ML-DSA approving a secp256k1 wallet's sign request).

**Alternatives considered:**
- Chain variant carries only the address; verification path queries the chain. Rejected — couples approval verification to chain liveness.

---

## D17 — `MAX_APPROVAL_AGE_SECS = 3600`

**What:** Approvals older than 1 hour are rejected as stale at verification time.

**Why:** Per-wallet windows live in M4 with the real approver flows; for M1 we pick a single conservative default. One hour is long enough to survive operator delays and short network outages, short enough that an exfiltrated approval has a bounded replay window.

**Alternatives considered:**
- 5 minutes. Rejected — too tight for human-in-the-loop approvers.
- 24 hours. Rejected — too long for an MVP; better to err short.

---

## D18 — Orchestrator audits at six points per sign

**What:** `WalletService::sign` emits audit events at: `SigningRequested`, `SigningEvaluated`, `QuorumNotified` / `QuorumApprovalReceived` (if quorum), `SigningAttempted`, `SigningSucceeded` or `SigningFailed`.

**Why:** Each transition is a distinct externally-observable state. An ops engineer reading the log should be able to tell the difference between "policy denied" and "enclave rejected" and "quorum timed out" without forensic guessing.

**Alternatives considered:**
- Single audit on completion. Rejected — loses intermediate state.
- One per state transition AND one per error class. Rejected — duplicate signal; intermediate states already cover errors.

---

## D19 — `WalletService::create_wallet` does not consult policy

**What:** Wallet creation is a config-time operation. The orchestrator does not evaluate `Policy::evaluate` on the create path.

**Why:** Per RFC §4.1, wallet creation is upstream of signing-policy enforcement. The policy controls what an *existing* wallet may sign; it does not control whether the operator may create one. Provisioning controls (which operator can call `create_wallet`) live at the API authorisation layer in M2.

**Alternatives considered:**
- Run a "creation policy" first. Rejected — conflates provisioning auth with signing auth.

---

## D20 — Workspace crate version is `0.0.0`; no semver yet

**What:** Every workspace member sets `version = "0.0.0"`. Bumping to `0.1.0` is gated on M2 GA.

**Why:** Until the M2 service surface stabilizes, we don't want callers to read `0.x` as a stability signal. `0.0.0` is the conventional "nothing here yet" version. CI / `cargo publish` is gated by `publish = false` on every crate, so the version field is purely cosmetic.

**Alternatives considered:**
- `0.1.0`. Rejected — premature stability signal.
- Bump in-step with milestones (`0.1.0` at M1, `0.2.0` at M2, etc.). Deferred — will decide at M2 wrap-up.
