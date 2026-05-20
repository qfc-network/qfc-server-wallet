# M1 + M2 retro

A look-back on what shipped against RFC v1.0, what diverged (and why), and what the RFC should pick up before M3 starts.

**Status:** retro, written 2026-05-20, covering bootstrap → M1 P1–P6 → M2 P1–P6 (15 commits on `main`, 228 tests).

---

## 1. Headline

| | M1 (RFC §7) | M2 (RFC §7) |
|---|---|---|
| Estimated | 6–8 sessions | 4–6 sessions |
| Actual | ~7 sessions, 6 stacked PRs | ~6 sessions, 6 parallel PRs |
| Tests | 124 at M1 wrap | 228 at M2 wrap (+104) |
| Scope hits | All M1 line items shipped | Five of six M2 line items shipped |

One M2 line item (`KafkaAuditSink`) was deliberately dropped, see §3.2 below.

---

## 2. What landed vs RFC §7

### M1

| RFC line | Status | Notes |
|---|---|---|
| Workspace + six crates + CI | ✅ + 1 | Seven crates (added internal `qfc-wallet-types`, see §3.1) |
| `Enclave`, `ShareStore`, `Signer`, `Policy`, `QuorumApprover`, `AuditSink` traits | ✅ | All six trait surfaces stable |
| `MockEnclave` (fail-closed) | ✅ | Env-gated per [D8](m1-decisions.md#d8) |
| `LocalFsShareStore` + `MockShareStore` | ✅ | XChaCha20-Poly1305, atomic write |
| `Ed25519Signer`, `Secp256k1Signer`, `Secp256k1RecoverableSigner` | ✅ | All three; recoverable double-checks `v` per [D4](m1-decisions.md#d4) |
| BIP32/BIP39 + SLIP-0010 derivation | ✅ | SLIP-0010 hand-rolled per [D5](m1-decisions.md#d5) |
| Basic `Policy` (allow/deny) | ✅ | `StaticAllowDenyPolicy` with fixed precedence per [D14](m1-decisions.md#d14) |
| `FileAuditSink` | ✅ | Hash-chained, signed; chain hashes `(preimage ‖ signature)` per [D12](m1-decisions.md#d12) |
| E2E test: create → sign → verify | ✅ | 6 E2E + 4 proptests |

### M2

| RFC line | Status | Notes |
|---|---|---|
| `axum` HTTP API (REST, OpenAPI) | ✅ | M2 P1; `utoipa` swagger ui |
| Full Policy DSL: chains, contracts, methods, value caps, time windows, rate limits, VM-shape | ✅ | M2 P3; token-bucket per `(wallet, requester)` per decision #10 |
| VM decoders: `EvmDecoder` | ✅ | M2 P4; legacy + EIP-2930/1559/4844 via `alloy-rlp` |
| VM decoders: `QvmDecoder` | ⛔ deferred to M5 | Per decision #5 / §9.6 — `qfc-core` has no `QvmCall` tx variant |
| VM decoders: `WasmDecoder` | ⛔ deferred indefinitely | Per decision #5 — `qfc-core` has no WASM execution path |
| `PostgresAuditSink` + hash chain + anchor commit | ✅ partial | M2 P2; sqlx + testcontainers. Anchor commit is a **stub** (`anchor.rs`); daily cron landing in M3 |
| `tracing-opentelemetry` + Prometheus `/metrics` | ✅ | M2 P5; OTLP gRPC export + `metrics-exporter-prometheus` 0.15 |
| Property tests for policy, golden tests for VM decoders | ✅ | Proptest in `qfc-policy`; golden EVM vectors in `tests/evm_golden.rs` |
| Bruno collection | ✅ | M2 P6; `dev/bruno/qfc-server-wallet/` |
| Docker compose local dev | ✅ + | M2 P6; bonus Grafana + Mimir + OTel collector |

---

## 3. Divergences from RFC v1.0 — explicit list

These are the places the implementation does not match the RFC as written. Each is either deliberate (with a recorded rationale) or process drift (with a follow-up).

### 3.1 Seven crates, not six

RFC §1.3 argued for six crates as "the smallest split that gives meaningful seams". Implementation has seven: the extra one is internal `qfc-wallet-types`, holding cross-crate ID/scheme/secret types.

- **Driver:** otherwise `qfc-enclave` and `qfc-sss` form a dep cycle (the enclave needs `EncryptedShare`, the share store needs `WalletId`).
- **Rationale:** see [D1](m1-decisions.md#d1).
- **RFC fold-back:** §1.1 / §1.3 should acknowledge the 7th internal crate. The "meaningful seams" reasoning still holds — `qfc-wallet-types` exists for *types*, not *seams*. One-line addition.

### 3.2 KafkaAuditSink dropped from M2

RFC §2.6 listed three M2 backends: Postgres, File, Kafka. We shipped Postgres + File only.

- **Driver:** Decision #6 in v1.0 already softened Kafka to "optional, picked at config time". No customer needed it for M2 dev/staging.
- **Effect on threat model:** none — Postgres is the durable audit backend and File is the local-dev backend. Kafka is opt-in for multi-tenant high-throughput, which is post-M3 anyway.
- **RFC fold-back:** §2.6 should list Kafka as "M2+ optional", not "M2 baseline". Strike the M2 line.

### 3.3 Wallet record is thinner than RFC §3.1

The shipped `WalletConfig` carries `{display_name, owner_id, scheme, threshold, total, policy_id}`. RFC §3.1 specified `{wallet_id, qfc_address, display_name, owner_id, created_at, status, master_public_key, scheme, hd_capable, policy_id, quorum_config, share_config, enclave_pcr_constraint}`.

Missing or deferred:
- `qfc_address` — derivable from `master_public_key`; recompute on demand for now. **M3 fold-back.**
- `hd_capable` — derivable from `scheme` (ed25519/secp256k1 → true; ML-DSA → false). Keep derived.
- `quorum_config` — quorum is policy-driven in M2; per-wallet override is M4 territory.
- `share_config.share_locations[]` — single `ShareStore` instance in M2; multi-store fan-out is M3 (`S3KmsShareStore`).
- `enclave_pcr_constraint` — the whole point of M3; not meaningful with `MockEnclave`.

**RFC fold-back:** §3.1 is correct as written; what's missing is a note that the M1/M2 in-memory `WalletRecord` is a **subset projection** of the full §3.1 shape, with these fields landing as M3 (PCR, share fan-out) and M4 (quorum config) feature work. Add a "shipping order" annotation table.

### 3.4 `Enclave::sign_in_enclave` missing `policy_decision` and `approvals`

RFC §2.1 specified `EnclaveSignRequest { …, policy_decision: SignedPolicyDecision, approvals: Vec<SignedApproval> }`. Shipped signature has neither — the orchestrator (`WalletService::sign`) collects the policy decision and approvals and trusts the enclave to do only the crypto.

- **Driver:** the hybrid scheme needs typed access to `wallet.max_value_cap` / `wallet.contract_allowlist` (RFC §2.1 second paragraph). M1 `Wallet` doesn't yet carry those. Adding stub fields in M1 wouldn't have exercised the verification path.
- **Rationale:** see [D10](m1-decisions.md#d10).
- **Trade-off:** in M1+M2 the enclave is a *crypto box* only; the security argument "policy decision is reverified inside the TEE" doesn't yet exist. With `MockEnclave` this is fine; with `NitroEnclave` (M3) we must add these fields *and* the wallet must carry hard ceilings *or* the hybrid policy security argument is hollow.
- **RFC fold-back:** §2.1's hybrid scheme is a **hard prerequisite for M3 GA**, not optional. The M3 line item in §7 should be expanded to call this out: "EIF binary includes invariant checker + signed-policy verifier; `Wallet.{max_value_cap, contract_allowlist, chain_allowlist}` populated; `EnclaveSignRequest` extended with `policy_decision` and `approvals` as additive fields." Without this, M3 ships a TEE that doesn't enforce the hybrid scheme.

### 3.5 Rust toolchain: 1.88.0, not 1.83.0

RFC §12.1 pinned `channel = "1.83.0"`. Implementation runs `1.88.0`.

- **Driver:** two forced bumps — (a) `wit-bindgen 0.57` (transitive via `wasip2` from sqlx?) needs edition 2024 → ≥ 1.85; (b) `cargo-deny 0.18.4+` parses CVSS 4.0 advisory entries → ≥ 1.88.
- **Effect on reproducible EIF (§9.5):** none yet — M3 will pin to whatever the EIF build container ships; the host toolchain is decoupled.
- **RFC fold-back:** §12.1 should say "current pin: 1.88.0" with a brief note that 1.83.0 was the initial target; revisit pin policy at M3 when the EIF build container is finalized.

### 3.6 No `qfc-core` dependency yet

RFC §1.4 specified an interim git dep on `qfc-core` (for `qfc-types::Address`, `qfc-crypto::Keypair`) → crates.io version dep before M1 tag.

- **Status:** workspace has *zero* `qfc-core` references. Public-key types are `Vec<u8>` everywhere, addresses don't exist as a typed value.
- **Driver:** M1 didn't need on-chain account derivation; the standalone `WalletId` (ULID) was enough. Adding an external dep before functional need would have added rebuild churn.
- **RFC fold-back:** §1.4's "interim git dep" step is unblocked but **also unstarted**. Two paths: (a) keep `Vec<u8>` everywhere until M3 needs `qfc-address` derivation; (b) start the `qfc-types`/`qfc-crypto` publish workflow now (it has its own calendar lag — see RFC §10 decision #1) so the dep is ready when M3 lands. Recommendation: **start (b) at the same time as M3 vendor outreach** — both are calendar-bound, both can proceed in parallel with M3 code.

### 3.7 Audit anchor commit is a stub

RFC §2.6 said: "the daily anchor commitment (M2) pins the chain head to an on-chain QFC transaction". M2 P2 shipped `qfc_audit::anchor` with the type shape, but the actual cron job + chain submission is a stub.

- **Driver:** chain submission needs the `qfc-core` dep (§3.6) and a funded operator account on the QFC chain.
- **RFC fold-back:** move the live anchor-cron to **M3**, not M2. Update §7 (M2 ships) → §7 (M3 ships) for the cron component. Stub stays in M2.

### 3.8 Internal code review before M2 GA — didn't happen

RFC §8.4 said "Internal code review (independent qfc team) — before M2 GA".

- **Status:** Claude was the sole author. No qfc-core team rotation happened.
- **Effect:** M2 shipped without a human security pass. Acceptable while no production traffic exists; **must not be skipped for M3**.
- **RFC fold-back:** §8.4 should clarify that pre-M2 internal review is **non-blocking when there is no production deployment**; pre-M3 external audit (Trail of Bits / Zellic / Cure53) becomes the first mandatory human review. Or add a note: "the M1+M2 milestones shipped to a non-production posture; first human security review is the M3 external audit."

### 3.9 `gRPC` and `tonic` are dead weight in `[workspace.dependencies]`

RFC §1.5 listed `tonic` for gRPC. Decision #7 in v1.0 moved gRPC to M4. Workspace `Cargo.toml` still pulls in nothing here — actually fine, we *didn't* add it prematurely. Verifying: no `tonic` in `Cargo.toml`. ✅ No drift.

### 3.10 Squash-merge rebase pain (process, not RFC)

Six stacked PRs against a single `main` mean each squash merge changes the commit SHA, breaking the next branch's `git merge-base`. Resolution required `git rebase main` + conflict resolution per branch on `Cargo.lock` / `Cargo.toml` / `deny.toml`.

- **Driver:** GitHub squash-merge policy + stacked PRs. Each rebase generated 30-90s of conflict resolution work.
- **Trade-off:** stacked PRs gave good per-step reviewability; the rebase tax is real.
- **Fold-back:** not RFC. Process note: for M3 (which is fewer, larger PRs because of EIF reproducibility constraints), expect less stacking. For M4 quorum work (multiple sub-services), stacked PRs again — pre-prepare a "rebase after merge" script.

---

## 4. What surprised us

### 4.1 vsss-rs API was guessed wrong twice

The initial Shamir code used `IdentifierPrimeField` + `shamir_split` — neither exists. Correct API: `shamir::split_secret::<F, I, S>(t, n, secret, rng)` with `[u8; 33]` share representation. ~2 hours of rework.

**Lesson:** for unfamiliar crypto crates, read the crate docs *and* one example before writing the wrapper. `cargo doc --open` first.

### 4.2 Subagent overload crashes are real

P1, P3, P4 subagents (M2) each hit Anthropic 529 Overload mid-work. Recovery required minimal manual fixes (clippy, version pinning, license additions). No code was lost; the worktree state was inspectable.

**Lesson:** subagent crashes are recoverable as long as the worktree state is salvageable. Plan recovery into the workflow; don't assume green from the agent's last status.

### 4.3 `unsafe std::env::set_var` in tests broke `forbid(unsafe_code)`

Rust edition 2024 marked `std::env::set_var` `unsafe`. The fail-closed env-gate test that called `set_var` couldn't compile under `#![forbid(unsafe_code)]`. Fix was to extract the gate as a pure helper. See [D9](m1-decisions.md#d9).

**Lesson:** edition-2024 audit on dep tree is worth doing once during bootstrap. Catches this kind of surprise early.

### 4.4 `primitive-types` 0.12 → 0.13 broke `to_big_endian`

EVM golden tests caught `to_big_endian()` changing from in-place buffer write to return-array between primitive-types 0.12 and 0.13. The golden test caught it; no production effect.

**Lesson:** dep version bumps in crypto-adjacent crates need golden test coverage. We had it; that's the win.

### 4.5 RFC §9.6 was right — and almost saved a wrong call

The honest QVM/WASM ABI assessment in RFC v1.0 (resolved after `qfc-core` code inspection) meant M2 didn't ship dead-end decoders. If we'd built `QvmDecoder` against a guessed ABI, every line of it would be thrown away when `qfc-core` lands a real `QvmCall`. The pre-M1 honesty paid for itself.

**Lesson:** when a dependency hasn't shipped its ABI yet, the right move is to defer, not stub. The deferral cost is one row in the M5 line item; the stub cost is a whole decoder.

---

## 5. What to fold back into the RFC before M3

A short list — each one is a small edit, mostly section-level annotations:

| RFC section | Edit |
|---|---|
| §1.1, §1.3 | One line acknowledging the 7th internal crate `qfc-wallet-types`; reasoning unchanged |
| §2.1 | Promote "hybrid policy verification inside enclave" from prose to **M3 GA blocker** — list as such in §7 (M3) |
| §2.6 | Strike Kafka from M2 backends; move to "M2+ optional" |
| §3.1 | Add "shipping order" annotation: `WalletRecord` is a subset in M1/M2; fields landing in M3 / M4 |
| §7 (M2 ships) | Strike `QvmDecoder` + `WasmDecoder` (already moved by decision #5 but §7 wasn't fully reconciled) |
| §7 (M2 ships) | Strike `KafkaAuditSink` line |
| §7 (M3 ships) | Add: extend `EnclaveSignRequest` with `policy_decision` + `approvals`; populate `Wallet.{max_value_cap, contract_allowlist, chain_allowlist}` |
| §7 (M3 ships) | Add: live audit anchor cron (deferred from M2) |
| §8.4 | Clarify: pre-M2 internal review non-blocking when no prod posture; pre-M3 external audit is first mandatory human review |
| §12.1 | Update toolchain pin to `1.88.0`; note 1.83.0 was initial target; revisit at EIF build container freeze |

A single PR — call it `rfc(v1.1): retro fold-back` — collects all of the above. Worth ~0.5 session hours.

---

## 6. Recommended next milestone

**M4 (quorum) before M3 (Nitro Enclave)** — same recommendation as the session-start option list, now better supported:

- M3 requires §3.4 / §2.1 hybrid scheme (per §3.4 above), and the hybrid scheme is much easier to design against if we already have *real* approvers (not mocks).
- M4 unblocks the most product-visible feature (M-of-N treasury approvals) without an AWS/audit calendar dependency.
- M3 sequencing benefits: once M4 ships, M3's hybrid-scheme enclave code has *integration tests with real approvals*, not mocks. Sharper threat model coverage.

If M3 must come first for external-stakeholder reasons (audit vendor calendar, AWS region work), it can — but call out that the M3 hybrid scheme will ship against mock approvers and be re-validated in M4.

---

## 7. Closing

- Both milestones shipped on or under the §7 session estimate.
- All deliberate divergences from RFC v1.0 are recorded above (and most were called out at the time in [`m1-decisions.md`](m1-decisions.md) or as M2 P# PR descriptions).
- The biggest *latent* risk for M3 is the §3.4 gap: shipping a Nitro EIF whose `sign_in_enclave` isn't doing hybrid policy verification leaves the most important security argument unmade. Promote this to a hard M3 GA gate.
- 228 tests, all passing on `main`. Audit chain replay works across the 13 events of an E2E happy-path. The crypto-touching code paths have property tests + golden vectors.

Next: open `rfc(v1.1)` PR with §5 fold-backs, then start M4 unless told otherwise.
