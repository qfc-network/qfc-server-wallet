# M3 + M4 retro

A look-back on what shipped against RFC v1.1, what diverged (and why), and what the RFC should pick up before the next milestone starts.

**Status:** retro, written 2026-05-21, covering RFC v1.1 fold-back → M4 (real quorum) → M3 (Nitro skeleton + hybrid verifier + S3+KMS) → CI cleanup (4 commits on `main` since `retro-m1-m2.md` was written, 312 tests).

---

## 1. Headline

| | RFC v1.1 fold-back | M4 (RFC §7) | M3 (RFC §7) |
|---|---|---|---|
| Estimated | ~0.5 sessions | 5–7 sessions | 10–14 sessions (skeleton portion) |
| Actual | ~0.5 sessions, 1 PR | ~4 sessions, 1 PR | ~5 sessions skeleton, 1 PR + 1 CI fix PR |
| Tests | n/a | 228 → 259 (+31) | 259 → 312 (+53 incl. 6 in `enclave/`) |
| Scope hits | All ten retro fold-backs landed | All M4 line items shipped | M3 skeleton (hybrid verifier, Nitro facade, S3+KMS mocked, `LocalFileAnchor`); live AWS path is the M3-GA blocker set |

The big shape: **M3, M4, and RFC v1.1 ran genuinely in parallel** — three subagents in three worktrees off the same `main`. The parent serialised the merges (RFC v1.1 first, then M4, then M3, then the CI cleanup). That sequencing is the same lesson the M1+M2 retro reinforced, plus three new surprises (§4) and one new failure mode (semantic rebase conflict).

---

## 2. What landed vs RFC §7

### M4 — M-of-N quorum

| RFC line | Status | Notes |
|---|---|---|
| Approver registration + identity types | ✅ | `POST/DELETE/GET /approvers`; all four `ApproverIdentity` variants supported (chain, external, hardware, nested-wallet); see [D21](m4-decisions.md#d21) for the `ApproverSetId`/`ApproverId` newtype split |
| Approver sets via `POST /approver-sets` | ✅ | Memory + Postgres backends; cycle detection at create-set time per [D26](m4-decisions.md#d26) |
| Notification channels (webhook + email + on-chain QFC event) | ✅ partial | Webhook (HMAC-SHA256 per [D27](m4-decisions.md#d27)) + on-chain (stub, see §3.3) shipped. Email channel intentionally out — same calendar dep as the on-chain path (operator-side templating) and not blocking M5 |
| Approval submission API | ✅ | `POST /requests/{request_id}/approvals`; verifies signature *before* persisting per [D35](m4-decisions.md#d35) |
| Quorum collection (concurrent listening, threshold, timeout) | ✅ | `OrchestratingApprover` polls + `tokio::sync::Notify` per [D30](m4-decisions.md#d30); replay protected via DB UNIQUE per [D24](m4-decisions.md#d24) |
| Enclave-side approval verification | ✅ | Landed inside the M3 hybrid verifier (`hybrid_verifier::verify_approvals`), see §3.2 — M4 wired the orchestrator-side and the M3 PR closed the enclave-side at the same time |
| Approver-side reference client (Rust + TS) | ⛔ deferred | Not blocking M5; lands when there's a real external approver to point at it |
| Bug bounty program launch | ⛔ deferred to GA | Immunefi page goes live with M3 GA + audit sign-off, not the M4 PR |

### M3 — Nitro Enclave skeleton

| RFC line | Status | Notes |
|---|---|---|
| `NitroEnclave` impl + vsock IPC | ✅ skeleton | Host-side facade + wire types compile by default; real vsock I/O behind `feature = "nitro"` per [D25](m3-decisions.md#d25). See §4.1 for why this was necessary |
| In-enclave binary (`enclave/boot.rs`) | ✅ | Standalone Cargo project per [D26](m3-decisions.md#d26); 6 tests; placeholder `Dockerfile.eif` with TODO digests per [D27](m3-decisions.md#d27) |
| Reproducible EIF build | ⛔ deferred to GA | Dockerfile structure shipped; bit-exact CI rebuild + `eif-reproducibility.yml` workflow are M3-GA |
| Hybrid scheme M3 GA blocker (per RFC §2.1) | ✅ unit-tested | `qfc-policy::SignedPolicyDecision` + `qfc-enclave::hybrid_verifier` (18 unit tests); `Wallet.{max_value_per_tx, contract_allowlist, chain_allowlist}` populated; `EnclaveSignRequest` extended with `policy_decision: Option<_>` + `approvals: Vec<EnclaveApproval>` per [D21](m3-decisions.md#d21) / [D22](m3-decisions.md#d22). End-to-end wiring through `WalletService::sign` is the **next milestone's first deliverable** — see §3.2 |
| Live audit anchor cron | ✅ partial | `LocalFileAnchor` ships per [D28](m3-decisions.md#d28); on-chain submitter blocked on `qfc-core` workspace integration, see retro-m1-m2 §3.6 |
| `S3KmsShareStore` with attestation-conditional KMS | ✅ mock-backed | Generic over `S3Like` + `KmsClient` per [D23](m3-decisions.md#d23); real `aws-sdk-s3`/`aws-sdk-kms` behind a future `feature = "aws"` |
| Attestation verification library | ✅ skeleton | Trait surface ready; real COSE_Sign1 CBOR + AWS Nitro root-cert chain validation deferred per [D24](m3-decisions.md#d24) — `coset` swap planned (RFC §1.5 already lists both) |
| Public attestation verification page | ⛔ deferred to GA | Static site deferred until real PCR0 hashes exist to publish |
| Terraform module + ops runbooks | ⛔ deferred to GA | `qfc-server-wallet-ops` work; lives outside Claude's runway |

### RFC v1.1

All ten fold-backs from retro-m1-m2 §5 landed in PR #14. No drift.

---

## 3. Divergences from RFC v1.1 — explicit list

### 3.1 M3 ships mock-backed AWS (deliberate)

RFC v1.1 §7 already lists "external security audit + AWS region work" as M3 GA gates outside Claude's runway. The M3 PR ships:
- `S3KmsShareStore` mock-backed end-to-end (the trait surface is exercised against `MockS3Client` + `MockKmsClient`); real `aws-sdk-*` behind a future `feature = "aws"` per [m3-decisions D23](m3-decisions.md#d23)
- `verify_attestation.rs` ships the trait surface using JSON as a stand-in for CBOR per [m3-decisions D24](m3-decisions.md#d24); real `coset` parsing + AWS Nitro root chain lands once the audit vendor signs off on the verifier
- `Dockerfile.eif` placeholder digests per [m3-decisions D27](m3-decisions.md#d27)

**RFC fold-back:** none required — RFC v1.1 §7 (M3 ships) already names live AWS as the GA gate; this is the deferral set, not a divergence from the written plan.

### 3.2 Hybrid verifier ships unit-tested, not yet wired through the orchestrator

`WalletService::sign` continues to pass `policy_decision: None, approvals: Vec::new()` into `EnclaveSignRequest`. The `HybridVerifier` is unit-tested in isolation (18 tests in `qfc-enclave/src/hybrid_verifier.rs`); the in-flow integration test (`WalletService` signs a `PolicyDecision`, the enclave re-verifies the signature, the round-trip is end-to-end-tested) is the **next milestone's first deliverable** per [m3-decisions D29](m3-decisions.md#d29).

PolicyServiceSigner wiring is running in another worktree as this retro is being written. The trait surface (`Option<SignedPolicyDecision>` per [D21](m3-decisions.md#d21)) is additive, so M4 callers compile unchanged today and will continue to compile after the wiring PR lands.

**RFC fold-back:** §7 (M3 ships) should note `PolicyServiceSigner` end-to-end wiring as the closing piece of the §2.1 hybrid scheme.

### 3.3 `OnChainQfcEventApprover` is a stub

The M4 PR ships `OnChainQfcEventApprover` over `tokio::broadcast` per [m4-decisions D28](m4-decisions.md#d28); real chain submission needs the `qfc-core` workspace dep that retro-m1-m2 [§3.6](retro-m1-m2.md) flagged. The audit event "we tried to notify the on-chain channel" still fires and subscribers can prove behaviour.

**RFC fold-back:** §7 (M4 ships) should note this is shipped-as-stub with the same `qfc-core` blocker as the audit anchor cron.

### 3.4 Cycle detection is create-set scoped

`MAX_NESTING_DEPTH = 3` per [m4-decisions D26](m4-decisions.md#d26). The DFS walks every existing set that mentions a nested wallet — at *create-set time*. This catches stored-set co-membership cycles but does **not** catch service-layer attachment cycles (a wallet attaching a set that — through wallet-attachment, not through nested-wallet membership — reaches itself). The honest caveat is recorded in [D26](m4-decisions.md#d26).

**RFC fold-back:** none — this matches the v1.1 §2.5 wording ("cycle check at approver-set registration time, hard limit on nesting depth at evaluation time"). The caveat is the cycle-check, not the RFC text.

---

## 4. What surprised us

### 4.1 vsock cross-platform pain

`tokio-vsock` pulls in `vsock 0.4.0`, which uses Linux-only `libc::accept4`, `SOCK_CLOEXEC`, `VMADDR_CID_LOCAL`, and `MsgFlags::MSG_NOSIGNAL`. The crate doesn't compile on macOS — not "errors at run time", "errors at `cargo check`". macOS dev needs `feature = "nitro"` **off**; CI on Ubuntu runs `--all-features` and pulls it in.

The fix was to gate the dep tree (not just the call sites) on the feature flag — per [m3-decisions D25](m3-decisions.md#d25). The trait surface and wire types stay compileable on every host; only the actual `tokio_vsock::VsockStream::connect` call sits behind the `nitro` feature.

**Lesson:** feature-gating an entire dep tree (not just call sites) is the right pattern for any Linux-only transitive dep. The host workspace stays portable; CI proves the Linux path.

### 4.2 `sqlx-macros` build chain pulls `sqlx-mysql` → `rsa 0.9.10` (RUSTSEC-2023-0071, Marvin attack)

Even though `qfc-quorum` and `qfc-audit` only use Postgres and the sqlx dep has `default-features = false`, `sqlx-macros-core` enables **every backend at compile time** for query verification — including `sqlx-mysql`, which depends on `rsa 0.9.10`. `cargo-audit` flagged it as a Marvin-attack vulnerability.

The crate doesn't link into the production binary (it's build-time only for `sqlx::query!` macros), so the right answer was an ignore in both `deny.toml` *and* `audit.yml`. The CI fix PR (#17) was the second commit that touched the ignore list — the first ignore landed with M3 and missed this one.

**Lesson:** dev-deps and build-time deps still get audited. Exclusion lists must live in **both** `deny.toml` AND the `audit.yml` workflow command. The two have to stay in sync (a checklist item for the v1.2 fold-back).

### 4.3 Subagent test gates missed `cargo fmt --check` and `cargo doc -D warnings`

Both M3 and M4 subagents ran `cargo test --workspace` + `cargo clippy --workspace -- -D warnings` locally and reported green. CI on `main` failed both PRs immediately on `cargo fmt --check` and `cargo doc --no-deps`. The PR #17 cleanup commit (5 files reformatted + one doc-link rewrite) was pure CI-parity work that the subagents should have caught locally.

The CI workflow runs **four** gates: `test`, `clippy`, `fmt`, `doc`. The subagent briefs were checking the first two. Adding a "CI parity checklist" to the standard subagent prompt — all four gates, plus `cargo audit` and `cargo deny check` — is a one-line process fix.

**Lesson:** the standard subagent brief needs an explicit "before reporting green, run all four gates + audit/deny/vet". This goes into RFC §8.6 (Contributor process).

### 4.4 Semantic merge conflicts at rebase time

`PolicyDecision::RequireQuorum.approver_set` was retyped from `ApprovalId` to `ApproverSetId` by M4 (per [m4-decisions D21](m4-decisions.md#d21)). M3 (built against pre-M4 `main`) compiled green in its worktree, using the old `ApprovalId` type. `git rebase main` auto-merged the textual conflicts cleanly; the **type mismatch only surfaced at `cargo check`** after the rebase finished.

This is a category of merge failure that `git` can't see — the text resolves, the types don't. Recovery was a one-line type fix in M3 plus a re-run of the M3 test suite, but the surprise was that the rebase reported "clean" while the workspace was broken.

**Lesson:** parallel subagents need to know the **shared-type surface** they should not retype. The parent agent's pre-rebase planning step should scan for cross-subagent type renaming (search for retyped `pub struct` / `pub enum` field signatures across the worktrees). When one subagent is renaming or retyping a workspace-shared type, the parallel subagents either get notified or get rebased first.

### 4.5 `--all-features` rustdoc redundant-link lint caught a latent M2 P5 bug

The CI fix PR removed a redundant explicit link target in `observability.rs` (M2 P5 code) that intra-doc resolution finds on its own. The link had been passing CI for a month — until M3's `nitro` feature flipped `--all-features` to actually pull in new crates, which surfaced the latent `cargo doc -D warnings` lint.

**Lesson:** lint coverage is feature-set-dependent. Adding a feature can flip latent warnings on. CI runs `--all-features` by design; the subagent local checks should too.

### 4.6 Worktree-held branches block local branch cleanup

After `gh pr merge --delete-branch`, the remote branch is gone but the local branch (held by a subagent worktree) stays. `git branch -d` refuses to delete a branch checked out by another worktree. The parent agent's cleanup pass either has to `git worktree remove <path>` first, or accept noise.

Not a problem in practice — the worktrees are scratch by design — but worth documenting if the parallel-subagent workflow becomes standard. The right pattern is `git worktree remove --force <path> && git branch -d claude/<task-slug>` as a single cleanup step.

**Lesson:** parallel-subagent cleanup is a two-step process. The parent agent's "merge complete" hook needs both worktree removal and local branch delete.

---

## 5. What to fold back into the RFC before the next milestone

A short list — each one is a small edit, mostly section-level annotation or footnote:

| RFC section | Edit |
|---|---|
| §7 (M3 ships) | Note that `PolicyServiceSigner` end-to-end wiring is the closing piece of the §2.1 hybrid scheme; reference [m3-decisions D29](m3-decisions.md#d29) and the upcoming PR. The verifier ships unit-tested today |
| §7 (M3 ships) | Note that the live audit anchor cron's **on-chain submitter** is blocked on `qfc-core` workspace integration (the file-backed `LocalFileAnchor` is shipped); reference retro-m1-m2 [§3.6](retro-m1-m2.md) |
| §7 (M4 ships) | Note that `OnChainQfcEventApprover` ships as a `tokio::broadcast` stub with the same `qfc-core` blocker as the audit anchor cron; reference [m4-decisions D28](m4-decisions.md#d28) |
| §8.6 (Contributor process) | Add a "CI parity checklist for subagents" subsection mentioning the four CI gates (`cargo test`, `cargo clippy`, `cargo fmt --check`, `cargo doc -D warnings`) plus the `cargo audit` / `cargo deny check` / `cargo vet` expectations. Subagent briefs reference this checklist |
| §12.4 (CI workflows) | Add the cargo-audit ignore-list note + the requirement that `audit.yml --ignore` flags must stay in sync with `deny.toml [advisories].ignore`. Reference the four current ignores (RUSTSEC-2025-0111, -2025-0134, -2024-0370, -2023-0071) with their justifications |
| §12.4 (CI workflows) | Strike the "MSRV warn" / "coverage informational" rows from the workflow table — those workflows are not currently in `.github/workflows/`. The table should match reality |

A single PR — call it `rfc(v1.2): M3+M4 retro fold-back` — collects all of the above. Worth ~0.5 session hours.

---

## 6. Recommended next milestone

The session that produced this retro kicked off **three parallel options** at the same time:

1. `PolicyServiceSigner` end-to-end wiring (closes [m3-decisions D29](m3-decisions.md#d29) — the hybrid verifier integration test)
2. M5 work proper (PQ signing + minimal QVM decoder per RFC §7)
3. This retro + RFC v1.2 fold-back

The chosen pattern: **user picks one or all; subagents execute in parallel; parent serialises the merges**. Same shape as M3+M4+RFC-v1.1; same lessons apply (§4.4 — pre-rebase shared-type scan).

After this batch lands, the **natural next ones** are both blocked on external state:

- **Real `qfc-core` workspace integration** (unblocks the on-chain audit anchor cron and `OnChainQfcEventApprover` real submission; needs `qfc-types`/`qfc-crypto` crates.io publish per RFC §1.4 and retro-m1-m2 [§3.6](retro-m1-m2.md))
- **M3 GA work** — real `aws-sdk-s3`/`aws-sdk-kms` impls behind the `aws` feature, real COSE_Sign1 + AWS Nitro root-cert chain in `verify_attestation`, bit-exact EIF reproducibility, external security audit (Trail of Bits / Zellic / Cure53)

Both are calendar-bound; both can proceed in parallel with M5 once the PolicyServiceSigner PR is in. Recommendation: queue the `qfc-core` publish workflow now (the calendar lag is dominated by `qfc-core` reviewer availability, not Claude session time), and start the audit vendor outreach in parallel with M5 code work.

---

## 7. Closing

- M3, M4, and the RFC v1.1 fold-back all shipped on or under the §7 session estimate; the parallel-subagent pattern stays the right call.
- All deliberate divergences from RFC v1.1 are recorded above (and most were called out in [`m3-decisions.md`](m3-decisions.md) or [`m4-decisions.md`](m4-decisions.md) at the time).
- The biggest *latent* risk for the next milestone is the §4.4 pattern: parallel subagents can produce a textually-clean rebase that fails at type-check. Pre-rebase shared-type scanning is now part of the parent agent's planning step.
- 312 tests passing on `main` (228 → 259 with M4, 259 → 312 with M3 incl. 6 in the standalone `enclave/` project). The hybrid verifier unit tests cover signature freshness, request/wallet binding, hard-ceiling re-evaluation, approval signature dispatch, and the 24h / 64-approval defensive bounds. All crypto-touching paths still have property tests + golden vectors from M1+M2.

Next: open `rfc(v1.2)` PR with §5 fold-backs; then PolicyServiceSigner + M5 in parallel.
