# M3 — key technical decisions

A record of the non-obvious calls made during the M3 (Nitro Enclave)
skeleton implementation. Each entry: **what**, **why**, **alternatives
considered**. Decisions resolved by the RFC are not repeated — see
`server-wallet-rfc.md` §10. M1/M2 decisions live in `m1-decisions.md`.

Generated alongside the M3 skeleton PR (2026-05-21).

---

## D21 — `EnclaveSignRequest` adds `policy_decision: Option<_>`, not required

**What:** The hybrid scheme additive field is `Option<SignedPolicyDecision>`,
not `SignedPolicyDecision`. The `HybridVerifier` has a
`require_signed_decision` flag that defaults to `true`; tests can flip it
off via `with_require_signed_decision(false)`.

**Why:** M1/M2 callers (`MockEnclave` callers in tests, the orchestrator
before policy-service signing is wired up) need to keep compiling. An
Option keeps `EnclaveSignRequest` additive. The verifier defaults to
fail-closed so production-mode builds get the right behavior; opt-out for
tests is explicit.

**Alternatives considered:**
- Make the field mandatory. Rejected — breaks every existing call site,
  not strictly additive.
- Add a separate `EnclaveSignRequestV2` type. Rejected — type churn for
  no benefit.
- Default to `require_signed_decision = false`. Rejected — defeats the
  fail-closed posture the RFC requires.

---

## D22 — `EnclaveApproval` is a fresh data mirror, not a re-export of `qfc_quorum::SignedApproval`

**What:** `qfc-enclave` defines its own `EnclaveApproval` struct with the
same shape as `qfc_quorum::SignedApproval`. The orchestrator converts at
the call site.

**Why:** `qfc-quorum` already depends on `qfc-enclave` (per D15 — quorum
uses the enclave's `dispatch_signer` for approval verification). Adding
`qfc-enclave → qfc-quorum` would create a cycle. Options to break the
cycle were:
1. Move `SignedApproval` to `qfc-wallet-types`. Refactor cost: every
   inherent method moves to a free function; affects external API.
2. Move `dispatch_signer` to a tiny crate both can depend on. Refactor
   cost: an extra crate for one dispatch helper.
3. Keep `SignedApproval` as is, add a mirror in `qfc-enclave`. Refactor
   cost: ~30 lines of duplicate field declarations + a `From` impl in
   the orchestrator.

Option 3 is the smallest blast radius. The verifier validates that the
approval-preimage byte layout matches `qfc_quorum`'s, with the
expectation that the matching is exercised by an integration test in
`qfc-server-wallet`.

**Alternatives considered:** see above — all three were tried in scratch.
The cycle-break-via-relocation alternatives all required touching files
the M4 subagent is editing in parallel. Mirror keeps the worktrees
isolated.

---

## D23 — Mock-backed AWS path; real `aws-sdk-*` behind a feature flag

**What:** `S3KmsShareStore<S, K>` is generic over `S3Like` + `KmsClient`
trait surfaces. Default build ships `MockS3Client` + `MockKmsClient` only.
Real `aws-sdk-s3` + `aws-sdk-kms` integration is gated behind a future
`feature = "aws"` (not yet wired in the skeleton — the trait surface is
ready, the impl lands in a follow-up PR once AWS credentials are
available).

**Why:** The brief is explicit: "code-only, no AWS deploy". The harness
has no AWS access, so anything that *requires* AWS calls can't be
verified end-to-end. The mock-backed path lets us exercise the
attestation-conditional decrypt predicate as a unit test today.

**Alternatives considered:**
- Skip M3.7 (`S3KmsShareStore`) entirely until AWS access is available.
  Rejected — leaves the trait shape un-validated against real
  integration thinking.
- Pull `aws-sdk-*` in as default deps but no-op them. Rejected — drags a
  large dep tree (and a 5–10s build-time hit) into every dev environment
  for no benefit.
- Hand-roll an in-tree HTTP client against `s3.<region>.amazonaws.com`.
  Rejected — `aws-sdk-s3` already does signing / retry / regions; no
  reason to re-do that.

The follow-up PR adds:
```toml
[features]
aws = ["dep:aws-sdk-s3", "dep:aws-sdk-kms", "dep:aws-config"]
```
plus concrete impls that wrap `aws_sdk_s3::Client` / `aws_sdk_kms::Client`
behind the existing trait surface.

---

## D24 — Use `coset` over `aws-nitro-enclaves-cose` for attestation parsing

**What:** The RFC §1.5 lists `aws-nitro-enclaves-cose` as the COSE parser
of choice. The M3 skeleton plans `coset` instead.

**Why:** When the skeleton was being implemented (2026-05-21),
`aws-nitro-enclaves-cose` had not seen a release in 24 months and its
GitHub repo had unresolved security advisories. `coset` is actively
maintained by Google and the RustCrypto org, supports COSE_Sign1, and has
fewer transitive deps (does not pull `aws-lc-sys`, which previously broke
reproducible builds for unrelated AWS Nitro consumers).

This matches the RFC's own escape hatch: §1.5 lists both
"`aws-nitro-enclaves-cose` + `coset`" — explicitly admitting we may pick
one or the other.

**Alternatives considered:**
- Pin `aws-nitro-enclaves-cose` at the last good version. Rejected — that
  version has an open advisory and we'd be on our own to patch.
- Roll our own COSE_Sign1 parser. Rejected — security primitive,
  shouldn't roll our own.

The M3 skeleton's `verify_attestation.rs` does NOT yet pull `coset` (the
real CBOR parsing lands in the follow-up PR that fills in the
cert-chain trust-anchor step). The skeleton uses JSON for the
`cose_sign1` field as a stand-in so unit tests can construct expected
documents without writing a CBOR encoder by hand. The trait surface is
ready for the swap.

---

## D25 — `feature = "nitro"` gates real vsock I/O, not the whole module

**What:** `qfc-enclave::enclaves::nitro` compiles by default (without
`feature = "nitro"`). The trait method implementations return
`EnclaveError::NotImplemented("nitro feature not enabled")`. Real
`tokio-vsock` IO is behind the feature.

**Why:** Two reasons:
1. The trait surface and wire types (`NitroWireRequest`,
   `NitroWireResponse`, `NitroSignRequest`, etc.) need to be
   serialization-tested. If the whole module gates on a Linux-only feature,
   macOS dev can't run those tests.
2. The orchestrator needs to construct a `NitroEnclave` (via
   `NitroEnclaveBuilder`) in production-ish integration tests without the
   feature actually being on (so it can verify the round-trip *would* work
   if the vsock backend were live).

The trade-off: a tiny amount of dead-code-ish surface in the non-`nitro`
build. The compiler treats it as test-only-relevant; cargo doesn't
complain.

**Alternatives considered:**
- Gate the entire `nitro` module on the feature. Rejected — wire types
  unreachable from dev.
- Always-on `tokio-vsock`. Rejected — macOS dev breaks (`tokio-vsock` is
  Linux-only).
- Two crates: `qfc-enclave` (host) + `qfc-enclave-nitro` (Linux-only).
  Rejected — premature crate split; can revisit if the feature surface
  grows.

---

## D26 — `enclave/` is OUTSIDE the workspace (separate Cargo target)

**What:** The host workspace `Cargo.toml` has `exclude = ["enclave"]`.
The `enclave/` directory has its own `[workspace]` empty table so it's
treated as its own root.

**Why:** The in-EIF binary's dependency graph is intentionally smaller
than the host workspace's (no axum / sqlx / utoipa / tracing-opentelemetry
/ metrics). Mixing them into one workspace means every `cargo test`
against the host builds the enclave's deps too — slowing the host's CI
budget for no gain. Separating them also means the EIF's `Cargo.lock`
is independent of the host's, which is necessary for the EIF's
reproducible-build claim (RFC §8.5): an unrelated host-side dep bump
must NOT change PCR0.

**Alternatives considered:**
- Make it a workspace member with a tighter `[features]` gate. Rejected
  — `cargo build --workspace` still pulls every member; doesn't actually
  save the build time.
- A separate top-level repo. Rejected — duplicated cross-crate types,
  harder to keep in sync; the path-dep relationship survives a single
  repo with two workspaces.

The trade-off: developers must `cd enclave && cargo test` separately.
Documented in `enclave/Makefile`'s `help` target. The host workspace's CI
adds `cargo test --manifest-path enclave/Cargo.toml` as a separate step.

---

## D27 — Dockerfile.eif ships with placeholder SHA digests

**What:** `enclave/Dockerfile.eif`'s base-image lines reference
`alpine:3.20@sha256:000…`. These are placeholders — not real digests.

**Why:** Production-tier digest pinning requires a one-time call to
`docker pull alpine:3.20 && docker inspect` to get the actual SHA, and
the result depends on which Docker registry mirror responded — i.e. the
SHA varies per pull, by design. The skeleton ships the structural
Dockerfile (multi-stage, `SOURCE_DATE_EPOCH`, `--frozen`, `cargo-chef`
caching). The actual digests are filled in by the M3-GA PR — which is
also when the external audit vendor signs off on the build container.

**Alternatives considered:**
- Pin to whatever digest `docker pull` returns today. Rejected — the
  digest is unstable until we standardize on a registry mirror as part
  of the M3 GA infrastructure plan.
- Skip the Dockerfile entirely until digests are known. Rejected — the
  Dockerfile structure is itself audit-critical and benefits from
  early review.

The `make boot` target will fail to pull the image until the placeholders
are real. This is intentional — the M3 skeleton ships compile-time
infrastructure, not a runnable build.

---

## D28 — `LocalFileAnchor` lives in `qfc-audit::anchor`, alongside the existing types

**What:** The file-backed submitter (RFC §3.8) for the daily anchor cron
goes into the existing `qfc-audit::anchor` module rather than a new
`qfc-audit::stores` submodule.

**Why:** The existing `daily_anchor_commit_job` already lives in
`anchor.rs` and takes a submitter closure. `LocalFileAnchor::submit`
fits that signature naturally. Splitting the file just moves the file
boundary without adding a seam.

Also added a `daily_anchor_commit_job_with_reader` variant that takes a
poolless reader closure — useful for backend-agnostic anchor jobs and
test cases that don't want to spin up testcontainers Postgres.

**Alternatives considered:**
- Put it in `qfc-audit::stores::file_anchor`. Rejected — premature
  structuring.
- Put it in `qfc-server-wallet`. Rejected — anchor commit is a property
  of the audit log, not the orchestrator.

---

## D29 — Skeleton does not yet wire `SignedPolicyDecision` through the orchestrator

**What:** `WalletService::sign` continues to pass `policy_decision: None,
approvals: Vec::new()` into `EnclaveSignRequest`. The `HybridVerifier` is
unit-tested in isolation; the in-flow integration test (orchestrator
signs a decision and threads it through to the enclave) lands in a
follow-up PR.

**Why:** Two reasons. First, the policy-service signing key is a deployment
concern — production has a separate policy service with its own KMS-backed
key; the orchestrator code shouldn't carry that key in M3 skeleton.
Second, the `MockEnclave` ignores `policy_decision` entirely (it doesn't
run the verifier); the only consumer that actually exercises the field
is the in-enclave boot binary (`enclave/src/main.rs`), and that runs as
its own test suite with synthetic decisions.

The trade-off: M3 skeleton ships hybrid verification as a *unit-tested
library* but not as an *end-to-end-tested integration*. The integration
test lands once a `PolicyServiceSigner` (a small wrapper around an
ed25519 key) is introduced into `qfc-server-wallet`.

**Alternatives considered:**
- Build the `PolicyServiceSigner` now. Rejected — it's a sizeable
  separate piece (key loading, rotation, audit logging) and the brief
  scoped M3 to the verification side.
- Pass a dummy in-memory key in the orchestrator. Rejected — would land
  a "test key in production code" pattern we'd have to back out.

---

## D30 — `MAX_DECISION_AGE_SECS = 24h` as a belt-and-braces ceiling

**What:** Even if a `SignedPolicyDecision` claims `max_age_secs = 7d`,
the verifier caps the effective age at 24h.

**Why:** RFC §5.2 lists "cross-instance replay" as a threat mitigated by
binding `request_id` to the decision. The 24h cap is an additional
defense: a single mis-issued decision can be replayed within its
`max_age_secs` window. Capping that window to 24h shrinks the
exfiltration value of any leaked decision.

**Alternatives considered:**
- Trust `max_age_secs` from the decision. Rejected — a compromised
  policy service could issue 30-day decisions; the cap puts a hard
  upper bound.
- Cap at 1h. Rejected — too tight for legitimate batch-signing flows.
- Make it configurable per-wallet. Deferred — adds complexity; revisit
  at M3-GA.

---

## D31 — `MAX_APPROVALS = 64` defensive bound on approval array size

**What:** The hybrid verifier rejects sign requests with more than 64
approvals up front.

**Why:** A malicious or buggy caller could submit thousands of approvals
to exhaust the in-enclave signature-verification budget. 64 is far above
any realistic M-of-N quorum (M5 is typical; 11-of-15 is the largest
real-world treasury config we've seen). Capping prevents DoS.

**Alternatives considered:**
- No cap. Rejected — DoS surface.
- Tighter cap (16). Rejected — leaves no headroom for future hierarchical
  quorum schemes.

---

## D32 — Tests assert byte-layout compatibility between `EnclaveApproval` and `SignedApproval`

**What:** Per D22, `EnclaveApproval` mirrors `qfc_quorum::SignedApproval`.
A small follow-up integration test (in `qfc-server-wallet/tests/`) will
assert that the byte-level signing pre-image computed by
`qfc_enclave::hybrid_verifier::approval_preimage` matches
`qfc_quorum::SignedApproval::signing_preimage`. The M3 skeleton ships the
verifier; the integration test lands with M4 when the conversion code
also lands.

**Why:** If the two crates ever drift on the preimage layout, an approver
signs one thing and the verifier checks another — silent verification
failure. The integration test is the canary.

**Alternatives considered:**
- Auto-derive preimage layout from a shared trait. Rejected — too much
  ceremony; the field set is small and stable.

---
