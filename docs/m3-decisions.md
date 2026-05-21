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

## D33 — `PolicyServiceSigner::sign_decision` takes a four-arg signature; `max_age_secs` is per-call, not stored on the signer

**What:** The trait surface is
`sign_decision(decision, request_id, wallet_id, max_age_secs)`. The
freshness window is a method parameter, not a field on the signer struct.

**Why:** The freshness ceiling is an operational dial. Different signing
flows (interactive UX, batch jobs, scheduled webhook callbacks) tolerate
different replay windows. Embedding `max_age_secs` in the signer would
force one global value across every flow; threading it per call lets the
orchestrator pick a tight value (60s for normal sign) and a looser value
(say 5 min) for batch jobs that gather a queue before submitting.

Defense-in-depth: the in-enclave verifier still caps with
`MAX_DECISION_AGE_SECS = 24h` (D30) regardless of the per-call value, so
a misconfigured caller cannot bypass the hard ceiling.

**Alternatives considered:**
- Single-arg trait carrying the decision only, with everything else
  hidden inside the signer. Rejected — couples the signer to a specific
  flow's policy on freshness.
- Embed `max_age_secs` on a `Signer::config()` struct. Rejected — adds
  a level of indirection for no benefit; the call site already knows the
  flow.
- Make it a const at the WalletService layer. Rejected — leaves the
  signer trait less expressive than the M3+M4 production needs (batch
  signing flows want a separate dial).

---

## D34 — `with_policy_service_signer` is an opt-in builder, not a required constructor arg

**What:** `WalletService::new` constructs a service with
`policy_service_signer: None`. Wiring is opt-in via
`with_policy_service_signer(self, Arc<dyn PolicyServiceSigner>) -> Self`.

**Why:** Three reasons:
1. **M1/M2 back-compat.** The M1/M2 test suites (228+ tests at retro
   time) wire `WalletService::new` directly. Adding a required arg would
   force every test through a refactor when the wiring isn't relevant to
   what they exercise.
2. **Production deployments MUST opt in.** Making the signer optional at
   the type level documents that the M1/M2 sign flow still works
   without it (with the verifier disabled at the enclave layer). The
   audit chain at `PolicyDecisionSigned` makes the distinction visible
   to operators: an event-pair of
   `SigningEvaluated → PolicyDecisionSigned → SigningAttempted` confirms
   the hybrid scheme is engaged; the older
   `SigningEvaluated → SigningAttempted` (no `PolicyDecisionSigned`
   between them) means it isn't. Production deployments check for the
   middle event in their audit chain monitoring.
3. **Mock-enclave parity.** The `MockEnclave` matches: the hybrid
   verifier runs only when `with_policy_service_pubkey(...)` is called.
   The two builders pair up — orchestrator wires a signer iff the
   enclave is pinned to its key.

The expectation is documented at the field and builder docs: production
deployments MUST set it; the brief explicitly calls out that absence
defeats the hybrid scheme's security argument.

**Alternatives considered:**
- Make it a required constructor argument. Rejected — every M1/M2 test
  becomes churn for an additive feature.
- Default to a "panic-on-use" signer. Rejected — defeats the back-compat
  promise; M1/M2 flows with `policy_decision: None` are still useful for
  testing and migration.
- Two constructors (`new_legacy` + `new_with_hybrid`). Rejected — adds
  surface for no expressive gain over the builder pattern.

---

## D35 — `AuditKind::PolicyDecisionSigned` is kind byte 17

**What:** The new audit kind for "policy decision was signed by the
policy-service signer and is being threaded into `EnclaveSignRequest`"
gets kind byte 17. M4's `QuorumThresholdReached` takes byte 16; D35
continues the sequence rather than slotting in.

**Why:** The kind byte is part of the audit chain's signed pre-image
(`event.rs::kind_byte`). Renumbering an existing kind would break every
deployed audit chain's replay verification. The right move is always
append-only.

The byte appears between `QuorumThresholdReached` (16) and any future
M5/M6 kinds. The corresponding `AuditKindDto` (OpenAPI mirror) is
extended in `crates/qfc-server-wallet/src/api/schemas.rs` so external
clients see the new value.

**Alternatives considered:**
- Renumber. Rejected — breaks audit chain replay.
- Skip a byte. Rejected — gives bad expectations for "what's the next
  free slot" without buying anything.

---

## D36 — Orchestrator default `max_age_secs = 60s` for production signing flows

**What:** `WalletService::sign` passes `MAX_DECISION_AGE_SECS_DEFAULT =
60` (constant in `service.rs`) to `PolicyServiceSigner::sign_decision`.

**Why:** 60s is long enough to absorb normal latency between policy
evaluation, audit emission, share fetch, and enclave round-trip
(observed at ~50ms p95 with M2 mock backends — the real Nitro round
trip will add a couple of hundred ms but stays well under 60s). It's
short enough that a leaked decision has a small effective replay window
before the in-enclave verifier rejects it.

The constant is `pub const` so production deployments can read it for
their own SLO docs; operator-tunable per flow is a follow-up (the
`max_age_secs` is already a parameter on the trait per D33).

**Alternatives considered:**
- 30s. Rejected — too tight for cold-start or testcontainers-warmup
  flows in CI.
- 5 min. Rejected — too loose; the whole point of binding the timestamp
  is to bound replay value.
- Make it a runtime config knob on `WalletService` immediately. Deferred
  — premature; bring it in when a real flow demands a different value.

---

## D37 — `EnclaveSignRequest.wallet_ceilings` + `policy_signing_payload` carry the M3 hard-ceiling inputs additively

**What:** Two new `Option<_>` fields on `EnclaveSignRequest`:
`wallet_ceilings: Option<WalletCeilings>` and
`policy_signing_payload: Option<qfc_policy::SigningPayload>`. The
orchestrator populates both whenever it threads a `SignedPolicyDecision`
through; `None` for legacy callers means the verifier (when it runs)
falls back to empty ceilings + a raw payload projection.

**Why:** The in-enclave verifier needs the structured payload to do its
hard-ceiling re-check — the verifier re-decodes the EVM tx itself via
`qfc_policy::decode_evm_tx` so the host can't lie about the decoded
value. The verifier also needs the wallet's `max_value_per_tx /
contract_allowlist / chain_allowlist` (already on `WalletConfig` per
M3 §3.4 schema additions, but not yet on the cross-boundary
`EnclaveSignRequest`).

Both fields are `Option<_>` so M1/M2 callers compile unchanged. The
`MockEnclave`'s back-compat behavior is: if `policy_service_pubkey` is
`None`, hybrid verification is skipped and the missing ceilings don't
matter. If `policy_service_pubkey` is `Some`, the verifier is invoked
with empty defaults when ceilings aren't passed.

**Alternatives considered:**
- Inline the ceilings into the `SignedPolicyDecision`. Rejected — the
  ceilings are an enclave-attested wallet property, not a per-decision
  one. Putting them on the decision means the policy service has to
  know them at decision time (it doesn't — they live in the wallet
  record).
- Pass the full `WalletConfig`. Rejected — leaks server-wallet shape
  into `qfc-enclave`. The `WalletCeilings` projection is the right
  seam.
- Re-decode the structured payload inside the enclave from
  `req.message`. Rejected — `req.message` is already
  `canonical_message_bytes(payload)` which for VM payloads IS the raw
  envelope, but the chain_id / target / vm tag are not recoverable
  from the bytes alone for some envelopes. Passing the structured
  payload is the cleanest cut.

---

## D46 — AWS Nitro root cert chain validation stays deferred; `verify_root_chain` lands as a typed stub

**What:** The COSE_Sign1 follow-up (`feat/cose-sign1-parse`) lands real
CBOR parsing + ed25519 envelope verification, but **does not** walk the
leaf cert + cabundle up to the AWS Nitro root. A new free function
`qfc_enclave::verify_attestation::verify_root_chain(leaf, cabundle, root)`
exists as the typed seam and returns `Ok(())` with a `TODO(D46)` comment.

**Why:** Three reasons.
1. **Need the AWS Nitro root cert.** AWS distributes the root via the
   `nitro-cli` toolchain (a 7-year cert; current root expires
   2027-04-21). Bundling it requires a one-time provenance step plus an
   internal review of "is this the right root, did anyone tamper with
   the source we pulled it from". That work is gated on an AWS account
   the brief explicitly excludes from this PR.
2. **No live AWS attestation to test against.** Without real Nitro
   output, we can't even integration-test a chain walker — only
   synthetic chains, which are exactly what an X.509 walker is most
   prone to false-negative on.
3. **Webpki vs custom walker is itself a decision.** `webpki` is the
   obvious choice (pure-Rust; already in the workspace via rustls),
   but the AWS Nitro chain uses ES384 leaves which webpki only added
   support for after v0.22. We need to confirm the pinned webpki
   version covers ES384 + that its trust-anchor parse accepts the
   AWS root's curve params before committing.

The typed seam ships today so the integration point is fixed: the
M3-GA PR drops in a real implementation against a known signature,
and the call site in `verify_attestation` already routes through it.

**Alternatives considered:**
- Land a fake walker that accepts any chain. Rejected — would invite
  callers to assume the verifier is doing work it isn't.
- Use a placeholder root + crate "any cert chains to it" verifier.
  Rejected — same false-confidence problem.
- Wait to land the COSE parser until the root + walker are ready.
  Rejected — the parse and verify are independently useful (e.g. for
  attestation-doc introspection tools that don't need root validation).

---

## D47 — ECDSA-P384 (ES384) deferred; ed25519 ships first; `SignatureKind` makes the dispatch explicit

**What:** The new COSE_Sign1 path verifies ed25519 signatures via
`verify_cose_signature`. AWS Nitro production uses ECDSA-P384 (ES384);
`verify_cose_signature_es384` exists as a stub returning
`CoseVerifyError::AlgorithmNotImplemented`. The `SignatureKind` enum
carries three variants — `Mock`, `CoseSign1Ed25519`, `CoseSign1Es384` —
so callers can detect ES384 envelopes today even though we can't verify
them.

**Why:** Three reasons.
1. **Our test envelopes are ed25519.** The mock attestation flow
   (`MockAttestationKey`) is ed25519. The PolicyServiceSigner is
   ed25519. The HybridVerifier verifies ed25519 approvals. Adding ES384
   to the verifier without a single ES384 fixture to test it on adds
   surface area we can't exercise.
2. **No AWS to capture a real ES384 envelope from.** Same constraint
   as D46 — without an AWS account, the only ES384 fixtures we can
   generate are synthetic ones we'd be both signing and verifying,
   which proves nothing about wire-format compatibility with what AWS
   actually emits.
3. **The wire format is identical.** `coset` already parses ES384
   envelopes (the `protected.header.alg` field surfaces the algorithm).
   `tbs_data` construction is curve-agnostic. The only line that
   changes is the verifier inside `verify_cose_signature_es384` —
   roughly `p384::ecdsa::VerifyingKey::from_sec1_bytes(...).verify(...)`.
   We can land that in a one-file diff the day we have a real AWS
   capture.

The `SignatureKind::CoseSign1Es384` variant exists today so:
- `NitroAttestationDoc::from_cose_sign1` correctly labels envelopes
  whose `protected.alg = -35` as ES384 (per IANA COSE algorithm
  registry).
- `verify_attestation` routes ES384 documents through the stub and
  surfaces `MalformedCose("signature algorithm not implemented (see
  D47)")` — distinguishable from a real signature failure.
- Consumers of the attestation library can detect ES384 envelopes
  and decide whether to fall back to a different verification path
  or wait for the AWS root cert chain integration.

**Alternatives considered:**
- Land ES384 verifier on synthetic test vectors. Rejected — gives
  false confidence; the only thing it would test is that our own
  signer agrees with our own verifier.
- Make `SignatureKind` boolean-ish (`Mock` vs `Real`) and dispatch
  curve inside the COSE path. Rejected — the enum surfaces "we know
  this is the ES384 format but can't verify it" at the type level,
  which is what downstream consumers actually want to know.
- Hold the whole COSE PR until ES384 is ready. Rejected — see D46
  for the same independence argument.

---
