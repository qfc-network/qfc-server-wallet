# v1.3 retro

A look-back on what shipped against RFC v1.2, what diverged (and why), and what the RFC should pick up before the next milestone starts.

**Status:** retro, written 2026-05-21, covering RFC v1.2 (commit `d832f6d`) → `PolicyServiceSigner` wiring → M5 (ML-DSA + QVM minimal) → runbooks → COSE parse-half → gRPC API → approver clients → CI fix (6 PRs on `main` since `retro-m3-m4.md` was written, 420 tests across four test surfaces).

---

## 1. Headline

| | M3 closing (RFC §7) | M5 (RFC §7) | M4 followup (RFC §7) | New surface |
|---|---|---|---|---|
| Estimated | ~1 session (PolicyServiceSigner) | 5–7 sessions | ~2 sessions (clients) | n/a |
| Actual | ~1 session, 1 PR (#19) | ~3 sessions, 1 PR (#20) | ~2 sessions, 1 PR (#24) | gRPC ~2 sessions, runbooks ~1 session, COSE ~1.5 sessions |
| Tests added | 315 → 322 (+7) | 322 → 351 (+29) | 351 → 372 + 32 outside workspace | 372 → 382 (+10 gRPC); 4 test surfaces in total |
| Scope hits | M3 §3.4 hybrid-scheme GA loop closed end-to-end | All in-scope M5 line items shipped | Approver clients + golden vectors shipped | Runbooks + COSE parse-half + gRPC alongside HTTP |

**Total: 420 tests** — 382 workspace + 15 in `clients/approver-rs/` + 17 in `clients/approver-ts/` + 6 in the standalone `enclave/` project. All seven CI gates green on `main`.

The big shape: **six PRs merged sequentially via the parallel-subagent pattern** now battle-tested for a third batch. Two notable wins this batch: closing the M3 §3.4 hybrid-scheme GA loop end-to-end (`PolicyServiceSigner` + audit kind `17` + `MockEnclave` parity with the eventual Nitro EIF), and the multi-curve quorum "already worked, just needed to be pinned" finding — M5's `m5_multi_curve_quorum.rs` integration test went green with zero new code because M4 [D16] per-identity scheme dispatch had been designed for it from day one.

---

## 2. What landed vs RFC §7

### M3 closing — `PolicyServiceSigner` end-to-end (PR #19)

| RFC line | Status | Notes |
|---|---|---|
| `PolicyServiceSigner` wiring closes §2.1 hybrid scheme | ✅ | `LocalPolicyServiceSigner` + `WalletService::with_policy_service_signer` + `MockEnclave` parity with the eventual EIF; 7 E2E tests cover the happy path + wrong-key + stale + value-cap + back-compat. Retro-m3-m4 [§3.2](retro-m3-m4.md) gap closed |
| Audit kind `PolicyDecisionSigned = 17` | ✅ | Stable kind byte; emitted between `SigningEvaluated` and `SigningAttempted` |
| Additive `EnclaveSignRequest.{wallet_ceilings, policy_signing_payload}` | ✅ | Both `Option<_>` per [m3-decisions D37](m3-decisions.md#d37); M1/M2 callers compile unchanged |

### M5 — PQ signing + QVM minimal (PR #20)

| RFC line | Status | Notes |
|---|---|---|
| `MlDsa44/65/87Signer` (FIPS 204) | ✅ | Pure-Rust `ml-dsa` v0.1 per [m5-decisions D38](m5-decisions.md#d38); zero C FFI, `#![forbid(unsafe_code)]` preserved |
| QVM minimal decoder | ✅ | Envelope-only per RFC §9.6 option (b) and [m5-decisions D41](m5-decisions.md#d41); `tx_type` / `chain_id` / `to` / `value` / `gas_limit`; `data` opaque |
| Multi-curve quorum (approvers on different curves than wallet) | ✅ | `m5_multi_curve_quorum.rs` integration test went green with zero new code — M4 [D16] per-identity scheme dispatch already supports it; the test pins the architecture |
| Cross-TEE quorum design doc | ✅ | `docs/design/cross-tee-quorum.md` per [m5-decisions D43](m5-decisions.md#d43); implementation deferred to M6 |
| Wallet migration tool | ⛔ deferred | Customer-facing flow, not crypto; lands in `tools/wallet-migrate` per [m5-decisions D42](m5-decisions.md#d42) |
| Full QVM method-level decoder | ⛔ deferred to M6 | Gated on `qfc-core` shipping a `QvmCall` tx variant |
| WASM decoder | ⛔ deferred indefinitely | `qfc-core` still has no WASM execution path |

### Operator runbooks (PR #21)

| RFC line | Status | Notes |
|---|---|---|
| Operational runbooks: deploy, EIF upgrade, key rotation, IR, DR, onboarding | ✅ | Six public redacted runbooks under `docs/runbooks/` per RFC §1.2 split. M3-GA-gated and `qfc-core`-gated sections marked "Pending" rather than written as if live |

### COSE parse-half (PR #22)

| RFC line | Status | Notes |
|---|---|---|
| Attestation verification library — real CBOR | ✅ partial | Real `coset` + `ciborium` CBOR parsing; ed25519 envelope verification end-to-end |
| ES384 verifier (AWS Nitro production curve) | ⛔ stub | `verify_cose_signature_es384` returns `AlgorithmNotImplemented` per [m3-decisions D47](m3-decisions.md#d47); `SignatureKind::CoseSign1Es384` detected at parse time so prod envelopes route through the stub loudly, not silently |
| AWS Nitro root cert chain validation | ⛔ stub | `verify_root_chain(leaf, cabundle, root)` typed stub per [m3-decisions D46](m3-decisions.md#d46); blocked on AWS account |

### gRPC API surface (PR #23)

| RFC line | Status | Notes |
|---|---|---|
| RFC §10 decision #7 — "HTTP first, gRPC later" | ✅ shipped earlier than v1.2 expected | gRPC alongside HTTP, not replacing; both back the same `Arc<WalletService>` handler core (zero logic duplication); both servers spawn from the same `Arc<AppState>` and share a graceful shutdown future per [grpc-decisions D51](grpc-decisions.md#d51) |
| Streaming RPCs | ⛔ deferred | Unary only; audit-event tailing is a separate proposal |
| Published gRPC client SDK | ⛔ deferred | Per [grpc-decisions D47](grpc-decisions.md#d47); external consumers can run `tonic-build` over the vendored protos for now |
| Direct TLS | ⛔ deferred | Operators terminate at envoy / nginx, identical to the HTTP story |

### Approver clients (PR #24)

| RFC line | Status | Notes |
|---|---|---|
| Approver-side reference client (Rust + TS) | ✅ | M4 line item deferred in retro-m3-m4; landed here. Standalone-workspace pattern per [clients-decisions D46](clients-decisions.md#d46) so integrators can fork without inheriting the wallet's dep tree |
| Cross-language preimage compat | ✅ | Rust-generated `preimage_golden.json` fixture pins TS preimage to byte-exact Rust output per [clients-decisions D52](clients-decisions.md#d52) |

### CI fix (PR #23 amend)

| Issue | Status | Notes |
|---|---|---|
| `protoc` not pre-installed on `ubuntu-latest` | ✅ | `arduino/setup-protoc@v3` added to all three CI jobs (test / clippy / doc). See §4.1 |

---

## 3. Divergences from RFC v1.2 — explicit list

### 3.1 gRPC operator port: `8088` HTTP + `9090` gRPC

The gRPC PR (#23) renamed the HTTP default bind from `127.0.0.1:8080` to `127.0.0.1:8088` to free `:9090` for gRPC (which previously was used by the Prometheus exposition in M2 P5; the metrics path moves with the HTTP server). The RFC v1.2 text is silent on specific ports but the M2 README + `docker-compose.yml` still document `:8080` for HTTP.

- **Driver:** gRPC's conventional default is `:9090`, and the M2 P5 metrics scrape moved to the HTTP server's `/metrics` endpoint — so freeing `:9090` for gRPC is the cleaner cut. The `QFC_SERVER_WALLET_BIND` env var stays as a back-compat alias for `QFC_SERVER_WALLET_HTTP_BIND` per [grpc-api](grpc-api.md).
- **RFC fold-back:** decision #7 (§10) is now shipped; the `8088` / `9090` defaults are documented in `docs/grpc-api.md`. RFC fold-back: note the new ports in §10 decision #7 status row. README / `docker-compose.yml` updates are runtime config and out of scope for this doc-only PR.

### 3.2 COSE ships ed25519, not ES384 (AWS Nitro production curve)

The COSE PR (#22) closes the **parse half** of [m3-decisions D24](m3-decisions.md#d24): `coset` + `ciborium` parse production-shape COSE_Sign1 envelopes including AWS-Nitro-tagged ones. But the verifier only verifies **ed25519** signatures. AWS Nitro production attestations are signed with **ECDSA-P384 (ES384)** — and the parser correctly detects them (the `SignatureKind::CoseSign1Es384` variant is set when `protected.alg = -35`), but the verifier surfaces `AlgorithmNotImplemented` rather than verifying.

- **Driver:** no live AWS to capture real ES384 envelopes from; only synthetic ones we'd both sign and verify (proves nothing). See [m3-decisions D46](m3-decisions.md#d46) (root chain) + [D47](m3-decisions.md#d47) (ES384).
- **What's still pending live AWS:** the ES384 verifier swap (one-file diff — `p384::ecdsa::VerifyingKey::from_sec1_bytes(...).verify(...)`); the AWS Nitro root cert chain validation (`verify_root_chain` stub); the cabundle walker.
- **RFC fold-back:** §7 (M3 ships) should distinguish the **shipped** parse-half (real CBOR + ed25519) from the still-deferred AWS-specific pieces (ES384 + root chain + cabundle walker). Currently the line item reads as a single bundle; splitting matches reality.

### 3.3 Approver clients live in `clients/`, not `tools/`

RFC §12 didn't specify a location for reference clients. The implementation lives under `clients/approver-rs/` and `clients/approver-ts/`, both **outside** the main Cargo workspace per [clients-decisions D46](clients-decisions.md#d46). `tools/gen-golden-vectors/` is also outside the workspace (it's the cross-language fixture generator).

- **Driver:** production integrators fork these directories as starting points. Pulling the full `qfc-server-wallet` dep graph (sqlx, axum, utoipa, opentelemetry, ...) into every approver fork would make forks harder to maintain than rewriting from scratch — defeating the "reference" framing.
- **`clients/` vs `tools/`:** `tools/` was already in use for internal helpers; `clients/` reads correctly as "things downstream consumers fork." The split is intentional.
- **RFC fold-back:** §8.5 (reproducible builds context) should mention the **standalone-workspace pattern** as the recommended approach for *any* future reference client (gRPC client SDK, web SDK, multi-VM signer reference, ...). See §4.3 below.

### 3.4 D-numbering split per-file

The decision-doc numbering has fragmented:
- `m1-decisions.md` D1–D20
- `m3-decisions.md` D21–D32, then D33–D37 (PolicyServiceSigner), then D46–D47 (COSE follow-up). **Note the jump** — D33–D37 came after M3 main; D46–D47 came with COSE.
- `m4-decisions.md` D21–D37 (collides with m3 D21–D32 numerically — same numbers, different decisions; only the file scopes them)
- `m5-decisions.md` D38–D45
- `grpc-decisions.md` D46–D52
- `clients-decisions.md` D46–D54

So **D46** exists in three files (m3, grpc, clients). **D21–D32** exists in two (m3, m4). Cross-references work because the markdown links are file-anchored (`[D21](m3-decisions.md#d21)` vs `[D21](m4-decisions.md#d21)`) but the human-eye scan "what is D46?" is now ambiguous without the filename.

- **Driver:** decisions doc was forked per-PR by parallel subagents; each restarted from the "next available number" they could see in their worktree. The retro-m3-m4 already lived with a partial overlap; this batch made the split a settled convention.
- **RFC fold-back:** standardize the convention. Two options: **(a) renumber globally** (D1, D2, ..., D62 across all files — high churn for low real benefit) or **(b) commit to per-file numbering and require all references be filename-anchored**. Recommend (b) — it's the de-facto convention, has zero churn cost, and matches the actual workflow (each milestone's decisions live with the milestone). State it explicitly in a new RFC section. See §5.

---

## 4. What surprised us

### 4.1 `protoc` not on `ubuntu-latest`

`tonic-build` shells out to the `protoc` binary at build time. GitHub Actions' `ubuntu-latest` image does not pre-install it. The gRPC PR (#23) compiled green locally on macOS / Linux dev machines (which had `protoc` installed for other projects) and surfaced a CI failure immediately on push: `protoc not found`.

The fix was a one-line addition to each of the three CI jobs in `ci.yml`:

```yaml
- uses: arduino/setup-protoc@v3
```

**Lesson:** any new code-gen build step → check the runner has the tool. This belongs on the **CI parity checklist** in RFC §8.6 — alongside the four CI gates and the audit/deny/vet trio. Adding it as a v1.3 fold-back.

### 4.2 Subagent CI gates now running all four

The retro-m3-m4 [§4.3](retro-m3-m4.md) lesson stuck. All four 2026-05-21 subagents (M5, PolicyServiceSigner, COSE, gRPC, approver clients) ran the full four-gate set locally (`test`, `clippy`, `fmt`, `doc`) plus `audit` / `deny` / `vet` before reporting green. M3 + M4 from the previous batch had skipped `fmt --check` and `cargo doc -D warnings`; this batch did not.

Only gRPC (PR #23) hit a CI failure, and the failure was **not** a gate-coverage issue — it was the runner-environment issue in §4.1 above (`protoc` missing on the runner). Once `arduino/setup-protoc@v3` was added, the gates that the subagent had run locally also passed on CI.

**Lesson:** the four-gate parity rule is the right rule. The fact that a single PR in this batch tripped CI is a runner-environment issue (orthogonal to gate parity) and produces a different fold-back (§4.1's CI prerequisites list).

### 4.3 Cross-language byte-exact compat via golden vectors

The approver clients live in two languages (Rust + TS). The byte-exact preimage layout from `qfc_quorum::SignedApproval::signing_preimage` is the *contract* the server and approver both write against; a silent drift would mean approvals verify on the server's side but produce the wrong signature on the approver's side.

The chosen pattern: `tools/gen-golden-vectors/` is a tiny Rust binary that calls `signing_preimage` on three deterministic inputs and writes `clients/approver-ts/test/fixtures/preimage_golden.json`. The TS preimage test reads the fixture and asserts byte equality. The Rust client carries the same pin internally via `tests/preimage_compat.rs::deterministic_preimage_snapshot` (inline hex literal). Both literals must update together if the layout shifts.

This is the kind of pattern that earns its keep across **any** wire surface that gets independently re-implemented. Likely candidates:
- M5 grows a TS PQ verifier (an integrator wants to verify ML-DSA signatures in a web app)
- gRPC client SDK in a third language (Python / Go) needs to construct the same `SigningContext` bytes
- Web SDK needs to compute audit-event preimage hashes

**Lesson:** golden vectors generated from the canonical Rust side, checked in, asserted byte-exact in the consumer test — pattern stays. Worth calling out in §8.5 alongside the standalone-workspace pattern (§4.4).

### 4.4 Standalone-workspace pattern for forkable clients

`clients/approver-rs/` declares its own `[workspace]` table, has its own `Cargo.lock`, and is listed in the root `Cargo.toml`'s `workspace.exclude`. Same for `clients/approver-ts/` (npm project, never touched the Cargo side) and `tools/gen-golden-vectors/` (separate Cargo workspace).

Trade-off: workspace-wide `cargo test` doesn't cover the clients. CI runs `cd clients/approver-rs && cargo test` as a separate gate. The TS client is opt-in per [clients-decisions D54](clients-decisions.md#d54): `npm test` locally before changes that touch `src/preimage.ts` or `src/signer.ts`.

Win: a fork doesn't inherit `sqlx-macros-core` (with its MySQL build dep), `utoipa-swagger-ui` (with its build-time `syn 1`), `opentelemetry-otlp` (which pins `tonic 0.12`), or any of the other transitive deps the wallet service drags in. Each fork is genuinely minimal.

**Lesson:** for any future reference client (gRPC client SDK, web SDK, wallet-migration tool, ...) that integrators are expected to fork, standalone-workspace is the right call. The cost is one extra CI gate per client; the benefit is the fork actually behaves like a starting point. Worth folding into RFC §8.5.

### 4.5 Multi-curve quorum — architecture paid off

The M5 spec line "multi-curve quorum (approvers can be on different curves than wallet)" sounded like new feature work. The implementation reality: M4 [D16] per-identity scheme dispatch already routed each approver's signature through their *own* registered scheme, independent of the wallet's scheme. The M5 work was to *pin* the property with `m5_multi_curve_quorum.rs`: an ML-DSA-65 wallet authorised by two ed25519 approvers, full sign flow, signature externally verifies.

**Zero new code paths.** The integration test passed first try.

This is the kind of "the architecture paid off" finding worth surfacing. M4 [D21] (separate `ApproverSetId` / `ApproverId` / `ApprovalId` newtypes) plus M4 [D16] (per-identity scheme dispatch) together meant the system was *already* multi-curve quorum-capable — M5 just shipped the test that confirms it.

**Lesson:** when a future RFC line item looks like "we should test that X works," check whether X already works because the underlying types were designed correctly. The cheaper move is an integration test that pins the property, not new feature work.

### 4.6 CHANGELOG `### Added` is the predictable conflict hotspot

All four subagents in this batch added their PR's `### Added` block to `CHANGELOG.md` under the same `[Unreleased]` heading. Every rebase produced a "keep both" conflict in exactly the same spot. Trivial to resolve (textual concatenation always works; the entries are independent) but predictable.

Two mitigations worth considering for the next batch:
- **Section-per-PR pattern:** each subagent writes to `CHANGELOG.d/<branch-slug>.md`; a release script concatenates them. Common pattern in larger projects (`towncrier` for Python, `scriv` for Rust).
- **Pre-allocate placeholder sections:** the parent agent writes empty sentinel comments before subagents start (`<!-- m5 entries below -->`, `<!-- grpc entries below -->`). Subagents append above the sentinel they own; rebases stay clean.

Not a fold-back to the RFC — pure process / tooling note. Worth a one-line callout in the next batch's planning.

---

## 5. What to fold back into the RFC before the next milestone

A short list — each one is a small edit, mostly section-level annotation or footnote:

| RFC section | Edit |
|---|---|
| §7 (M3 ships) | Mark **shipped** (with this batch): `PolicyServiceSigner` end-to-end wiring closes the §2.1 hybrid scheme; the six operator runbooks (`docs/runbooks/`); the COSE parse-half (real CBOR + ed25519 envelope verification). |
| §7 (M3 ships) | Mark **still deferred to GA / live AWS**: AWS Nitro root cert chain validation (`verify_root_chain` is a typed stub per [m3-decisions D46](m3-decisions.md#d46)); ES384 signature verification (`verify_cose_signature_es384` is a stub per [m3-decisions D47](m3-decisions.md#d47)); real `aws-sdk-s3` / `aws-sdk-kms` integration behind `feature = "aws"`; bit-exact EIF rebuild + the `eif-reproducibility.yml` workflow. |
| §7 (M4 ships) | Mark **shipped** (with this batch): approver-side reference client (Rust + TS) — RFC §7 M4 line previously listed "shipped later when a real external approver exists"; that condition has now been met by the standalone-workspace + golden-vector pattern. |
| §7 (M4 ships) | Mark **still deferred**: real `OnChainQfcEventApprover` chain submission (still a `tokio::broadcast` stub blocked on `qfc-core` workspace integration); published gRPC client SDK; streaming RPCs; direct TLS. |
| §7 (M5 ships) | Mark **shipped**: `MlDsa44/65/87Signer` (FIPS 204) backed by pure-Rust `ml-dsa` v0.1; QVM minimal envelope decoder per option (b); multi-curve quorum confirmed by `m5_multi_curve_quorum.rs` (architecture already supported it — M4 [D16]); cross-TEE quorum design doc at `docs/design/cross-tee-quorum.md`. |
| §7 (M5 ships) | Mark **still deferred**: wallet migration tool (`tools/wallet-migrate` — separate post-M5 deliverable per [m5-decisions D42](m5-decisions.md#d42)); full QVM method-level decoder (blocked on `qfc-core` `QvmCall` tx variant); WASM decoder (blocked on `qfc-core` WASM execution path). |
| §8.4 | Note that the approver clients have shipped — was an M4 deliverable that the v1.2 retro-m3-m4 left deferred; condition (real-external-approver-to-point-at) is now met. |
| §8.5 | New paragraph: the **standalone-workspace pattern** for any future forkable reference client (gRPC client SDK, web SDK, wallet-migration tool, ...). `clients/approver-rs/` + `clients/approver-ts/` + `tools/gen-golden-vectors/` are the working precedents; root `Cargo.toml`'s `workspace.exclude` is the integration point. Cross-language byte-exact compat is pinned via Rust-generated golden-vector fixtures (see §4.3 / §4.4 of this retro). |
| §10 decision #7 | Mark **shipped**: gRPC alongside HTTP, not replacing. Default ports: HTTP `127.0.0.1:8088` (env `QFC_SERVER_WALLET_HTTP_BIND`; back-compat env `QFC_SERVER_WALLET_BIND`); gRPC `127.0.0.1:9090` (env `QFC_SERVER_WALLET_GRPC_BIND`). Reference: `docs/grpc-api.md`. |
| §12.4 | CI workflow prerequisite: `arduino/setup-protoc@v3` step is required before any `cargo` step that hits `tonic-build`. Update the workflow table's prereq list. |
| §12.4 | The four-gate CI parity (test / clippy / fmt / doc) + audit / deny / vet trio per §8.6 stays. Add a `--all-features` cautionary footnote: on macOS dev hosts, `vsock 0.4.0` does not compile (`feature = "nitro"` cannot be enabled), so `--all-features` is exercised on the Linux CI runner — local `cargo check --all-features` will fail on a Mac (per retro-m3-m4 [§4.1](retro-m3-m4.md)). |
| New §13 (or §8 subsection) | **D-numbering convention**: each milestone / feature-area decision doc continues its own per-file `Dnn` sequence (m1-decisions D1–D20; m3-decisions D21–D32, D33–D37, D46–D47; m4-decisions D21–D37; m5-decisions D38–D45; grpc-decisions D46–D52; clients-decisions D46–D54). Cross-references must be filename-anchored (`[D21](m3-decisions.md#d21)` vs `[D21](m4-decisions.md#d21)`). Per-file is the chosen convention; global renumbering is explicitly rejected as high-churn / low-benefit. |

A single PR — call it `rfc(v1.3): retro fold-back` — collects all of the above (and is the doc-only PR this retro accompanies). Worth ~0.5 session hours.

---

## 6. Recommended next milestone

Three buckets, ordered by what unblocks the most downstream work:

### 6.1 In-workspace, immediately actionable

1. **gRPC client SDK** — mirror the standalone-workspace pattern from approver clients. `clients/grpc-client-rs/` + `clients/grpc-client-ts/`; protos already vendored; tonic stubs already generated for the integration tests. Closes [grpc-decisions D47](grpc-decisions.md#d47). ~2 Claude session hours.
2. **v0.1.0 release tag** + CHANGELOG split (move `[Unreleased]` → `[0.1.0]`; cut a signed tag; SBOMs attached via existing `sbom.yml`). ~0.5 sessions.
3. **`sqlx 0.9` upgrade** — drops the `RUSTSEC-2023-0071` (`rsa` Marvin attack) ignore from `deny.toml` + `audit.yml`. Per retro-m3-m4 [§4.2](retro-m3-m4.md), the ignore exists because `sqlx-macros-core` enables every backend at compile time for query verification; sqlx 0.9 reportedly scopes the build chain by backend. ~1 session (sqlx 0.9 may have macro-call-site breaking changes).
4. **Real ES384 in `verify_cose_signature_es384`** — needs only the `p384` crate (pure-Rust, already in the workspace's transitive graph via webpki). Wire-format-identical to ed25519; only the verifier inside the stub changes. Closes the curve-plug half of [m3-decisions D47](m3-decisions.md#d47). No AWS account needed for the implementation; only for end-to-end validation against real Nitro output. ~0.5 sessions.

### 6.2 Blocked on `qfc-core` workspace integration

1. **`OnChainQfcEventApprover` real chain submission** — closes [m4-decisions D28](m4-decisions.md#d28).
2. **Live audit anchor cron** — closes the on-chain submitter half of [m3-decisions D28](m3-decisions.md#d28).
3. **Full QVM method-level decoder** — RFC §9.6 option (a); requires `qfc-core` to land a `QvmCall` tx variant + canonical encoding + version field.
4. **`qfc-types` / `qfc-crypto` on crates.io** — RFC §1.4 / decision #1; this is the actual gate on all four items above. Per retro-m1-m2 [§3.6](retro-m1-m2.md), the workspace currently has zero `qfc-core` dependency; the publish workflow has its own calendar lag dominated by `qfc-core` reviewer availability, not Claude session time.

### 6.3 Blocked on live AWS

1. Real `aws-sdk-s3` / `aws-sdk-kms` behind `feature = "aws"` — RFC §7 M3.
2. AWS Nitro root cert chain validation — completes [m3-decisions D46](m3-decisions.md#d46).
3. Bit-exact EIF rebuild + `eif-reproducibility.yml` workflow — RFC §8.5.
4. External security audit (Trail of Bits / Zellic / Cure53) — RFC §8.4, first mandatory human review.
5. M3 GA cutover.

### 6.4 Recommendation

**gRPC client SDK + ES384 verifier** are tiny (sub-session each) and unblock more downstream work than they cost. After that, the real question is whether to push on **`qfc-core` integration** (which unblocks 4 items at once: on-chain approver, audit anchor cron, full QVM, `qfc-address` derivation) or pivot to **AWS** (which unblocks live custody but is dominated by external-vendor calendar time). The `qfc-core` path has less calendar lag and a higher "items unblocked per session" ratio; the AWS path is necessary for GA but is dominated by audit-vendor scheduling.

Suggest: queue gRPC client SDK + ES384 verifier as the next two PRs (parallel-subagent pattern; same workflow as this batch); start `qfc-core` publish-workflow outreach in parallel; queue AWS work behind audit-vendor calendar.

---

## 7. Closing

- All six PRs shipped on or under the §7 session estimate; the **parallel-subagent pattern is now sufficiently battle-tested across three batches** (M1+M2, M3+M4, this v1.3 batch) that we can trust it without process babysitting. The two surprises this batch (§4.1 `protoc` runner-environment, §4.6 CHANGELOG conflicts) were both predictable in retrospect and produce concrete tooling fixes rather than process changes.
- All deliberate divergences from RFC v1.2 are recorded above (and most were called out in [`m3-decisions.md`](m3-decisions.md) D33–D37 + D46–D47, [`m5-decisions.md`](m5-decisions.md), [`grpc-decisions.md`](grpc-decisions.md), or [`clients-decisions.md`](clients-decisions.md) at the time).
- The biggest *latent* finding from this batch is §4.5 — multi-curve quorum "just worked" because M4 [D16] / [D21] had set up the type system correctly. The architecture paid off; the test that pins it cost ~30 minutes.
- 420 tests across four test surfaces (382 workspace + 15 Rust client + 17 TS client + 6 enclave-boot), all passing on `main`. All seven CI gates green. The COSE parser handles tampered signatures, tampered payloads, wrong keys, malformed inputs, truncated input, garbage bytes, empty bytes, missing fields, and ES384 stub routing — every gate surfaces a typed error. The hybrid verifier integration tests now cover the orchestrator → policy-service signer → enclave-side verifier path end-to-end, ready to swap `MockEnclave` for `NitroEnclave` when the M3 GA PR lands.

Next: open `rfc(v1.3)` PR with §5 fold-backs (this doc accompanies it); then queue gRPC client SDK + ES384 verifier in parallel.
