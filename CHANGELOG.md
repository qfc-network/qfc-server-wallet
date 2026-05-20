# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **M4**: real M-of-N quorum backend — registry, approval store, real notifiers, HTTP API.
  - `qfc-wallet-types`: two new ULID newtypes — `ApproverSetId` (an M-of-N group) and `ApproverId` (one registered approver record). Replaces the M1 placeholder where `qfc_policy::PolicyDecision::RequireQuorum` carried `ApprovalId` as a stand-in for the set id.
  - `qfc-quorum::registry` — `ApproverRegistry` async trait with `MemoryApproverRegistry` (in-memory `tokio::sync::RwLock<HashMap>`) and `PostgresApproverRegistry` (sqlx, embedded migrations `0002_approvers.sql`). Trait surface: `add_approver`, `revoke_approver` (soft delete), `get_approver`, `list_approvers_by_owner` (with `include_revoked` flag), `create_approver_set`, `get_approver_set`, `list_approver_sets`. Approver records carry the four-variant `ApproverIdentity` (Chain / External / Hardware / NestedWallet), curve, label, owner, optional webhook URL, lifecycle status, registration timestamp. Approver sets carry `(threshold, total)`, ordered member list, optional per-set `quorum_timeout_secs`. Cycle detection on `NestedWallet` membership at `create_approver_set` time via co-membership DFS with `MAX_NESTING_DEPTH = 3` hard ceiling. Per-set tx + advisory-lock-free design: validation done in application code inside a Postgres transaction (D33).
  - `qfc-quorum::store` — `ApprovalStore` async trait + `MemoryApprovalStore` + `PostgresApprovalStore`. Replay protection enforced at the DB layer via a `UNIQUE (request_id, approver_id)` constraint on the `approvals` table. Idempotent re-submission of the *same* approval payload returns `RecordOutcome::AlreadyRecorded`; a *different* payload from the same approver for the same request returns `ApprovalStoreError::DuplicateApproval`. Both backends agree on the outcome enum.
  - `qfc-quorum::approvers` — replaces `MockQuorumApprover` as the sole production `QuorumApprover` choice (mock remains for tests):
    - `WebhookApprover` — POSTs `application/json` notifications to a registered URL with `X-QFC-Signature: hex(HMAC-SHA256(secret, body))`. Per-request timeout configurable (default 5s).
    - `OnChainQfcEventApprover` — STUB: emits an `OnChainEvent` into a `tokio::sync::broadcast` channel. Real chain submission is gated on `qfc-core` integration not yet in the workspace (retro-m1-m2 §3.6); the trait shape + audit dispatch are wired so M5 can drop in the live submitter.
    - `HardwareApproverNotifier` — dispatch-only, same wire shape as `WebhookApprover` but distinct label `"hardware"` for ops dashboards. The hardware-key signing happens in the approver-side client; this type just notifies.
    - `OrchestratingApprover` — composes `Vec<Arc<dyn ApproverNotifier>>` + one `Arc<dyn ApprovalStore>`. `request_approval` fans out notifications concurrently; `collect_approvals` polls the store with a configurable backoff (default 50ms) AND wakes promptly on `notify_arrival` via an embedded `tokio::sync::Notify`. Surfaces the first reject; times out per the wallet/set-configured window.
  - `qfc-server-wallet::WalletService` integrates the new pieces additively:
    - `WalletService::new` now defaults to `MemoryApproverRegistry` + `MemoryApprovalStore`; production wires `PostgresApproverRegistry` / `PostgresApprovalStore` via the new `with_approver_registry` / `with_approval_store` builders. The `with_quorum_timeout` setter remains.
    - `sign` on `PolicyDecision::RequireQuorum` resolves the set from the registry, builds the `ApprovalRequest` from the registered identities, dispatches `request_approval` to the quorum, then awaits `collect_approvals` honouring the set's `quorum_timeout_secs` override. Audit emits the full transition set: `QuorumNotified`, `QuorumApprovalReceived(approver_key)`, `QuorumApprovalRejected(approver_key)`, `QuorumTimedOut`, and the new `QuorumThresholdReached` (kind byte 16).
    - `record_approval` now verifies the embedded signature, freshness, and approver-identity match against the registry record before persisting (D35); idempotent re-submit returns the `RecordOutcome` distinction so the HTTP layer can map to a stable `recorded: true|false`.
  - `qfc-server-wallet::api` (HTTP surface, all utoipa-annotated):
    - `POST /approvers` + `DELETE /approvers/{id}` + `GET /approvers/{id}` + `GET /approvers?owner=` (admin-gated).
    - `POST /approver-sets` + `GET /approver-sets/{id}` + `GET /approver-sets?owner=`. Cycle / depth / threshold violations map to `422 Unprocessable Entity`.
    - `POST /requests/{request_id}/approvals` (submit signed approval; verify-then-persist; 422 on signature/freshness failure, 409 on duplicate payload, 200 with `recorded: false` on idempotent re-submit) + `GET /requests/{request_id}/approvals`.
    - New schema DTOs: `ApproverIdentityDto` (all four variants, hex byte fields), `CreateApproverRequest`, `ApproverView`, `CreateApproverSetRequest`, `ApproverSetView`, `SubmitApprovalRequest`, `SubmitApprovalResponse`, `ApprovalView`, `ApprovalDecisionDto`, `ApproverStatusDto`.
  - `qfc-audit`: new `AuditKind::QuorumThresholdReached` variant + stable kind byte `16`. `PostgresAuditSink` decoder + the API DTO mirror updated. The hash-chain preimage format is unchanged for kinds `1..=15`; chains generated before M4 remain replay-verifiable.
  - `qfc-policy`: `PolicyDecision::RequireQuorum`'s `approver_set` field is retyped from `ApprovalId` to the new `ApproverSetId`. Internal-only churn (the field was a placeholder in M1).
  - Tests: 31 new (workspace total 259), spanning registry happy-path + every failure mode (unknown member, revoked member, duplicate member, member-count mismatch, threshold ≤ total, threshold > 0, cycle detection, depth cap), webhook + hardware + on-chain stub notifiers (HMAC header asserted via `wiremock`), `OrchestratingApprover` (threshold reached, reject surfaces, timeout, notify-arrival wakeup, notifier failure surfaces, fan-out of N channels), `MemoryApprovalStore` idempotency, HTTP API integration (`tests/api_quorum.rs` — 5 tests, signature verify, duplicate-payload conflict, threshold validation), quorum-driven sign E2E (`tests/quorum_e2e.rs` — 2 tests, threshold-unblocks-sign and timeout-emits-quorum-timed-out). Postgres integration tests for `PostgresApproverRegistry` + `PostgresApprovalStore` run under `--ignored` via `testcontainers` (mirrors `qfc-audit` pattern).
  - New deps in `[workspace.dependencies]`: `reqwest = "0.12"` (`json` + `rustls-tls` only), `wiremock = "0.6"` (dev-dep for webhook + hardware integration tests).
  - Migration `crates/qfc-quorum/migrations/0002_approvers.sql` creates `approvers`, `approver_sets`, `approver_set_members`, `approvals`.
  - `docs/m4-decisions.md` documents the 17 non-obvious calls (D21–D37) from this milestone.

- **M2 P5**: observability — tracing → OTLP + metrics → Prometheus.
  - `qfc_server_wallet::observability` module exposes `init(ObservabilityConfig) -> ObservabilityHandle`, a thin one-shot installer that wires up:
    - `tracing-subscriber` with `EnvFilter` (composes with `RUST_LOG`) and a pretty / JSON fmt layer (`json_logs` flag).
    - Optional `tracing-opentelemetry` layer exporting batched spans to OTLP over Tonic gRPC when `otlp_endpoint` is set.
    - `metrics-exporter-prometheus` recorder with optional standalone HTTP listener (`prometheus_listen_addr`).
  - `observability::http_layer()` — `tower_http::trace::TraceLayer` for per-request HTTP tracing.
  - `observability::prometheus_endpoint(handle)` — `axum::Router` serving `GET /metrics` for embedded mounting (M2 P1's HTTP server merges this in).
  - Canonical QFC metrics pre-registered with `# HELP` descriptions:
    - `qfc_server_wallet_signs_total{scheme, result}` counter
    - `qfc_server_wallet_wallets_created_total{scheme}` counter
    - `qfc_server_wallet_audit_events_total{kind}` counter
    - `qfc_server_wallet_sign_duration_seconds{scheme}` histogram
    - `qfc_server_wallet_policy_evaluation_seconds` histogram
    - `qfc_server_wallet_quorum_collect_seconds` histogram
  - `WalletService::create_wallet`, `sign`, `get_wallet` instrumented additively with `#[tracing::instrument]` + per-stage `histogram!` / `counter!` emits — no public-API change.
  - Versions: `opentelemetry = 0.26`, `opentelemetry-otlp = 0.26`, `opentelemetry_sdk = 0.26`, `tracing-opentelemetry = 0.27`, `metrics = 0.23`, `metrics-exporter-prometheus = 0.15`, `tower = 0.5`, `tower-http = 0.6`, `axum = 0.7`.
  - 6 new tests (130 workspace total).

- Initial Cargo workspace bootstrap per RFC v1.0 §12.
- Six stub crates: `qfc-server-wallet`, `qfc-enclave`, `qfc-sss`, `qfc-policy`, `qfc-quorum`, `qfc-audit`.
- Apache 2.0 license, security policy, contributor guide.
- CI workflows: clippy, fmt, test, cargo-deny, cargo-audit, cargo-vet.
- **M1 P1**: internal `qfc-wallet-types` crate with shared identifiers (`WalletId`, `RequestId`, `ShareId`, `OwnerId`, `PolicyId`, `DecisionId`, `ApprovalId`, `EventId`), signing-scheme + hash-algorithm enums, BIP32-style `HdPath` parser/formatter, and a redacting `SecretBytes` wrapper backed by `Zeroizing` + constant-time comparison.
- **M1 P2**: cryptographic foundation.
  - `qfc-enclave`: `Signer` trait with `Ed25519Signer`, `Secp256k1Signer`, `Secp256k1RecoverableSigner` (`k256` + `ed25519-dalek`, pure Rust, no FFI). Constant-time / deterministic signing where the scheme allows. Recovery byte normalized to `{0, 1}` and re-verified against the public key to reject malformed `v`.
  - `qfc-enclave`: `derivation` module — BIP32 over secp256k1 via `bip32`; SLIP-0010 over ed25519 implemented in-tree (HMAC-SHA512). BIP39 mnemonic → 64-byte seed helper. All-hardened enforcement for ed25519 paths. PQ schemes return `DerivationError::SchemeNotHd`.
  - `qfc-sss`: byte-secret Shamir split / combine via `vsss-rs` over `k256::Scalar`. Length-prefixed, 31-byte-chunked construction so every chunk fits within the curve order without rejection sampling. Self-describing `ShamirShare` blobs carry their `(M, N)` parameters; duplicate indices and parameter mismatches are detected on combine.
  - 54 tests across both crates (unit + 4 proptests, including round-trip over arbitrary secrets and BIP32 / SLIP-0010 reference vectors).
- **M1 P3**: share storage layer.
  - `qfc-sss::ShareStore` async trait + `StoredShare` envelope (wraps a `ShamirShare` with a creation timestamp). Trait surface is put / get / delete / list, all idempotent.
  - `MockShareStore`: in-memory `tokio::sync::RwLock<HashMap>` for tests and dev only.
  - `LocalFsShareStore`: filesystem-backed with XChaCha20-Poly1305 AEAD at-rest encryption. Per-write random 24-byte nonce, magic-prefixed file format, atomic write via `tempfile + rename`. Constructor takes a raw 32-byte key (passphrase / KDF wrapping is intentionally an operator-startup concern, not part of this layer).
  - 20 new tests including wrong-key rejection, ciphertext-tamper rejection, truncated-file rejection, on-disk-bytes-are-actually-encrypted assertion.
- **M1 P4**: enclave abstraction and in-process mock.
  - `qfc-enclave::Enclave` async trait: `attest`, `sign_in_enclave`, `generate_wallet`. Forwards-compatible shape; P5 adds optional `policy_decision` and `approvals` fields without breaking it.
  - `qfc-enclave::attestation::{AttestationDoc, AttestationPayload, MockAttestationKey}` — JSON-canonical payload (`BTreeMap` for `pcrs`), ed25519 signature over `raw_payload` so verifiers re-check the exact issued bytes. `pcr_mock_sentinel()` returns the production-recognizable `0xCD * 48` pattern.
  - `MockEnclave`: combines production crypto (k256 / ed25519-dalek / vsss-rs) in-process. `new()` is **fail-closed** unless `QFC_ALLOW_MOCK_ENCLAVE=yes-i-know`; `new_for_testing()` / `new_for_testing_with_seed()` provide explicit opt-in for tests. Sign-time attestations bind `(request_id, wallet_id, sha256(message), sha256(signature), hd_path, context_json)` into `user_data`.
  - 18 new tests including: env-gate pure helper (no `unsafe` env mutation, no `serial_test` lock), generate→sign→external-verify across ed25519 and secp256k1+HD, attestation-tamper rejection, share-shortage rejection, duplicate-share rejection, PQ-scheme rejection, attestation `user_data` binding cross-check.
- **M1 P5**: audit, policy, and quorum subsystems.
  - `qfc-audit::AuditSink` async trait + `FileAuditSink`: append-only NDJSON with SHA-256 hash chain (`prev_event_hash`) and ed25519 `server_signature` over a canonical preimage. `recover_chain_head` reconstructs the chain cursor on reopen so reload-then-emit keeps linking. `replay_verify(path, pubkey)` does a full chain + signature check; tests cover tampered-body, reordered-events, distinct-key rejection.
  - `qfc-policy::Policy` async trait + `StaticAllowDenyPolicy`: M1 backend with fixed decision precedence (wallet-inactive → chain-deny → chain-allow → requester-deny → requester-allow → default). Decisions carry a `policy_id`, a `decision_id` (ULID), and a `rationale: Vec<RuleHit>` so audit traces can show *why*. Full DSL deferred to M2 per RFC §7.
  - `qfc-quorum::QuorumApprover` async trait + `MockQuorumApprover` + `ApproverIdentity` (all 4 variants: `Chain` / `External` / `Hardware` / `NestedWallet` per RFC decision #3) + `SignedApproval` with `verify(expected_request_id, expected_message_hash, now_ms)`. Enforces `MAX_APPROVAL_AGE_SECS = 3600`; rejects from-the-future timestamps. Signature verification reuses `qfc-enclave::Signer` (no new crypto surface).
  - 26 new tests; 118 total across the workspace.
- **M1 P6**: top-level orchestrator + E2E.
  - `qfc-server-wallet::WalletService` wires `Enclave` + `ShareStore` + `Policy` + `QuorumApprover` + `AuditSink` behind one async API: `create_wallet`, `sign`, `get_wallet`, `record_approval`.
  - In-memory `wallets: HashMap<WalletId, WalletRecord>` registry; M2 swaps for Postgres.
  - `sign` audits at six transition points (`SigningRequested`, `SigningEvaluated`, optional `QuorumNotified`/`QuorumApprovalReceived`, `SigningAttempted`, `SigningSucceeded`/`SigningFailed`).
  - 6 E2E integration tests covering: ed25519 create-then-sign-then-external-verify, secp256k1 create-then-sign-then-external-verify, policy-deny blocks signing, full-flow audit-replay (13 chained events verify), unknown-wallet returns `NotFound`, quorum approval round-trip.
  - 124 tests passing across the workspace.
- **`docs/m1-decisions.md`**: persistent record of the 20 non-obvious decisions made during M1 (crate layout, SSS chunk size, recoverable-`v` cross-check, fail-closed mock enclave, audit chain construction, etc.).
- **M2 P6**: local dev stack + manual API testing collection.
  - `docker-compose.yml` at repo root: brings up `qfc-server-wallet`, `postgres:16-alpine`, `otel/opentelemetry-collector-contrib:latest`, `grafana/mimir:latest`, and `grafana/grafana:latest` with healthchecks, named volumes (`postgres-data`, `mimir-data`, `grafana-data`), and `depends_on: condition: service_healthy` so the app waits on Postgres before starting.
  - `Dockerfile` (repo root): three-stage `cargo-chef` build (planner -> dep-cache builder -> distroless runtime on `gcr.io/distroless/cc-debian12:nonroot`) shipping only the `qfc-server-wallet` binary. `.dockerignore` keeps `target/`, `.git/`, `.claude/`, and Docker volume directories out of the build context but intentionally retains `Cargo.lock` for reproducible binary builds.
  - `deploy/postgres-init/01-create.sql`: idempotent init that adds `pgcrypto` + `btree_gin` extensions and a `qfc` schema (table DDL lives in qfc-audit sqlx migrations).
  - `deploy/otel-collector-config.yaml`: OTLP receivers (gRPC :4317, HTTP :4318) -> batch + resource processors -> `debug` (stdout) and `prometheusremotewrite` -> `mimir:9009/api/v1/push`. Traces and logs export to stdout in dev.
  - `deploy/mimir-config.yaml`: single-process Mimir (`target: all`, multitenancy off, filesystem storage) — minimal viable Prometheus-compatible TSDB for local dashboards.
  - `deploy/grafana/`: provisioned Mimir datasource (Prometheus type, pointed at `http://mimir:9009/prometheus`) and a dashboard provider importing `qfc-server-wallet.json` (panels: signs/sec by scheme, policy evaluation latency p50/p95/p99, audit events/sec by kind).
  - `dev/bruno/qfc-server-wallet/`: Bruno collection with `local` environment (`baseUrl`, `metricsUrl`, `apiKey`, `walletId`) and seven requests — health, create wallet (ed25519), get wallet, sign, audit events, OpenAPI, metrics. Request #02 uses `vars:post-response` to capture `wallet_id` into the `walletId` env var so #03 to #05 reuse it automatically.
  - `tests/dev_stack_smoke.sh`: executable bash smoke test (not part of `cargo test`) — `docker compose ps` precheck, then `/health` -> create wallet -> sign -> audit events (asserts >=2) -> metrics check, with coloured PASS/FAIL output and three exit codes (0 ok / 1 precondition / 2 contract failure).
  - README: new `## Running locally with Docker` section documenting bring-up, Bruno usage, smoke test, and tear-down.
  - Base images use named tags rather than SHA digests at this milestone; pinning by `@sha256:` lands once M3 reaches release-tier (documented inline in the `Dockerfile`).

## [0.0.0] — 2026-05-19

Bootstrap tag for reproducibility baseline. No functionality yet.
