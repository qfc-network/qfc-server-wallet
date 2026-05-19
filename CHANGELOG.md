# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
- **M2 P2**: Postgres-backed audit sink + anchor-commit stub.
  - `qfc-audit::PostgresAuditSink`: sqlx 0.8 backend implementing the same `AuditSink` trait shape as `FileAuditSink`. Chain integrity under concurrent emit is enforced by a transaction-level Postgres advisory lock (`pg_advisory_xact_lock`) keyed on the deterministic constant `0x7146_4353_5343_484E` (ASCII `qFCSSCHN`) so all processes sharing one database serialise their chain-head updates without coordinating.
  - Schema: single `audit_events` table keyed by ULID `event_id`, with `prev_event_hash BYTEA`, `kind SMALLINT` (stable `AuditKind::kind_byte` per M1 D13), JSONB `details`, 64-byte `server_signature`, partial indexes on `wallet_id` / `request_id`, and a full index on `timestamp_unix_ms`. Embedded via `sqlx::migrate!("./migrations")`.
  - `replay_verify_postgres(pool, pubkey)` mirrors the file backend's `replay_verify` over Postgres rows; tampering, signature mismatch, or chain breakage all return `AuditError::Crypto`.
  - `qfc-audit::anchor`: `anchor_payload(pool)` reads the current chain head as `SHA256(preimage ‖ signature)` (M1 D12) plus `{date_utc, head_event_id, event_count}`; `daily_anchor_commit_job(pool, interval, submit)` spawns a tokio interval task that invokes a user-supplied async submit callback. M2 stops at the read side — M3 wires the submitter to qfc-core for on-chain anchoring.
  - 5 integration tests (`crates/qfc-audit/tests/postgres_integration.rs`) using `testcontainers` 0.23 + the Postgres module: emit-fetch chain links, 16-way concurrent emit chain integrity, replay-verify equivalence, wrong-key rejection, anchor-payload latest-head. Gated `#[ignore]` so the default `cargo test` run stays Docker-free; run with `cargo test --workspace -- --ignored` to exercise.
  - `deny.toml`: allow `CDLA-Permissive-2.0` (webpki-roots, permissive); ignore `RUSTSEC-2025-0111` (tokio-tar) and `RUSTSEC-2025-0134` (rustls-pemfile) — both are dev-dependency-only via `testcontainers → bollard` and never link into production binaries.

## [0.0.0] — 2026-05-19

Bootstrap tag for reproducibility baseline. No functionality yet.
