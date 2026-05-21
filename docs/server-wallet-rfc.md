# RFC: QFC Server Wallet (Privy-style TEE custody + M-of-N quorum)

**Status:** v1.3 — accepted
**Author:** Claude (drafted for Larry)
**Date:** 2026-05-19 (v0.1) · 2026-05-19 (v1.0, decisions applied) · 2026-05-21 (v1.1, retro fold-back) · 2026-05-21 (v1.2, M3+M4 retro fold-back) · 2026-05-21 (v1.3, v1.3 batch retro fold-back)
**License of this doc:** Apache 2.0 (will live in public repo `qfc-server-wallet`)

**Changelog**
- v0.1 (2026-05-19) — initial draft, 11 open decisions in §10
- v1.0 (2026-05-19) — decisions resolved by Larry; §10 rewritten as "Resolved decisions"; §9.6 rewritten with honest QVM/WASM ABI assessment from qfc-core code inspection; M5 scope adjusted accordingly; §12 "Repo bootstrap checklist" added
- v1.1 (2026-05-21) — applied retro fold-backs after M1+M2 shipped (228 tests on main); see docs/retro-m1-m2.md
- v1.2 (2026-05-21) — applied retro fold-backs after M3 skeleton + M4 quorum shipped (312 tests on main); see docs/retro-m3-m4.md
- v1.3 (2026-05-21) — applied retro fold-backs after the v1.3 batch shipped — PolicyServiceSigner end-to-end wiring, M5 (ML-DSA + QVM minimal), operator runbooks, COSE parse-half, gRPC API alongside HTTP, approver clients (Rust + TS) — six PRs, 420 tests across four test surfaces; see docs/retro-v1.3.md

---

## 0. Scope & non-goals

In scope:
- Server-side wallet subsystem for programmable treasury, agent wallets, enterprise approval flows
- TEE-isolated key custody, SSS sharding, declarative policy, M-of-N quorum, audit log
- Nitro Enclaves as reference TEE backend; trait-abstracted for SGX/TDX/Mock
- secp256k1 + ed25519 from M1; Dilithium / ML-DSA placeholder from M1, implementation in M5
- Multi-VM policy decoders: EVM, QVM, WASM
- Reproducible enclave image build

Out of scope:
- Client-side wallets (`qfc-wallet`, `qfc-wallet-desktop`, `qfc-wallet-mobile` cover these)
- Custodial UX (login, KYC, recovery flows) — those layer on top, separate product
- Cross-chain bridging (`qfc-bridge` covers it)
- HSM-replacement for chain validators (different threat model)

---

## 1. Crate layout

### 1.1 New repo: `qfc-server-wallet` (public, Apache 2.0)

Cargo workspace with seven crates (six external seams + one internal types crate; see §1.3):

```
qfc-server-wallet/
├── Cargo.toml                       # workspace root
├── crates/
│   ├── qfc-server-wallet/           # binary + top-level lib (HTTP/gRPC API)
│   ├── qfc-enclave/                 # TEE trait + MockEnclave + NitroEnclave backends
│   ├── qfc-sss/                     # SSS wrapper + ShareStore trait + backends
│   ├── qfc-policy/                  # Policy DSL + evaluator + EVM/QVM/WASM decoders
│   ├── qfc-quorum/                  # M-of-N approver coordination
│   ├── qfc-audit/                   # AuditSink trait + Postgres/Kafka/file backends
│   └── qfc-wallet-types/            # internal shared types (IDs, schemes, secret bytes) — breaks qfc-enclave↔qfc-sss dep cycle; see §1.3
├── enclave/
│   ├── Dockerfile.eif               # reproducible Nitro EIF build
│   ├── boot.rs                      # in-enclave binary entrypoint
│   └── kbuild.lock                  # pinned kernel/initramfs versions for reproducibility
├── docs/
│   ├── server-wallet-rfc.md         # this doc
│   ├── threat-model.md
│   ├── attestation.md
│   └── policy-dsl.md
├── examples/
│   └── policies/                    # sample policy configs
├── deny.toml                        # cargo-deny config
├── SECURITY.md                      # disclosure policy
├── LICENSE                          # Apache 2.0
└── NOTICE
```

### 1.2 Sister private repo: `qfc-server-wallet-ops`

```
qfc-server-wallet-ops/               # private
├── terraform/                       # AWS infra (Nitro EC2, KMS, S3, RDS, MSK)
├── kms/                             # KMS key policies, attestation conditions
├── runbooks/                        # incident response (redacted version may land in public docs/)
└── policies/                        # production customer policies (encrypted at rest)
```

### 1.3 Why six crates (not three, not one)

| Crate | Why separate |
|-------|--------------|
| `qfc-server-wallet` | Top-level binary; can be replaced by integrators with their own API surface (gRPC vs HTTP vs in-process embed) |
| `qfc-enclave` | TEE abstraction is the hardest-to-test piece; isolating it lets us swap backends and run the rest of the system against `MockEnclave` |
| `qfc-sss` | SSS layer + ShareStore is a clean abstraction; integrators may want to plug their own storage (Vault, custom HSM) without touching enclave code |
| `qfc-policy` | Policy DSL is the most product-touching surface; tight iteration loop, deserves its own version cadence and test surface |
| `qfc-quorum` | Approver coordination is async/networked logic; very different test profile from the rest (needs mock notification channels) |
| `qfc-audit` | Audit sink is the most likely thing integrators replace (their existing SIEM, their existing event bus) |
| `qfc-wallet-types` | Internal-only — holds cross-crate ID/scheme/secret types so `qfc-enclave` and `qfc-sss` don't form a dep cycle (the enclave needs `EncryptedShare`, the share store needs `WalletId`). Not a "seam" for integrators; a types crate. Added in M1 per [D1](m1-decisions.md#d1). |

Three-crate or one-crate layouts make the binary monolithic and force integrators to fork to customize any single piece. Six is the smallest split that gives meaningful seams; the 7th `qfc-wallet-types` crate exists for *types*, not *seams*, and the "meaningful seams" reasoning above is unchanged.

### 1.4 Dependencies on `qfc-core`

Must depend on:
- `qfc-types` — `Address`, `Hash`, `PublicKey`, `Signature` (reuse types across the ecosystem)
- `qfc-crypto` — `Keypair`, `verify_signature` for ed25519 baseline

**Decision (v1.0):** `qfc-types` and `qfc-crypto` ship on **public crates.io**. This requires a small piece of preparatory work in `qfc-core`:
- Add `[package].publish = true`, populate `description`, `documentation`, `repository`, `readme`, `keywords`, `categories`
- Adopt a public semver policy (likely `0.x` until the first stable cut)
- Add a release workflow (tag → `cargo publish` with `--token`-from-secret), with order: `qfc-types` → `qfc-crypto` (crypto depends on types)
- During the interim (before first publish), `qfc-server-wallet` uses a **git dep pinned to a commit hash**, replaced with a crates.io version dep before the M1 tag.

### 1.5 Crate selection — third-party

| Need | Crate | Why |
|------|-------|-----|
| Async runtime | `tokio` (1.x, multi-thread) | de facto standard, matches rest of qfc ecosystem |
| HTTP server | `axum` | tower-compatible, easy middleware for auth/tracing, low overhead |
| gRPC (later) | `tonic` | most mature pure-rust gRPC |
| SSS | `vsss-rs` | active maintenance, supports Shamir + Feldman + Pedersen VSS (matters for future verifiable shares without library swap), no_std friendly (will run inside enclave) |
| secp256k1 | `k256` (RustCrypto) | pure rust, audited, no FFI surface for the enclave |
| ed25519 | `ed25519-dalek` | already used in qfc-crypto |
| BIP32/BIP39 | `bip32` + `bip39` (RustCrypto) | pure rust; HD derivation runs inside enclave |
| PQ (M5) | `pqcrypto-dilithium` (NIST ML-DSA / FIPS 204) | NIST-standardized, pure-Rust wrappers around ref implementation. Avoid `oqs-rs` for enclave — pulls in liboqs C lib, complicates reproducible builds |
| Nitro SDK | `aws-nitro-enclaves-nsm-api` + `aws-nitro-enclaves-attestation` | official AWS crates; thin and audited |
| Vsock IPC | `tokio-vsock` | host↔enclave channel |
| KMS | `aws-sdk-kms` | for share encryption-at-rest |
| Attestation parsing | `aws-nitro-enclaves-cose` + `coset` | COSE_Sign1 verification |
| Audit storage | `sqlx` (Postgres) + `rdkafka` (optional) | tracing-compatible, async |
| Policy serialization | `serde` + `serde_json` for v1; consider `protobuf` if cross-language clients emerge | start simple |
| Tracing | `tracing` + `tracing-subscriber` + `tracing-opentelemetry` | matches existing qfc stack |
| Metrics | `metrics` + `metrics-exporter-prometheus` | Mimir-compatible (matches existing infra) |
| Testing | `proptest`, `tokio-test`, `wiremock`, `testcontainers` | property tests for policy engine; integration tests for enclave/store |
| Build hygiene | `cargo-deny`, `cargo-vet`, `cargo-audit` | mandatory in CI |

Crates explicitly rejected:
- `sharks` (SSS) — too basic, no verifiable variants, would need swap-out later
- `secp256k1` (libsecp256k1 FFI) — FFI from inside enclave complicates reproducible build; `k256` is fast enough
- `openssl` — pulls in libssl, terrible for enclave attack surface; we use `rustls` if TLS is needed

---

## 2. Core traits

All traits `Send + Sync + 'static` and use `async_trait` until rust-lang stabilizes async-in-traits enough for object safety (likely 2026 stable, will migrate).

### 2.1 `Enclave`

The TEE boundary. Everything inside `sign_in_enclave` runs in a memory-isolated environment; key shares enter as encrypted blobs that only the enclave's KMS-granted policy can decrypt.

```rust
// crates/qfc-enclave/src/lib.rs
#[async_trait]
pub trait Enclave: Send + Sync {
    /// Returns the enclave's measurement (PCR0..PCR4 for Nitro) and a fresh
    /// attestation document binding the enclave identity key to those PCRs.
    /// The nonce is included in the attestation to prevent replay.
    async fn attest(&self, nonce: [u8; 32]) -> Result<AttestationDoc, EnclaveError>;

    /// Reconstruct the secret from M-of-N shares INSIDE the enclave, derive
    /// the requested HD path (if applicable), sign the message under the given
    /// scheme, and return the signature plus an attestation that binds:
    ///   (request_id, message_hash, signature_hash, scheme, public_key, hd_path)
    /// to the enclave identity key.
    async fn sign_in_enclave(
        &self,
        req: EnclaveSignRequest,
    ) -> Result<EnclaveSignResponse, EnclaveError>;

    /// Generate a new master seed inside the enclave, split it via SSS,
    /// encrypt each share under a different recipient public key (typically
    /// KMS-wrapped per ShareStore backend), and return the encrypted shares
    /// + the derived public key for the requested HD path (usually m/).
    /// The master seed is zeroized before this function returns.
    async fn generate_wallet(
        &self,
        req: GenerateWalletRequest,
    ) -> Result<GenerateWalletResponse, EnclaveError>;
}

pub struct EnclaveSignRequest {
    pub request_id: RequestId,
    pub shares: Vec<EncryptedShare>,    // already fetched from ShareStore
    pub threshold: u8,
    pub scheme: SigningScheme,
    pub hd_path: Option<HdPath>,        // None = sign with master key directly
    pub message: Vec<u8>,               // raw bytes to sign (caller hashes if needed)
    pub context: SigningContext,        // chain id, vm type, tx hash, etc. — for attestation binding
    pub policy_decision: SignedPolicyDecision, // policy engine output, signed by policy service
    pub approvals: Vec<SignedApproval>, // if quorum required
}

pub struct EnclaveSignResponse {
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation: AttestationDoc,
}
```

**Decision (v1.0): hybrid policy evaluation.** The policy engine does the heavy work (decode tx, walk rules, compute rate-limit state, evaluate VM-shape constraints) and emits a `SignedPolicyDecision` signed by the policy service key. The enclave then re-verifies a small, *fixed-shape* set of invariants on top of the signed decision:
- Policy service signature is valid (key pinned at EIF build time via attested config)
- `request_id` binds the decision to *this* signing request
- `wallet_id` matches the wallet whose shares are being reconstructed
- **Hard ceilings**: `value <= wallet.max_value_cap`, `to ∈ wallet.contract_allowlist` (allowlist hash pinned in `Wallet`), `chain_id ∈ wallet.chain_allowlist`
- Decision freshness: `now - decision_timestamp <= max_age`

The split is: policy service is the *authority on flexible rules* (custom DSL, ad-hoc rate limits, time windows); the enclave is the *authority on a small fixed set of hard limits* that can be reasoned about and audited line-by-line. Policy upgrades that touch only flexible rules do **not** require a new EIF; changes to hard ceilings do.

**M3 GA blocker (v1.1).** This hybrid scheme is a **hard prerequisite for M3 GA**, not optional. Shipping a Nitro EIF whose `sign_in_enclave` doesn't re-verify the signed policy decision against hard ceilings leaves the most important security argument unmade — the enclave would be a crypto box only. M3 must extend `EnclaveSignRequest` with `policy_decision` and `approvals`, populate `Wallet.{max_value_cap, contract_allowlist, chain_allowlist}` as hard ceilings, and bake the invariant checker + signed-policy verifier into the EIF binary. See §7 (M3 ships) and the retro [§3.4](retro-m1-m2.md) for why M1+M2 deferred this (the orchestrator currently collects the policy decision; `MockEnclave` only does crypto).

### 2.2 `ShareStore`

```rust
// crates/qfc-sss/src/store.rs
#[async_trait]
pub trait ShareStore: Send + Sync {
    /// Store an encrypted share. Idempotent on share_id.
    async fn put(&self, share_id: &ShareId, share: EncryptedShare) -> Result<(), StoreError>;

    /// Retrieve an encrypted share. The share is encrypted under a key only the
    /// target enclave can decrypt (via KMS attestation-conditional decryption);
    /// this trait does NOT decrypt.
    async fn get(&self, share_id: &ShareId) -> Result<EncryptedShare, StoreError>;

    /// Delete a share (for wallet revocation). Soft delete with retention is
    /// implementation-defined; the trait contract is "the share is no longer
    /// retrievable via get()".
    async fn delete(&self, share_id: &ShareId) -> Result<(), StoreError>;

    /// List shares for a wallet. Used during signing-quorum collection.
    async fn list(&self, wallet_id: &WalletId) -> Result<Vec<ShareId>, StoreError>;
}
```

Backends in M1:
- `LocalFsShareStore` — encrypted files on local disk, key in age-encrypted file unlocked by an operator passphrase at server start
- `MockShareStore` — in-memory, for unit tests

M3:
- `S3KmsShareStore` — share at `s3://bucket/wallet-id/share-index`, encrypted via AWS KMS envelope encryption where the KMS key has an attestation-conditional decrypt policy (only enclaves with PCR0 = expected can decrypt)

Future:
- `VaultShareStore` — HashiCorp Vault Transit
- `MultiCloudShareStore` — composite that puts shares in different cloud providers (this is how SSS achieves real "no single boundary" — see threat model)

### 2.3 `Signer`

Curve-agnostic. Lives inside the enclave; never exposed to host.

```rust
// crates/qfc-enclave/src/signer.rs
pub trait Signer: Send + Sync {
    fn scheme(&self) -> SigningScheme;

    /// Derive public key from secret bytes. Secret format is scheme-specific.
    fn public_key(&self, secret: &SecretBytes) -> Result<PublicKey, SignerError>;

    /// Sign a message. `message` is raw bytes; scheme-specific pre-hashing
    /// happens inside the impl (ed25519 doesn't pre-hash, secp256k1 hashes
    /// with keccak256 for Ethereum, with sha256 for Bitcoin, etc.).
    fn sign(&self, secret: &SecretBytes, message: &[u8], hash_alg: HashAlg)
        -> Result<Vec<u8>, SignerError>;

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8],
              hash_alg: HashAlg) -> Result<bool, SignerError>;
}

pub enum SigningScheme {
    Ed25519,
    Secp256k1,
    Secp256k1Recoverable,   // EIP-155 / Ethereum-style with v
    MlDsa44,                // Dilithium2 / FIPS 204 ML-DSA-44 — M5
    MlDsa65,                // Dilithium3 — M5
    MlDsa87,                // Dilithium5 — M5
}

pub enum HashAlg {
    None,        // ed25519 - signs message directly
    Sha256,
    Keccak256,
    Blake3,
}
```

`SecretBytes` is a `zeroize::Zeroizing<Vec<u8>>` — auto-zeroed on drop.

### 2.4 `Policy`

```rust
// crates/qfc-policy/src/lib.rs
#[async_trait]
pub trait Policy: Send + Sync {
    async fn evaluate(&self, req: &SigningRequest, wallet: &Wallet)
        -> Result<PolicyDecision, PolicyError>;
}

pub enum PolicyDecision {
    Allow {
        decision_id: DecisionId,
        rationale: Vec<RuleHit>,         // which rules matched
    },
    Deny {
        decision_id: DecisionId,
        reason: DenyReason,
        rationale: Vec<RuleHit>,
    },
    RequireQuorum {
        decision_id: DecisionId,
        threshold: u8,
        total: u8,
        approver_set: ApproverSetId,
        rationale: Vec<RuleHit>,
    },
}
```

Policy rules cover:
- **Chains** — allowlist of `chain_id`
- **Targets** — allowlist of contract addresses, optionally per chain
- **Methods** — allowlist of method selectors (per ABI), or method allowlists by contract
- **Value caps** — max value per tx, max cumulative value per time window (per chain, per asset)
- **Time windows** — sign only during specified UTC windows / weekdays
- **Rate limits** — token-bucket per wallet, per requester, per (wallet, requester)
- **VM-shape constraints** — decoded constraints per VM:
  - EVM: `to`, `value`, `data[0..4]` selector, `gasLimit` upper bound
  - QVM: `target_module`, `function`, `args_schema` constraints
  - WASM: `module_hash`, `entry_point`, `arg_constraints`
- **Quorum triggers** — declarative "this combination of conditions requires M-of-N approval before signing"

Rule format is `serde_json` for v1 (CUE-like later if it grows). One example:

```json
{
  "version": 1,
  "rules": [
    {
      "id": "evm-only-treasury-contracts",
      "match": { "vm": "evm", "chain_id": 9001 },
      "require": { "to": { "in": ["0xAbC...", "0xDef..."] } }
    },
    {
      "id": "large-value-needs-quorum",
      "match": { "vm": "evm", "value_qfc": { "gte": "1000000" } },
      "action": "require_quorum",
      "quorum": { "approver_set": "treasury-keyholders", "threshold": 3, "total": 5 }
    },
    {
      "id": "rate-limit-5-per-minute",
      "match": { "vm": "*" },
      "action": "rate_limit",
      "limit": { "tokens": 5, "refill_per": "1m" }
    }
  ]
}
```

### 2.5 `QuorumApprover`

```rust
// crates/qfc-quorum/src/lib.rs
#[async_trait]
pub trait QuorumApprover: Send + Sync {
    /// Notify approvers of a pending signing request.
    async fn request_approval(&self, req: &ApprovalRequest)
        -> Result<(), QuorumError>;

    /// Block until threshold approvals are collected or timeout.
    /// Returns the approvals (signed by approver private keys over the request_id+message_hash).
    async fn collect_approvals(
        &self,
        request_id: &RequestId,
        threshold: u8,
        timeout: Duration,
    ) -> Result<Vec<SignedApproval>, QuorumError>;

    /// Verify a single approval signature against the approver's registered public key.
    /// Called by the enclave (yes, the enclave re-verifies — see threat model).
    fn verify_approval(&self, approval: &SignedApproval, expected: &ApproverIdentity)
        -> Result<bool, QuorumError>;
}

pub struct SignedApproval {
    pub approver_id: ApproverId,
    pub request_id: RequestId,
    pub message_hash: [u8; 32],
    pub decision: ApprovalDecision,    // Approve | Reject
    pub signature: Vec<u8>,            // over (request_id || message_hash || decision || timestamp)
    pub timestamp: i64,
    pub scheme: SigningScheme,         // approvers can be different curves
}
```

**Decision (v1.0):** all four approver identity variants are supported.

```rust
pub enum ApproverIdentity {
    Chain(qfc_types::Address),         // QFC on-chain account; approval signed by that account's key
    External(PublicKey),               // raw ed25519/secp256k1 pubkey registered out-of-band
    Hardware(HardwareApproverHandle),  // YubiKey / Ledger / Trezor — approver client uses hw device to sign
    NestedWallet(WalletId),            // another QFC server wallet (treasury-of-treasuries composition)
}
```

`HardwareApproverHandle` is opaque to the server (an identifier the approver-side client maps to a specific device + slot). The system only sees the resulting signature + scheme. `NestedWallet` recursion is bounded — a wallet's approver set must not contain itself, transitively (cycle check at approver-set registration time, hard limit on nesting depth at evaluation time).

### 2.6 `AuditSink`

```rust
// crates/qfc-audit/src/lib.rs
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn emit(&self, event: AuditEvent) -> Result<(), AuditError>;

    /// Optional bulk emit for high-throughput scenarios. Default impl loops.
    async fn emit_batch(&self, events: Vec<AuditEvent>) -> Result<(), AuditError> {
        for e in events { self.emit(e).await?; }
        Ok(())
    }
}

pub struct AuditEvent {
    pub event_id: EventId,             // ULID, monotonic per server instance
    pub prev_event_hash: [u8; 32],     // hash-chained for tamper evidence
    pub timestamp_unix_ms: i64,
    pub actor: Actor,                  // Requester | Approver | System | Enclave
    pub kind: AuditKind,               // see below
    pub request_id: Option<RequestId>,
    pub wallet_id: Option<WalletId>,
    pub details: serde_json::Value,    // kind-specific payload
    pub server_signature: Vec<u8>,     // signature over (prev_hash || event_id || kind || details)
}

pub enum AuditKind {
    WalletCreated, WalletRevoked,
    SigningRequested, SigningEvaluated,
    QuorumNotified, QuorumApprovalReceived, QuorumApprovalRejected, QuorumTimedOut,
    SigningAttempted, SigningSucceeded, SigningFailed,
    PolicyChanged, ApproverSetChanged,
    SystemError, EnclaveAttested,
}
```

Backends in M2:
- `PostgresAuditSink` — strict ordering via row-level locks + sequence
- `FileAuditSink` — append-only NDJSON file, for dev/local

M2+ optional:
- `KafkaAuditSink` — for high-throughput multi-tenant deployments, partition by `wallet_id`. Picked at config time per decision #6; deferred from M2 baseline because no customer needed it for M2 dev/staging.

The hash-chained structure means tampering with any event invalidates the chain from that point forward; the daily anchor commitment (M2) pins the chain head to an on-chain QFC transaction so even chain operators can't quietly rewrite history.

---

## 3. Data model

### 3.1 `Wallet`

```rust
pub struct Wallet {
    pub wallet_id: WalletId,           // ULID — opaque, sortable, ecosystem-standard
    pub qfc_address: Option<qfc_types::Address>, // derived from master_public_key for chain-compatible schemes; None for PQ wallets
    pub display_name: String,
    pub owner_id: OwnerId,             // tenant/customer identifier
    pub created_at: i64,
    pub status: WalletStatus,          // Active | Frozen | Revoked
    pub master_public_key: PublicKey,  // derived at creation, never changes
    pub scheme: SigningScheme,
    pub hd_capable: bool,              // true for ed25519/secp256k1, false for PQ schemes
    pub policy_id: PolicyId,
    pub quorum_config: Option<QuorumConfig>,
    pub share_config: ShareConfig,     // M, N, store backends per share
    pub enclave_pcr_constraint: PcrConstraint,  // which EIF measurement is allowed to sign for this wallet
}

pub struct ShareConfig {
    pub threshold: u8,                 // M
    pub total: u8,                     // N
    pub share_locations: Vec<ShareLocation>,  // N entries, one per share
}

pub struct ShareLocation {
    pub share_index: u8,
    pub store_backend: StoreBackendId, // s3-primary, s3-backup, vault, etc.
    pub kms_key_arn: String,           // attestation-conditional key
}

pub struct PcrConstraint {
    pub pcr0: [u8; 48],                // measurement of the EIF
    pub pcr1: [u8; 48],                // measurement of the kernel + boot ramfs
    pub pcr2: [u8; 48],                // measurement of the application
    // upgrades work by adding a new acceptable PCR set; downgrade prevention enforced at KMS policy level
}
```

**Decision (v1.0):** `wallet_id` is a **ULID**; the on-chain `qfc_address` (when applicable) is a separate field on `Wallet`. Two IDs serve two purposes: `wallet_id` is the stable logical identifier (curve-agnostic, survives PQ migration), `qfc_address` is the chain-queryable account. PQ wallets have `qfc_address = None` until/unless the chain accepts ML-DSA-derived addresses.

**Shipping order annotation (v1.1).** The `Wallet` shape above is the target. The M1+M2 in-memory `WalletRecord` is a **subset projection**; full §3.1 fields land in stages. No field is removed — this is annotation, not redesign. See retro [§3.3](retro-m1-m2.md) for rationale.

| Field | First shipped in |
|-------|------------------|
| `wallet_id`, `scheme`, `owner_id`, `threshold`, `total`, `policy_id`, `master_public_key`, `status`, `created_at`, `display_name` | **M1 / M2** (`WalletConfig` carries the M1 subset; service-level `WalletRecord` adds the rest) |
| `enclave_pcr_constraint` | **M3** — only meaningful with `NitroEnclave`; no-op with `MockEnclave` |
| `share_config.share_locations[]` | **M3** — single `ShareStore` instance in M2; multi-store fan-out lands with `S3KmsShareStore` |
| `qfc_address` populated | **M3** — derivable from `master_public_key`; recompute on demand until M3 |
| `quorum_config` | **M4** — quorum is policy-driven in M2; per-wallet override is M4 territory |
| `hd_capable` | derived from `scheme` (ed25519/secp256k1 → true; ML-DSA → false); kept derived, not stored |

### 3.2 `KeyShare` record (stored in `ShareStore`)

```rust
pub struct EncryptedShare {
    pub share_id: ShareId,             // {wallet_id}-{share_index}
    pub wallet_id: WalletId,
    pub share_index: u8,
    pub total: u8,                     // N
    pub threshold: u8,                 // M
    pub scheme: ShareScheme,           // Shamir | FeldmanVerifiable | PedersenVerifiable
    pub ciphertext: Vec<u8>,           // KMS-envelope-encrypted SSS share
    pub wrapped_dek: Vec<u8>,          // data encryption key wrapped by KMS, KMS policy gates on enclave attestation
    pub integrity_mac: [u8; 32],       // HMAC over (share_id || ciphertext || wrapped_dek)
    pub kms_key_arn: String,
    pub pcr_constraint: PcrConstraint, // enforced by KMS policy
    pub created_at: i64,
}
```

### 3.3 `SigningRequest`

```rust
pub struct SigningRequest {
    pub request_id: RequestId,         // ULID
    pub wallet_id: WalletId,
    pub requester: Requester,          // ApiKey | OAuthSubject | NestedWallet | OnChainContract
    pub vm_type: VmType,               // Evm | Qvm | Wasm
    pub chain_id: u64,
    pub payload: SigningPayload,       // decoded once for policy, signed as raw bytes
    pub hd_path: Option<HdPath>,
    pub hash_alg: HashAlg,
    pub ttl_seconds: u32,              // expires from queue if not signed in time
    pub idempotency_key: Option<String>, // for retry-safe submission
    pub created_at: i64,
}

pub enum SigningPayload {
    Raw { bytes: Vec<u8> },            // arbitrary message
    Evm(EvmTxPayload),
    Qvm(QvmTxPayload),
    Wasm(WasmTxPayload),
    PersonalSign { bytes: Vec<u8> },   // EIP-191
    TypedData(EvmTypedData),           // EIP-712
}
```

VM-specific payload types decoded by `qfc-policy` for rule evaluation, then re-serialized to canonical bytes for the actual signature. Decoders for each VM live in `qfc-policy/src/decoders/`.

### 3.4 `AttestationDoc`

Nitro AttestationDoc is a COSE_Sign1 envelope containing PCR measurements + user_data + public_key + nonce, signed by AWS's Nitro root certificate.

```rust
pub struct AttestationDoc {
    pub raw_cose_sign1: Vec<u8>,       // exact bytes for re-verification by anyone
    pub parsed: AttestationPayload,
    pub root_cert_chain: Vec<Vec<u8>>, // AWS Nitro root chain at the time of issue
}

pub struct AttestationPayload {
    pub module_id: String,             // Nitro module ID
    pub timestamp: i64,
    pub pcrs: BTreeMap<u8, Vec<u8>>,   // PCR0..PCR4
    pub certificate: Vec<u8>,          // enclave's ephemeral certificate
    pub public_key: Vec<u8>,           // enclave identity key
    pub user_data: Vec<u8>,            // we put the request_id + message_hash + signature_hash here
    pub nonce: Vec<u8>,
}
```

The `user_data` field is what binds the attestation to the *specific* signing operation. This is the only way Nitro gives us per-operation attestation — there is no "the enclave attests to this specific computation" primitive in Nitro. See §5.2.

### 3.5 `AuditEvent`

See §2.6.

---

## 4. Sequence diagrams

### 4.1 Wallet creation

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant SW as qfc-server-wallet
    participant POL as qfc-policy
    participant ENC as qfc-enclave (Nitro)
    participant KMS as AWS KMS
    participant SS as ShareStore (S3)
    participant AUD as AuditSink

    C->>SW: POST /wallets {scheme, share_config, policy_id, quorum_config}
    SW->>POL: validate(policy_id)
    POL-->>SW: ok
    SW->>ENC: generate_wallet(scheme, M, N, hd_capable)
    Note over ENC: entropy = RNG inside enclave<br/>seed = entropy<br/>shares = SSS::split(seed, M, N)<br/>master_pub = derive(seed, m/)<br/>zeroize(seed, entropy)
    ENC->>KMS: GenerateDataKey per share<br/>(KMS policy requires PCR0=expected)
    KMS-->>ENC: wrapped DEKs
    Note over ENC: encrypt(share_i, dek_i)
    ENC-->>SW: {encrypted_shares[], master_pub, attestation}
    SW->>SS: put(share_id_i, encrypted_share_i) [for each share]
    SS-->>SW: ok
    SW->>SW: persist Wallet record (master_pub, policy_id, ...)
    SW->>AUD: WalletCreated event
    SW-->>C: {wallet_id, master_pub, attestation}
    Note over C: client verifies attestation against<br/>known PCR0 and AWS Nitro root
```

### 4.2 Signing — no quorum

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant SW as qfc-server-wallet
    participant POL as qfc-policy
    participant ENC as qfc-enclave
    participant KMS as KMS
    participant SS as ShareStore
    participant AUD as AuditSink

    C->>SW: POST /wallets/{id}/sign {vm, chain_id, payload, hd_path}
    SW->>AUD: SigningRequested
    SW->>POL: evaluate(request, wallet)
    Note over POL: decode payload by vm_type<br/>match rules<br/>check rate limits
    POL-->>SW: PolicyDecision::Allow + signed_decision
    SW->>AUD: SigningEvaluated(Allow)
    SW->>SS: get(share_id_i) for M of N
    SS-->>SW: encrypted_shares[]
    SW->>ENC: sign_in_enclave(shares, scheme, hd_path, message, signed_decision)
    ENC->>KMS: Decrypt(wrapped_dek_i) [KMS verifies attestation→PCR0]
    KMS-->>ENC: dek_i
    Note over ENC: decrypt shares<br/>verify signed_decision sig<br/>re-check invariants (value cap, allowlist)<br/>seed = SSS::combine(shares)<br/>key = derive(seed, hd_path)<br/>sig = sign(key, message)<br/>attestation.user_data = (req_id || msg_hash || sig_hash)<br/>zeroize(seed, key, shares)
    ENC-->>SW: {signature, public_key, attestation}
    SW->>AUD: SigningSucceeded
    SW-->>C: {signature, public_key, attestation}
```

### 4.3 Signing — M-of-N quorum

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant SW as qfc-server-wallet
    participant POL as qfc-policy
    participant Q as qfc-quorum
    participant A1 as Approver 1
    participant AN as Approver N
    participant ENC as qfc-enclave
    participant SS as ShareStore
    participant AUD as AuditSink

    C->>SW: POST /wallets/{id}/sign {...}
    SW->>AUD: SigningRequested
    SW->>POL: evaluate(request, wallet)
    POL-->>SW: RequireQuorum{threshold=M, total=N, approver_set}
    SW->>AUD: SigningEvaluated(RequireQuorum)
    SW->>Q: request_approval({request_id, message_hash, approver_set})
    par notify approvers
        Q->>A1: notify (webhook/email/onchain event)
    and
        Q->>AN: notify
    end
    SW->>AUD: QuorumNotified
    A1-->>Q: SignedApproval (Approve, sig over req_id||msg_hash)
    SW->>AUD: QuorumApprovalReceived(A1)
    AN-->>Q: SignedApproval (Approve)
    SW->>AUD: QuorumApprovalReceived(AN)
    Note over Q: M approvals reached
    Q-->>SW: approvals[]
    SW->>SS: get(share_id_i) for M of N
    SS-->>SW: encrypted_shares[]
    SW->>ENC: sign_in_enclave(shares, ..., approvals)
    Note over ENC: KMS-decrypt shares<br/>verify each approval sig against registered approver pubkey<br/>verify approval count >= threshold<br/>verify approval message_hash matches actual message_hash<br/>verify approval not expired<br/>re-check invariants<br/>combine + derive + sign<br/>attestation.user_data = (req_id || msg_hash || sig_hash || approval_set_hash)
    ENC-->>SW: {signature, public_key, attestation}
    SW->>AUD: SigningSucceeded
    SW-->>C: {signature, public_key, attestation}
```

Notes on §4.3:
- Approval verification happens **inside** the enclave, not just in `qfc-quorum`. The enclave must not trust the host to have correctly counted approvals — host could be compromised
- `approval_set_hash` in attestation user_data lets external verifiers reconstruct which approvers signed for any historical signing event
- Approvals expire (signed timestamp + max_age); enclave rejects stale approvals to prevent replay across requests

---

## 5. Threat model

### 5.1 What each layer defends against

| Layer | Defends against | How |
|-------|-----------------|-----|
| TEE (Nitro) | Malicious operator with root on host; compromised host OS/hypervisor; memory dumps; debugger attach | Enclaves run in isolated VMs with no persistent storage, no networking except vsock to parent, no user/ssh access; memory cannot be inspected by parent EC2 instance |
| TEE attestation | Substituted enclave binary; downgraded EIF | KMS decrypt policy gates on PCR0; old EIFs become unusable after rotation |
| SSS | Single share-store compromise (S3 breach, single bucket access) | M-of-N shares; reconstructing requires M independent stores; threshold tuning is operational choice |
| Multi-cloud SSS (M3+) | Single cloud provider compromise / nation-state seizure | Distribute shares across AWS + GCP + on-prem Vault |
| Policy engine | Out-of-policy signing (wrong contract, oversize value, off-hours); request flooding | Declarative rules + rate limits; re-verified inside enclave |
| Quorum | Single approver compromise (key theft, coercion); insider operator with one approver key | Need M signatures from N independent keys; approver keys held by different humans/HSMs |
| Audit log | Tampering by operator; replay attacks | Hash-chained events; server signature; daily anchor commit to QFC chain |
| Reproducible EIF | Hidden backdoor in shipped enclave image | Bit-for-bit reproducible build from public repo; anyone can rebuild and compare PCR0 |
| Cargo supply chain | Malicious dep update | cargo-vet + cargo-deny + audit lockfile; full SBOM published per release |

### 5.2 What it does NOT defend against — be explicit

| Threat | Mitigation we have | Mitigation we don't have |
|--------|--------------------|--------------------------|
| AWS itself is compromised (insider with Nitro signing keys) | Multi-cloud SSS makes a single-cloud compromise insufficient; the *signing* still requires Nitro PCR if the wallet was configured for Nitro-only | If the wallet was Nitro-only and AWS forges attestation, game over for that wallet. Mitigation: support multiple TEE backends and let high-value wallets require *cross-TEE* M-of-N (e.g. 2 of [Nitro, SGX, TDX]) — design accommodates this but M1-M4 don't implement it |
| Side channels in Nitro (timing, cache, microarchitectural) | Constant-time crypto libs (`k256` is CT; ed25519-dalek's signing path is CT); Nitro better than SGX here because parent EC2 cannot observe enclave's microarch state | Not perfect — research-grade attacks may exist. Don't store secrets >5 seconds in enclave; zeroize aggressively |
| Compromise of M of N approvers | Quorum config — make M larger; distribute approvers across orgs/jurisdictions; require hardware-backed approver keys | If a customer's M approvers all get phished, their wallet drains. This is by design — we don't replace the customer's judgment, just enforce it |
| Compelled signing under legal/state duress | Operational: jurisdictional spread of approvers; legal: published transparency reports | Cryptographic: none. If valid signers sign, the system signs. There's no "duress code" primitive |
| Operator with prod KMS admin access | KMS key policies pinned to specific PCR0; key policy changes require IAM-level multi-party approval (managed in `qfc-server-wallet-ops`) | If a single human at qfc-network org has KMS:PutKeyPolicy + EC2 LaunchEnclave, they can rewrite policy to allow a backdoored EIF and sign. **Mitigation: KMS policy changes themselves require M-of-N via AWS IAM Access Analyzer + organizational policy + GitHub branch protection on `qfc-server-wallet-ops`** |
| Supply chain on `tokio` or any pinned crate | cargo-vet, cargo-audit, cargo-deny, reproducible builds, SBOM | Not eliminable — high-impact compromise of a critical crate (e.g. `serde_json` 2024-incident-style) requires emergency response, not prevention |
| Quantum computer breaks secp256k1/ed25519 | M5 PQ signer (Dilithium/ML-DSA) available | Wallets created before M5 still use classical curves; require migration tool (M5+) to re-shard under PQ scheme |
| Replay attacks (same signing request twice) | `request_id` is in attestation user_data; idempotency keys; nonce/sequence in approval payload; rate limits | Cross-instance replay if multiple server instances don't share state — mitigated by single-writer Postgres for request_id uniqueness |
| Share store compromise + concurrent enclave compromise | This is the "M shares + enclave both leak simultaneously" case | If both happen at once, attacker has everything. Multi-cloud SSS + cross-TEE quorum makes "everything at once" require multiple separate compromises |

### 5.3 "Operation attestation" caveat

The task brief says: *"every signing operation produces a cryptographic attestation that the operation ran in a verified enclave with verified code."*

What Nitro actually gives us:
- An attestation document at any time, with arbitrary `user_data` and `nonce`
- The doc is signed by the Nitro hypervisor and includes PCR measurements

What this means:
- We **cannot** produce an attestation that says "this signature is the result of running this exact code on these exact inputs" as a single Nitro primitive
- We **can** produce an attestation that says "this enclave (with PCR0 = X) had `user_data = (request_id || message_hash || signature_hash || ...)` at time T" — and we trust the enclave code (because PCR0 binds it) to only emit attestations matching real signing operations

This is the standard TEE attestation pattern but worth stating plainly: **the security argument is "the code in the EIF (which you can rebuild and verify) only emits attestations for real signing events; if PCR0 matches and the user_data binds the inputs, the signature is legitimate."**

If we wanted unconditional "the computation itself is attested," we'd need ZK proofs over the signing circuit — out of scope for v1.

---

## 6. Privy comparison

| Property | Privy | QFC Server Wallet |
|----------|-------|-------------------|
| TEE | AWS Nitro Enclaves | AWS Nitro (default M3); SGX, TDX, Mock pluggable behind `Enclave` trait |
| Key sharding scheme | Shamir SSS, 3 shares | Shamir SSS, configurable M-of-N; future Feldman/Pedersen VSS via vsss-rs |
| HD wallet | BIP32/BIP39 | BIP32/BIP39 for classical curves; PQ schemes are non-HD (one keypair per wallet for ML-DSA) |
| Curve support | secp256k1, ed25519 | secp256k1, ed25519, **+ ML-DSA (Dilithium) from M5** |
| Multi-VM policy | EVM, Solana (siloed) | EVM (full ABI), QVM (minimal — envelope-level controls only at M5; full method/argument-level decoder gated on `qfc-core` shipping a `QvmCall` tx variant), WASM (deferred — not yet implemented in `qfc-core`) |
| Quorum approval | Optional, manual flows | **First-class M-of-N, declarative trigger from policy, enclave-verified approvals** |
| Approver identity | Privy user / external pubkey | QFC chain account / external pubkey / hardware / **nested server wallet** |
| Attestation surface | Internal, customer-visible per-request | **Public verification page** — anyone can verify attestation against published reproducible EIF |
| Audit log | Webhook-based | `AuditSink` trait + hash-chained events + **daily anchor commit to QFC chain** |
| License | Closed source, SaaS only | **Apache 2.0**, self-host or QFC-hosted; reproducible builds |
| Share store backends | Privy-managed | Pluggable: LocalFs / S3+KMS / Vault / **MultiCloud** for cross-cloud SSS |
| Policy upgrade path | SaaS-managed | Versioned per wallet, customer-controlled, policy changes audit-logged |
| KMS attestation gating | Yes | Yes, **explicit PCR allowlist per wallet** (allows controlled EIF upgrades without instant cutover) |
| Composability | API only | **Library + binary** — embed `qfc-enclave` and `qfc-sss` in custom applications |

Intentional divergences (where we diverge, with reasoning):
1. **PQ support** — QFC's long-term thesis includes post-quantum security. Privy doesn't need it; we do.
2. **Multi-VM** — Privy doesn't have to think about QVM/WASM because they only serve EVM/Solana. Our policy DSL needs first-class VM-aware decoders.
3. **Open source + reproducible** — Privy is a SaaS moat; we're infrastructure. Trust must be verifiable.
4. **Nested wallet approvers** — "treasury of treasuries" is a natural pattern; Privy doesn't expose it.
5. **Cross-TEE quorum (future)** — defense against single-vendor TEE compromise. Privy is Nitro-only.

---

## 7. Roadmap — 5 milestones

Each milestone is independently shippable: it produces a tagged release on the public repo with a published changelog and SBOM. Times are Claude session hours (1 Claude session ≈ 1–2h of focused work).

### M1 — Foundation (in-process only, no TEE, no network)

**Goal:** prove the architecture with full unit + integration test coverage; no real enclave, no real network.

**Ships:**
- Workspace skeleton, six crates, CI (test/clippy/fmt/deny/audit)
- Traits: `Enclave`, `ShareStore`, `Signer`, `Policy`, `QuorumApprover`, `AuditSink`
- `MockEnclave` (in-process; SSS, derivation, signing — production crypto, just no isolation)
- `LocalFsShareStore`, `MockShareStore`
- `Ed25519Signer`, `Secp256k1Signer`, `Secp256k1RecoverableSigner`
- BIP32/BIP39 derivation
- Basic `Policy` (allow/deny only; no rate limit, no VM decoders yet)
- `FileAuditSink`
- End-to-end test: create wallet → sign message → verify signature → verify attestation (mock)
- Property tests for SSS round-trips, signing determinism, audit chain integrity

**Out of scope:** no HTTP, no real enclave, no quorum coordination logic, no real policy DSL.

**Estimate:** ~6–8 Claude sessions.

### M2 — Service + Policy + Observability

**Goal:** a runnable single-tenant service with real policy engine and audit storage. Still no TEE; still no quorum.

**Ships:**
- `axum` HTTP API (REST, OpenAPI-documented): `POST /wallets`, `POST /wallets/{id}/sign`, `GET /wallets/{id}`, `GET /audit/events`
- Full `Policy` DSL: chains, contracts, methods, value caps, time windows, rate limits, VM-shape constraints
- VM decoders: `EvmDecoder` (~~`QvmDecoder`, `WasmDecoder` — deferred per decision #5 / §9.6; QVM-minimal lands in M5, full QVM in M6, WASM indefinitely~~)
- `PostgresAuditSink` with hash-chained events; anchor commit **type shape only** (live cron deferred to M3 per retro [§3.7](retro-m1-m2.md))
- ~~`KafkaAuditSink` — moved to "M2+ optional" per §2.6 / retro [§3.2](retro-m1-m2.md)~~
- `tracing` + `tracing-opentelemetry` integration; `metrics-exporter-prometheus` endpoint at `/metrics`
- Property tests for policy rule evaluation (proptest); golden tests for VM decoders
- Postman/Bruno collection for manual API testing
- Docker compose for local dev (server + Postgres + Mimir)

**Out of scope:** real TEE, multi-tenant auth, gRPC.

**Estimate:** ~4–6 Claude sessions.

### M3 — Nitro Enclave backend

**Goal:** real TEE running on Nitro-enabled EC2; production-grade share storage.

**Ships:**
- `NitroEnclave` impl of `Enclave` trait (host-side; vsock IPC)
- In-enclave binary (`enclave/boot.rs`) — minimal, no_std-friendly where possible, statically linked
- Reproducible EIF build (Dockerfile.eif pinned; documented bit-exact reproduction steps; CI verifies PCR0 is stable across builds)
- **Hybrid-scheme M3 GA blocker** (per §2.1): extend `EnclaveSignRequest` with `policy_decision: SignedPolicyDecision` and `approvals: Vec<SignedApproval>` (additive fields); populate `Wallet.{max_value_cap, contract_allowlist, chain_allowlist}` as hard ceilings; EIF binary includes the invariant checker + signed-policy verifier. Without this, M3 ships a TEE that doesn't enforce the hybrid scheme. **v1.2 update:** the M3 skeleton PR (#16) shipped the `HybridVerifier` and `SignedPolicyDecision` as unit-tested library code (18 tests), with `EnclaveSignRequest.policy_decision` landed as `Option<_>` per [m3-decisions D21](m3-decisions.md#d21) for additive callsite compatibility. The closing piece is `PolicyServiceSigner` end-to-end wiring through `WalletService::sign` — the orchestrator currently passes `None`; the integration PR is the next milestone's first deliverable. See [m3-decisions D29](m3-decisions.md#d29) and retro-m3-m4 [§3.2](retro-m3-m4.md). **v1.3 update — shipped.** PR #19 lands `PolicyServiceSigner` + `LocalPolicyServiceSigner` + `WalletService::with_policy_service_signer` + `MockEnclave` parity with the eventual Nitro EIF; new `AuditKind::PolicyDecisionSigned` (kind byte 17) per [m3-decisions D35](m3-decisions.md#d35); additive `EnclaveSignRequest.{wallet_ceilings, policy_signing_payload}` per [m3-decisions D37](m3-decisions.md#d37). 7 E2E tests in `policy_service_signer_e2e.rs` cover happy path + wrong-key + stale + value-cap + back-compat. The retro-m3-m4 §3.2 gap is closed end-to-end; the orchestrator → policy-service signer → enclave-side verifier path is ready to swap to `NitroEnclave` when the M3 GA PR lands. See retro-v1.3 [§2 / §3.1](retro-v1.3.md).
- Live audit anchor cron (deferred from M2; M2 P2 shipped only the type shape — actual cron job + on-chain commit lands here, needs `qfc-core` dep and a funded operator account). **v1.2 update:** the M3 skeleton PR shipped `LocalFileAnchor` (file-backed signed JSONL submitter) per [m3-decisions D28](m3-decisions.md#d28); the on-chain submitter remains blocked on `qfc-core` workspace integration per retro-m1-m2 [§3.6](retro-m1-m2.md). **v1.3 status:** unchanged — `LocalFileAnchor` ships; on-chain submitter remains blocked on `qfc-core` integration (retro-v1.3 [§6.2](retro-v1.3.md)).
- `S3KmsShareStore` with attestation-conditional KMS decrypt policy. **v1.3 status:** mock-backed (per [m3-decisions D23](m3-decisions.md#d23)); real `aws-sdk-s3` / `aws-sdk-kms` behind a future `feature = "aws"` remains deferred to live-AWS work (retro-v1.3 [§6.3](retro-v1.3.md)).
- Attestation verification library (`qfc-enclave::verify_attestation`) — anyone can pull this in to verify a QFC server wallet attestation. **v1.3 update — parse half shipped.** PR #22 lands real COSE_Sign1 CBOR parsing via `coset` + `ciborium` (pure-Rust, no FFI, matches the no-OpenSSL-in-the-enclave-attack-surface rule per RFC §1.5). `parse_cose_sign1` / `extract_payload` / `verify_cose_signature` (ed25519) ship end-to-end; `SignatureKind::{Mock, CoseSign1Ed25519, CoseSign1Es384}` enum makes the verification path explicit. AWS-Nitro-tagged envelopes parse correctly today. **Still deferred to live-AWS / GA:** the ES384 signature verifier (`verify_cose_signature_es384` is a typed stub returning `AlgorithmNotImplemented` per [m3-decisions D47](m3-decisions.md#d47)) — production AWS Nitro attestations use ES384, but without a real AWS capture we'd only be signing+verifying our own synthetic vectors; the curve plug is a one-file diff against the `p384` crate when a real fixture exists. The AWS Nitro root cert chain validation (`verify_root_chain(leaf, cabundle, root)` is a typed stub per [m3-decisions D46](m3-decisions.md#d46)) blocked on bundling the AWS root cert + reviewing the chain walker against real envelopes. See retro-v1.3 [§3.2](retro-v1.3.md).
- Public attestation verification page (static HTML on `attestation.qfc.network`) — takes attestation doc, returns "matches PCR0 X (rebuild yourself with `make verify-eif`)". **v1.3 status:** still deferred to GA (no real PCR0 hashes yet to publish).
- Bit-exact EIF rebuild + `eif-reproducibility.yml` workflow — see RFC §8.5 + §12.4. **v1.3 status:** Dockerfile.eif placeholder ships per [m3-decisions D27](m3-decisions.md#d27); bit-exact CI rebuild remains deferred to GA (retro-v1.3 [§6.3](retro-v1.3.md)).
- Terraform module in `qfc-server-wallet-ops` for the EC2 + KMS + S3 + IAM setup. **v1.3 status:** still deferred to GA (`qfc-server-wallet-ops` work; lives outside Claude's runway).
- Operational runbooks: deploy, EIF upgrade, key rotation, incident response (redacted public version in `docs/`). **v1.3 update — shipped.** PR #21 lands six public redacted runbooks under `docs/runbooks/` (`00-deploy.md`, `01-eif-upgrade.md`, `02-key-rotation.md`, `03-incident-response.md`, `04-disaster-recovery.md`, `05-operator-onboarding.md`). M3-GA-gated and `qfc-core`-gated sections are marked "Pending" rather than written as if live. Private counterparts live in `qfc-server-wallet-ops`. See retro-v1.3 [§2](retro-v1.3.md).

**User-side dependencies (outside Claude's control):**
- AWS account with Nitro-enabled regions
- Code signing for production deployment
- External security audit (Trail of Bits / Zellic / Cure53) — must happen before M3 GA

**Estimate (code only):** ~10–14 Claude sessions. Audit + AWS setup adds calendar time you control.

### M4 — M-of-N Quorum

**Goal:** approver flows end-to-end.

**Ships:**
- Approver registration: `POST /approvers`, identity types (chain account, external pubkey, hardware, nested wallet)
- Approver sets: `POST /approver-sets`, ties approvers to wallets via policy
- Approval request notification channels: webhook (M4 baseline), email, on-chain QFC event (for chain-account approvers). **v1.2 update:** the M4 PR (#15) shipped `WebhookApprover` (HMAC-SHA256 per [m4-decisions D27](m4-decisions.md#d27)), `HardwareApproverNotifier`, and `OnChainQfcEventApprover` as a `tokio::broadcast` stub per [m4-decisions D28](m4-decisions.md#d28). Real on-chain submission is blocked on the same `qfc-core` workspace integration as the audit anchor cron above (retro-m1-m2 [§3.6](retro-m1-m2.md)). Email channel deferred (operator-side templating, not blocking M5).
- Approval submission API: `POST /approvals/{request_id}` with signed approval payload
- Quorum collection logic (concurrent listening, threshold detection, timeout handling)
- Enclave-side approval verification (the enclave fetches approver public keys via attested config and verifies M signatures)
- Approver-side reference client (Rust + TS) for signing approvals. **v1.3 update — shipped.** PR #24 lands `clients/approver-rs/` (Rust 1.88+ daemon + library, 15 tests) and `clients/approver-ts/` (Node 20 + TypeScript with `@noble/curves`, 17 vitest tests) per [clients-decisions D46–D54](clients-decisions.md). Standalone-workspace pattern — both directories sit **outside** the main Cargo workspace (root `Cargo.toml` `workspace.exclude`) so production integrators can fork without inheriting the wallet's dep tree per [clients-decisions D46](clients-decisions.md#d46). Cross-language preimage compat pinned byte-exact via the Rust-generated `tools/gen-golden-vectors/` fixture per [clients-decisions D52](clients-decisions.md#d52). Default decision policy is fail-closed Refuse per [clients-decisions D49](clients-decisions.md#d49); `--webhook-secret @path` indirection per [D50](clients-decisions.md#d50). See retro-v1.3 [§2 / §3.3 / §4.3 / §4.4](retro-v1.3.md).
- Bug bounty program launch (Immunefi). **v1.3 status:** still deferred to GA + audit sign-off per retro-m3-m4 §2 M4 row.

**v1.3 update — also shipped under M4 / RFC decision #7:** gRPC API surface alongside HTTP — see §10 decision #7 status row + `docs/grpc-api.md` + `docs/grpc-decisions.md` (D46–D52). PR #23 lands `tonic 0.12` + `prost 0.13` + `tonic-reflection 0.12` server, three protos under `crates/qfc-server-wallet/proto/`, both servers spawned from a single `Arc<AppState>` sharing a graceful-shutdown future per [grpc-decisions D51](grpc-decisions.md#d51), zero logic duplication (both adapt to the same `Arc<WalletService>` handler core). 10 new tests (7 integration + 3 unit). **Still deferred:** streaming RPCs (M2 surface is unary; audit-event tailing is a separate proposal); published gRPC client SDK per [grpc-decisions D47](grpc-decisions.md#d47); direct TLS (operators terminate at envoy / nginx).

**Estimate:** ~5–7 Claude sessions.

### M5 — PQ signing + minimal QVM decoder

**Goal:** post-quantum readiness shippable on its own clock; partial QVM coverage matching what `qfc-core` actually supports today.

**Ships:**
- `MlDsa44/65/87Signer` implementing PQ signing (FIPS 204 / Dilithium). **v1.3 update — shipped.** PR #20 lands all three signers backed by the pure-Rust `ml-dsa` v0.1 crate (RustCrypto signatures workspace; zero C FFI per RFC §1.5 and [m5-decisions D38](m5-decisions.md#d38)). 32-byte FIPS 204 seed `xi` as `SecretBytes` per [m5-decisions D39](m5-decisions.md#d39); `HashAlg::None` is the only accepted hash alg per [m5-decisions D40](m5-decisions.md#d40); `signer_for_scheme` / `dispatch_signer` keep their `Result` return shape per [m5-decisions D45](m5-decisions.md#d45) for future PQ schemes. `MockEnclave::generate_wallet` PQ branch allocates a 32-byte seed (not 64) per [m5-decisions D44](m5-decisions.md#d44). `#![forbid(unsafe_code)]` preserved everywhere.
- Wallet migration tool: re-shard existing ed25519/secp256k1 wallet under ML-DSA scheme (with operator approval flow, since the new wallet has a different address). **v1.3 status:** still deferred — explicitly scoped to a separate post-M5 `tools/wallet-migrate` deliverable per [m5-decisions D42](m5-decisions.md#d42); migration is a customer-facing flow (multi-step ceremony: drain old wallet, fund new, retire old shares), not a crypto primitive. Mixing it into the M5 PR would conflate PQ-signing readiness with operational ceremony.
- **QVM minimal decoder** (option (b) of §9.6): parses the stable borsh-encoded tx envelope (`tx_type`, `to`, `value`, `gas_limit`); treats `data` as opaque; supports policy on chain_id + target allowlist + value caps + gas caps. Method-level / argument-level QVM policy is **deferred to M6** pending a first-class `QvmCall` tx variant in `qfc-core`. **v1.3 update — shipped.** PR #20 lands `qfc_policy::decoders::qvm` with a local `QvmTxEnvelope` mirror per [m5-decisions D41](m5-decisions.md#d41) (no `qfc-core` workspace dep per retro-m1-m2 [§3.6](retro-m1-m2.md)). Forward-compatible — unknown tx-type discriminants surface as `QvmTxType::Other(d)`; trailing bytes tolerated.
- Multi-curve quorum (approvers can be on different curves than wallet). **v1.3 update — shipped, no new code.** `m5_multi_curve_quorum.rs` integration test pins the property (ML-DSA-65 wallet authorised by two ed25519 approvers, full sign flow, FIPS 204 signature externally verifies). The architecture already supported it — M4 [D16] per-identity scheme dispatch routed each approver's signature through their own registered scheme. The M5 work was *pinning* the architecture, not extending it. See retro-v1.3 [§4.5](retro-v1.3.md).
- Cross-TEE quorum design doc (implementation may be M6) — wallet config can require M-of-N attestations across {Nitro, SGX, TDX}. **v1.3 update — shipped.** PR #20 lands `docs/design/cross-tee-quorum.md` per [m5-decisions D43](m5-decisions.md#d43): threat model (RFC §5.2 row 1 — single-vendor TEE compromise), `Vec<TeeBackendConstraint>` wallet-config shape, M-of-N attestation composition rule, KMS implications, M-of-2 sequence diagram. Implementation deferred to M6 pending SGX + TDX backend acquisition + external review of the verifier composition rule.

**Explicitly deferred from M5 (was in v0.1, deferred in v1.0):**
- Full QVM method/argument decoder — requires `qfc-core` to land a stable QVM tx ABI first
- WASM policy decoder — `qfc-core` has no WASM execution path today; defer until WASM is on the qfc-core roadmap

**Coordination dependency**: track `qfc-core` for a `QvmCall` tx variant; revisit M6 scope when it lands.

**Estimate:** ~5–7 Claude sessions (down from 6–8 — WASM and full QVM decoder out of scope).

---

## 8. Open-source strategy

### 8.1 License

**Apache 2.0** for `qfc-server-wallet`. Reasons:
- Patent grant (we may use novel TEE+SSS+PQ combinations; patent grant protects users)
- Enterprise-friendly (no copyleft, integrators don't fear it)
- Aligns with Rust ecosystem default and existing qfc-network repos
- Allows commercial hosted offering by QFC team alongside self-host

Not chosen and why: MIT (no patent grant), GPL/AGPL (blocks enterprise integration), MPL 2.0 (unfamiliar to most Rust contributors), BSL (signals "we plan to close-source this" — wrong message for a custody system).

### 8.2 Public vs private split

| Repo | Visibility | Contents |
|------|------------|----------|
| `qfc-server-wallet` | Public Apache 2.0 | All Rust source, EIF Dockerfile, threat model, example policies, integration tests, attestation verification library, public runbooks |
| `qfc-server-wallet-ops` | Private | Terraform with account-specific values, KMS key policy templates, prod attestation root pinning, customer policy data, full incident runbooks |

Rule: if leaked content would directly enable attacks on running production, it goes in `-ops`. Everything else is public.

### 8.3 Security disclosure

`SECURITY.md` in public repo:
- Contact: `security@qfc.network` (PGP key published)
- Embargo: 90-day default; coordinated disclosure
- Bounty: link to Immunefi page (launches M4)
- Hall of fame for responsible reporters

### 8.4 Audit roadmap

| Audit type | Target milestone | Vendor candidates |
|------------|------------------|-------------------|
| Internal code review (independent qfc team) | Before M2 GA — **non-blocking when there is no production posture** (clarified v1.1) | qfc-core team rotation |
| External Rust + crypto audit | Before M3 GA (Nitro) — **first mandatory human review** (v1.1) | Trail of Bits, Zellic, Cure53 |
| External infra audit (Terraform, KMS, AWS hardening) | Before M3 GA | NCC Group, Doyensec, Bishop Fox |
| Continuous: Immunefi bounty | From M4 | n/a |
| PQ signer audit | Before M5 GA (PQ touches enclave code) | Trail of Bits has Dilithium familiarity |
| Annual re-audit | Ongoing | Rotate vendors |

**Clarification (v1.1).** M1+M2 shipped without an independent human security pass — Claude was the sole author and no qfc-core team rotation happened. This is acceptable while there is **no production deployment**: the pre-M2 internal review is non-blocking when the milestone has no production posture. The **pre-M3 external audit becomes the first mandatory human security review** and must not be skipped, since M3 is when real TEE custody begins serving real signing requests. See retro [§3.8](retro-m1-m2.md).

**Approver-client status (v1.3).** The M4 line item "approver-side reference client (Rust + TS)" — flagged in the retro-m3-m4 §2 M4 table as "deferred until there's a real external approver to point at it" — shipped under PR #24. The condition was met by the standalone-workspace + golden-vector pattern (RFC §8.5): the reference clients are forkable starting points for real external approvers, not toys. See retro-v1.3 [§2 / §3.3](retro-v1.3.md). The Immunefi bug bounty launch line in the table above remains deferred to GA + audit sign-off.

### 8.5 Reproducible builds

- `make verify-eif` in public repo rebuilds the enclave image bit-exactly
- CI publishes PCR0 hashes per tag
- Attestation verification page lets anyone check "this signature came from EIF tag X" → "EIF tag X has PCR0 Y" → "you can `git checkout X && make verify-eif` and confirm PCR0 = Y locally"

This is the closure that makes "open source TEE" mean something. Without reproducible builds, public source doesn't give the user any guarantee about what's running.

#### Standalone-workspace pattern for forkable reference clients (v1.3)

For any reference client an integrator is expected to **fork** as a starting point (rather than depend on as a published crate), the M4 approver-client PR (#24) establishes the pattern: the client directory declares its own `[workspace]` table, has its own `Cargo.lock`, and is listed in the root `Cargo.toml`'s `workspace.exclude`. The current working precedents:

- `clients/approver-rs/` — Rust 1.88+ approver daemon (own Cargo workspace, own `Cargo.lock`)
- `clients/approver-ts/` — Node 20+ TypeScript approver (npm project; never touched the Cargo side)
- `tools/gen-golden-vectors/` — Rust helper that emits the cross-language preimage fixture (own Cargo workspace)

Why: pulling the full `qfc-server-wallet` dep graph (`sqlx-macros-core` with its MySQL build chain, `utoipa-swagger-ui` with its build-time `syn 1`, `opentelemetry-otlp` pinning `tonic 0.12`, ...) into every approver fork would make the fork harder to maintain than rewriting from scratch — defeating the "reference" framing. The standalone-workspace pattern means a fork is genuinely minimal. Trade-off: workspace-wide `cargo test` doesn't cover the clients, so each gets its own CI gate (`cd clients/approver-rs && cargo test`; TS client is opt-in per [clients-decisions D54](clients-decisions.md#d54)).

**Cross-language byte-exact compat via golden vectors.** When the same wire format is re-implemented in a second language (today: TypeScript for the approver-side preimage layout), a generated Rust fixture pins the bytes. `tools/gen-golden-vectors/` calls `qfc_quorum::SignedApproval::signing_preimage` on three deterministic inputs and writes `clients/approver-ts/test/fixtures/preimage_golden.json`. The TS test reads the fixture and asserts byte equality; the Rust client carries the same pin via an inline hex literal in `tests/preimage_compat.rs::deterministic_preimage_snapshot`. Both literals must update together if the layout shifts. See [clients-decisions D52](clients-decisions.md#d52) and retro-v1.3 [§4.3](retro-v1.3.md).

**Recommended for future reference clients:** gRPC client SDK (Rust + TS, mirroring the approver-client structure); web SDK; wallet-migration tool (`tools/wallet-migrate` per [m5-decisions D42](m5-decisions.md#d42)); any future multi-VM reference signer. The pattern is: standalone workspace + (where relevant) golden-vector fixture generated from the canonical Rust side.

### 8.6 Contributor process

- Standard GitHub PR flow
- `cargo-deny`, `cargo-vet`, `cargo-audit` mandatory in CI
- All cryptography-touching PRs require two reviewers
- All `enclave/` PRs trigger a rebuild + PCR0 diff comment

#### CI parity checklist for subagents (v1.2)

Subagent briefs (parallel-worktree workflow per global instructions and retro-m3-m4 §4.3) must include the full CI parity gate before reporting green. The four `ci.yml` gates plus the three supply-chain gates:

1. `cargo test --workspace --all-features` — full test suite
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` — lint gate
3. `cargo fmt --all -- --check` — formatting gate
4. `cargo doc --workspace --no-deps --all-features` with `RUSTDOCFLAGS="-D warnings"` — rustdoc lint gate
5. `cargo audit` with the in-tree ignore list (see §12.4)
6. `cargo deny check` (advisories + bans + licenses + sources)
7. `cargo vet --locked` (or `cargo vet diff` when adding deps)

All seven gates must pass locally before a subagent declares done. The `clippy` + `rustdoc` gates are feature-set-sensitive — `--all-features` can flip latent warnings on (retro-m3-m4 [§4.5](retro-m3-m4.md)), so local checks must use the same feature flags as CI. On macOS dev where `vsock 0.4.0` does not compile, `--all-features` is exercised on CI's Linux runner instead.

Subagents working in parallel worktrees off the same `main` must also flag any **workspace-shared type renames** in their plan (the M3+M4 retype of `PolicyDecision::RequireQuorum.approver_set` from `ApprovalId` to `ApproverSetId` produced a textually-clean rebase that failed `cargo check` — retro-m3-m4 [§4.4](retro-m3-m4.md)). The parent agent's pre-rebase planning step scans for cross-subagent type renaming.

---

## 9. Pushback — things in the brief I think need adjustment

Per instructions, calling out where I disagree.

### 9.1 "BIP32/BIP39 derivation" is incompatible with PQ signatures

ML-DSA / Dilithium **has no standard HD derivation scheme**. There's no equivalent of BIP32 child-key derivation for lattice-based keys (and the academic proposals are not interoperable).

**Recommendation:** decouple "HD wallet" from "PQ support."
- Classical curves (ed25519, secp256k1): one master seed per wallet, BIP32/BIP39 derivation, many addresses
- PQ schemes (ML-DSA): one keypair per wallet, no derivation, multiple wallets if you want multiple PQ addresses

This is reflected in the `Wallet.hd_capable` field in §3.1.

### 9.2 "Webhooks / audit log" conflates two different things

The brief lumps webhooks and audit logs together. They're different:
- **Webhooks** are customer-facing event notifications (pull/push for customer integration)
- **Audit log** is an internal-compliance, tamper-evident, hash-chained record

The RFC treats them separately. Audit log is `AuditSink` (§2.6); webhooks come later as a thin layer that filters audit events to customer-registered endpoints (M2+).

### 9.3 "Cryptographic attestation that the operation ran in a verified enclave with verified code" oversells what Nitro can do

See §5.3. Plain TEE attestation gives us PCR-bound enclave identity + arbitrary user_data; it does **not** give us "the computation itself is attested." The RFC is explicit about this so we don't shape product copy around a security property we don't actually have.

### 9.4 Storing key shares "across separate security boundaries" — M1 doesn't achieve this

The brief implies SSS provides "separate security boundaries" but in M1-M3 all shares live in the same AWS account (different S3 buckets, maybe different KMS keys). That's not "separate boundaries" — it's "different keys in the same vault."

**Recommendation:** real separation requires **multi-cloud** SSS — at least one share in AWS, one in GCP, one in on-prem Vault (or similar). This is `MultiCloudShareStore` and lives in M3+ or post-M5. The RFC should be honest about this: until multi-cloud is implemented, the SSS adds defense-in-depth against partial S3/KMS misconfiguration but does **not** defend against a single-AWS-account compromise.

### 9.5 "Deterministic builds for the enclave image" needs more than a Cargo lockfile

Reproducible Rust + reproducible Linux + reproducible base image is hard. The brief states it as a constraint but it's actually a multi-week effort:
- Pin `rustc` exact version (rust-toolchain.toml)
- Use `nixpkgs`-pinned base image or `apko`/`distroless` with locked digests
- Strip timestamps from binaries (`SOURCE_DATE_EPOCH`)
- Pin `linker` + sort linker inputs
- Pin every `cargo` dep to exact version + checksum
- CI verifies PCR0 stability across two independent rebuilds

I'll do this in M3, but flagging that it's a serious chunk of work (~2 Claude sessions on its own) and "we have a deterministic build" should not be claimed before it's verified.

### 9.6 "Multi-VM aware" — honest assessment of QVM and WASM ABI today (v1.0)

This section was rewritten in v1.0 after inspecting `qfc-core` (commit current at 2026-05-19).

**EVM**: mature ABI. The existing `Transaction` (`crates/qfc-types/src/transaction.rs:73-183`) carries `data: Vec<u8>` for contract calls, executed by `revm` (`crates/qfc-executor/src/evm.rs`). Policy decoders match the 4-byte selector + ABI JSON convention, identical to Privy / every other EVM custody system. ✅ M5 EVM decoder is trivially feasible.

**QVM**: the **VM exists** (`crates/qfc-qvm` is a custom stack machine for QuantumScript bytecode, with executor / value / memory / stdlib / interop layers; `crates/qfc-qsc` is the QuantumScript→QVM compiler). But the **tx ABI does not exist as a first-class shape**:
- There is no `QvmCall` variant on `TransactionType`. The only contract-flavored variants are `ContractCreate` and `ContractCall`, and both carry an opaque `data: Vec<u8>`.
- There is no documented mapping from a `ContractCall` tx to a QVM dispatch (target module / function selector / canonical arg encoding).
- The language spec lives in `qfc-design/10-QUANTUMSCRIPT-SPEC-{CN,EN}.md`, but no tx-layer ABI doc.
- The QVM has an `EvmBackend` interop layer, which strongly suggests QVM is still being threaded through a unified contract-call path rather than getting its own tx variant.

**WASM**: **not implemented** in `qfc-core`. Exhaustive grep across `qfc-types`, `qfc-executor`, `qfc-qvm`, `qfc-rpc` finds no WASM execution path. The QFC docs do not currently commit to WASM execution.

**Implications for M5 — two options, pick at M4→M5 boundary:**

- **Option (a) — wait for QFC core to land a QVM tx ABI before M5 decoder ships.** Cleanest. M5 ships PQ signing only; QVM/WASM decoders punt to M6. Requires coordination with `qfc-core` team to define a `QvmCall` tx variant + canonical encoding + version field, ideally before M5 starts. Adds calendar dependency.
- **Option (b) — ship a "QVM minimal" decoder in M5 that parses what's stable today.** Decode `tx_type, to, value, gas_limit` from the borsh-encoded transaction (these *are* stable — `TransactionType` uses explicit u8 discriminants, sealed by borsh `use_discriminant`). Treat `data` as opaque for QVM. Document that "QVM method-level policy" is gated on a future qfc-core release. WASM decoder is dropped from M5 entirely until WASM execution exists in qfc-core.

**Recommendation (v1.0): adopt option (b).** It keeps M5 shippable on its own clock, gives operators *some* QVM-flavored controls immediately (value caps, target contract allowlist, gas caps), and is forward-compatible with a future first-class QVM ABI. Re-evaluate at the M5 design review.

This is reflected in the M5 scope (§7).

### 9.7 Brief asks for "a `MockEnclave` for local dev/tests" — yes, but be clear what it's NOT

`MockEnclave` runs SSS + signing in-process. It's functionally identical to real signing but has **no** memory isolation, **no** real attestation (only signed-by-test-key fake attestations), and **no** PCR binding. It's for development and CI, not for any kind of production or staging.

The RFC makes `MockEnclave` fail-closed when env var `QFC_ALLOW_MOCK_ENCLAVE != "yes-i-know"` to prevent accidental production use.

---

## 10. Resolved decisions

All open decisions from v0.1 §10 are resolved below. Each entry: decision, where it applies in the RFC, and a one-line rationale.

| # | Decision | Outcome | Where in RFC | Rationale |
|---|----------|---------|--------------|-----------|
| 1 | Crate publishing path for `qfc-types` / `qfc-crypto` | **Public crates.io.** Interim: git dep pinned to commit; final: crates.io version dep before M1 tag. `qfc-core` adds a publish workflow and semver policy. | §1.4 | External Rust users can adopt the QFC SDK; aligns with the open-source thesis. |
| 2 | Re-evaluate policy inside enclave, or trust signed input? | **Hybrid.** Policy service emits a signed decision; enclave verifies the signature and re-checks a small, fixed set of hard invariants (value cap, contract allowlist, chain allowlist, request_id binding, freshness). Flexible rules iterate without rebuilding the EIF; hard ceilings require an EIF bump. | §2.1 | Splits "flexible policy iteration" from "auditable hard limits" — the Privy-ish pattern with explicit boundaries. |
| 3 | Approver identity model | **All four variants:** `Chain(Address)`, `External(PublicKey)`, `Hardware(HardwareApproverHandle)`, `NestedWallet(WalletId)`. Nested-wallet cycles forbidden; nesting depth capped at evaluation time. | §2.5 | Flexibility costs little in code; nested-wallet composition is the most powerful pattern (treasury-of-treasuries). |
| 4 | Wallet ID format | **ULID** for `wallet_id`; **`qfc_address: Option<Address>`** as a separate field, derived from `master_public_key` when the scheme is chain-compatible. PQ wallets have `qfc_address = None` until the chain accepts ML-DSA-derived addresses. | §3.1 | Two IDs serve two purposes — stable logical ID survives PQ migration; chain address is for queryability. |
| 5 | QVM and WASM tx ABI stability | **Option (b) of §9.6** — M5 ships a QVM **minimal decoder** (envelope-level: chain_id, to, value, gas_limit; opaque `data`). **WASM decoder deferred** entirely until `qfc-core` implements WASM execution. Full QVM method-level decoder deferred to M6 pending a `QvmCall` tx variant in `qfc-core`. | §7 (M5), §9.6 | Source-of-truth read: `qfc-core` has a QVM but no QVM tx variant; WASM execution doesn't exist. Honesty over slide-deck completeness. |
| 6 | Default audit backend | **Postgres default**, **Kafka optional**, picked at config time. `FileAuditSink` remains for dev/local. | §2.6 | Postgres covers >90% of deployments cleanly with hash-chained ordering; Kafka is opt-in for high-throughput multi-tenant. |
| 7 | HTTP vs gRPC for top-level API | **HTTP/REST in M2**, **gRPC in M4** (added alongside, not replacing — both share the same handler core). **v1.3 — shipped.** PR #23 lands the gRPC surface via `tonic 0.12` + `prost 0.13` + `tonic-reflection 0.12`; both servers spawned from a single `Arc<AppState>` sharing a graceful-shutdown future ([grpc-decisions D51](grpc-decisions.md#d51)); zero logic duplication (both adapt to the same `Arc<WalletService>` core). Default ports: HTTP `127.0.0.1:8088` (env `QFC_SERVER_WALLET_HTTP_BIND`; back-compat env `QFC_SERVER_WALLET_BIND`); gRPC `127.0.0.1:9090` (env `QFC_SERVER_WALLET_GRPC_BIND`). The HTTP default moved from `8080` (M2) to `8088` to free `:9090` for gRPC. Reference: `docs/grpc-api.md`. Still deferred: streaming RPCs; published gRPC client SDK ([grpc-decisions D47](grpc-decisions.md#d47)); direct TLS. | §7 (M2, M4) | REST is faster to integrate and easier for ops; gRPC follows once customer demand materializes. |
| 8 | KMS choice in production | **AWS KMS for M3 baseline**; **Vault Transit as second backend** for cross-cloud customers, planned for M3+ or M4. Trait stays `KmsBackend`. | §2.2, §7 | AWS KMS gives us attestation-conditional decrypt natively for Nitro; Vault unlocks GCP/on-prem deployments without rewriting the share path. |
| 9 | Approver notification channels at M4 launch | **Webhook (mandatory)** + **email (optional)** + **QFC on-chain event (for `Chain` approver identities)**. Telegram/Slack/PagerDuty added post-M4 as plug-in channels. | §7 (M4) | Webhook is the universal integration; on-chain events compose with on-chain governance; email is the "nothing else works" fallback. |
| 10 | Rate-limit primitives | **Token bucket per (wallet, requester) tuple.** Sliding window not adopted. | §2.4 (policy DSL) | Token bucket is predictable, cheap to reason about, easy to expose in policy DSL; sliding-window subtleties don't earn their complexity here. |
| 11 | Where to land this RFC | **Migrated** into `qfc-server-wallet/docs/server-wallet-rfc.md` (this file). The v0.1 draft was staged in a sibling workspace before the public repo existed; that staging directory is now archival. | — | RFC moves with the project so PRs that change architecture also change the document. |

---

## 11. Next steps (post-v1.1)

Bootstrap, `gh repo create`, and M1+M2 implementation are all done (228 tests on `main` at v1.1 cut). What's next, in order:

1. **Start M4 (M-of-N Quorum) before M3 (Nitro Enclave)** — per the retro's recommendation ([retro §6](retro-m1-m2.md)). M3 requires the §2.1 hybrid scheme; the hybrid scheme is much easier to design against once *real* approvers exist (not mocks). M4 also unblocks the most product-visible feature (treasury approvals) without an AWS / external-audit calendar dependency. If external constraints (audit vendor calendar, AWS region work) force M3 first, the M3 hybrid scheme ships against mock approvers and gets re-validated in M4 — call this out explicitly when sequencing.
2. **Schedule M3 audit vendor outreach now** — Trail of Bits / Zellic / Cure53 book 8–12 weeks out; reaching out during M4 keeps the M3 GA calendar tight. Per §8.4 this is the first mandatory human security review.
3. **Kick off `qfc-core` preparatory work in parallel with M4** — add `publish = true`, descriptions, repository URL, release workflow for `qfc-types` then `qfc-crypto`. The server-wallet workspace currently has no `qfc-core` dep (see retro [§3.6](retro-m1-m2.md)); landing it in parallel with M4 keeps M3 unblocked since M3 needs `qfc-address` derivation and the live audit anchor cron both depend on `qfc-core`.
4. **Watch `qfc-core`** for a `QvmCall` tx variant + canonical encoding; revisit M5/M6 QVM decoder scope when it lands.

---

## 12. Repo bootstrap checklist (do **before** `gh repo create`)

Everything to prepare locally before the public `qfc-network/qfc-server-wallet` repo and private `qfc-network/qfc-server-wallet-ops` repo exist. Do not run `gh repo create` until this checklist is green — once the repo is public, anything in `git log` is permanent and indexed.

### 12.1 Files at the workspace root

| File | Purpose | Content sketch |
|------|---------|----------------|
| `LICENSE` | Apache 2.0 license text | Full text from [apache.org/licenses/LICENSE-2.0.txt](https://www.apache.org/licenses/LICENSE-2.0.txt) — verbatim, no edits |
| `NOTICE` | Attribution under Apache 2.0 §4(d) | `QFC Server Wallet\nCopyright 2026 QFC Network\n\nThis product includes software developed at QFC Network.` |
| `README.md` | Project front door | Title, one-paragraph elevator pitch, "Status: pre-M1", link to `docs/server-wallet-rfc.md`, license badge, link to `SECURITY.md`. **No screenshots or marketing copy yet.** |
| `SECURITY.md` | Disclosure policy | Contact (`security@qfc.network` — must exist), PGP public key fingerprint, embargo (90 days), bug-bounty section (placeholder; Immunefi link added at M4), out-of-scope list, response SLA |
| `CODE_OF_CONDUCT.md` | Contributor expectations | Contributor Covenant 2.1 verbatim; substitute project name + contact email |
| `CONTRIBUTING.md` | How to contribute | DCO sign-off required, PR template, link to `docs/policy-dsl.md` once written, CI requirements (clippy/fmt/deny/audit must pass), crypto PR rule (2 reviewers) |
| `.gitignore` | Standard Rust + workspace | `/target/`, `Cargo.lock` (keep for binary crates — see below), `.envrc`, `.direnv/`, `.vscode/`, `.idea/`, `*.swp`, `.DS_Store`, `enclave/build/`, `enclave/*.eif`, `policies/*.local.json` |
| `.gitattributes` | LF normalization | `* text=auto eol=lf`, mark `*.eif` and `enclave/build/**` as binary |
| `rust-toolchain.toml` | Pin rustc | `[toolchain]\nchannel = "1.88.0"\ncomponents = ["rustfmt", "clippy", "rust-src"]\nprofile = "minimal"` — pinning patch version is necessary for reproducible EIF (§9.5). **v1.1 update**: bumped from initial 1.83.0 target due to two forced upgrades — (a) edition 2024 via `wit-bindgen` → ≥ 1.85; (b) `cargo-deny` CVSS 4.0 advisory parser → ≥ 1.88. Revisit pin policy at M3 when the EIF build container is finalized; host toolchain is decoupled from the in-enclave build per §9.5. |
| `Cargo.toml` (workspace root) | Workspace manifest | Members = all six crates + (later) `enclave/`. Shared `[workspace.package]` and `[workspace.dependencies]` mirroring `qfc-core/Cargo.toml` style |
| `deny.toml` | cargo-deny config | See §12.5 |
| `cargo-vet.toml` (`supply-chain/`) | cargo-vet config | Initialized via `cargo vet init`; trust seeded with Rustsec + RustCrypto orgs |
| `SBOM-policy.md` | SBOM publishing rules | Per-release SBOM via `cargo cyclonedx`; attached to GitHub release |

**Cargo.lock policy**: commit `Cargo.lock` for the binary crate (`qfc-server-wallet`) — needed for reproducible builds. The five library crates don't have their own lockfiles; the workspace root lockfile covers them.

### 12.2 Cargo workspace skeleton

```
qfc-server-wallet/
├── Cargo.toml                          # workspace root (members, shared deps)
├── Cargo.lock                          # committed for reproducibility
├── rust-toolchain.toml
├── deny.toml
├── supply-chain/                       # cargo-vet
│   └── config.toml
├── crates/
│   ├── qfc-server-wallet/
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, main.rs}
│   ├── qfc-enclave/
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── qfc-sss/
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── qfc-policy/
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── qfc-quorum/
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   └── qfc-audit/
│       ├── Cargo.toml
│       └── src/lib.rs
├── docs/
│   ├── server-wallet-rfc.md            # this file, migrated
│   ├── threat-model.md                 # initially: stub linking to §5
│   ├── attestation.md                  # initially: stub
│   └── policy-dsl.md                   # initially: stub linking to §2.4
├── enclave/                            # added in M3, not at bootstrap
├── examples/
│   └── policies/
│       └── README.md                   # placeholder; samples land in M2
├── .github/
│   ├── workflows/                      # see §12.4
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── security_report.md          # redirects to SECURITY.md
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── CODEOWNERS                      # crypto/ + enclave/ require crypto reviewers
├── LICENSE
├── NOTICE
├── README.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── CHANGELOG.md                        # keep-a-changelog format; v0.0.0 entry only
├── .gitignore
└── .gitattributes
```

Each crate's `Cargo.toml` inherits `version`, `edition`, `authors`, `license`, `repository` from `[workspace.package]`. Each gets a one-line `description = "..."`. Mark all five library crates `publish = false` until APIs settle (likely M3); `qfc-server-wallet` binary stays unpublished.

### 12.3 Stub crate contents at bootstrap

Each `src/lib.rs` ships with:
```rust
//! qfc-<crate-name> — see docs/server-wallet-rfc.md §<section>.
//!
//! Status: pre-M1 skeleton; types/traits land in M1.
#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]
```

`#![forbid(unsafe_code)]` on every crate; the **only** place `unsafe` is allowed is `qfc-enclave/src/nitro/` (vsock IPC FFI) — that file flips the lint with a `#[allow]` and a `SAFETY:` comment per block.

### 12.4 CI workflows (`.github/workflows/`)

| File | Triggers | Prereq steps | Steps |
|------|----------|-------------|-------|
| `ci.yml` | PR + push to main | `arduino/setup-protoc@v3` (v1.3 — see note below) | `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `cargo doc --workspace --no-deps --all-features` with `RUSTDOCFLAGS="-D warnings"` |
| `deny.yml` | PR + nightly cron | — | `cargo deny --workspace check` (advisories + bans + licenses + sources) |
| `audit.yml` | PR + nightly cron | — | `cargo audit --deny warnings --ignore <RUSTSEC-IDs>` — ignore list **must stay in sync** with `deny.toml [advisories].ignore` (v1.2). See note below |
| `vet.yml` | PR | — | `cargo vet --locked` |
| `sbom.yml` | release tag | — | `cargo cyclonedx -f json` for each binary, attached to release |
| `eif-reproducibility.yml` | added in M3 GA | — | Two parallel builds, diff PCR0; fail if non-bit-exact |

All workflows run on `ubuntu-latest`. macOS/Windows added when there's user demand. (The `msrv.yml` and `coverage.yml` rows from earlier drafts have been struck — those workflows are not currently in `.github/workflows/`; revisit at M3 GA when MSRV policy and coverage tooling are owned.)

**v1.3 — `protoc` prerequisite.** PR #23 introduced the gRPC build, which invokes `tonic-build` at compile time; `tonic-build` shells out to the `protoc` binary, which `ubuntu-latest` does **not** pre-install. The `ci.yml` `test`, `clippy`, and `doc` jobs each include an `arduino/setup-protoc@v3` step before any `cargo` invocation. **Process rule:** any new code-gen build step → check the runner has the tool before reporting CI-green. Adding the tool to the CI-parity checklist in §8.6. See retro-v1.3 [§4.1](retro-v1.3.md).

**v1.3 — `--all-features` cautionary footnote.** `ci.yml` runs `--all-features` to exercise the `nitro` feature's Linux-only `tokio-vsock` dep tree. On macOS dev hosts, `vsock 0.4.0` (the transitive crate via `tokio-vsock`) does **not** compile — it uses Linux-only `libc::accept4` / `SOCK_CLOEXEC` / `VMADDR_CID_LOCAL` / `MsgFlags::MSG_NOSIGNAL`. So `cargo check --all-features` will fail on a Mac. Local subagent checks must either run on a Linux dev box / VM, or run with the default feature set and rely on CI for the `nitro`-on path. See retro-m3-m4 [§4.1](retro-m3-m4.md).

**v1.3 — four-gate parity + audit/deny/vet trio.** The §8.6 CI parity checklist for subagents (test / clippy / fmt / doc + audit / deny / vet) is now the workflow contract: a subagent must pass all seven gates locally before reporting green. The four CI gates (`ci.yml`'s `test`, `clippy`, `fmt`, `doc`) are listed explicitly above. The three supply-chain gates live in `deny.yml`, `audit.yml`, `vet.yml`. Branch protection on `main` requires all four CI files (`ci.yml`, `deny.yml`, `audit.yml`, `vet.yml`) to pass — see below.

**v1.2 — `audit.yml` ignore list sync.** `cargo audit` and `cargo deny` consult separate config surfaces. Any advisory ignore added to `deny.toml [advisories].ignore` must also be added to the `audit.yml --ignore` invocation (and vice versa). The current ignores (as of v1.2):

| Advisory | Crate | Why ignored |
|---|---|---|
| RUSTSEC-2025-0111 | `tokio-tar` (via `testcontainers`) | Dev-dep chain; not in production binary |
| RUSTSEC-2025-0134 | `rustls-pemfile` unmaintained (via `testcontainers`) | Dev-dep chain; not in production binary |
| RUSTSEC-2024-0370 | `syn` 1 (via `utoipa-swagger-ui` build-time macros) | Build-time only; not linked into production binary |
| RUSTSEC-2023-0071 | `rsa` 0.9.10 Marvin attack (via `sqlx-macros-core` → `sqlx-mysql`) | `sqlx-macros-core` enables every backend at compile time for query verification; we only use Postgres at runtime, `sqlx-mysql` does not link in. Revisit when sqlx 0.9 scopes the build chain by backend |

Retro-m3-m4 [§4.2](retro-m3-m4.md) records the surprise (the `sqlx-macros` build chain pulling MySQL deps even with `default-features = false` on Postgres-only call sites).

Branch protection on `main`:
- Require PR, 1 review (2 for `enclave/`, `qfc-sss/`, `qfc-enclave/`, `crates/*/src/crypto/`)
- Require `ci.yml`, `deny.yml`, `audit.yml`, `vet.yml` to pass
- No force-push, no deletion
- Linear history (squash or rebase merge only)

### 12.5 `deny.toml` content sketch

```toml
[graph]
all-features = true

[licenses]
# Allow MIT/Apache-2.0/BSD; explicitly reject GPL/AGPL/copyleft in any dep
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-DFS-2016", "CC0-1.0", "Zlib"]
confidence-threshold = 0.93
exceptions = []

[bans]
multiple-versions = "warn"  # promote to "deny" once tree is clean
wildcards = "deny"
deny = [
  # avoid OpenSSL inside enclave path (§1.5)
  { name = "openssl-sys" },
  { name = "native-tls" },
  # avoid libsecp256k1 FFI inside enclave path (§1.5)
  { name = "secp256k1-sys" },
]

[advisories]
db-path = "~/.cargo/advisory-db"
vulnerability = "deny"
unmaintained = "warn"
unsound = "deny"
yanked = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-git = []  # populate ONLY with git-pinned qfc-types/qfc-crypto until crates.io publish
```

### 12.6 GitHub repo settings (pre-create checklist)

Before `gh repo create`:
- [ ] `security@qfc.network` mailbox provisioned + monitored
- [ ] PGP key for `security@qfc.network` generated, fingerprint in `SECURITY.md`, public key on a keyserver
- [ ] CODEOWNERS list confirmed with Larry — crypto/enclave reviewers identified
- [ ] Decided: org or user namespace (`qfc-network/qfc-server-wallet` per §8.2)
- [ ] No production secrets, customer policies, or attestation roots are in tree (those live in `qfc-server-wallet-ops`)
- [ ] `Cargo.lock` does not contain a path-dep that leaks a local absolute path
- [ ] Initial commit is squashed and DCO-signed
- [ ] First commit message: `feat: bootstrap qfc-server-wallet workspace per RFC v1.0`

After `gh repo create`:
- [ ] Enable **Issues**, **Discussions** (disable wiki — docs live in tree)
- [ ] Enable **Dependabot alerts**, **Dependabot security updates**, **Secret scanning**, **Push protection for secrets**
- [ ] Configure branch protection (see §12.4) before merging anything else
- [ ] Add `qfc-network/security` team as security advisory admin
- [ ] Create v0.0.0 release tag for the bootstrap commit (signed) so SBOMs and reproducible builds have a baseline

### 12.7 Sister private repo (`qfc-server-wallet-ops`)

Bootstrap content:
- `README.md` — internal, "Operations and infra for qfc-server-wallet. Public source lives in qfc-network/qfc-server-wallet."
- `LICENSE` — proprietary (or unlicensed) — explicitly NOT Apache 2.0
- `terraform/` — empty, ready for M3
- `kms/` — empty
- `runbooks/` — `README.md` explaining the redacted-public-version policy
- `policies/` — `README.md` plus `.gitattributes` enforcing `git-crypt` on production policies
- `.gitignore` — same as public repo plus `*.tfstate*`, `*.tfvars`, `secrets/`

Settings: private; restricted-team access; required reviews from `qfc-network/ops` team for any `terraform/` or `kms/` change.

### 12.8 "Definition of done" for §12

The repo is ready to create when:
1. Every file above exists locally with the listed content (placeholders OK for `docs/{threat-model,attestation,policy-dsl}.md`)
2. `cargo check --workspace` succeeds on the bootstrap skeleton
3. `cargo fmt --check` and `cargo clippy --workspace -- -D warnings` succeed
4. `cargo deny check` succeeds against the seeded `deny.toml`
5. `security@qfc.network` is live and PGP-keyed
6. Larry has signed off on the CODEOWNERS list

Only then run `gh repo create qfc-network/qfc-server-wallet --public --source . --remote origin --description "QFC server wallet — TEE custody + SSS + M-of-N quorum"` and `git push -u origin main`.

---

## 13. Decision-doc D-numbering convention (v1.3)

The project's non-obvious technical decisions live in per-milestone / per-feature-area markdown files. The numbering convention is **per-file**, not global. Each file owns its own `Dnn` sequence; the same `Dnn` number can (and does) appear in multiple files. Cross-references are filename-anchored — `[D21](m4-decisions.md#d21)` is distinct from `[D21](m3-decisions.md#d21)`.

### Current files and ranges

| File | D-range | Scope |
|---|---|---|
| `m1-decisions.md` | D1 – D20 | M1 (foundation) — workspace, crates, traits, mock backends, signers, SSS, audit chain |
| `m3-decisions.md` | D21 – D32 (skeleton) · D33 – D37 (`PolicyServiceSigner`) · D46 – D47 (COSE follow-up) | M3 Nitro skeleton, hybrid verifier, attestation parsing. Note the non-contiguous range — D33–D37 landed with PR #19 (post-skeleton); D46–D47 landed with PR #22 (COSE parse-half) |
| `m4-decisions.md` | D21 – D37 | M4 quorum — approver registry, approval store, orchestrator, webhook + on-chain stub. **Numerically overlaps `m3-decisions.md` D21–D32.** Anchored by filename only |
| `m5-decisions.md` | D38 – D45 | M5 PQ signing + QVM minimal decoder + multi-curve quorum + cross-TEE design doc |
| `grpc-decisions.md` | D46 – D52 | gRPC API surface (PR #23) — proto types, client SDK deferral, reflection gating, dual-server topology. **Numerically overlaps `m3-decisions.md` D46–D47 and `clients-decisions.md` D46+.** Anchored by filename only |
| `clients-decisions.md` | D46 – D54 | Approver-side reference clients (PR #24) — forkability, dependency choices, identity override, cross-language preimage compat. **Numerically overlaps `m3-decisions.md` D46–D47 and `grpc-decisions.md` D46–D52.** Anchored by filename only |

### Rules

1. **Per-file numbering.** Each decision-doc file maintains its own `Dnn` sequence. The next decision added to `m5-decisions.md` is `D46` (continuing from D45); the next added to `m4-decisions.md` is `D38` (continuing from D37). New milestone / feature-area files start at whichever number is most informative (the first M5 decision was `D38` because it followed the M4 range; the first grpc decision was `D46` because it followed M5's range at the time of writing, even though `m3-decisions.md` later also acquired D46–D47).
2. **Cross-references must be filename-anchored.** Always `[D21](m4-decisions.md#d21)`, never bare `[D21]`. Anchors are stable (`#d21` works in every markdown renderer the project uses).
3. **No global renumbering.** Renumbering to a single global sequence would churn every existing cross-reference in the codebase, the CHANGELOG, prior retros, and external links (e.g. PR descriptions) for no real benefit — per-file numbering matches the actual workflow (each milestone / feature ships with its own decision doc).
4. **New feature-area decision docs are encouraged.** When a feature stops being part of an in-flight milestone (e.g. `grpc-decisions.md`, `clients-decisions.md`), it gets its own file rather than crowding into a milestone doc. Pick a starting `Dnn` that's clearly distinct from any active milestone's range, or just continue the project-wide max — both are acceptable.

### Why this convention

Decision docs are written by subagents in parallel worktrees. Forcing a global sequence would require subagents to coordinate ahead of time on numeric ranges (or to renumber at merge time, producing CHANGELOG churn). Per-file numbering means each subagent picks its own next-available number with zero coordination cost, and the rebase is textually clean. See retro-v1.3 [§3.4](retro-v1.3.md) for the rationale write-up.
