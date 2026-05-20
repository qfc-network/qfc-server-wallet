# Cross-TEE quorum — design

**Status:** design only — implementation deferred to M6 or later.
**Owner:** server-wallet team
**RFC anchors:** §5.2 row 1 (single-vendor TEE compromise), §7 M5
(this design doc is the M5 deliverable), §2.1 (hybrid policy
verification — relevant for the verifier-side composition rule).

## 1. Problem

The M3 design pins one wallet to one Nitro EIF identity (PCR0 set).
If a vulnerability in Nitro firmware, AWS KMS attestation conditional
decrypt, or the EIF's attestation library lets an attacker forge a
"this signed inside our enclave" attestation, **every wallet in the
fleet** is exposed.

This is the row in RFC §5.2 we annotate as "single-vendor TEE
compromise — assume eventually possible; mitigate via cross-vendor
attestation". The mitigation: require that a wallet's signing flow
collect M-of-N attestations from independent TEE vendors before the
host accepts the signature.

## 2. Threat model

- **In scope:** an adversary who compromises one TEE vendor's
  attestation root of trust (e.g. AWS Nitro NSM key compromise, or a
  firmware bug that lets an attacker generate attestation documents
  outside a real enclave).
- **In scope:** a malicious cloud operator at one vendor.
- **Out of scope:** an adversary who simultaneously compromises ≥ M
  vendors' attestation chains. M-of-N quorum tolerates strictly fewer
  than M failures by construction.
- **Out of scope:** side-channel leakage from a single TEE — that is a
  different mitigation (process-isolated enclaves, constant-time
  primitives, the existing pure-Rust crypto choice).

## 3. Trust anchor split — wallet schema change

Today `WalletRecord` carries a single PCR constraint (M3 D24):

```rust
struct WalletRecord {
    enclave_pcr_constraint: PcrConstraint,
    …
}
```

For cross-TEE wallets, we widen to a vector of per-backend
constraints with a threshold:

```rust
struct WalletRecord {
    enclave_constraints: TeeQuorumConstraint,
    …
}

struct TeeQuorumConstraint {
    backends: Vec<TeeBackendConstraint>,
    threshold: u8,             // M of `backends.len()` (N)
}

enum TeeBackendConstraint {
    Nitro { pcr0: [u8; 48], pcr2: [u8; 48] },
    Sgx   { mrenclave: [u8; 32], mrsigner: [u8; 32] },
    Tdx   { mrtd: [u8; 48], rtmr0: [u8; 48] },
}
```

Default is the M3 shape — `threshold = 1, backends = [Nitro(...)]` —
so existing wallets compose forward without schema migration.

## 4. Wire flow

```
client ──► orchestrator ──► sign_in_enclave_N ──► attestation_doc_N
                       └─► sign_in_enclave_S ──► attestation_doc_S
                       └─► sign_in_enclave_T ──► attestation_doc_T
                                                       │
                       ◄───────── attestation bundle ──┘
              │
              ▼
   TeeQuorumVerifier (host-side; verifies attestation_bundle)
              │
              ▼
      if M attestations valid → signature accepted
      else                    → fail-closed
```

### 4.1 Per-backend sign

Each backend runs the full hybrid scheme (RFC §2.1):
- decrypt shares (using its own backend's KMS attestation-conditional
  decrypt — independent KMS keys per backend)
- re-verify the signed policy decision
- check hard ceilings
- sign and emit an attestation that binds
  `(request_id || message_hash || backend_id)` to its attestation key

### 4.2 Verifier composition rule

The host verifies:
1. Every attestation document is well-formed for its backend
   (Nitro COSE_Sign1, SGX Quote, TDX Report).
2. Every attestation's `user_data` carries the **same** `request_id`
   and `message_hash`.
3. Each attestation's `backend_id` is in `wallet.enclave_constraints.backends`.
4. The set of valid attestations is ≥ `wallet.enclave_constraints.threshold`.

If any step fails → fail-closed (no signature returned to the client).

### 4.3 Signature uniqueness

The signature itself is produced by **one** enclave (the first to
reach the cross-attest step) and re-validated by the others before
they sign their attestation. The other M-1 backends are attesting
"we observed and validated the same signing request". They are
**not** producing M independent signatures — that would require M
independent secret shares, doubling SSS overhead and forcing curve
homogeneity across backends.

This means cross-TEE quorum gives us:
- Each backend independently certifies the policy/ceiling check
  passed.
- Compromising one backend's attestation chain still gives the
  attacker `M-1 < M` attestations; the host rejects.

It does **not** give us:
- Protection from a leak inside one backend's memory (the secret is
  still reconstructed there once).
- Protection from a backend that selectively refuses to sign valid
  requests (availability, not safety — handled at M-of-N quorum
  *availability* layer).

## 5. KMS implications

Each TEE backend has its own KMS key with an attestation-conditional
decrypt policy keyed to **that** backend's identity:
- AWS KMS / Nitro: `kms:RecipientAttestation:ImageSha384` = PCR0
- Azure Confidential Ledger / SGX: SGX attestation conditions in the
  Azure KeyVault policy
- GCP Confidential Space / TDX: TDX attestation conditions in GCP KMS
  policy

A wallet's shares are wrapped under M-of-N KMS keys (each backend has
its own share envelope). Storage layout:

```
s3://qfc-shares/<wallet_id>/aws-nitro/share-index
s3://qfc-shares/<wallet_id>/azure-sgx/share-index
s3://qfc-shares/<wallet_id>/gcp-tdx/share-index
```

This means **each backend can decrypt only its own share** — and the
SSS threshold still ensures that `threshold` backends are needed to
reconstruct the secret. Cross-TEE adds a second axis of M-of-N:

| Axis              | M-of-N      |
|-------------------|-------------|
| SSS shares        | T_share-of-N_share (existing) |
| TEE attestations  | T_tee-of-N_tee (new) |

In the simplest deployment these are aligned — same threshold, same
backends own one share each. More complex deployments could put 2
SSS shares per backend (so a single backend can already reach the
SSS threshold), still requiring M TEE attestations to authorise the
signing flow.

## 6. Audit + observability

- Each backend's attestation is captured in the audit log as its own
  event (kind: `tee_attestation_received`, with `backend_id`).
- A `tee_quorum_reached` event fires once `threshold` attestations
  are valid (before the host returns the signature to the client).
- A `tee_quorum_failed` event captures partial / mismatched
  attestation sets so SREs can spot a degraded backend.

## 7. Sequence diagram

```
 client       orchestrator           Nitro             SGX             TDX
   │              │                    │                │               │
   ├─sign req────►│                    │                │               │
   │              │                    │                │               │
   │              ├─sign_in_enclave───►│                │               │
   │              │                    │ verify policy  │               │
   │              │                    │ check ceilings │               │
   │              │                    │ sign + attest  │               │
   │              │◄─sig + att.N───────│                │               │
   │              │                                     │               │
   │              ├─cross-attest req───────────────────►│               │
   │              │                                     │ verify policy │
   │              │                                     │ verify sig.N  │
   │              │                                     │ attest        │
   │              │◄─att.S──────────────────────────────│               │
   │              │                                                     │
   │              ├─cross-attest req───────────────────────────────────►│
   │              │                                                     │ verify policy
   │              │                                                     │ verify sig.N
   │              │                                                     │ attest
   │              │◄─att.T──────────────────────────────────────────────│
   │              │
   │              │ TeeQuorumVerifier:
   │              │   • 3 attestations
   │              │   • all bind same request_id + message_hash
   │              │   • all backends in wallet.enclave_constraints
   │              │   • ≥ threshold → accept
   │              │
   │◄─sig + att...│
```

## 8. Open questions (resolve before implementation)

- **Vendor for SGX?** Azure Confidential Ledger or DCsv3 series?
  Affects KMS choice.
- **Vendor for TDX?** GCP Confidential Space or Intel TDX-on-Azure?
  Affects KMS choice.
- **Latency budget.** Each backend round-trip adds ~50–150 ms.
  Cross-TEE quorum with 3 backends in parallel ≈ slowest round-trip;
  sequential ≈ 3x. Probably parallel; need to confirm the verifier
  composition tolerates out-of-order arrivals (yes per the design;
  re-check during impl).
- **Reproducible-EIF parity.** The Nitro EIF is reproducible today;
  SGX / TDX equivalents require separate reproducibility work.
  Decide whether the rebuild verification page (`attestation.qfc.network`)
  needs to host all three or only the canonical backend.
- **Per-backend signing pluralization.** Should the host signature
  payload include all backends' attestation docs concatenated, or just
  the threshold-reaching subset? Concatenating all is more
  transparent; subset is smaller. Defer to impl.

## 9. Implementation deferred

This design lands as a doc in M5. Implementation is deferred to M6 or
later, gated on:
- An SGX backend acquisition (vendor + KMS + attestation-verifier).
- A TDX backend acquisition (same).
- An external security review of the verifier composition rule (the
  failure mode "two attestations from the same backend with different
  PCRs" needs explicit handling).

When the implementation lands, it lives behind a wallet config flag
(`tee_quorum: Option<TeeQuorumConstraint>`) so M3-shape wallets keep
working unchanged.
