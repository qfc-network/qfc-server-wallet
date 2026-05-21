# 02 — Key rotation

**Status:** Partially Live. The DEK and approver-key sections describe
mechanisms that exist today; the policy-service signer rotation is
**Pending PolicyServiceSigner production deployment** (per
[m3-decisions D29](../m3-decisions.md#d29) — the orchestrator currently
threads `policy_decision: None` and the production policy service is not
yet wired). The `PolicyServiceKeyRotated` audit kind is also not yet
assigned a kind byte and must land before the rotation procedure here
can emit it.
**Audience:** ops, security responder (for emergency rotations).
**Last reviewed:** 2026-05-21.

## Three keys, three cadences

`qfc-server-wallet` has three distinct rotation surfaces. Each has its
own cadence and its own ceremony.

| Key                                   | Owned by               | Rotation cadence                      | Procedure section |
|---------------------------------------|------------------------|---------------------------------------|-------------------|
| KMS data-encryption keys (DEKs)       | AWS (managed)          | Annual, AWS-automatic                 | §1 below          |
| Policy-service identity key           | QFC ops                | On-demand; quarterly review           | §2 below          |
| Approver public keys                  | Each individual approver | Per-approver discretion             | §3 below          |

Wallet master keys (the secp256k1 / ed25519 / ML-DSA keys actually used
to sign blockchain transactions) are **not** rotated in place — by
construction. Per RFC §3.1 D4, a new wallet has a different address;
"rotating" a wallet master key means generating a fresh wallet and
migrating the funds, which is a customer-facing flow (the wallet
migration tool is deferred to a follow-up deliverable per
[m5-decisions D42](../m5-decisions.md#d42)).

## §1 KMS data-encryption keys (DEKs)

**Live (M3-GA).** Each `S3KmsShareStore` write generates a per-share
DEK, encrypts the share with XChaCha20-Poly1305 AEAD under that DEK,
then wraps the DEK with the KMS CMK ("envelope encryption"). KMS
manages the CMK's underlying material.

### Cadence

AWS rotates the CMK's underlying key material annually by default
(KMS "automatic key rotation"). The KMS CMK ARN does not change; the
key material behind it does. Existing wrapped DEKs continue to decrypt
under the rotated key material — AWS keeps the old material around
indefinitely for unwrapping.

### What ops does

For routine rotation: nothing. KMS handles it transparently.

For emergency rotation (suspected CMK compromise, see
`03-incident-response.md` P0 path):

1. Open a P0 incident.
2. Revoke the existing CMK's grants and policies (terraform apply in
   the ops repo's KMS module — see `<OPS_REPO>/runbooks/02-key-rotation.md`
   for the exact terraform diff).
3. Create a fresh CMK. Update the `S3KmsShareStore` config to point at
   the new ARN.
4. **Existing shares are now unreadable.** This is the failure mode of
   "the CMK was compromised" — the shares must be re-generated.
   Affected wallets enter the wallet-regeneration flow (operator
   intervention, all customers notified, per `04-disaster-recovery.md`'s
   "NOT recoverable" section).
5. Audit-log the rotation event.

### Audit

KMS CloudTrail entries are the source of truth for KMS rotation events.
The `qfc-audit` chain does not currently emit a `KmsKeyRotated` event;
KMS events live in the AWS-side audit trail and the ops repo's
runbook references them by ARN + timestamp.

## §2 Policy-service identity key

**Pending PolicyServiceSigner production deployment.** The
`LocalPolicyServiceSigner` (ed25519, M3-followup) ships as
unit-tested library code today, but is not yet wired through
`WalletService::sign` in the production binary. The rotation
procedure below describes the **target** state.

### What this key does

The policy-service identity key signs every `PolicyDecision` before it
crosses the enclave boundary. The in-enclave `HybridVerifier`
([`crates/qfc-enclave/src/hybrid_verifier.rs`](../../crates/qfc-enclave/src/hybrid_verifier.rs))
holds the pinned policy-service public key and rejects any decision
that doesn't verify against it.

Compromising this key would let an attacker forge `PolicyDecision`s.
The in-enclave hard ceilings (`max_value_per_tx`, `contract_allowlist`,
`chain_allowlist`) still bound the damage — see RFC §2.1 hybrid scheme
— but the rotation surface still matters.

### Cadence

- **Routine:** quarterly review. Rotate if review surfaces evidence of
  key-material exposure (lost laptop, unexpected access pattern).
- **Emergency:** on any P0 incident touching the policy service. See
  `03-incident-response.md`.

### Procedure

1. Generate the new ed25519 key in the production policy-service KMS.
   The ops repo's `<OPS_REPO>/runbooks/02-key-rotation.md` carries the
   KMS commands.
2. Update the EIF config to pin the new pubkey. **This is an EIF
   change**, so run through `01-eif-upgrade.md` from the top — the new
   pubkey changes the in-EIF config which changes the PCR0.
3. During the EIF upgrade rollout window, old EIFs (with the old
   pubkey pinned) and new EIFs (with the new pubkey pinned) coexist.
   The policy service must continue to sign with the old key
   throughout this window, otherwise the new EIFs accept signatures
   the old EIFs do not.
4. After the old EIFs are decommissioned (per `01-eif-upgrade.md`'s
   KMS allowlist trim step), cut the policy service over to the new
   signing key.
5. Old `SignedPolicyDecision`s remain valid until their
   `max_age_secs` expires (default 60s per [m3-decisions D33](../m3-decisions.md#d33);
   hard upper bound 24h per [m3-decisions D30](../m3-decisions.md#d30)).
   After 24h, no decision signed under the old key is acceptable.
6. Decommission the old policy-service key material.

### Audit

Emit a `PolicyServiceKeyRotated` event with `{ old_pubkey,
new_pubkey, eif_pcr0, operator_id }`.

**Pending.** `AuditKind::PolicyServiceKeyRotated` is not yet a variant
in [`crates/qfc-audit/src/event.rs`](../../crates/qfc-audit/src/event.rs).
Add it (with a kind byte assignment — likely 19 or 20, after the
`EnclaveUpgraded` byte assigned per `01-eif-upgrade.md`) in the same
PR that lights up this runbook operationally.

## §3 Approver public keys

**Live (M4-GA).** Each approver in the registry
(`qfc-quorum::ApproverRegistry`) holds their own signing key. The server
only stores the **public key**; the approver is responsible for the
private key material.

### Cadence

Per-approver discretion. Common triggers:

- Hardware approver (Ledger / YubiKey / similar) replaced or
  re-provisioned.
- Approver leaves the role (offboarding).
- Approver suspects their key material is compromised.

### Procedure (high level)

The approver-side procedure lives in the customer/approver runbook
(separate document, out of scope here). The server-side touchpoints:

1. Approver POSTs the new pubkey through the approver-registration
   flow (`POST /approvers`).
2. The previous approver record is soft-revoked
   (`DELETE /approvers/{id}` — sets the lifecycle status, doesn't
   delete the row, so audit history stays intact).
3. The approver-set that included the previous approver is updated
   (`POST /approver-sets` creates the replacement set; the customer
   may need to migrate wallets to the new set if the policy pins a
   specific set ID).
4. The `ApproverSetChanged` audit event (kind byte `13`) fires on the
   approver-set update.

The on-chain approver type (`ApproverIdentity::Chain`) rotates by
re-registering with the new chain account — same flow.

### What the server enforces

- The approver-set's `(threshold, total)` invariants are re-validated
  on update.
- Cycle detection (per [m4-decisions D26](../m4-decisions.md#d26))
  re-runs on the new set.
- Pending sign requests against the old set continue to use the old
  set's snapshot — the registry update is forward-only.

### Audit

`ApproverSetChanged` (kind byte `13`) is emitted on every set
update. No additional new audit kind needed.

## Cross-cutting: rotation under attack

If rotation is happening because of a suspected compromise, see
`03-incident-response.md` first. The rotation here is the *recovery*
step; the *triage* step (freeze affected wallets, snapshot audit chain,
preserve forensics) comes before any key replacement.

Do not delete old key material until the incident is resolved and
forensics has acknowledged. The audit chain replay needs the old
key's signature to verify historical events. "Rotate" means
"introduce new key, retire old key from active use", not "destroy old
key".
