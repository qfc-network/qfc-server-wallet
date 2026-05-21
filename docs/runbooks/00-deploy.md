# 00 — Production deploy

**Status:** Pending M3-GA. The procedure below assumes the M3-GA work has
landed: real `aws-sdk-s3` + `aws-sdk-kms` integration behind `feature = "aws"`
([m3-decisions D23](../m3-decisions.md#d23)), real COSE_Sign1 + AWS Nitro
root-cert chain in `verify_attestation` ([D24](../m3-decisions.md#d24)),
pinned `alpine` SHA digest in `enclave/Dockerfile.eif`
([D27](../m3-decisions.md#d27)), and the `PolicyServiceSigner` end-to-end
wiring through `WalletService::sign` ([D29](../m3-decisions.md#d29)). Sections
that require those gates are marked inline.
**Audience:** ops, release engineer.
**Last reviewed:** 2026-05-21.

## Scope

A normal forward-only production deploy of a new tagged release of
`qfc-server-wallet`. Covers: tagging on `main`, EIF + SBOM publication
from CI, terraform plan/apply in the ops repo, enclave launch on Nitro
EC2, post-launch verification, traffic flip, rollback.

**Out of scope:**
- Brand-new region bring-up (separate one-time runbook in the ops repo).
- Schema-breaking migrations (separate runbook to be written when the
  first such migration ships).
- First-time enclave bring-up on a new AWS account (separate ops-repo
  runbook — covers KMS policy bootstrap, S3 bucket creation, IAM role
  set-up).

## Prerequisites

Before starting:

- AWS Nitro-enabled EC2 instance type. Reference target is `m5.xlarge`
  or larger (per RFC §7 M3). The ops repo's terraform pins the actual
  type used in production. **Pending M3-GA.**
- AWS account with the required IAM permissions for KMS, S3, EC2,
  CloudWatch. The exact policy set lives in `<OPS_REPO>/terraform/iam/`.
- Read access to the GitHub releases page for `qfc-network/qfc-server-wallet`.
- An open change-management ticket. Tag the ticket onto the GitHub
  release for the audit trail.
- `nitro-cli` available on the deploy host. The ops repo's AMI ships it
  pre-installed; verify with `nitro-cli --version`.
- Grafana access (`<GRAFANA_DASHBOARD>`) to watch the rollout.
- Pager on for the duration of the deploy window.

## Procedure

### 1. Tag the release on `main`

```sh
# from a clean checkout of main, with all required PRs merged
git checkout main
git pull
git tag -s -a v<X.Y.Z> -m "Release v<X.Y.Z>"
git push origin v<X.Y.Z>
```

The tag must be signed. The signing key lives in `<OPS_REPO>` per
release-engineer per the security model (RFC §8.6).

### 2. Wait for CI to publish artifacts

The release workflow on the tag push produces:

1. Reproducible EIF (`qfc-server-wallet.eif`) plus the `PCR0` / `PCR1` /
   `PCR2` hashes attached to the GitHub release.
2. SBOM (CycloneDX JSON) for both the host binary and the enclave binary.
3. Provenance attestation (SLSA-style).

Verify each artifact is present on the release page before continuing.
If the EIF build reports a PCR0 different from a fresh local
`make verify-eif` (per `01-eif-upgrade.md`), **stop**: the build is
non-reproducible.

### 3. Apply terraform in the ops repo

Live in `<OPS_REPO>/terraform/`. The ops repo runbook
`runbooks/00-deploy.md` carries the exact `terraform plan` / `apply`
sequence including the workspace selection and the variable file. Public
shape:

```sh
# in qfc-server-wallet-ops, after PR review and approval
terraform workspace select <ENV>
terraform plan -var release_tag=v<X.Y.Z> -out=plan.tfplan
# review plan with a second ops engineer (RFC §5.2: KMS policy changes
# require M-of-N via IAM + branch protection)
terraform apply plan.tfplan
```

The terraform run **adds the new EIF's PCR0 to the KMS decrypt policy**
without removing the previous PCR0. Both PCRs are accepted during the
rollout window. The previous PCR0 stays in the allowlist until step 7
explicitly removes it.

### 4. Launch the enclave on EC2 via `nitro-cli`

On each Nitro EC2 host in the deploy target group:

```sh
nitro-cli run-enclave \
    --cpu-count <N> \
    --memory <M_MB> \
    --eif-path /var/lib/qfc/eif/qfc-server-wallet-v<X.Y.Z>.eif \
    --enclave-cid <CID>
nitro-cli describe-enclaves
```

The exact `--cpu-count`, `--memory`, and `--enclave-cid` come from the
ops repo's host configuration (`<OPS_REPO>/runbooks/00-deploy.md` lists
them per instance class). The previous EIF stays running on the same
host — both old and new attest to KMS under the rolling allowlist.

**Pending M3-GA.** Until `qfc-server-wallet` has the M3-GA feature flag
shipped, this step runs against the M1 in-process `MockEnclave` per
[mock guard](../../crates/qfc-enclave/src/enclaves/mock.rs) and is
**not** a production deploy of TEE-isolated custody.

### 5. Verify `/health` from outside

From an external host (not the EC2 itself):

```sh
curl -fSs https://<PRODUCTION_HOST>/health
# expect: 200 OK, body shape per OpenAPI spec
```

The `/health` endpoint reports the orchestrator's liveness; it does
**not** prove the enclave is signing. The smoke test below does.

### 6. Smoke-test sign with a known-good test wallet

The ops repo carries a long-lived `test-wallet-canary` whose policy
allows a no-op signing call. The full sign request lives in the ops
repo's Bruno collection. Public shape:

```sh
# pseudocode — see <OPS_REPO>/bruno/canary/ for the actual collection
POST /wallets/<CANARY_WALLET_ID>/sign
  X-API-Key: <CANARY_API_KEY>
  body: { request_id: <ULID>, message: <fixed-test-bytes>, scheme: ed25519 }
# expect: 200 OK, attestation present, signature externally verifies
# expect: audit chain replay clean
```

Verify the returned attestation against the published PCR0 of the new
EIF using the public verifier (`qfc-enclave::verify_attestation`).
**Pending M3-GA** for the real-attestation half — `verify_attestation`
must have the COSE_Sign1 + cert-chain work done.

### 7. Flip traffic via load balancer / DNS

Once steps 5 and 6 are green on each new-EIF host:

1. Drain the old-EIF hosts from the load balancer (gracefully — let
   in-flight sign requests finish; the orchestrator's quorum timeout
   bounds the worst case).
2. Wait for the audit chain to settle on each draining host. Replay
   verifies against the published `qfc-audit` public key.
3. Detach the old-EIF hosts from the target group.
4. Remove the old PCR0 from the KMS decrypt policy (this is the second
   terraform apply; the ops repo holds the variable that turns the
   allowlist from `{old, new}` to `{new}`).

The KMS allowlist trim is the **point of no rollback** — once the old
PCR0 is removed, decrypt under the old EIF is impossible. Keep the
old-EIF hosts warm in the auto-scaling group, but with the trimmed
allowlist they are functionally inert. See *Rollback* below for the
opposite case.

## Definition of done

All of the following are green:

- `/health` returns 200 on every host in the new target group.
- The canary smoke-test sign request succeeds and the returned
  attestation matches the new PCR0.
- `qfc-audit` replay-verify is clean from the chain head back to the
  most recent daily anchor commit.
- Grafana shows nominal `qfc_server_wallet_signs_total{result="ok"}`
  rate on the new target group; `qfc_server_wallet_audit_events_total`
  is flowing; no spike in `qfc_server_wallet_signs_total{result!="ok"}`.
- The ops war room is paged out: the change-management ticket is
  closed with the release tag and the post-deploy verification artifacts
  attached.

## Rollback

The previous EIF stays warm in the auto-scaling group for a configurable
hold window (default: 60 minutes from step 7). During that window:

1. Re-add the previous PCR0 to the KMS decrypt policy if step 7 trimmed
   it. (If the rollback decision lands before step 7, no KMS change is
   needed — the allowlist still has both PCR0s.)
2. Re-attach the previous-EIF hosts to the target group.
3. Drain the new-EIF hosts.
4. Open an incident ticket per `03-incident-response.md` with the
   rollback reason; this is treated as a P1 minimum (regression in a
   release).

If the hold window has expired and the previous EIF is no longer warm,
roll forward to a hotfix release rather than rolling back. The
"re-launch the old EIF" path requires reproducing the old EIF from its
tag (`make verify-eif` against the previous tag) and going through this
runbook from step 1 with that tag. **Reproducibility is what makes
rollback survivable** — the published PCR0 from the previous release
plus a clean repo plus `make verify-eif` is the proof.

**Pending M3-GA.** The hold-window timer is implemented in the terraform
that manages the auto-scaling group; that terraform lives in the ops
repo and is one of the M3-GA gates.

## Post-deploy checklist

- Confirm `qfc-audit` daily anchor cron emitted an anchor commit
  covering the post-deploy chain head. **Pending `qfc-core` integration**
  for the on-chain anchor (per [retro-m1-m2 §3.7](../retro-m1-m2.md));
  until then verify the `LocalFileAnchor` JSONL file rolled over
  correctly (per [m3-decisions D28](../m3-decisions.md#d28)).
- File the deploy artifacts (PCR0 hashes, SBOM, provenance) with the
  change-management ticket.
- If this deploy was driven by a security patch, notify
  `<SECURITY_TEAM_HANDLE>` that it has landed in production and update
  any embargoed advisory accordingly.
- Schedule the next DR drill if the post-deploy hold window pushed the
  current one past schedule (see `04-disaster-recovery.md`).
