# 01 — EIF upgrade

**Status:** Pending M3-GA. The EIF build infrastructure ships compile-time
only today: `enclave/Dockerfile.eif` carries placeholder SHA digests
([m3-decisions D27](../m3-decisions.md#d27)) and `make verify` cannot
produce a runnable EIF until the M3-GA PR fills in pinned base images.
The `EnclaveUpgraded` audit kind referenced below is not yet assigned a
kind byte in [`crates/qfc-audit/src/event.rs`](../../crates/qfc-audit/src/event.rs)
— treat this runbook as operationally relevant only after both gates clear.
**Audience:** ops, release engineer, security reviewer.
**Last reviewed:** 2026-05-21.

## When this runbook fires

An EIF upgrade is required for any of:

- Dependency bump that touches enclave code (anything pulled by the
  `enclave/` cargo target). The host-side workspace is decoupled per
  [m3-decisions D26](../m3-decisions.md#d26), so most host-only dep
  bumps do **not** require an EIF upgrade.
- Security patch for a crate in the enclave dep tree (cargo-audit /
  cargo-vet advisory).
- Policy hard-ceiling change. Per RFC §2.1, the hard ceilings
  (`max_value_per_tx`, `contract_allowlist`, `chain_allowlist`) are
  re-enforced inside the enclave; relaxing them is a wallet-config
  change but **tightening them globally** is an EIF change because the
  in-EIF verifier carries the bound.
- Rust toolchain bump (the EIF's `rust-toolchain.toml` is pinned
  independently of the host workspace's — see
  [m3-decisions D26](../m3-decisions.md#d26)).
- `qfc-policy` `SigningPayload` shape change that requires the
  in-enclave EVM/QVM re-decoder to add a new variant.

Things that are NOT EIF upgrades:

- Wallet-config changes (`max_value_per_tx` on a single wallet,
  approver-set membership). These are runtime data, not EIF code.
- API surface changes that don't reach the enclave (new HTTP routes
  in `crates/qfc-server-wallet/src/api/`).
- Grafana dashboard / OpenTelemetry collector config tweaks.

## Pre-flight

### Reproducibility check

Before producing the production EIF, verify the build is bit-exact:

```sh
cd enclave/
make verify
```

`make verify` runs two independent containerized builds (`build/a` and
`build/b`) and diffs `boot.bin`. On pass it prints
`PASS: reproducible build, sha256 = <hex>`. On fail it dumps the
hexdiff and exits non-zero.

If `make verify` fails:

1. **Stop.** Do not ship a non-reproducible EIF.
2. Inspect the diff. Likely culprits: a build-time timestamp,
   path-dependent embedded debug info, an unpinned dep, a non-static
   link.
3. Open a PR against `enclave/` fixing the non-determinism. Re-run.

### PCR0 diff against `main`

Once `make verify` is green, compute the PCR0 of the new EIF (via
`nitro-cli describe-eif` on a Nitro-enabled host — see
`enclave/Makefile`'s `make eif` target) and diff it against the
currently-running PCR0 (the one in the KMS allowlist).

- **PCR0 changed.** Expected — that's why you're upgrading. Continue.
- **PCR0 unchanged.** The "upgrade" produces an identical enclave
  image. Either the change didn't reach the enclave (this is not an
  EIF upgrade, abort) or the change is invisible to PCR0 (e.g. a code
  comment). Investigate before continuing.

### Audit + security review

Per RFC §8.4 + §8.6, every enclave-touching PR requires two reviewers
and triggers a rebuild + PCR0 diff comment in CI. For an EIF upgrade
the additional checklist:

- The diff against the previous EIF's source is reviewed by
  `<SECURITY_TEAM_HANDLE>`.
- The new PCR0 is recorded in the change-management ticket alongside
  the release tag.
- `cargo audit` + `cargo deny check` against the enclave's `Cargo.lock`
  is clean (recall: the enclave has its own lockfile per
  [m3-decisions D26](../m3-decisions.md#d26)).

## KMS allowlist update — BEFORE the swap

Add the new PCR0 to the KMS decrypt policy *before* launching the new
EIF instances. This makes the allowlist `{old_PCR0, new_PCR0}` for the
duration of the rollout. Both EIFs can decrypt shares; both can serve
traffic.

The change is a `terraform apply` against the KMS module in the ops
repo. The terraform variable shape:

```hcl
# in <OPS_REPO>/terraform/kms/
variable "allowed_pcrs" {
  type    = list(string)
  default = ["<OLD_PCR0_HEX>"]
}
```

becomes

```hcl
default = ["<OLD_PCR0_HEX>", "<NEW_PCR0_HEX>"]
```

Two reviewers per RFC §5.2 ("KMS policy changes themselves require
M-of-N via AWS IAM Access Analyzer + organizational policy + GitHub
branch protection on `qfc-server-wallet-ops`"). Apply, verify the KMS
key policy via `aws kms get-key-policy` (or the ops repo's equivalent
wrapper), then move on.

**Do not skip this step.** If you launch the new EIF before the KMS
policy is updated, every sign request fails with a KMS decrypt error
because the new PCR0 isn't allowed yet.

## Live swap

Run the deploy procedure in `00-deploy.md` from step 4 onward. The KMS
allowlist update above replaces step 3 for this case — terraform has
already been applied.

Specific to an EIF upgrade:

1. Launch the new EIF on each Nitro host alongside the old EIF. Both
   are reachable via the load balancer.
2. Bleed traffic from old to new in increments (10% → 50% → 100%). At
   each increment, watch:
   - `qfc_server_wallet_signs_total{result="ok"}` rate stays nominal.
   - `qfc_server_wallet_signs_total{result!="ok"}` rate does not climb.
   - `qfc_server_wallet_sign_duration_seconds` p99 stays nominal.
3. Once 100% of traffic is on the new EIF and the canary smoke-test
   from `00-deploy.md` step 6 has passed against it: decommission the
   old-EIF processes (`nitro-cli terminate-enclave --enclave-id <ID>`).

## KMS allowlist trim — AFTER the swap

After the post-deploy hold window expires (default 60 minutes — see
`00-deploy.md` Rollback), trim the old PCR0 from the KMS policy.

```hcl
# back to single-PCR0
default = ["<NEW_PCR0_HEX>"]
```

This is the point of no rollback. From here, the only way back to the
old EIF is to reproduce it from its tag and run a fresh upgrade in the
opposite direction.

## Audit

Emit an `EnclaveUpgraded` audit event with `{ old_pcr0, new_pcr0,
release_tag, operator_id }` as the event payload.

**Pending.** `AuditKind::EnclaveUpgraded` is not yet a variant in
[`crates/qfc-audit/src/event.rs`](../../crates/qfc-audit/src/event.rs).
Add it (plus a stable kind byte assignment — the next free byte after
`PolicyDecisionSigned = 17`) in the same PR that lights this runbook up
operationally.

## Rollback

Same shape as `00-deploy.md`'s Rollback section, with the additional
constraint that the KMS allowlist trim is reversed first (re-add the
old PCR0). If the trim has not yet happened, the rollback is just a
traffic-flip back to the old-EIF hosts.

## Common failure modes

- **`nitro-cli run-enclave` returns "PCR0 not in KMS allowlist".** The
  KMS allowlist update either didn't apply or didn't propagate. Wait
  ~60 seconds for AWS to settle, retry. If it persists, verify with
  `aws kms get-key-policy` directly.
- **`make verify` fails on a second-run host.** Reproducibility is
  sensitive to the host's filesystem timestamps; `SOURCE_DATE_EPOCH`
  catches most cases but not all. Build inside the Docker container
  the Makefile pins (any rust/alpine version drift breaks
  reproducibility).
- **Smoke-test sign fails with `InvalidAttestation`.** The published
  PCR0 in the release artifact does not match the running EIF. Either
  CI published a stale artifact (treat as a release-engineering bug)
  or the EIF on the host is not the one terraform claims to have
  shipped (terraform/state drift — open a P1).
