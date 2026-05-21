# 05 — Operator onboarding

**Status:** Live. Some onboarding steps reference systems that come on
line at M3-GA (production AWS access, paging rotation against the live
service). Where a step is gated on M3-GA it's marked inline.
**Audience:** new ops / SRE engineer, hiring manager, security lead.
**Last reviewed:** 2026-05-21.

## Scope

This runbook is the checklist for bringing a new ops engineer up to
"can take a P2 page" status. P1 readiness is the end-of-month-one
target; P0 readiness lives on the shadow-an-incident path that
extends past the onboarding window.

## Day 1 — Access provisioning

### IAM roles

- AWS IAM role provisioning for the production account. The exact role
  set lives in `<OPS_REPO>/terraform/iam/`. Public shape: separate
  roles for read-only (always-on) and write (requires SSO + MFA elevation
  per request). New hires get read-only first; write access lights up
  after the first month per the rotation policy.
- Staging AWS IAM role with broader write access. Used for DR drills.

The actual role assignments + the SSO group memberships are managed by
`<OPS_TEAM_HANDLE>` per the ops repo's onboarding ticket template.

### GitHub access

- Membership in `qfc-network/ops` (read access to `qfc-server-wallet`
  and `qfc-server-wallet-ops`; write to the latter is per-PR review).
- Membership in `qfc-network/security` once the P0-shadowing
  prerequisite is met (typically end of month two).

### Tooling access

- Grafana: viewer access on day 1; editor access after first DR drill
  participation.
- Alert manager (`<ALERT_MANAGER_URL>` — placeholder, real URL in
  ops repo): page-receiver enrolled in the on-call rotation tool. The
  new engineer is added to the rotation in shadow mode for the first
  two weeks (paged in parallel with the primary; no expectation to
  resolve).
- The on-call paging tool itself: device enrollment, phone-number
  registration, schedule shadow.
- Postgres read-only access for triage queries (the ops repo's
  Postgres bastion docs cover the connection flow).

### Security credentials

- PGP key generation. The new engineer generates a personal PGP key
  per the standard ceremony (key length, expiry, photo-ID inclusion
  documented in the ops repo). The pubkey is published to
  `security@qfc.network` per RFC §8.3 and added to the security team
  keyring.
- Hardware MFA token (YubiKey or equivalent). Required for production
  write access and for any privileged AWS console action.
- Signed laptop policy: the new engineer's primary work laptop is
  enrolled in the org's MDM and runs the standard hardening profile.
  Production credentials never live on an unmanaged device.

## Reading list

Required before the first on-call shadow rotation:

1. **RFC v1.2** ([`docs/server-wallet-rfc.md`](../server-wallet-rfc.md))
   in full. Sections to re-read in depth:
   - §1.2 — repo split (you'll work across both).
   - §2 — core traits (the abstraction surface you'll be debugging
     against).
   - §5 — threat model (what each layer defends against and what it
     doesn't). This is the framing for every P0 triage call.
   - §7 — roadmap. So you know which milestone the service is in and
     what's deferred.
   - §8.4 — audit roadmap.
2. **Threat model** ([`docs/threat-model.md`](../threat-model.md)) —
   companion to RFC §5, deeper material.
3. **This directory** — all six public runbooks. Read in order
   (00 → 05). Take notes on placeholders you don't yet know the values
   for; the ops repo's matching runbooks fill those in.
4. **`qfc-server-wallet-ops` private runbooks.** Once you have access
   to the private repo, read the matching `runbooks/00-05.md` files
   side by side with these. The private repo carries the account
   IDs, KMS ARNs, exact terraform commands, escalation paths, and
   customer-policy specifics.
5. **M3 + M5 decisions docs** ([`docs/m3-decisions.md`](../m3-decisions.md)
   and [`docs/m5-decisions.md`](../m5-decisions.md)) — the
   non-obvious calls that shape what the system actually does.
6. **Both retros** ([`docs/retro-m1-m2.md`](../retro-m1-m2.md) and
   [`docs/retro-m3-m4.md`](../retro-m3-m4.md)) — the gap list. Knowing
   what's deferred or stubbed is how you avoid trusting a runbook
   section that's still aspirational.

## First-month exercises

These are gated; complete them in order. Each one has a
sign-off from a senior ops engineer.

### Week 1: walk through `00-deploy.md` in staging

Run a full deploy from a freshly tagged staging release through to a
post-deploy `/health` + canary-sign verification. Roll back. Roll
forward again. Document any place the runbook tripped you up — that's
free runbook-improvement signal.

### Week 2: shadow on-call for one rotation

You're paged in parallel with the primary; the primary owns
resolution. Watch every P2 (and P1 if any) end-to-end. Take notes on:
- How the primary forms the initial triage hypothesis.
- What triage commands they run that aren't in the runbooks.
- Where Grafana's panels gave them the answer vs where they had to
  drop to Postgres / Loki.

After the rotation, file a "what's missing from the runbooks" PR
against this directory.

### Week 3: run a quarterly DR drill

Per `04-disaster-recovery.md` — pick one scenario from the matrix
(audit-chain restore is the lowest-risk first one) and walk through
the recovery in staging. Produce the drill report. The senior ops
engineer signs off.

### Week 4: own a P2 incident end-to-end

The next P2 page after week 3 is yours to drive. The primary
on-call shadow-supports. You own:
- The initial triage call.
- The decision to scale / rollback / config-tweak.
- The comms updates to the ticket.
- The post-incident root-cause doc.

After this, you're cleared for the regular on-call rotation as
primary for P2 + P1; P0 readiness needs additional shadow time on
security-led incidents.

## Ongoing

- Every quarter: participate in at least one DR drill.
- Every six months: refresh PGP key (if at expiry); refresh hardware
  MFA token assignment.
- Every year: re-read the RFC, threat model, and this directory.
  Update any runbook section that's drifted from reality.

## What this runbook does NOT cover

- Onboarding to the `qfc-core` on-call rotation — separate runbook in
  the `qfc-core` repo.
- Onboarding to the customer-success rotation — separate runbook in
  `<OPS_REPO>/runbooks/customer/`.
- Performance-engineering deep dives — those live alongside the
  performance benchmarks in the ops repo, not in the public runbooks.
