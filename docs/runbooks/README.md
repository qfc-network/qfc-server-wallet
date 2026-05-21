# Operator runbooks

**Status:** Living document. Individual runbooks below carry their own status
markers (Live / Pending M3-GA / etc).
**Audience:** on-call engineers, ops, security responders.
**Last reviewed:** 2026-05-21.

This directory holds the **public** operator runbooks for `qfc-server-wallet`.

## Public vs private split (per RFC §1.2 and §8.2)

| Repo                       | Visibility | What lives here                                                                                                  |
|----------------------------|------------|------------------------------------------------------------------------------------------------------------------|
| `qfc-server-wallet`        | Public     | Redacted runbooks. Procedure, command shapes, decision criteria. Placeholders for all account-specific values.   |
| `qfc-server-wallet-ops`    | Private    | Account-specific runbook counterparts. Real KMS ARNs, AWS account IDs, VPC IDs, on-call paging escalation paths. |

Rule (from RFC §8.2): *if leaked content would directly enable attacks on
running production, it goes in `-ops`. Everything else is public.*

Every public runbook in this directory has a corresponding ops-only
counterpart in `qfc-server-wallet-ops/runbooks/` with the same filename.
The private counterpart fills in the placeholders (`<ACCOUNT_ID>`,
`<KMS_KEY_ARN>`, `<OPS_TEAM_HANDLE>`, etc) and adds account-specific
escalation steps. **This repo does not link to the private repo**; ops
engineers find it through the org-internal repo index.

## Index

| File                                         | Status            | One-line                                                                |
|----------------------------------------------|-------------------|-------------------------------------------------------------------------|
| [`00-deploy.md`](00-deploy.md)               | Pending M3-GA     | Production deploy on Nitro EC2 (tag → EIF → KMS attach → traffic flip). |
| [`01-eif-upgrade.md`](01-eif-upgrade.md)     | Pending M3-GA     | EIF re-build, PCR0 reproducibility check, KMS allowlist swap.           |
| [`02-key-rotation.md`](02-key-rotation.md)   | Partially Live    | DEK / policy-service / approver key rotation cadences.                  |
| [`03-incident-response.md`](03-incident-response.md) | Live (M3-GA gates the P0 commands) | P0/P1/P2 triage, with the freeze + audit-snapshot procedure.       |
| [`04-disaster-recovery.md`](04-disaster-recovery.md) | Targets stated, parts Pending M3-GA | Recovery targets, drill cadence, known gaps.                       |
| [`05-operator-onboarding.md`](05-operator-onboarding.md) | Live    | New ops engineer onboarding checklist + reading list.                   |

## Conventions

- **Placeholders.** `<ACCOUNT_ID>`, `<KMS_KEY_ARN>`, `<OPS_TEAM_HANDLE>`,
  `<SECURITY_TEAM_HANDLE>`, `<GRAFANA_DASHBOARD>`, `<ALERT_MANAGER_URL>`,
  `<RELEASE_TAG>`, `<PCR0_HEX>`. The private repo's counterpart fills these in.
- **Imperative tense.** "Tag the release. Verify CI. Apply terraform."
  Not "you should tag a release."
- **Marked deferrals.** Anything that depends on M3-GA AWS work, the
  `qfc-core` dep, or external signoff carries a "Pending …" tag inline.
  When the gate clears, drop the tag in the same PR that lights up the
  procedure.
- **No live URLs.** This is a public repo. Do not paste real Grafana,
  Slack, AWS-console, or paging-system URLs. Use the placeholder
  `<GRAFANA_DASHBOARD>` etc, and put the real URL in the private
  counterpart.
- **No SLA guarantees.** Recovery targets (RPO, RTO) are stated as
  *targets* in `04-disaster-recovery.md`, not promises.

## When to update a runbook

Update the runbook in the same PR that ships the operational change.
A runbook that is wrong is worse than a runbook that is missing —
ops engineers trust what they read here. The "Last reviewed" date at
the top of each file is updated on every substantive edit.
