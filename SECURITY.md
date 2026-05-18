# Security policy

## Reporting a vulnerability

Email **security@qfc.network**, encrypted with our PGP key (fingerprint below). Do **not** open a public GitHub issue. Do **not** disclose on social media before coordinated disclosure.

We acknowledge receipt within **2 business days** and provide an initial assessment within **5 business days**.

### PGP

Fingerprint: _(to be populated before public repo creation — see RFC §12.6)_
Public key: _(linked from a keyserver / posted at qfc.network/.well-known/pgp-key.txt)_

## Embargo policy

- Default embargo: **90 days** from acknowledgement, or until a patched release is available, whichever is sooner.
- We will coordinate disclosure timelines with reporters in good faith.
- Reporters who give us reasonable time to fix are credited in the advisory and in the project hall of fame.

## In scope

- Any crate published from this repository (`qfc-server-wallet`, `qfc-enclave`, `qfc-sss`, `qfc-policy`, `qfc-quorum`, `qfc-audit`)
- The reference enclave image (EIF) built from `enclave/` (once landed in M3)
- Sample policies in `examples/policies/`
- The attestation verification library and verification page (once landed in M3)

## Out of scope

- Vulnerabilities in third-party dependencies that we cannot fix without an upstream patch (please report upstream; we'll track and roll out fixes as they ship)
- Production deployments operated by third parties (report directly to that operator)
- Denial-of-service via unauthenticated public endpoints in development (`MockEnclave` builds; `localhost`-only configurations)
- Anything requiring physical access to a production host beyond what the Nitro threat model already concedes (§5 of the RFC)

## Bug bounty

To be launched at M4 (see RFC §7) via Immunefi. Until then, we credit responsible reporters and offer swag + hall of fame; cash bounties for high-severity reports will be considered case-by-case.

## Hall of fame

(Empty — this list will populate as reports come in.)
