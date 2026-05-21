# Approver-client decisions (D46+)

Continuation of the `D1..D45` series spread across
`m1-decisions.md` / `m3-decisions.md` / `m4-decisions.md` /
`m5-decisions.md`. These calls cover the M4 "approver-side reference
client" deliverable (`clients/approver-rs/` and `clients/approver-ts/`).

## D46 — Reference clients ship outside the main Cargo workspace

`clients/approver-rs/` declares its own `[workspace]` table and is
listed in the root `Cargo.toml`'s `workspace.exclude`. Same call for
`tools/gen-golden-vectors/`.

**Why.** A reference client only delivers value if integrators can
fork the directory and ship it. Pulling the entire
`qfc-server-wallet` dep graph (sqlx, axum 0.7 with server extras,
utoipa, opentelemetry, ...) into every approver fork would make that
fork harder to maintain than rewriting from scratch — defeating the
"reference" framing. The cost we accept: workspace-wide `cargo test`
doesn't cover the clients, so the M4 deliverable's CI gate is "run
`cargo test` inside `clients/approver-rs/` separately."

**Alternatives considered.** (a) Add as a workspace member with a
trimmed feature set — rejected, the deps still arrive in `Cargo.lock`.
(b) Publish to crates.io with a path-only fallback — premature, M4
isn't yet stable.

## D47 — `qfc-approver` depends on `qfc-quorum`, not on a serialised wire spec

`clients/approver-rs/Cargo.toml` pulls in `qfc-quorum` (and transitively
`qfc-enclave` for the `Signer` trait + concrete signers). This means
the client reuses `SignedApproval::signing_preimage` directly rather
than re-implementing the byte layout.

**Why.** The whole hazard the M4 deliverable closes is
preimage-drift between server and approver. A path-dep + a shared
function guarantees both sides agree by construction. The reference TS
client cannot do this (no Rust at runtime); it instead pins equality
via a generated golden-vector fixture.

**Cost.** A bytes-level wire change to `SignedApproval` would force a
recompile of every forked approver daemon. We consider this a
*feature*: the wire contract is currently versionless and "you must
rebuild on protocol change" is a clearer story than "you might pick up
a silent mismatch."

## D48 — Wire DTOs mirrored locally, not re-exported from `qfc-server-wallet`

`clients/approver-rs/src/wire.rs` declares its own
`ApprovalRequestWire`, `ApproverIdentityWire`, `SubmitApprovalWire`
serde shapes rather than importing
`qfc_server_wallet::api::schemas::*`.

**Why.** `qfc-server-wallet` is the wallet *service*: it pulls in
axum-server, sqlx, utoipa, the full audit + policy stack. Pulling it
into the client just to reach a `SubmitApprovalRequest` struct would
break D46 ("forkable in isolation"). The mirror is a few dozen lines
and is byte-equivalent — drift is caught by the
`tests/preimage_compat.rs` integration test + the wire test in
`tests/end_to_end.rs` (which posts a JSON shape, parses it via the
client's mirror, and verifies the round-trip).

## D49 — Default decision policy is `Refuse`, not `AutoApprove`

The CLI defaults to fail-closed when no `--auto-approve` /
`--auto-reject` / `--interactive` flag is passed. The daemon still
starts, logs each incoming webhook, but drops every request.

**Why.** Approval daemons are high-value targets. Defaulting to
"approve unless told not to" is a footgun — operators who forget to
pass `--interactive` would silently rubber-stamp the next million-
dollar transfer. Refusing instead causes a visible quorum timeout on
the server side, which is loud and recoverable. The startup banner
warns loudly that the policy is refuse.

## D50 — `--webhook-secret` accepts an `@path` indirection

`--webhook-secret value` treats `value` as the literal secret;
`--webhook-secret @/etc/qfc/webhook.secret` reads the file. Same for
the TS client.

**Why.** Argv is world-readable on multi-tenant boxes
(`ps`/`/proc/$pid/cmdline`). A file with mode `0600` is the standard
hand-off pattern. We surface both forms so the dev-mode "paste it on
the command line" workflow still works for tutorials.

## D51 — Approver identity defaults to `External`, override via `Processor::with_identity`

The CLI binary only knows how to derive the public key from the
secret file; it doesn't know whether the operator registered as
`Chain`, `External`, `Hardware`, or `NestedWallet`. So the default
identity payload echoed back to the server is `External { id:
approver_id, public_key_hex: derived, scheme }`.

Library callers that registered under a different variant can override
via `Processor::with_identity(ApproverIdentityWire::Chain { ... })`.

**Why.** Most approvers register as `External` — the chain /
hardware / nested-wallet variants exist for advanced use cases and
those operators are already writing custom code. Forcing every CLI
user to pass an identity blob would punish the common case.

## D52 — Cross-language preimage compat is pinned by a generated fixture

`tools/gen-golden-vectors/` is a tiny Rust binary that calls
`qfc_quorum::SignedApproval::signing_preimage` on deterministic
inputs and writes
`clients/approver-ts/test/fixtures/preimage_golden.json`. The TS
client's `test/preimage.test.ts` reads the fixture and asserts
`buildSigningPreimage(...)` produces the same bytes.

**Why.** Independent re-implementation of the preimage layout in
TypeScript carries real drift risk. A generated fixture means a
breaking change to the Rust-side layout (e.g. switching `i64` from
big-endian to little-endian) breaks the TS test loudly; the fix is
"regenerate the fixture and update the TS preimage builder if
needed." The fixture is checked in so contributors don't need to run
the Rust tool to run the TS tests.

The Rust client carries the same pin internally as
`tests/preimage_compat.rs::deterministic_preimage_snapshot`, with an
inline hex literal. Both literals must update together if the layout
shifts.

## D53 — TS client uses `@noble/curves`, not `tweetnacl` / `elliptic` / `node:crypto` raw curves

**Why.** `@noble/curves` is pure JS, audited, maintained by the same
group as `@noble/hashes`, and exposes both ed25519 and secp256k1 with
the exact signature encodings we need (ed25519 = 64-byte R||S,
secp256k1 = compact `toCompactRawBytes()` = 64-byte r||s). `node:crypto`
*does* ship both curves natively but its secp256k1 ECDSA mode emits
DER-encoded sigs by default, which doesn't match the Rust enclave's
fixed-width output — fixing that would mean a DER → raw post-process
on every signature. `tweetnacl` is ed25519-only.

## D54 — TS client doesn't run in CI

Only the four Rust CI gates (build, test, clippy, fmt) run on the
workspace. The TS client is opt-in: `cd clients/approver-ts && npm
test` locally before merging changes that touch the preimage or
signer modules.

**Why.** Adding a Node toolchain to CI for one downstream that lives
outside the workspace is more friction than it's worth at this scope.
The TS fixture pinning catches the case CI would catch (preimage
drift); everything else is conventional unit testing.
