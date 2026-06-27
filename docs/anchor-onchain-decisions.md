# On-chain audit anchor — decisions

Per-call non-obvious decisions for `ChainAnchor`, the on-chain submitter that
closes RFC §2.6's "daily on-chain anchor commit" deferral. Numbering continues
the project's `Dxx` convention (decisions specific to this work).

Context: through v0.1.0 the anchor had only `LocalFileAnchor` (a file-backed
JSONL stub). The on-chain submitter was tracked as "blocked on `qfc-core`
workspace integration". This work ships it.

## D60 — No `qfc-core` workspace dependency; speak EVM JSON-RPC instead

The deferral framing ("needs a `qfc-core` dep") was wrong. qfc-core exposes
transaction submission through its **EVM-compatible JSON-RPC**
(`eth_sendRawTransaction`) — the same surface `qfc-cli` and the SDKs already
use to submit. There is no native borsh-tx submission RPC and no reusable
qfc-core RPC *client* crate.

So `ChainAnchor` talks plain Ethereum JSON-RPC over HTTP. This keeps the lean
server-wallet workspace free of the entire qfc-core tree (consensus, network,
QVM, inference, CUDA, …) — exactly the dependency the RFC deliberately avoided
(retro-m1-m2 §3.6). The cost is that we hand-build + sign the transaction
ourselves rather than calling a qfc-core helper; that is ~120 lines, fully
unit-tested, and reuses crates already in the tree.

## D61 — Zero new dependencies; hand-rolled RLP + RustCrypto signing

Adding `alloy` or `ethers` would drag a large dependency subtree through
cargo-deny / cargo-vet / cargo-audit for what is, at bottom, "RLP-encode nine
fields, keccak, ECDSA-sign, POST". Everything needed was already a workspace
dependency:

- `k256` — secp256k1; `SigningKey::sign_prehash_recoverable` gives the
  recoverable `(r, s, recid)` EVM needs (low-S normalized per EIP-2 by default).
- `sha3` — keccak256 for the signing hash, tx hash, and address derivation.
- `reqwest` — the JSON-RPC transport (already used by the M4 webhook client).

RLP is hand-rolled (~40 lines, encode-only). To make that safe it is **pinned
against the canonical EIP-155 worked example** (nonce 9, 20 gwei, 21000 gas,
to `0x3535…35`, 1 ETH, chainId 1, key `0x46…46`) — the unit test asserts the
exact expected raw transaction bytes. A second test pins the operator-address
derivation against the known address for that key. If the encoding were wrong
in any field, the byte-exact comparison fails loudly.

## D62 — Legacy EIP-155 transactions, not EIP-1559

A legacy (type-0) tx is universally accepted by `eth_sendRawTransaction` and
needs no fee-market introspection (`baseFee`, priority tips). The anchor is a
low-frequency (daily) zero-value self-send where gas-price optimality is
irrelevant; legacy keeps the encoder to one code path. `v = recid + 35 +
chain_id * 2`.

## D63 — Commitment lives in calldata of a zero-value self-send

The commitment is opaque calldata, not a contract call:

```
b"qfc-audit-anchor-v1\0" ‖ chain_head[32] ‖ event_count_be[8] ‖ date_utc(ascii)
```

`to` defaults to the operator's own address (a self-send), so **no contract
deployment is required** to start anchoring — a verifier just reads the tx
`input`. `to` is overridable (`QFC_ANCHOR_TO`) for operators who prefer a
dedicated sink/registry contract later. The 20-byte domain tag makes anchor
txs trivially greppable on a block explorer and prevents calldata collisions
with other self-sends.

## D64 — `event_count` included so truncation is detectable, not just tampering

The hash chain already makes *editing* a past event detectable. The on-chain
anchor's job is to also catch *tail truncation* (deleting the most recent N
events). Committing `event_count` alongside `chain_head` lets a verifier detect
a chain that was rewound to an earlier valid prefix: the on-chain count won't
match the shortened log. (Same rationale as the `LocalFileAnchor` memo field.)

## D65 — `FileAuditSink::current_anchor_payload()`; head, not last-event-id

The existing read-side helper (`anchor::anchor_payload`) is Postgres-only, but
the binary runs the file sink. Rather than require Postgres to anchor, the file
sink now exposes its live cursor as an `AnchorPayload`. `head_event_id` is left
`None` for the file sink — the in-memory cursor tracks the head hash and count,
not the last event id, and on-chain verification keys off `chain_head` +
`event_count`, which are sufficient for truncation detection. The Postgres path
still populates `head_event_id` for callers that want it.

## D66 — Off by default; misconfiguration is a hard startup error

The cron is spawned only when `QFC_ANCHOR_RPC_URL` is set, so existing dev runs
are untouched. **When** it is set, a missing/invalid `QFC_ANCHOR_OPERATOR_KEY`
(or bad `to` / chain-id / gas) aborts startup rather than silently disabling
the anchor — a silently-off audit anchor is exactly the failure a tamper-evident
log must not have. `chain_id` and `gas_price` are auto-queried
(`eth_chainId`, `eth_gasPrice`) unless pinned via env.

## Still open

- **Live end-to-end exercise** needs a funded operator account + a reachable
  qfc-node RPC. Unit + wiremock-integration tests cover construction, signing,
  and the full submit round-trip offline; they do not prove a real qfc-node
  accepts the tx. First live run is a deploy-time checklist item (operator
  account funding + RPC URL), not a code change.
- **Receipt confirmation / retry.** `submit` broadcasts and logs the returned
  tx hash; it does not poll `eth_getTransactionReceipt` or retry on a dropped
  tx. The daily cadence + best-effort cron (logs at WARN, continues) is the
  v1 posture; confirmation-tracking can layer on if operators want it.
- **Nonce management** is delegated to the node (`eth_getTransactionCount` with
  `pending`). Fine for a single daily submitter; would need a local nonce
  cache if the operator key is ever shared with another sender.
