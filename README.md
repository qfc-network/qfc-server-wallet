# qfc-server-wallet

Server-side wallet subsystem for the QFC ecosystem: programmable treasury, agent wallets, enterprise approval flows.

- TEE-isolated key custody (AWS Nitro reference backend; trait-abstracted for SGX, TDX, Mock)
- Shamir Secret Sharing with M-of-N quorum and pluggable share stores
- Declarative policy DSL with multi-VM aware decoders (EVM today, QVM growing)
- Hash-chained audit log with daily on-chain anchor commitments
- Reproducible enclave image builds; public attestation verification

**Status:** pre-M1 bootstrap. See [`docs/server-wallet-rfc.md`](docs/server-wallet-rfc.md) for the v1.0 design RFC.

## Layout

```
crates/
  qfc-server-wallet/    # binary + top-level lib (HTTP API)
  qfc-enclave/          # TEE trait + MockEnclave (M1) + NitroEnclave (M3)
  qfc-sss/              # Shamir wrapper + ShareStore trait
  qfc-policy/           # Policy DSL + evaluator + VM decoders
  qfc-quorum/           # M-of-N approver coordination
  qfc-audit/            # AuditSink trait + backends
```

## Security

Reporting: see [`SECURITY.md`](SECURITY.md). Do **not** open public issues for security reports.

## License

Apache 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
