# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial Cargo workspace bootstrap per RFC v1.0 §12.
- Six stub crates: `qfc-server-wallet`, `qfc-enclave`, `qfc-sss`, `qfc-policy`, `qfc-quorum`, `qfc-audit`.
- Apache 2.0 license, security policy, contributor guide.
- CI workflows: clippy, fmt, test, cargo-deny, cargo-audit, cargo-vet.
- **M1 P1**: internal `qfc-wallet-types` crate with shared identifiers (`WalletId`, `RequestId`, `ShareId`, `OwnerId`, `PolicyId`, `DecisionId`, `ApprovalId`, `EventId`), signing-scheme + hash-algorithm enums, BIP32-style `HdPath` parser/formatter, and a redacting `SecretBytes` wrapper backed by `Zeroizing` + constant-time comparison.
- **M1 P2**: cryptographic foundation.
  - `qfc-enclave`: `Signer` trait with `Ed25519Signer`, `Secp256k1Signer`, `Secp256k1RecoverableSigner` (`k256` + `ed25519-dalek`, pure Rust, no FFI). Constant-time / deterministic signing where the scheme allows. Recovery byte normalized to `{0, 1}` and re-verified against the public key to reject malformed `v`.
  - `qfc-enclave`: `derivation` module — BIP32 over secp256k1 via `bip32`; SLIP-0010 over ed25519 implemented in-tree (HMAC-SHA512). BIP39 mnemonic → 64-byte seed helper. All-hardened enforcement for ed25519 paths. PQ schemes return `DerivationError::SchemeNotHd`.
  - `qfc-sss`: byte-secret Shamir split / combine via `vsss-rs` over `k256::Scalar`. Length-prefixed, 31-byte-chunked construction so every chunk fits within the curve order without rejection sampling. Self-describing `ShamirShare` blobs carry their `(M, N)` parameters; duplicate indices and parameter mismatches are detected on combine.
  - 54 tests across both crates (unit + 4 proptests, including round-trip over arbitrary secrets and BIP32 / SLIP-0010 reference vectors).
- **M1 P3**: share storage layer.
  - `qfc-sss::ShareStore` async trait + `StoredShare` envelope (wraps a `ShamirShare` with a creation timestamp). Trait surface is put / get / delete / list, all idempotent.
  - `MockShareStore`: in-memory `tokio::sync::RwLock<HashMap>` for tests and dev only.
  - `LocalFsShareStore`: filesystem-backed with XChaCha20-Poly1305 AEAD at-rest encryption. Per-write random 24-byte nonce, magic-prefixed file format, atomic write via `tempfile + rename`. Constructor takes a raw 32-byte key (passphrase / KDF wrapping is intentionally an operator-startup concern, not part of this layer).
  - 20 new tests including wrong-key rejection, ciphertext-tamper rejection, truncated-file rejection, on-disk-bytes-are-actually-encrypted assertion.

## [0.0.0] — 2026-05-19

Bootstrap tag for reproducibility baseline. No functionality yet.
