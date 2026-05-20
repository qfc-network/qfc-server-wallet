//! Concrete `ShareStore` impls.
//!
//! - `MockShareStore`: in-memory `HashMap`, for tests and dev. Cleartext —
//!   never use outside the process.
//! - `LocalFsShareStore`: encrypted files on local disk. Uses
//!   XChaCha20-Poly1305 AEAD with a 32-byte key passed in at construction
//!   time. The store does *not* derive that key from a passphrase — that
//!   responsibility belongs to the operator-startup layer (RFC §2.2:
//!   "key in age-encrypted file unlocked by an operator passphrase at server
//!   start").
//! - `S3KmsShareStore` (M3 skeleton): S3 object store + KMS envelope
//!   encryption with attestation-conditional decrypt. Real `aws-sdk-*`
//!   integration ships behind the `aws` feature; default build uses
//!   `MockS3Client` + `MockKmsClient` for tests + non-AWS dev.

mod local_fs;
mod mock;
mod s3_kms;

pub use local_fs::LocalFsShareStore;
pub use mock::MockShareStore;
pub use s3_kms::{
    AttestationPredicate, DataKeyMaterial, KmsClient, MockKmsClient, MockS3Client, S3Envelope,
    S3KmsShareStore, S3Like,
};
