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

mod local_fs;
mod mock;

pub use local_fs::LocalFsShareStore;
pub use mock::MockShareStore;
