//! Secret material wrapper.
//!
//! `SecretBytes` is the only sanctioned container for raw key material
//! crossing crate boundaries inside the workspace. It is `Zeroizing<Vec<u8>>`
//! under the hood, so the buffer is wiped when dropped, and it implements
//! constant-time equality so that comparisons cannot leak length-equal
//! prefixes through early-exit branches.

use core::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// A heap-allocated, auto-zeroized byte buffer for secret material.
///
/// `Debug` and `Display` deliberately do *not* print contents; they only
/// reveal the length. Use the explicit [`SecretBytes::expose`] method if you
/// truly need to look at the bytes — its presence makes secret access
/// grep-able in audits.
#[derive(Clone)]
pub struct SecretBytes {
    inner: Zeroizing<Vec<u8>>,
}

impl SecretBytes {
    /// Wrap an existing buffer. The buffer will be zeroized when this
    /// `SecretBytes` is dropped.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Zeroizing::new(bytes),
        }
    }

    /// Construct from a slice. Copies the input.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    /// Byte length of the underlying secret. Available without exposing
    /// contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Borrow the underlying bytes. This method is intentionally named
    /// `expose` (not `as_ref` or `as_slice`) so that audits can grep for it.
    /// Prefer narrow, line-bounded uses of the returned slice.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.inner
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<{} bytes redacted>)", self.inner.len())
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes redacted>", self.inner.len())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner).into()
    }
}

impl Eq for SecretBytes {}

impl From<Vec<u8>> for SecretBytes {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_contents() {
        let s = SecretBytes::from_slice(b"super-secret-key-material");
        let d = format!("{s:?}");
        assert!(d.contains("redacted"));
        assert!(!d.contains("super-secret"));
    }

    #[test]
    fn display_redacts_contents() {
        let s = SecretBytes::from_slice(b"abc");
        assert_eq!(format!("{s}"), "<3 bytes redacted>");
    }

    #[test]
    fn equal_buffers_compare_equal() {
        let a = SecretBytes::from_slice(b"k");
        let b = SecretBytes::from_slice(b"k");
        assert_eq!(a, b);
    }

    #[test]
    fn unequal_buffers_compare_unequal() {
        let a = SecretBytes::from_slice(b"k1");
        let b = SecretBytes::from_slice(b"k2");
        assert_ne!(a, b);
    }

    #[test]
    fn length_is_observable() {
        let s = SecretBytes::from_slice(b"abcd");
        assert_eq!(s.len(), 4);
        assert!(!s.is_empty());
    }

    #[test]
    fn expose_returns_underlying_bytes() {
        let s = SecretBytes::from_slice(&[1, 2, 3]);
        assert_eq!(s.expose(), &[1, 2, 3]);
    }
}
