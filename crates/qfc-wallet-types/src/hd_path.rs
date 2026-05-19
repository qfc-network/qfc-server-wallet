//! BIP32 / SLIP-0010 hierarchical derivation paths.
//!
//! A path is a sequence of `HdPathSegment`s. Each segment is either *normal*
//! (index `< 0x80000000`) or *hardened* (index `>= 0x80000000`). The textual
//! form follows the de-facto standard: segments separated by `/`, hardened
//! segments suffixed with `'` or `h`, leading `m` representing the master.
//!
//! Example: `m/44'/60'/0'/0/0`.

use core::fmt;
use core::str::FromStr;
use serde::{Deserialize, Serialize};

use crate::errors::ParseError;

/// A single component of an HD derivation path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HdPathSegment {
    /// Normal (non-hardened) derivation. Index `< 2^31`.
    Normal(u32),
    /// Hardened derivation. The stored value is the *unhardened* index;
    /// the actual derivation index is `value | 0x8000_0000`.
    Hardened(u32),
}

impl HdPathSegment {
    /// Raw 32-bit child index used by BIP32 derivation maths.
    #[must_use]
    pub const fn child_index(self) -> u32 {
        match self {
            Self::Normal(i) => i,
            Self::Hardened(i) => i | 0x8000_0000,
        }
    }

    /// Whether this segment is hardened.
    #[must_use]
    pub const fn is_hardened(self) -> bool {
        matches!(self, Self::Hardened(_))
    }
}

impl fmt::Display for HdPathSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal(i) => write!(f, "{i}"),
            Self::Hardened(i) => write!(f, "{i}'"),
        }
    }
}

/// A full BIP32 / SLIP-0010 derivation path.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HdPath(Vec<HdPathSegment>);

impl HdPath {
    /// Empty (master) path.
    #[must_use]
    pub const fn master() -> Self {
        Self(Vec::new())
    }

    /// Build a path from an ordered list of segments.
    #[must_use]
    pub fn from_segments<I: IntoIterator<Item = HdPathSegment>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }

    /// Borrow the path's segments in order.
    #[must_use]
    pub fn segments(&self) -> &[HdPathSegment] {
        &self.0
    }

    /// Number of segments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True iff this is the master path (no segments).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for HdPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for seg in &self.0 {
            write!(f, "/{seg}")?;
        }
        Ok(())
    }
}

impl FromStr for HdPath {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParseError::InvalidHdPath("empty string".into()));
        }
        let mut parts = s.split('/');
        let head = parts.next().expect("split always yields >=1 part");
        if head != "m" && head != "M" {
            return Err(ParseError::InvalidHdPath(format!(
                "path must start with 'm', got {head:?}"
            )));
        }
        let mut segments = Vec::new();
        for raw in parts {
            if raw.is_empty() {
                return Err(ParseError::InvalidHdPath("empty segment".into()));
            }
            let (digits, hardened) = if let Some(rest) = raw.strip_suffix('\'') {
                (rest, true)
            } else if let Some(rest) = raw.strip_suffix('h') {
                (rest, true)
            } else if let Some(rest) = raw.strip_suffix('H') {
                (rest, true)
            } else {
                (raw, false)
            };
            let value: u32 = digits
                .parse()
                .map_err(|_| ParseError::InvalidHdPath(format!("non-numeric segment {raw:?}")))?;
            if value >= 0x8000_0000 {
                return Err(ParseError::InvalidHdPath(format!(
                    "segment {value} exceeds 2^31-1"
                )));
            }
            segments.push(if hardened {
                HdPathSegment::Hardened(value)
            } else {
                HdPathSegment::Normal(value)
            });
        }
        Ok(Self(segments))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn master_parses_and_prints() {
        let p: HdPath = "m".parse().unwrap();
        assert!(p.is_empty());
        assert_eq!(p.to_string(), "m");
    }

    #[test]
    fn classic_eth_path_round_trip() {
        let raw = "m/44'/60'/0'/0/0";
        let p: HdPath = raw.parse().unwrap();
        assert_eq!(p.len(), 5);
        assert!(p.segments()[0].is_hardened());
        assert!(p.segments()[1].is_hardened());
        assert!(p.segments()[2].is_hardened());
        assert!(!p.segments()[3].is_hardened());
        assert!(!p.segments()[4].is_hardened());
        assert_eq!(p.to_string(), raw);
        assert_eq!(p.segments()[0].child_index(), 44 | 0x8000_0000);
        assert_eq!(p.segments()[3].child_index(), 0);
    }

    #[test]
    fn h_suffix_is_accepted() {
        let p: HdPath = "m/44h/60h/0h".parse().unwrap();
        assert_eq!(p.len(), 3);
        for s in p.segments() {
            assert!(s.is_hardened());
        }
        // Display normalizes to apostrophe form.
        assert_eq!(p.to_string(), "m/44'/60'/0'");
    }

    #[test]
    fn rejects_missing_leading_m() {
        let err: Result<HdPath, _> = "44'/60'/0'".parse();
        assert!(matches!(err, Err(ParseError::InvalidHdPath(_))));
    }

    #[test]
    fn rejects_oversize_segment() {
        let err: Result<HdPath, _> = "m/2147483648".parse();
        assert!(matches!(err, Err(ParseError::InvalidHdPath(_))));
    }

    proptest! {
        #[test]
        fn round_trip_random_path(
            indices in proptest::collection::vec(0u32..0x8000_0000, 0..8),
            hardened in proptest::collection::vec(any::<bool>(), 0..8),
        ) {
            let segs: Vec<HdPathSegment> = indices
                .iter()
                .zip(hardened.iter().chain(std::iter::repeat(&false)))
                .map(|(i, h)| if *h { HdPathSegment::Hardened(*i) } else { HdPathSegment::Normal(*i) })
                .collect();
            let path = HdPath::from_segments(segs.clone());
            let text = path.to_string();
            let parsed: HdPath = text.parse().unwrap();
            prop_assert_eq!(path, parsed);
        }
    }
}
