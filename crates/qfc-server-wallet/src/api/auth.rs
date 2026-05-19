//! API-key authentication middleware.
//!
//! Allowed keys are loaded once at server startup from the
//! `QFC_SERVER_WALLET_API_KEYS` env var (comma-separated) and held as an
//! `Arc<HashSet<String>>` on `AppState`. Every request other than
//! `/health` and `/metrics` must carry the `X-API-Key` header with a value
//! present in that set.
//!
//! The set is compared in constant time (per-key) to avoid trivial timing
//! oracles. Empty entries from the env are dropped.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use subtle::ConstantTimeEq;

use super::error::ApiError;
use super::AppState;

/// Header name carrying the API key.
pub const API_KEY_HEADER: &str = "x-api-key";

/// Load allowed API keys from a comma-separated string (typically the
/// value of `QFC_SERVER_WALLET_API_KEYS`). Empty / whitespace-only tokens
/// are dropped. Returns an empty set for an empty input.
#[must_use]
pub fn load_api_keys(raw: &str) -> HashSet<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Constant-time membership check across the allowed-keys set.
///
/// We iterate every entry — branching on length is fine (it would leak the
/// length of the *configured* keys, not the presented one), but the
/// byte-level comparison uses `subtle::ConstantTimeEq` to avoid leaking
/// any prefix information about the configured keys.
#[must_use]
pub fn is_allowed<S: std::hash::BuildHasher>(keys: &HashSet<String, S>, presented: &str) -> bool {
    let presented_b = presented.as_bytes();
    let mut hit = 0u8;
    for k in keys {
        let kb = k.as_bytes();
        if kb.len() == presented_b.len() && bool::from(kb.ct_eq(presented_b)) {
            hit = 1;
        }
    }
    hit == 1
}

/// Axum middleware: enforce `X-API-Key` on every request that flows
/// through it. Mounted on the protected sub-router (so `/health` and
/// `/metrics` bypass it by virtue of being on an unprotected router).
///
/// # Errors
///
/// Returns `ApiError::Unauthorized` if the header is missing or its
/// value is not in the allow-list.
pub async fn require_api_key(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    require_api_key_inner(&state.api_keys, req.headers().get(API_KEY_HEADER))?;
    Ok(next.run(req).await)
}

fn require_api_key_inner(
    keys: &Arc<HashSet<String>>,
    header: Option<&axum::http::HeaderValue>,
) -> Result<(), ApiError> {
    let Some(hv) = header else {
        return Err(ApiError::Unauthorized(
            "missing X-API-Key header".to_string(),
        ));
    };
    let presented = hv
        .to_str()
        .map_err(|_| ApiError::Unauthorized("invalid X-API-Key encoding".to_string()))?;
    if is_allowed(keys, presented) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized("invalid API key".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_strips_blanks_and_dupes() {
        let set = load_api_keys(" a , b , , a ,b");
        assert_eq!(set.len(), 2);
        assert!(set.contains("a"));
        assert!(set.contains("b"));
    }

    #[test]
    fn empty_input_yields_empty_set() {
        let set = load_api_keys("");
        assert!(set.is_empty());
    }

    #[test]
    fn membership_constant_time_basic() {
        let set = load_api_keys("alpha,beta");
        assert!(is_allowed(&set, "alpha"));
        assert!(is_allowed(&set, "beta"));
        assert!(!is_allowed(&set, "gamma"));
        assert!(!is_allowed(&set, "alph"));
        assert!(!is_allowed(&set, "alphax"));
    }
}
