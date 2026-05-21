//! Axum router that receives `POST /` webhooks from the server, verifies
//! the `X-QFC-Signature` HMAC, parses the body, and hands it to the
//! `Processor`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::processor::Processor;
use crate::wire::ApprovalRequestWire;

/// HTTP header carrying the HMAC. Mirrors
/// `qfc_quorum::WebhookSignatureHeader::name()` exactly — kept as a
/// local constant so the client compiles even if a future server-side
/// rename happens (the cross-crate integration test catches drift).
pub const WEBHOOK_SIGNATURE_HEADER: &str = "x-qfc-signature";

/// Shared state for the webhook router.
#[derive(Clone)]
pub struct AppState {
    /// Shared HMAC secret. Must equal what was registered with the server.
    pub hmac_secret: Arc<Vec<u8>>,
    /// Per-request processor.
    pub processor: Processor,
}

/// Build the axum router. Mounts `POST /` as the single webhook entry
/// point — keeps the receiver dead simple.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", post(handle_webhook))
        .with_state(state)
}

/// Why a webhook was rejected. Translated into an HTTP status by axum.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// Missing `X-QFC-Signature` header.
    #[error("missing X-QFC-Signature header")]
    MissingSignature,
    /// Header malformed (not hex, wrong length).
    #[error("malformed X-QFC-Signature header: {0}")]
    MalformedSignature(String),
    /// HMAC mismatch.
    #[error("X-QFC-Signature mismatch")]
    BadSignature,
    /// Body wasn't valid JSON / wasn't the expected shape.
    #[error("invalid body: {0}")]
    BadBody(String),
    /// Processor failed.
    #[error("processor failed: {0}")]
    Processor(String),
}

impl IntoResponse for WebhookError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match &self {
            Self::MissingSignature | Self::MalformedSignature(_) | Self::BadSignature => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            Self::BadBody(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::Processor(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        (status, msg).into_response()
    }
}

async fn handle_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, WebhookError> {
    // 1. Verify HMAC over the raw body bytes (must happen before any
    //    serde-deserialize trust, so a hostile body can't tamper with
    //    the verification path).
    verify_hmac(&headers, &state.hmac_secret, &body)?;

    // 2. Parse
    let req: ApprovalRequestWire =
        serde_json::from_slice(&body).map_err(|e| WebhookError::BadBody(format!("json: {e}")))?;

    // 3. Process. Note: we await here so the HTTP response back to the
    //    server reflects whether we accepted the webhook — but the
    //    POST-to-server happens inside `process`, not async-spawned.
    //    The server doesn't actually wait for this (it just wants the
    //    202-ish ack); a future iteration can move processing onto a
    //    background tokio task if processing time grows.
    state
        .processor
        .process(&req)
        .await
        .map_err(|e| WebhookError::Processor(e.to_string()))?;

    Ok(StatusCode::OK)
}

/// Verify the `X-QFC-Signature` header over `body` using `secret`.
///
/// Constant-time comparison via `subtle::ConstantTimeEq` to avoid
/// length / byte-position leaks.
///
/// # Errors
///
/// `WebhookError::MissingSignature` if the header is absent,
/// `WebhookError::MalformedSignature` if it's not 64 hex chars,
/// `WebhookError::BadSignature` on mismatch.
///
/// # Panics
///
/// Never in practice — `Hmac::<Sha256>::new_from_slice` accepts any
/// key length for SHA-256 and the `expect` is defensive.
pub fn verify_hmac(headers: &HeaderMap, secret: &[u8], body: &[u8]) -> Result<(), WebhookError> {
    let header = headers
        .get(WEBHOOK_SIGNATURE_HEADER)
        .ok_or(WebhookError::MissingSignature)?;
    let header_str = header
        .to_str()
        .map_err(|e| WebhookError::MalformedSignature(e.to_string()))?;
    let provided = hex::decode(header_str)
        .map_err(|e| WebhookError::MalformedSignature(format!("hex: {e}")))?;
    if provided.len() != 32 {
        return Err(WebhookError::MalformedSignature(format!(
            "expected 32 raw bytes, got {}",
            provided.len()
        )));
    }
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).expect("hmac-sha256 accepts any key length");
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    if expected.ct_eq(&provided).into() {
        Ok(())
    } else {
        Err(WebhookError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    fn headers_with_sig(sig: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static(WEBHOOK_SIGNATURE_HEADER),
            HeaderValue::from_str(sig).unwrap(),
        );
        h
    }

    #[test]
    fn accepts_correct_hmac() {
        let secret = b"sssh";
        let body = br#"{"any":"body"}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());
        let headers = headers_with_sig(&sig);
        assert!(verify_hmac(&headers, secret, body).is_ok());
    }

    #[test]
    fn rejects_wrong_hmac() {
        let secret = b"sssh";
        let body = br#"{"any":"body"}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(b"DIFFERENT").unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());
        let headers = headers_with_sig(&sig);
        let err = verify_hmac(&headers, secret, body).unwrap_err();
        assert!(matches!(err, WebhookError::BadSignature));
    }

    #[test]
    fn rejects_missing_header() {
        let secret = b"sssh";
        let body = b"";
        let headers = HeaderMap::new();
        let err = verify_hmac(&headers, secret, body).unwrap_err();
        assert!(matches!(err, WebhookError::MissingSignature));
    }

    #[test]
    fn rejects_malformed_header_hex() {
        let secret = b"sssh";
        let body = b"";
        let headers = headers_with_sig("zzznotvalidhex");
        let err = verify_hmac(&headers, secret, body).unwrap_err();
        assert!(matches!(err, WebhookError::MalformedSignature(_)));
    }

    #[test]
    fn rejects_malformed_header_length() {
        let secret = b"sssh";
        let body = b"";
        // 30 bytes of hex (60 chars) — valid hex but wrong byte length.
        let headers = headers_with_sig(&"aa".repeat(30));
        let err = verify_hmac(&headers, secret, body).unwrap_err();
        assert!(matches!(err, WebhookError::MalformedSignature(_)));
    }
}
