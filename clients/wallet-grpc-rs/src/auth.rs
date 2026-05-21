//! Client-side `x-api-key` metadata interceptor.
//!
//! Mirror of the server-side `qfc_server_wallet::grpc::auth::ApiKeyInterceptor`.
//! Tonic's `Channel` accepts an interceptor that runs on every outgoing
//! request — the interceptor here injects the operator-supplied API key
//! into the `x-api-key` metadata key.
//!
//! Missing keys are not a client-side error: we let the server reject
//! the request with `UNAUTHENTICATED` so the behaviour is symmetrical
//! with the HTTP middleware story (the operator can still build a
//! client without a key and have RPCs fail loudly, which is the right
//! debug experience).

use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::{Request, Status};

/// Metadata key the server's `ApiKeyInterceptor` reads.
pub const API_KEY_HEADER: &str = "x-api-key";

/// Tonic interceptor that injects `x-api-key: <key>` on every outgoing RPC.
///
/// Cheap to clone (`String` inside an `Arc` would be overkill — the
/// interceptor is stored per-channel and never shared across threads in
/// practice; tonic's `InterceptedService` wants `Interceptor + Clone`).
#[derive(Clone, Debug)]
pub struct ApiKeyInterceptor {
    key: String,
}

impl ApiKeyInterceptor {
    /// Build an interceptor that injects `key` on every outgoing request.
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }

    /// Return the configured key. Useful for debugging / testing only.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }
}

impl Interceptor for ApiKeyInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let value = MetadataValue::try_from(&self.key).map_err(|_| {
            Status::invalid_argument("api_key contains characters invalid for HTTP/2 metadata")
        })?;
        request.metadata_mut().insert(API_KEY_HEADER, value);
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_metadata() {
        let mut i = ApiKeyInterceptor::new("test-key");
        let req = i.call(Request::new(())).unwrap();
        let v = req.metadata().get(API_KEY_HEADER).unwrap();
        assert_eq!(v.to_str().unwrap(), "test-key");
    }

    #[test]
    fn rejects_invalid_chars() {
        // newline isn't a valid HTTP/2 metadata-value byte.
        let mut i = ApiKeyInterceptor::new("bad\nkey");
        let err = i.call(Request::new(())).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
