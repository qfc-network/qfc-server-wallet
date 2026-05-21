//! `x-api-key` metadata interceptor for the gRPC surface.
//!
//! Reuses the constant-time membership check from `api::auth` (the HTTP
//! middleware) so HTTP + gRPC accept exactly the same set of keys.
//! On a missing or invalid key the interceptor returns
//! `tonic::Status::unauthenticated`.
#![allow(clippy::result_large_err)] // tonic::Status is intrinsically ~176B

use std::collections::HashSet;
use std::sync::Arc;

use tonic::metadata::MetadataMap;
use tonic::service::Interceptor;
use tonic::{Request, Status};

use crate::api::auth::{is_allowed, API_KEY_HEADER};

/// Tonic interceptor that enforces `x-api-key` on every RPC.
///
/// Cheap to clone (`Arc<HashSet<String>>` inside) so the same instance
/// can be reused across `InterceptedService` wrappers.
#[derive(Clone)]
pub struct ApiKeyInterceptor {
    keys: Arc<HashSet<String>>,
}

impl ApiKeyInterceptor {
    /// Build an interceptor over the supplied allow-list.
    #[must_use]
    pub fn new(keys: Arc<HashSet<String>>) -> Self {
        Self { keys }
    }

    /// Inspect a metadata map for `x-api-key` and validate it.
    ///
    /// Pulled out as a free function so the test in `tests/grpc_integration.rs`
    /// can drive it directly without going through the `Interceptor` trait.
    pub fn check(&self, metadata: &MetadataMap) -> Result<(), Status> {
        let Some(hv) = metadata.get(API_KEY_HEADER) else {
            return Err(Status::unauthenticated("missing x-api-key metadata"));
        };
        let presented = hv
            .to_str()
            .map_err(|_| Status::unauthenticated("invalid x-api-key encoding"))?;
        if is_allowed(&self.keys, presented) {
            Ok(())
        } else {
            Err(Status::unauthenticated("invalid x-api-key"))
        }
    }
}

impl Interceptor for ApiKeyInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        self.check(request.metadata())?;
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::MetadataValue;

    fn keys(values: &[&str]) -> Arc<HashSet<String>> {
        Arc::new(values.iter().map(|s| (*s).to_string()).collect())
    }

    #[test]
    fn rejects_missing_metadata() {
        let i = ApiKeyInterceptor::new(keys(&["k1"]));
        let req: Request<()> = Request::new(());
        let err = i.check(req.metadata()).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn rejects_wrong_key() {
        let i = ApiKeyInterceptor::new(keys(&["k1"]));
        let mut req: Request<()> = Request::new(());
        req.metadata_mut()
            .insert(API_KEY_HEADER, MetadataValue::from_static("not-k1"));
        let err = i.check(req.metadata()).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn accepts_valid_key() {
        let i = ApiKeyInterceptor::new(keys(&["k1", "k2"]));
        let mut req: Request<()> = Request::new(());
        req.metadata_mut()
            .insert(API_KEY_HEADER, MetadataValue::from_static("k2"));
        assert!(i.check(req.metadata()).is_ok());
    }
}
