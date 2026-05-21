//! Typed error type returned by every SDK method.
//!
//! Wraps the common `tonic::Status` codes into named variants
//! (`Unauthenticated`, `NotFound`, `AlreadyExists`, …) so callers can
//! `match` without poking at `status.code()`. Anything we don't recognise
//! falls through to `Rpc(Status)` so no information is lost.
//!
//! See `docs/clients-decisions.md` D58 for the rationale.

use thiserror::Error;

/// The single error type returned by all of the SDK's async methods.
#[derive(Debug, Error)]
pub enum SdkError {
    /// The underlying transport could not be established or was lost
    /// mid-call. Maps from `tonic::transport::Error`.
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    /// The request was malformed before it could be sent (bad ULID,
    /// invalid hex, etc).
    #[error("bad input: {0}")]
    BadInput(String),

    /// The server returned `UNAUTHENTICATED` — usually a missing or
    /// wrong `x-api-key`.
    #[error("unauthenticated: {0}")]
    Unauthenticated(String),

    /// The server returned `PERMISSION_DENIED` — the API key is valid
    /// but the policy rejected the operation.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// The server returned `NOT_FOUND` — wallet, approver, set, or
    /// request id does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// The server returned `ALREADY_EXISTS` — usually a duplicate
    /// approval submission or wallet creation conflict.
    #[error("already exists: {0}")]
    AlreadyExists(String),

    /// The server returned `INVALID_ARGUMENT` — the server-side
    /// validators rejected the request shape (length, range, missing
    /// required field, …).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// The server returned `FAILED_PRECONDITION` — typically a signature
    /// / freshness / binding check rejected the payload.
    #[error("failed precondition: {0}")]
    FailedPrecondition(String),

    /// The server returned `ABORTED` — quorum collection or registry
    /// state-transition failed.
    #[error("aborted: {0}")]
    Aborted(String),

    /// The server returned `INTERNAL` — backend failure.
    #[error("internal: {0}")]
    Internal(String),

    /// Catch-all for any tonic status code we don't translate explicitly
    /// (the `Status` is preserved so callers can still inspect it).
    #[error("rpc: {0}")]
    Rpc(tonic::Status),
}

impl From<tonic::Status> for SdkError {
    fn from(s: tonic::Status) -> Self {
        // Match on the well-known codes from the server's mapping
        // (see crates/qfc-server-wallet/src/grpc/convert.rs::map_service_error).
        // Anything else falls through to Rpc(Status) so we never lose info.
        let msg = s.message().to_string();
        match s.code() {
            tonic::Code::Unauthenticated => Self::Unauthenticated(msg),
            tonic::Code::PermissionDenied => Self::PermissionDenied(msg),
            tonic::Code::NotFound => Self::NotFound(msg),
            tonic::Code::AlreadyExists => Self::AlreadyExists(msg),
            tonic::Code::InvalidArgument => Self::InvalidArgument(msg),
            tonic::Code::FailedPrecondition => Self::FailedPrecondition(msg),
            tonic::Code::Aborted => Self::Aborted(msg),
            tonic::Code::Internal => Self::Internal(msg),
            _ => Self::Rpc(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Status;

    #[test]
    fn maps_unauthenticated() {
        let s = Status::unauthenticated("no key");
        match SdkError::from(s) {
            SdkError::Unauthenticated(m) => assert_eq!(m, "no key"),
            e => panic!("wrong variant: {e:?}"),
        }
    }

    #[test]
    fn maps_not_found() {
        let s = Status::not_found("wallet x");
        assert!(matches!(SdkError::from(s), SdkError::NotFound(_)));
    }

    #[test]
    fn falls_through_to_rpc() {
        // Cancelled isn't mapped explicitly — should land in Rpc(_).
        let s = Status::cancelled("nope");
        assert!(matches!(SdkError::from(s), SdkError::Rpc(_)));
    }
}
