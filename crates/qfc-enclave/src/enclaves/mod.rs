//! Concrete `Enclave` impls.
//!
//! - `MockEnclave` (M1): in-process, no real isolation.
//! - `NitroEnclave` (M3 skeleton): host-side vsock client. Actual NSM calls
//!   live behind the `nitro` feature; default build returns
//!   `EnclaveError::NotImplemented` so non-Linux dev can still build.

mod mock;
mod nitro;

pub use mock::MockEnclave;
pub use nitro::{
    NitroEnclave, NitroEnclaveBuilder, NitroGenerateRequest, NitroSignRequest, NitroWireRequest,
    NitroWireResponse, VsockAddr, NITRO_DEFAULT_PORT, VMADDR_CID_PARENT,
};
