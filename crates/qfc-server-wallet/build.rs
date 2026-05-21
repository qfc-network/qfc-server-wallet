//! Build script: compile the gRPC proto files via `tonic-build`.
//!
//! Generates server stubs and client stubs. Server stubs back the
//! `grpc/wallet.rs` + `grpc/approver.rs` impls; client stubs are exposed
//! purely so the in-process integration tests under `tests/grpc_integration.rs`
//! can fire RPCs without hand-rolling a transport. The public stand-alone
//! gRPC client SDK is a separate deliverable (see `docs/grpc-decisions.md`
//! D47); these stubs are internal-use.
//!
//! Generated code lands in `OUT_DIR` and is pulled in by `src/grpc/mod.rs`
//! via `tonic::include_proto!`. Also emits a `FileDescriptorSet` so the
//! `tonic-reflection` server can expose schema info to `grpcurl`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("qfc_descriptor.bin");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(
            &[
                "proto/common.proto",
                "proto/wallet.proto",
                "proto/approver.proto",
            ],
            &["proto/"],
        )?;

    println!("cargo:rerun-if-changed=proto/common.proto");
    println!("cargo:rerun-if-changed=proto/wallet.proto");
    println!("cargo:rerun-if-changed=proto/approver.proto");
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
