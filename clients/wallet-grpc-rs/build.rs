//! Build script: compile the gRPC proto files via `tonic-build`.
//!
//! Generates client stubs (and server stubs — the dev-dep integration
//! tests use the in-tree wallet crate's stubs, not these, but emitting
//! both keeps the generated code symmetric with the server crate). The
//! protos under `proto/` are a synced copy of
//! `crates/qfc-server-wallet/proto/` — see `tools/sync-protos.sh` and
//! `docs/clients-decisions.md` D55 for why a copy instead of a symlink.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
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
