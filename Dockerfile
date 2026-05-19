# syntax=docker/dockerfile:1.7
#
# qfc-server-wallet Dockerfile — multi-stage build with cargo-chef
# dependency caching, builds the workspace, ships a minimal distroless
# runtime image containing only the binary.
#
# Base image pinning policy:
# We use named tags (`:latest-rust-1.88`, `:bookworm-slim`, `:nonroot`) at
# the moment so that the image set tracks routine security patches. Once
# M3 reaches "release-tier", every base image will be pinned by `@sha256:`
# digest with renovate-style automation tracking upgrades. For now the
# build is reproducible across a single checkout; downstream operators
# who need stricter reproducibility should `docker pull && docker image
# inspect --format '{{.Id}}'` and pin themselves.

# -------------------------------------------------------------------
# Stage 1: cargo-chef recipe planner
# -------------------------------------------------------------------
FROM lukemathwalker/cargo-chef:latest-rust-1.88-bookworm AS chef
WORKDIR /build

FROM chef AS planner
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo chef prepare --recipe-path recipe.json

# -------------------------------------------------------------------
# Stage 2: cargo-chef builder — caches dependency layer
# -------------------------------------------------------------------
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
# Build only deps for cache layer
RUN cargo chef cook --release --recipe-path recipe.json
# Now copy the actual sources and compile the binary
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --release --bin qfc-server-wallet \
    && strip target/release/qfc-server-wallet || true

# -------------------------------------------------------------------
# Stage 3: distroless runtime
# -------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
WORKDIR /app
COPY --from=builder /build/target/release/qfc-server-wallet /app/qfc-server-wallet

# 8080 = HTTP API, 9090 = Prometheus scrape endpoint
EXPOSE 8080 9090

USER nonroot:nonroot
ENTRYPOINT ["/app/qfc-server-wallet"]
