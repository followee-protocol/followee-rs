# Reproducible container build for the Followee demonstration handle
# authority (Milestone 5). Build context is the repository root (see the
# root .dockerignore for the bounded context and railway.json for the
# Railway wiring).
#
# The image contains only public material: the compiled binary, the
# reviewed public authority configuration, and the public signed record
# bytes. No private key, credential, or mutable state exists in the
# image, and the authority itself is immutable and needs no database.

# --- Build stage: the repository's pinned toolchain, locked build -------
# The fully qualified tag matches rust-toolchain.toml; the rustup shim
# inside the image resolves the same version, so no toolchain drift is
# possible. Both FROM references are additionally pinned by immutable
# multi-platform manifest-list digest (resolved from the Docker registry
# on 2026-08-13); the readable tag documents intent, the digest governs.
FROM docker.io/library/rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin followee

# --- Runtime stage: minimal, non-root, public data only -----------------
FROM docker.io/library/debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS runtime
RUN useradd --system --uid 10001 --home /app --shell /usr/sbin/nologin followee
WORKDIR /app
COPY --from=build /src/target/release/followee /usr/local/bin/followee
# The reviewed public configuration and the public signed record it
# references (paths inside the configuration are relative to /app).
COPY demo/public-authority/railway/authority.json /app/authority.json
COPY demo/public-authority/railway/alice.cose /app/alice.cose
COPY demo/public-authority/railway/entrypoint.sh /usr/local/bin/followee-entrypoint
RUN chmod 0555 /usr/local/bin/followee-entrypoint && chown -R followee /app
USER followee
# Railway injects PORT; the entrypoint binds 0.0.0.0:$PORT and derives
# the public base URI from FOLLOWEE_BASE_URI or RAILWAY_PUBLIC_DOMAIN.
ENTRYPOINT ["/usr/local/bin/followee-entrypoint"]
