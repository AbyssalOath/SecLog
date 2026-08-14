# --- Stage 1: build ---
# Full Rust toolchain, used only to compile. This image is large,
# but it never ships -- only its output does.
FROM rust:bookworm AS builder

WORKDIR /app

# Copy dependency manifests first, separately from source code.
# Docker caches each step; if only your .rs files change (not Cargo.toml),
# this dependency-download/compile steps gets reused from cache instead of
# re-running -- much faster rebuilds during development.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY VERSION ./VERSION

# Builds all binaties in the project (main + shipped) in release mode
# (optimized, slower to compile, much faster to run than a debug build).
RUN cargo build --release

# --- Stage 2: runtime ---
# A minimal Debian base -- no Rust toolchain, no build tools, just enough
# to run a compiled Linux binary plus a couple runtime libraries it needs.
FROM debian:bookworm-slim

# openssl/ca-certificates are commonly needed for outbound HTTPS/TLS,
# even though we don't use it directly yet -- cheap to include now.
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy ONLY the compiled binary out of the builder stage -- nothing else
# from that huge first stage makes it into this final image.
COPY --from=builder /app/target/release/seclog /app/seclog

# Also bring in the static frontend files, since our server serves them.
COPY static ./static

EXPOSE 3000

CMD ["./seclog"]
