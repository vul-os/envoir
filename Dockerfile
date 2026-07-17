# envoir-gateway — personal DMTAP <-> legacy SMTP bridge.
#
# This is the standalone repo: dmtap-core / dmtap-mail are pulled as git-tag dependencies
# (see Cargo.toml), not path deps, so the build context is just this repo root:
#
#     docker build -t envoir-gateway .
#
# (docker-compose.yml sets `context: .` so `docker compose up` does this for you.)

# ---- builder ----------------------------------------------------------------------------
FROM rust:1-slim-bookworm AS builder
# git + CA roots so cargo can fetch the git-tag dmtap-core / dmtap-mail deps over https.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Fetch git deps via the git CLI (plain https; the monorepo is public).
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
WORKDIR /src
# Copy the crate (sources + Cargo.lock for a reproducible build).
COPY . .
RUN cargo build --release --locked --bin envoir-gateway

# ---- runtime ----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
# ca-certificates: for outbound SMTP-over-STARTTLS trust anchors (webpki uses the system roots).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user. NOTE: binding port 25 as non-root needs either a published
# host port mapping (compose maps 25->2525) or `CAP_NET_BIND_SERVICE`. See README.
RUN useradd --system --home /gateway --shell /usr/sbin/nologin gateway
WORKDIR /gateway

COPY --from=builder /src/target/release/envoir-gateway /usr/local/bin/envoir-gateway
# Config + directory are mounted at runtime (see docker-compose.yml). /gateway/config is the
# expected mount point for personal.toml and recipients.directory.
USER gateway

# The daemon is stateless; it holds no queue and no mailbox — restart it freely.
ENTRYPOINT ["envoir-gateway"]
CMD ["personal", "/gateway/config/personal.toml"]
