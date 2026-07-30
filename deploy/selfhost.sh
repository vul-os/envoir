#!/usr/bin/env bash
# Envoir self-host — one-command bring-up wrapper around docker compose.
#
# What this does (nothing more): pick a docker compose invocation, make sure deploy/.env exists
# (copying deploy/.env.example on first run), build the node image from the real workspace, and
# start it in the background. It does not touch anything outside deploy/. The legacy gateway is
# NOT part of this stack — it moved to the separate Ephor repo (github.com/vul-os/ephor); see
# deploy/README.md if you want to run one alongside this.
#
# Usage:
#   deploy/selfhost.sh up       # build + start (default)
#   deploy/selfhost.sh down     # stop + remove containers (keeps the node-data volume)
#   deploy/selfhost.sh logs     # follow logs
#   deploy/selfhost.sh ps       # show status
#
# Read deploy/README.md first — several pieces of this stack are honestly-labelled demo/seam
# behavior (pre-alpha), not hardened self-host infrastructure.

set -euo pipefail

# Resolve paths relative to this script, not the caller's cwd.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
ENV_FILE="$SCRIPT_DIR/.env"
ENV_EXAMPLE="$SCRIPT_DIR/.env.example"

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is not installed / not on PATH. See deploy/README.md prerequisites." >&2
    exit 1
fi

# Prefer the `docker compose` plugin (v2); fall back to the standalone `docker-compose` (v1).
if docker compose version >/dev/null 2>&1; then
    compose() { docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
    compose() { docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }
else
    echo "error: neither 'docker compose' (plugin) nor 'docker-compose' (standalone) is available." >&2
    exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    echo "wrote $ENV_FILE from .env.example (node-only defaults) — edit it, then re-run." >&2
fi

mkdir -p "$SCRIPT_DIR/certs"

cmd="${1:-up}"
case "$cmd" in
    up)
        compose build
        compose up -d
        echo
        echo "Started. Node mesh transport listening on \${NODE_MESH_PORT:-4600} (host)."
        echo "No legacy gateway is built/run by this stack — see deploy/README.md if you want one"
        echo "(built separately from https://github.com/vul-os/ephor)."
        echo "First time only: create the node's identity keystore with"
        echo "  docker compose -f deploy/docker-compose.yml run --rm node init"
        echo "See deploy/README.md for the full rundown."
        echo
        echo "  $0 logs   # follow logs"
        echo "  $0 ps     # status"
        echo "  $0 down   # stop"
        ;;
    down)
        compose down
        ;;
    logs)
        compose logs -f
        ;;
    ps)
        compose ps
        ;;
    *)
        echo "usage: $0 {up|down|logs|ps}" >&2
        exit 1
        ;;
esac
