#!/usr/bin/env bash
# Build and launch the HealthSecure stack, then perform a TLS health check.
# Requires PKI artifacts from bash/2-pki_setup.sh and a working Docker + Compose install

# Fail fast on errors and unset vars to avoid half-started stacks
set -euo pipefail

# Small log helpers to keep output readable during compose/build steps
say() { echo -e "\033[32m$*\033[0m"; }
say_red() { echo -e "\033[31m$*\033[0m"; }
err() { echo -e "\033[31m$*\033[0m"; exit 1; }

# Resolve repo paths so script works from any directory and can locate .env and PKI roots
USER_ID=$(id -un)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ROOT}/.env"
ROOTS_DIR="$ROOT/pki/roots"

# Support both Compose v2 (docker compose) and legacy docker-compose for compatibility
if docker compose version &>/dev/null; then
    COMPOSE_CMD=("docker" "compose")
    say "Using compose: docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD=("docker-compose")
    say "Using compose: docker-compose"
else
    # Without Compose we cannot start the stack, user must install Docker Compose v2
    say_red "Neither 'docker-compose' nor 'docker compose' found. Install Docker Compose v2."
fi

say "Project root: ${ROOT}"
# Ensure all relative paths in docker-compose.yml and PKI references resolve correctly
cd "$ROOT" || say_red "Project root not found."

# Prefer explicit .env so fingerprints, passwords, and pins are consistent across runs
if [[ -f "$ENV_FILE" ]]; then
    say "Using env-file: $ENV_FILE"
    ENV_OPTS=(--env-file "$ENV_FILE")
else
    say "No .env file found: relying on docker-compose.yml env-var"
    ENV_OPTS=()
fi

# Workaround for transient buildx/container driver issues by recreating the builder cleanly
reset_builder() {
    say "Resetting builder..."
    docker buildx rm -f healthsecure healthsecure-builder 2>/dev/null || true
    docker buildx create --name healthsecure-builder --driver docker-container --use
    docker buildx inspect --bootstrap
    docker ps --filter name=buildx_
}

# Ensure our expected builder exists before running compose builds
if ! docker buildx use healthsecure-builder 2>/dev/null; then
    say "Initializing builder..."
    reset_builder
fi

# Stop any existing containers to prevent port conflicts and stale state
say "Stopping previous stack.."
"${COMPOSE_CMD[@]}" "${ENV_OPTS[@]}" down --remove-orphans

# Wrapper to log compose commands and auto-recover from a known buildx "read |0: file" error
run_compose() {
    local cmd=("${COMPOSE_CMD[@]}" "${ENV_OPTS[@]}" "$@")
    say_red "Executing: ${cmd[*]}"

    local output
    if ! output=$(
        set -o pipefail
        "${cmd[@]}" 2>&1 | tee /dev/tty
    ); then
        if [[ $output == *"read |0: file"* ]]; then
            say "Builder error detected - resetting"
            reset_builder
            say "Retrying: ${cmd[*]}"
            "${cmd[@]}"
        else
            err "Command failed: ${cmd[*]}\n$output"
        fi
    fi
}

# Build images (if needed) and start services in the background
run_compose up -d --build

say "Waiting for containers to initialize..."
# Short grace period for DB migrations and nginx startup, adjust if your machine is slow
sleep 5

say "Inspecting self-signed root cert:"
# Quick sanity check that the exported root CA exists and is self-signed
openssl x509 -in "$ROOT/step-root.pem" -noout -text | grep -E 'Issuer:|Subject:|Self-signed'

say "Inspecting TLS handshake:"
# Verify TLS works end-to-end using our CApath so curl trusts the local HealthSecure PKI
curl -v --capath "$ROOTS_DIR" \
             https://localhost:3443/api/health/ -o /dev/null

printf "\n"
# Entry point through nginx, backend stays behind the reverse proxy
say "HealthSecure UI @ https://localhost:3443"
