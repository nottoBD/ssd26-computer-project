#!/usr/bin/env bash
# Build and launch the HealthSecure stack, then perform a TLS health check.

set -euo pipefail

say() { echo -e "\033[32m$*\033[0m"; }
say_red() { echo -e "\033[31m$*\033[0m"; }
err() { echo -e "\033[31m$*\033[0m"; exit 1; }

USER_ID=$(id -un)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ROOT}/.env"
ROOTS_DIR="$ROOT/pki/roots"
P12_PASS=""
P12_BUNDLE="$ROOT/pki/leafs/browser/${USER_ID}.p12"

if docker compose version &>/dev/null; then
    COMPOSE_CMD=("docker" "compose")
    say "Using compose: docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD=("docker-compose")
    say "Using compose: docker-compose"
else
    say_red "Neither 'docker-compose' nor 'docker compose' found. Install Docker Compose v2."
fi

say "Project root: ${ROOT}"
cd "$ROOT" || say_red "Project root not found."

if [[ -f "$ENV_FILE" ]]; then
    say "Using env-file: $ENV_FILE"
    ENV_OPTS=(--env-file "$ENV_FILE")
    P12_PASS=$(grep -E '^BROWSER_P12_PASSWORD=' "$ENV_FILE" | cut -d= -f2 || true)
else
    say "No .env file found: relying on docker-compose.yml env-var"
    ENV_OPTS=()
fi

reset_builder() {
    say "Resetting builder..."
    docker buildx rm -f healthsecure healthsecure-builder 2>/dev/null || true
    docker buildx create --name healthsecure-builder --driver docker-container --use
    docker buildx inspect --bootstrap
    docker ps --filter name=buildx_
}

if ! docker buildx use healthsecure-builder 2>/dev/null; then
    say "Initializing builder..."
    reset_builder
fi

say "Stopping previous stack.."
"${COMPOSE_CMD[@]}" "${ENV_OPTS[@]}" down --remove-orphans

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

run_compose up -d --build

say "Waiting for containers to initialize..."
sleep 5

say "Inspecting self-signed root cert:"
openssl x509 -in "$ROOT/step-root.pem" -noout -text | grep -E 'Issuer:|Subject:|Self-signed'

say "Inspecting TLS handshake:"
if [[ -f "$P12_BUNDLE" && -n "${P12_PASS:-}" ]]; then
  curl -v --capath "$ROOTS_DIR" \
             --cert-type P12 --cert "${P12_BUNDLE}:${P12_PASS}" \
             https://localhost:3443/api/health/ -o /dev/null
else
  curl -v --capath "$ROOTS_DIR" \
             https://localhost:3443/api/health/ -o /dev/null
fi

printf "\n"

say "HealthSecure UI @ https://localhost:3443"
