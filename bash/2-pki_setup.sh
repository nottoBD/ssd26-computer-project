#!/usr/bin/env bash
# Bootstraps a fresh Step-CA, generates leaf certs, and exports full chains into pki/
# Updates .env with the CA root fingerprint and backend cert pin for client-side trust checks
# Safe to rerun after 1-reset.sh, not meant for production CA operations

# Hard fail on errors and unset variables to avoid half-written PKI state
set -euo pipefail

# helpers
################################################################################
# Minimal colored output helpers for progress and fatal errors
say() { echo -e "\033[32m$*\033[0m"; }
err() { echo -e "\033[31m$*\033[0m"; exit 1; }

# Resolve repo root so relative pki/ paths work regardless of current shell location
script_dir=$(realpath "$(dirname "$0")")
PROJECT_ROOT=$(realpath "$script_dir/..")
cd "$PROJECT_ROOT" || err "Failed to enter $PROJECT_ROOT"

# layout variables
################################################################################
PKI_DIR="$PROJECT_ROOT/pki"
LEAFS_DIR="$PKI_DIR/leafs"
ROOTS_DIR="$PKI_DIR/roots"

# Host-side directories where generated certs and keys are copied
mkdir -p "$LEAFS_DIR/nginx" "$LEAFS_DIR/client" "$LEAFS_DIR/server" "$LEAFS_DIR/logger" "$ROOTS_DIR"

# 1) Fresh password
################################################################################
# Reuse an existing CA password if present, otherwise generate a strong one for Step-CA init
if [[ -f .step-ca-password ]]; then
    CA_PASSWORD=$(<.step-ca-password)
else
    CA_PASSWORD=$(openssl rand -hex 32)
    echo -n "$CA_PASSWORD" > .step-ca-password
    # Restrict local temp password file since it grants CA admin capability
    chmod 600 .step-ca-password
fi

# 2) Launch new CA
################################################################################
# Ensure we start from a clean CA container and fresh persistent volume
docker rm -f step-ca step-ca-bootstrap 2>/dev/null || true
docker volume rm -f stepca-data 2>/dev/null || true
docker volume create stepca-data
sleep 2

# Initialize Step-CA with a local root + intermediate and enable ACME for later convenience
docker run -d --name step-ca \
  -v stepca-data:/home/step \
  -e DOCKER_STEPCA_INIT_NAME="HealthSecure/CA" \
  -e DOCKER_STEPCA_INIT_PASSWORD="$CA_PASSWORD" \
  -e DOCKER_STEPCA_INIT_DNS_NAMES="localhost,step-ca,healthsecure.local,nginx" \
  -e DOCKER_STEPCA_INIT_IPS="127.0.0.1" \
  -e DOCKER_STEPCA_INIT_ACME="true" \
  -e DOCKER_STEPCA_INIT_KTY="RSA" \
  -e DOCKER_STEPCA_INIT_SIZE="2048" \
  -p 9000-9001:9000-9001 \
  smallstep/step-ca:0.28.4
sleep 6

# wait for root ca
# Wait until Step-CA has produced its root cert before provisioning and issuing leaf certs
for _ in {1..20}; do
  docker exec step-ca test -f /home/step/certs/root_ca.crt && break
  sleep 1
done

# sync password file, then persist it to .env and shred the temp file
sleep 2
# Step-CA expects the password file under /home/step/secrets for provisioning operations
docker exec step-ca sh -c "echo -n $CA_PASSWORD > /home/step/secrets/password"

docker exec step-ca chown step:step /home/step/secrets/password
docker exec step-ca chmod 600 /home/step/secrets/password

# Persist CA password into .env for docker-compose services that need to talk to Step-CA
ENV_FILE="$PROJECT_ROOT/.env"; touch "$ENV_FILE"
if grep -q '^STEP_CA_PASSWORD=' "$ENV_FILE"; then
  sed -i.bak "s|^STEP_CA_PASSWORD=.*|STEP_CA_PASSWORD=$CA_PASSWORD|" "$ENV_FILE"
else
  echo "STEP_CA_PASSWORD=$CA_PASSWORD" >> "$ENV_FILE"
fi
say "STEP_CA_PASSWORD stored in $(basename "$ENV_FILE")"
# shred doesn't work on macOS
if command -v shred >/dev/null 2>&1; then
  shred -u .step-ca-password
else
  rm -f .step-ca-password
fi
# 3) Provisioner
################################################################################
# Add a dedicated JWK provisioner used to mint X.509 leaf certificates for our services
docker exec step-ca step ca provisioner add healthsecure-provisioner \
  --type JWK --create --x509-max-dur 8760h --x509-default-dur 8760h \
  --password-file /home/step/secrets/password 2>/dev/null || true

# Reload Step-CA config so the new provisioner is available immediately
docker exec step-ca kill -HUP 1

# Best-effort check that the provisioner is registered before issuing certificates
for _ in {1..10}; do
  if docker exec step-ca step ca provisioner list | grep -q "healthsecure-provisioner"; then
    break
  fi
  sleep 1
done

# 4) Leaf certs
################################################################################
# Issue one leaf cert per service with the expected SANs so nginx and internal services validate cleanly
docker exec step-ca bash -c "
  set -e
  mkdir -p /home/step/leaf
  export STEP_PASSWORD_FILE=/home/step/secrets/password

  step ca certificate healthsecure.local \
    /home/step/leaf/nginx.crt \
    /home/step/leaf/nginx.key \
    --provisioner healthsecure-provisioner --password-file \$STEP_PASSWORD_FILE \
    --san healthsecure.local \
    --san localhost --san 127.0.0.1 --san ::1 \
    --san nginx \
    --not-after 8760h \
    --kty RSA --size 2048

  step ca certificate client.healthsecure.local \
    /home/step/leaf/client.crt \
    /home/step/leaf/client.key \
    --provisioner healthsecure-provisioner --password-file \$STEP_PASSWORD_FILE \
    --san client --san client.healthsecure.local \
    --san localhost --san 127.0.0.1 --san ::1 \
    --not-after 8760h \
    --kty RSA --size 2048

  step ca certificate server.healthsecure.local \
    /home/step/leaf/server.crt \
    /home/step/leaf/server.key \
    --provisioner healthsecure-provisioner --password-file \$STEP_PASSWORD_FILE \
    --san server --san server.healthsecure.local \
    --san localhost --san 127.0.0.1 --san ::1 \
    --not-after 8760h \
    --kty RSA --size 2048

  step ca certificate logger.healthsecure.local \
    /home/step/leaf/logger.crt \
    /home/step/leaf/logger.key \
    --provisioner healthsecure-provisioner --password-file \$STEP_PASSWORD_FILE \
    --san logger --san logger.healthsecure.local \
    --san localhost --san 127.0.0.1 --san ::1 \
    --not-after 8760h \
    --kty RSA --size 2048

"

# 5) Build full chains
################################################################################
# Build fullchain files (leaf + intermediate) for services that expect chain bundles
docker exec step-ca bash -c "
  set -e
  INT=/home/step/certs/intermediate_ca.crt
  for name in nginx client server logger; do
    cat /home/step/leaf/\${name}.crt \"\$INT\" > /home/step/leaf/\${name}.fullchain.crt
  done"

docker cp step-ca:/home/step/certs/root_ca.crt         "$ROOTS_DIR/step-root.pem"
docker cp step-ca:/home/step/certs/intermediate_ca.crt "$ROOTS_DIR/intermediate_ca.crt"
# Create hashed CApath symlink so OpenSSL can discover the intermediate via CAPATH
ln -sf intermediate_ca.crt "$ROOTS_DIR/$(openssl x509 -noout -hash -in "$ROOTS_DIR/intermediate_ca.crt").0"
# conv full CA chain for verify bundles
docker exec step-ca bash -c "cat /home/step/certs/intermediate_ca.crt /home/step/certs/root_ca.crt > /home/step/certs/ca_chain.crt"
docker cp step-ca:/home/step/certs/ca_chain.crt "$ROOTS_DIR/ca_chain.crt"
# conv rehash
command -v c_rehash >/dev/null 2>&1 && c_rehash "$ROOTS_DIR" || openssl rehash "$ROOTS_DIR"

# 6) Copy leaf certs to host
################################################################################
# Export leaf certs and keys from the CA container into tracked pki/ folders for local services
for name in nginx client server logger; do
  remote_base="/home/step/leaf/${name}"
  local_dir="$LEAFS_DIR/${name}"
  docker cp step-ca:${remote_base}.crt                  "$local_dir/${name}.crt"
  docker cp step-ca:${remote_base}.fullchain.crt        "$local_dir/fullchain.crt"
  docker cp step-ca:${remote_base}.key                  "$local_dir/${name}.key"
done

# Convenience bundle for clients that want a single PEM containing root + intermediate
CHAIN="$ROOTS_DIR/clients_ca_chain.pem"
cat "$ROOTS_DIR/step-root.pem" "$ROOTS_DIR/intermediate_ca.crt" > "$CHAIN"

cp "$ROOTS_DIR/step-root.pem" "$PROJECT_ROOT/step-root.pem"

# CA container is only needed for issuance during setup, runtime services use the exported artifacts
docker rm -f step-ca step-ca-bootstrap 2>/dev/null || true

# Pin OpenSSL trust to our generated root so local verification commands behave consistently
export SSL_CERT_FILE="$ROOTS_DIR/step-root.pem" # CAfile(anchor)
export SSL_CERT_DIR="$ROOTS_DIR" # CApath(c_rehash)

# fingerprints
# Compute fingerprints used for trust pinning in the frontend and backend configuration
CA_ROOT_FINGERPRINT=$(openssl x509 -in "$ROOTS_DIR/step-root.pem" -outform der | openssl dgst -sha256 | sed 's/^.* //' | tr 'A-F' 'a-f')

SERVER_CERT_PATH="$LEAFS_DIR/server/fullchain.crt"
# SPKI pin (hash of public key) is stable across re-issuance as long as keypair stays the same
SERVER_CERT_FINGERPRINT=$(openssl x509 -in "$SERVER_CERT_PATH" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64 -A)

say "CA root SHA-256 fingerprint:"; printf " %s\n" "$CA_ROOT_FINGERPRINT"
say "Server cert SHA-256 fingerprint:"; printf " %s\n" "$SERVER_CERT_FINGERPRINT"

# Write public pins into .env so the client can verify it is talking to the expected backend identity
# Set in .env
if grep -q '^PUBLIC_CA_ROOT_FINGERPRINT=' "$ENV_FILE"; then
  sed -i.bak "s|^PUBLIC_CA_ROOT_FINGERPRINT=.*|PUBLIC_CA_ROOT_FINGERPRINT=$CA_ROOT_FINGERPRINT|" "$ENV_FILE"
else
  echo "PUBLIC_CA_ROOT_FINGERPRINT=$CA_ROOT_FINGERPRINT" >> "$ENV_FILE"
fi

if grep -q '^PUBLIC_BACKEND_CERT_FINGERPRINT=' "$ENV_FILE"; then
  sed -i.bak "s|^PUBLIC_BACKEND_CERT_FINGERPRINT=.*|PUBLIC_BACKEND_CERT_FINGERPRINT=$SERVER_CERT_FINGERPRINT|" "$ENV_FILE"
else
  echo "PUBLIC_BACKEND_CERT_FINGERPRINT=$SERVER_CERT_FINGERPRINT" >> "$ENV_FILE"
fi

printf "\n"

# Next step starts the full docker-compose stack using the generated PKI artifacts
DOCKER_SCRIPT="$PROJECT_ROOT/bash/3-run.sh"
say "PKI ready, next step:"
say "         (here) file://$DOCKER_SCRIPT"
