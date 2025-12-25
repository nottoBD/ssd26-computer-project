#!/usr/bin/env bash

set -euo pipefail

# helpers
################################################################################
say() { echo -e "\033[32m$*\033[0m"; }
err() { echo -e "\033[31m$*\033[0m"; exit 1; }

script_dir=$(realpath "$(dirname "$0")")
PROJECT_ROOT=$(realpath "$script_dir/..")
cd "$PROJECT_ROOT" || err "Failed to enter $PROJECT_ROOT"

# layout variables
################################################################################
PKI_DIR="$PROJECT_ROOT/pki"
LEAFS_DIR="$PKI_DIR/leafs"
ROOTS_DIR="$PKI_DIR/roots"

mkdir -p "$LEAFS_DIR/nginx" "$LEAFS_DIR/client" "$LEAFS_DIR/server" "$LEAFS_DIR/logger" "$ROOTS_DIR"

# 1) Fresh password
################################################################################
if [[ -f .step-ca-password ]]; then
    CA_PASSWORD=$(<.step-ca-password)
else
    CA_PASSWORD=$(openssl rand -hex 32)
    echo -n "$CA_PASSWORD" > .step-ca-password
    chmod 600 .step-ca-password
fi

# 2) Launch new CA
################################################################################
docker rm -f step-ca step-ca-bootstrap 2>/dev/null || true
docker volume rm -f stepca-data 2>/dev/null || true
docker volume create stepca-data
sleep 2

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
for _ in {1..20}; do
  docker exec step-ca test -f /home/step/certs/root_ca.crt && break
  sleep 1
done

# sync password file, then persist it to .env and shred the temp file
sleep 2
docker exec step-ca sh -c "echo -n $CA_PASSWORD > /home/step/secrets/password"

docker exec step-ca chown step:step /home/step/secrets/password
docker exec step-ca chmod 600 /home/step/secrets/password

ENV_FILE="$PROJECT_ROOT/.env"; touch "$ENV_FILE"
if grep -q '^STEP_CA_PASSWORD=' "$ENV_FILE"; then
  sed -i.bak "s|^STEP_CA_PASSWORD=.*|STEP_CA_PASSWORD=$CA_PASSWORD|" "$ENV_FILE"
else
  echo "STEP_CA_PASSWORD=$CA_PASSWORD" >> "$ENV_FILE"
fi
say "STEP_CA_PASSWORD stored in $(basename "$ENV_FILE")"
shred -u .step-ca-password

# 3) Provisioner
################################################################################
docker exec step-ca step ca provisioner add healthsecure-provisioner \
  --type JWK --create --x509-max-dur 8760h --x509-default-dur 8760h \
  --password-file /home/step/secrets/password 2>/dev/null || true

docker exec step-ca kill -HUP 1

for _ in {1..10}; do
  if docker exec step-ca step ca provisioner list | grep -q "healthsecure-provisioner"; then
    break
  fi
  sleep 1
done

# 4) Leaf certs
################################################################################
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
docker exec step-ca bash -c "
  set -e
  INT=/home/step/certs/intermediate_ca.crt
  for name in nginx client server logger; do
    cat /home/step/leaf/\${name}.crt \"\$INT\" > /home/step/leaf/\${name}.fullchain.crt
  done"

docker cp step-ca:/home/step/certs/root_ca.crt         "$ROOTS_DIR/step-root.pem"
docker cp step-ca:/home/step/certs/intermediate_ca.crt "$ROOTS_DIR/intermediate_ca.crt"
ln -sf intermediate_ca.crt "$ROOTS_DIR/$(openssl x509 -noout -hash -in "$ROOTS_DIR/intermediate_ca.crt").0"
command -v c_rehash >/dev/null 2>&1 && c_rehash "$ROOTS_DIR" || openssl rehash "$ROOTS_DIR"

# 6) Copy leaf certs to host
################################################################################
for name in nginx client server logger; do
  remote_base="/home/step/leaf/${name}"
  local_dir="$LEAFS_DIR/${name}"
  docker cp step-ca:${remote_base}.crt                  "$local_dir/${name}.crt"
  docker cp step-ca:${remote_base}.fullchain.crt        "$local_dir/fullchain.crt"
  docker cp step-ca:${remote_base}.key                  "$local_dir/${name}.key"
done

CHAIN="$ROOTS_DIR/clients_ca_chain.pem"
cat "$ROOTS_DIR/step-root.pem" "$ROOTS_DIR/intermediate_ca.crt" > "$CHAIN"

cp "$ROOTS_DIR/step-root.pem" "$PROJECT_ROOT/step-root.pem"

docker rm -f step-ca step-ca-bootstrap 2>/dev/null || true

export SSL_CERT_FILE="$ROOTS_DIR/step-root.pem" # CAfile(anchor)
export SSL_CERT_DIR="$ROOTS_DIR" # CApath(c_rehash)

# fingerprints
CA_ROOT_FINGERPRINT=$(openssl x509 -in "$ROOTS_DIR/step-root.pem" -outform der | openssl dgst -sha256 | sed 's/^.* //' | tr 'A-F' 'a-f')

SERVER_CERT_PATH="$LEAFS_DIR/server/fullchain.crt"
SERVER_CERT_FINGERPRINT=$(openssl x509 -in "$SERVER_CERT_PATH" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64 -A)

say "CA root SHA-256 fingerprint:"; printf " %s\n" "$CA_ROOT_FINGERPRINT"
say "Server cert SHA-256 fingerprint:"; printf " %s\n" "$SERVER_CERT_FINGERPRINT"

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

DOCKER_SCRIPT="$PROJECT_ROOT/bash/3-run.sh"
say "PKI ready, next step:"
say "         (here) file://$DOCKER_SCRIPT"
