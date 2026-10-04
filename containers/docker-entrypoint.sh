#!/bin/bash
set -e

# ---------------------------------------------------------------------------
# Optional UID/GID remapping
# ---------------------------------------------------------------------------
if [ -n "${STRIX_HOST_UID:-}" ] && \
   [ "${STRIX_HOST_UID}" != "0" ] && \
   [ "${STRIX_HOST_UID}" != "$(id -u)" ]; then

  exec sudo -E -- bash -c '
    set -e

    gid="${STRIX_HOST_GID:-$STRIX_HOST_UID}"
    old_uid="$1"
    old_gid="$2"
    export PATH="$3"
    shift 3

    sed -i "s|^pentester:x:${old_uid}:${old_gid}:|pentester:x:${STRIX_HOST_UID}:${gid}:|" /etc/passwd
    sed -i "s|^pentester:x:${old_gid}:|pentester:x:${gid}:|" /etc/group

    chown -R "${STRIX_HOST_UID}:${gid}" /home/pentester /app/certs
    chown "${STRIX_HOST_UID}:${gid}" /workspace

    exec setpriv \
      --reuid "${STRIX_HOST_UID}" \
      --regid "${gid}" \
      --init-groups \
      "$0" "$@"

  ' "$0" "$(id -u)" "$(id -g)" "$PATH" "$@"
fi


# ---------------------------------------------------------------------------
# Caido configuration
# ---------------------------------------------------------------------------
CAIDO_PORT=48080
CAIDO_LOG="/tmp/caido_startup.log"


# ---------------------------------------------------------------------------
# Verify CA certificate
# ---------------------------------------------------------------------------
if [ ! -f /app/certs/ca.p12 ]; then
  echo "ERROR: CA certificate file /app/certs/ca.p12 not found."
  exit 1
fi


# ---------------------------------------------------------------------------
# Caido Host allowlist
# ---------------------------------------------------------------------------
CAIDO_UI_DOMAIN_ARGS=()

if [ -n "${STRIX_CAIDO_ALLOWED_DOMAINS:-}" ]; then
  IFS=',' read -ra _caido_domains <<< "${STRIX_CAIDO_ALLOWED_DOMAINS}"

  for _d in "${_caido_domains[@]}"; do
    [ -n "$_d" ] && CAIDO_UI_DOMAIN_ARGS+=(--ui-domain "$_d")
  done
fi


# ---------------------------------------------------------------------------
# Start Caido
# ---------------------------------------------------------------------------
echo "Starting Caido..."

caido-cli \
  --listen 0.0.0.0:${CAIDO_PORT} \
  --allow-guests \
  --no-logging \
  --no-open \
  "${CAIDO_UI_DOMAIN_ARGS[@]}" \
  --import-ca-cert /app/certs/ca.p12 \
  --import-ca-cert-pass "" \
  > "$CAIDO_LOG" 2>&1 &

CAIDO_PID=$!

echo "Started Caido with PID $CAIDO_PID on port $CAIDO_PORT"


# ---------------------------------------------------------------------------
# Wait for Caido API
# ---------------------------------------------------------------------------
echo "Waiting for Caido API to be ready..."

CAIDO_READY=false

for i in {1..30}; do

  if ! kill -0 "$CAIDO_PID" 2>/dev/null; then
    echo "ERROR: Caido process died while waiting for API."
    echo "Iteration: $i"
    echo "=== Caido log ==="
    cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
    exit 1
  fi

  HTTP_CODE=$(
    curl \
      -s \
      -o /dev/null \
      -w "%{http_code}" \
      "http://127.0.0.1:${CAIDO_PORT}/graphql/" \
      || true
  )

  if echo "$HTTP_CODE" | grep -qE "^(200|400)$"; then
    echo "Caido API is ready (attempt $i)."
    CAIDO_READY=true
    break
  fi

  sleep 1
done


if [ "$CAIDO_READY" = false ]; then
  echo "ERROR: Caido API did not become ready within 30 seconds."
  echo "Caido process status:"

  if kill -0 "$CAIDO_PID" 2>/dev/null; then
    echo "running"
  else
    echo "dead"
  fi

  echo "=== Caido log ==="
  cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"

  exit 1
fi


sleep 2


echo "Caido is up — host bootstraps the guest token + project via the Python SDK."


# ---------------------------------------------------------------------------
# Render-safe proxy configuration
#
# IMPORTANT:
# Do NOT use sudo here.
#
# Render containers can run with the "no new privileges" security flag,
# which prevents sudo from elevating privileges at runtime.
#
# Exporting the variables directly affects the current entrypoint process
# and every child process started from it.
# ---------------------------------------------------------------------------
echo "Configuring proxy settings..."

export http_proxy="http://127.0.0.1:${CAIDO_PORT}"
export https_proxy="http://127.0.0.1:${CAIDO_PORT}"

export HTTP_PROXY="http://127.0.0.1:${CAIDO_PORT}"
export HTTPS_PROXY="http://127.0.0.1:${CAIDO_PORT}"

export ALL_PROXY="http://127.0.0.1:${CAIDO_PORT}"

export NO_PROXY="localhost,127.0.0.1"

export REQUESTS_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
export SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"

echo "HTTP proxy:  ${http_proxy}"
echo "HTTPS proxy: ${https_proxy}"
echo "NO_PROXY:    ${NO_PROXY}"

echo "Proxy configuration complete."


# ---------------------------------------------------------------------------
# Browser CA trust store
#
# No sudo required because the container starts as pentester.
# ---------------------------------------------------------------------------
echo "Adding CA to browser trust store..."

mkdir -p /home/pentester/.pki/nssdb

if [ ! -f /home/pentester/.pki/nssdb/cert9.db ]; then
  certutil \
    -N \
    -d sql:/home/pentester/.pki/nssdb \
    --empty-password || true
fi

certutil \
  -A \
  -n "Testing Root CA" \
  -t "C,," \
  -i /app/certs/ca.crt \
  -d sql:/home/pentester/.pki/nssdb \
  || true

echo "CA browser trust configuration complete."


# ---------------------------------------------------------------------------
# Agent browser screenshot directory
# ---------------------------------------------------------------------------
mkdir -p /workspace/.agent-browser-screenshots

echo "Container ready."


# ---------------------------------------------------------------------------
# Start the supplied command
# ---------------------------------------------------------------------------
cd /workspace

if [ "$#" -gt 0 ]; then
  echo "Starting command: $*"
  exec "$@"
fi


# ---------------------------------------------------------------------------
# If no command was supplied, keep the container alive.
#
# This prevents the container from immediately exiting after Caido starts.
# ---------------------------------------------------------------------------
echo "No additional command supplied."
echo "Caido is running on port ${CAIDO_PORT}."

wait "$CAIDO_PID"
