#!/bin/bash

set -e

echo "=========================================="
echo "      iqAudi360 Container Starting"
echo "=========================================="

# ---------------------------------------------------------------------------
# Optional host UID/GID handling
# ---------------------------------------------------------------------------
if [ -n "${STRIX_HOST_UID:-}" ] && [ -n "${STRIX_HOST_GID:-}" ]; then
    echo "Host UID/GID requested:"
    echo "UID: ${STRIX_HOST_UID}"
    echo "GID: ${STRIX_HOST_GID}"
fi


# ---------------------------------------------------------------------------
# Caido configuration
# ---------------------------------------------------------------------------
CAIDO_PORT=48080
CAIDO_LOG="/tmp/caido_startup.log"

echo ""
echo "Starting Caido..."

if [ ! -f /app/certs/ca.p12 ]; then
    echo "ERROR: Caido CA certificate not found."
    exit 1
fi


# ---------------------------------------------------------------------------
# Caido allowed domains
# ---------------------------------------------------------------------------
CAIDO_UI_DOMAIN_ARGS=()

if [ -n "${STRIX_CAIDO_ALLOWED_DOMAINS:-}" ]; then

    echo "Configuring Caido allowed domains..."

    IFS=',' read -ra _caido_domains <<< "${STRIX_CAIDO_ALLOWED_DOMAINS}"

    for _d in "${_caido_domains[@]}"; do

        _d="$(echo "$_d" | xargs)"

        if [ -n "$_d" ]; then
            echo "Allowed domain: $_d"
            CAIDO_UI_DOMAIN_ARGS+=(--ui-domain "$_d")
        fi

    done

fi


# ---------------------------------------------------------------------------
# Start Caido in background
# ---------------------------------------------------------------------------
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

echo "Started Caido with PID ${CAIDO_PID} on port ${CAIDO_PORT}"


# ---------------------------------------------------------------------------
# Wait for Caido
# ---------------------------------------------------------------------------
echo "Waiting for Caido API to be ready..."

CAIDO_READY=0

for attempt in $(seq 1 30); do

    if curl -fsS \
        "http://127.0.0.1:${CAIDO_PORT}/graphql/" \
        >/dev/null 2>&1; then

        echo "Caido API is ready (attempt ${attempt})."

        CAIDO_READY=1
        break
    fi

    sleep 1

done


if [ "$CAIDO_READY" -ne 1 ]; then

    echo "WARNING: Caido did not become ready."

    if [ -f "$CAIDO_LOG" ]; then
        echo "---------- Caido log ----------"
        cat "$CAIDO_LOG"
        echo "--------------------------------"
    fi

fi


echo "Caido is running in background."


# ---------------------------------------------------------------------------
# Proxy environment
#
# IMPORTANT:
# Do NOT use sudo here.
# Render containers may run with no-new-privileges enabled.
# ---------------------------------------------------------------------------
echo ""
echo "Configuring proxy settings..."

export http_proxy="http://127.0.0.1:${CAIDO_PORT}"
export https_proxy="http://127.0.0.1:${CAIDO_PORT}"

export HTTP_PROXY="http://127.0.0.1:${CAIDO_PORT}"
export HTTPS_PROXY="http://127.0.0.1:${CAIDO_PORT}"

export ALL_PROXY="http://127.0.0.1:${CAIDO_PORT}"

export NO_PROXY="localhost,127.0.0.1"

export no_proxy="localhost,127.0.0.1"

export REQUESTS_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
export SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"

echo "HTTP proxy:  ${HTTP_PROXY}"
echo "HTTPS proxy: ${HTTPS_PROXY}"
echo "NO_PROXY:    ${NO_PROXY}"

echo "Proxy configuration complete."


# ---------------------------------------------------------------------------
# Browser CA trust
# ---------------------------------------------------------------------------
echo ""
echo "Adding CA to browser trust store..."

mkdir -p /home/pentester/.pki/nssdb

if command -v certutil >/dev/null 2>&1; then

    certutil -N \
        -d "sql:/home/pentester/.pki/nssdb" \
        --empty-password \
        >/dev/null 2>&1 || true

    certutil -D \
        -d "sql:/home/pentester/.pki/nssdb" \
        -n "Testing Root CA" \
        >/dev/null 2>&1 || true

    certutil -A \
        -d "sql:/home/pentester/.pki/nssdb" \
        -n "Testing Root CA" \
        -t "C,," \
        -i /app/certs/ca.crt \
        >/dev/null 2>&1 || true

fi

echo "CA browser trust configuration complete."


# ---------------------------------------------------------------------------
# Screenshot directory
# ---------------------------------------------------------------------------
mkdir -p /workspace/.agent-browser-screenshots

echo ""
echo "=========================================="
echo "       iqAudi360 Container Ready"
echo "=========================================="

echo "Caido PID: ${CAIDO_PID}"
echo "Caido Port: ${CAIDO_PORT}"
echo "Dashboard Port: ${PORT:-10000}"


# ---------------------------------------------------------------------------
# Start iqAudi360 Web Dashboard
#
# THIS IS THE IMPORTANT PART.
#
# Render gives us $PORT.
# Flask must listen on 0.0.0.0:$PORT.
# ---------------------------------------------------------------------------
echo ""
echo "Starting iqAudi360 Web Dashboard..."

cd /app

if [ ! -f /app/run_gui.py ]; then

    echo "ERROR: /app/run_gui.py not found."
    echo "The iqAudi360 application was not copied into the Docker image."

    kill "${CAIDO_PID}" 2>/dev/null || true

    exit 1

fi


if [ ! -d /app/strix ]; then

    echo "ERROR: /app/strix directory not found."

    kill "${CAIDO_PID}" 2>/dev/null || true

    exit 1

fi


# ---------------------------------------------------------------------------
# Cleanup Caido when Flask exits
# ---------------------------------------------------------------------------
cleanup() {

    echo ""
    echo "Stopping iqAudi360..."

    if kill -0 "${CAIDO_PID}" 2>/dev/null; then
        kill "${CAIDO_PID}" 2>/dev/null || true
    fi

}

trap cleanup EXIT INT TERM


# ---------------------------------------------------------------------------
# Launch Flask dashboard
# ---------------------------------------------------------------------------
exec /app/.venv/bin/python \
    /app/run_gui.py \
    --host 0.0.0.0 \
    --port "${PORT:-10000}" \
    --no-browser
