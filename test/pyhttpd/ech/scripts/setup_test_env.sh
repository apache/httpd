#!/bin/bash
# setup_test_env.sh - Automated Setup for ECH Testing

set -e 

PROJECT_ROOT=$(pwd)
CONF_DIR="$PROJECT_ROOT/conf"
SSL_DIR="$CONF_DIR/ssl"
ECH_DIR="$CONF_DIR/ech"

# FIX: Added 'then'
if [ -z "$OPENSSL_ECH_PATH" ]; then 
    echo "ERROR: OPENSSL_ECH_PATH is not set."
    echo "Please set it to your OpenSSL build directory (e.g., export OPENSSL_ECH_PATH=/path/to/openssl)"
    exit 1
fi

OPENSSL_BIN="$OPENSSL_ECH_PATH/bin/openssl"
export LD_LIBRARY_PATH="$OPENSSL_ECH_PATH/lib64:$LD_LIBRARY_PATH"

echo "[1/5] Cleaning old environment"
rm -rf "$CONF_DIR"
mkdir -p "$SSL_DIR" "$ECH_DIR"

echo "[2/5] Generating Local Root CA"
$OPENSSL_BIN genrsa -out "$SSL_DIR/MyLocalCA.key" 4096
$OPENSSL_BIN req -x509 -new -nodes -key "$SSL_DIR/MyLocalCA.key" -sha256 -days 365 \
    -out "$SSL_DIR/MyLocalCA.pem" \
    -subj "/C=IE/ST=Dublin/L=Dublin/O=FYP_Research/CN=MyLocalECH_CA"

echo "[3/5] Generating & Signing Server Certificate"
$OPENSSL_BIN genrsa -out "$SSL_DIR/server.key" 2048

cat <<EOF > "$SSL_DIR/domains.ext"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
EOF

$OPENSSL_BIN req -new -key "$SSL_DIR/server.key" -out "$SSL_DIR/server.csr" -subj "/CN=localhost"
$OPENSSL_BIN x509 -req -in "$SSL_DIR/server.csr" -CA "$SSL_DIR/MyLocalCA.pem" \
    -CAkey "$SSL_DIR/MyLocalCA.key" -CAcreateserial -out "$SSL_DIR/server.crt" \
    -days 365 -sha256 -extfile "$SSL_DIR/domains.ext"

echo "[4/5] Generating ECH Key Pair"
$OPENSSL_BIN ech -public_name "localhost"

# FIX: Added 'then'
if [ -f "echconfig.pem" ]; then
    mv echconfig.pem "$ECH_DIR/ECH_key.pem"
    echo "Successfully moved ECH key to $ECH_DIR/ECH_key.pem"
else
    echo "ERROR: OpenSSL did not create echconfig.pem"
    exit 1
fi

echo "[5/5] Checking for geckodriver"
GECKO_VERSION="v0.34.0"
if [ ! -f "./geckodriver" ]; then
    echo "Downloading Geckodriver $GECKO_VERSION..."
    wget --no-check-certificate https://github.com/mozilla/geckodriver/releases/download/$GECKO_VERSION/geckodriver-$GECKO_VERSION-linux64.tar.gz
    tar -xzf geckodriver-$GECKO_VERSION-linux64.tar.gz
    rm geckodriver-$GECKO_VERSION-linux64.tar.gz
    chmod +x geckodriver
    echo "Geckodriver installed locally."
else
    echo "Geckodriver already present."
fi

echo "Environment ready for pytest."
echo "Config located in: $CONF_DIR"