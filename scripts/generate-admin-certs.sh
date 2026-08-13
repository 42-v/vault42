#!/usr/bin/env bash
# generate-admin-certs.sh — Generate mTLS certificates for the admin gateway.
# Creates: CA cert/key, server cert/key, client cert/key.
# Usage: ./scripts/generate-admin-certs.sh [output-dir]

set -euo pipefail

OUTDIR="${1:-secrets/admin-tls}"
mkdir -p "$OUTDIR"

DAYS=365
SUBJECT="/O=Vault/CN=admin-gateway"

echo "=== Generating Admin Gateway mTLS Certificates ==="
echo "Output: $OUTDIR"

# 1. CA (Certificate Authority)
echo "--- CA ---"
openssl genrsa -out "$OUTDIR/ca.key" 4096 2>/dev/null
openssl req -new -x509 -days "$DAYS" -key "$OUTDIR/ca.key" \
    -out "$OUTDIR/ca.crt" -subj "/O=Vault/CN=Admin Gateway CA" 2>/dev/null
echo "CA: $OUTDIR/ca.crt"

# 2. Server certificate (for the admin gateway)
echo "--- Server Certificate ---"
openssl genrsa -out "$OUTDIR/server.key" 2048 2>/dev/null
openssl req -new -key "$OUTDIR/server.key" \
    -out "$OUTDIR/server.csr" -subj "$SUBJECT" 2>/dev/null

# SAN: localhost + loopback only
cat > "$OUTDIR/server-ext.cnf" <<EOF
[req]
req_extensions = v3_req
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl x509 -req -days "$DAYS" -in "$OUTDIR/server.csr" \
    -CA "$OUTDIR/ca.crt" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
    -out "$OUTDIR/server.crt" \
    -extfile "$OUTDIR/server-ext.cnf" -extensions v3_req 2>/dev/null
echo "Server: $OUTDIR/server.crt"

# 3. Client certificate (for the operator)
echo "--- Client Certificate ---"
openssl genrsa -out "$OUTDIR/client.key" 2048 2>/dev/null
openssl req -new -key "$OUTDIR/client.key" \
    -out "$OUTDIR/client.csr" -subj "/O=Vault/CN=admin-operator" 2>/dev/null
openssl x509 -req -days "$DAYS" -in "$OUTDIR/client.csr" \
    -CA "$OUTDIR/ca.crt" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
    -out "$OUTDIR/client.crt" 2>/dev/null
echo "Client: $OUTDIR/client.crt"

# Cleanup CSRs and temp files
rm -f "$OUTDIR"/*.csr "$OUTDIR"/*.cnf "$OUTDIR"/*.srl

echo ""
echo "=== Done ==="
echo "Server: ADMIN_GW_TLS_CERT_FILE=$OUTDIR/server.crt"
echo "         ADMIN_GW_TLS_KEY_FILE=$OUTDIR/server.key"
echo "         ADMIN_GW_CLIENT_CA_FILE=$OUTDIR/ca.crt"
echo ""
echo "Client: curl --cert $OUTDIR/client.crt --key $OUTDIR/client.key --cacert $OUTDIR/ca.crt"
echo ""
echo "SSH tunnel: ssh -L 9443:127.0.0.1:9443 user@k8s-node"
echo "Browser:    https://localhost:9443/admin/login"

# Create Kubernetes secret command
echo ""
echo "To create a Kubernetes secret:"
echo "  kubectl create secret generic vault-admin-tls \\"
echo "    --from-file=tls.crt=$OUTDIR/server.crt \\"
echo "    --from-file=tls.key=$OUTDIR/server.key \\"
echo "    --from-file=ca.crt=$OUTDIR/ca.crt"
