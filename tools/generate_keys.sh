#!/usr/bin/env bash
# Manually generate the HSM keys via the HSM-API (mTLS).
# Usage: tools/generate_keys.sh <signing-key-id> <hashing-key-id>
set -euo pipefail

URL="${HSM_URL:-https://localhost:8000}"
MODULE="${HSM_MODULE:-softhsm}"
SLOT="${HSM_SLOT:-SoftHSMLabel}"
CERT="${HSM_CERT:-secrets/hsm-api.crt}"
KEY="${HSM_KEY:-secrets/hsm-api.key}"
CA="${HSM_CA:-secrets/hsm-api-ca.crt}"

SIGNING_KEY_ID="${1:?usage: $0 <signing-key-id> <hashing-key-id>}"
HASHING_KEY_ID="${2:?usage: $0 <signing-key-id> <hashing-key-id>}"
SECRET_KEY_ID="${3:?usage: $0 <signing-key-id> <hashing-key-id>}"

curl_hsm() { curl -fsS --cert "$CERT" --key "$KEY" --cacert "$CA" -H 'Content-Type: application/json' "$@"; }

echo "Generating RSA signing key: $SIGNING_KEY_ID"
curl_hsm -X POST "$URL/hsm/$MODULE/$SLOT/generate/rsa" -d "{\"label\": \"$SIGNING_KEY_ID\", \"bits\": 4096}"
echo

echo "Generating HMAC hashing key: $HASHING_KEY_ID"
curl_hsm -X POST "$URL/hsm/$MODULE/$SLOT/generate/secret" -d "{\"label\": \"$HASHING_KEY_ID\", \"bits\": 256}"
echo

echo "Generating AES hashing key: $SECRET_KEY_ID"
curl_hsm -X POST "$URL/hsm/$MODULE/$SLOT/generate/aes" -d "{\"label\": \"$SECRET_KEY_ID\", \"bits\": 256}"
echo
