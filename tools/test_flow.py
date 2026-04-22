"""Debug and test script for /decrypt_and_hash endpoint.

Blinds a pseudonym with OPRF, wraps it in a JWE, and sends it to the endpoint.
"""
import argparse
import base64
import json
import sys

import pyoprf
import requests
from jwcrypto import jwe, jwk


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8577")
    parser.add_argument("--pseudonym", default="test-pseudonym-123")
    args = parser.parse_args()

    # Fetch public key
    print(f"Fetching public key from {args.url}/test/public_key")
    key_resp = requests.get(f"{args.url}/test/public_key", timeout=10)
    key_resp.raise_for_status()
    kid = key_resp.json()["kid"]
    pub_pem = key_resp.json()["pem"].encode()

    # Blind the pseudonym
    print(f"Blinding: {args.pseudonym}")
    blind_factor, blinded = pyoprf.blind(args.pseudonym.encode())

    # Create JWE
    payload = {"subject": f"pseudonym:eval:{b64url(blinded)}"}
    pub_jwk = jwk.JWK.from_pem(pub_pem)
    protected = {"alg": "RSA-OAEP", "enc": "A256GCM", "kid": kid}
    token = jwe.JWE(json.dumps(payload).encode(), json.dumps(protected))
    token.add_recipient(pub_jwk)
    jwe_compact = token.serialize(compact=True)
    print(f"Token created: {jwe_compact}")
    print(f"JWE created ({len(jwe_compact)} chars)")

    # Send to endpoint
    resp = requests.get(
        f"{args.url}/decrypt_and_hash",
        params={"jwe": jwe_compact, "blind_factor": b64url(blind_factor)},
        timeout=10,
    )
    print(f"Response: {resp.status_code}")
    print(resp.text)
    return 0 if resp.ok else 1


if __name__ == "__main__":
    sys.exit(main())
