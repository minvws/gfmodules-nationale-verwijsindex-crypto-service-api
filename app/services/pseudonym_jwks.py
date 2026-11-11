import json
import threading
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwcrypto import jwk

from app.config import ConfigPseudonym
from app.exceptions.exception import InvalidSignedPseudonymError, JwksUnavailableError
from app.services.http import HttpService
from app.services.pseudonym_constants import EXPECTED_ALG

EXPECTED_USE = "sig"
EXPECTED_KTY = "RSA"
EXPECTED_OPERATION = "verify"
EXPECTED_MINIMUM_KEY_SIZE = 3072
JWKS_CACHE_TTL_SECONDS = 300


def _unique_keys_by_kid(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for entry in entries:
        kid = entry.get("kid")
        if not isinstance(kid, str) or not kid.strip():
            continue
        if kid in unique and unique[kid] != entry:
            raise JwksUnavailableError("JWKS contains duplicate signing key IDs")
        unique[kid] = entry
    return list(unique.values())


@dataclass(frozen=True)
class _CachedJwks:
    keys: jwk.JWKSet
    expires_at: float


class PseudonymJwksService:
    def __init__(self, config: ConfigPseudonym) -> None:
        if config.jwks_url is None:
            raise ValueError("JWKS URL is not configured")
        self._http = HttpService(
            endpoint=config.jwks_url,
            timeout=config.timeout,
            mtls_cert=config.cert_path,
            mtls_key=config.key_path,
            verify_ca=config.verify_ca,
        )
        self._cache: _CachedJwks | None = None
        self._lock = threading.Lock()

    def health_check(self) -> bool:
        try:
            self.get_keys()
            return True
        except JwksUnavailableError:
            return False

    def get_keys(self) -> jwk.JWKSet:
        with self._lock:
            if self._cache is None or time.monotonic() >= self._cache.expires_at:
                self._cache = self._fetch_jwks()
            return self._cache.keys

    def _fetch_jwks(self) -> _CachedJwks:
        try:
            response = self._http.do_request("GET")
            received_monotonic = time.monotonic()
            if response.status_code != 200:
                raise ValueError("Unexpected JWKS response status")
            content = response.content
            document = json.loads(content)
            if not isinstance(document, dict):
                raise TypeError("Expected a JSON object")
            if isinstance(document.get("keys"), list):
                document["keys"] = _unique_keys_by_kid(document["keys"])
            keys = jwk.JWKSet()
            keys.import_keyset(json.dumps(document))
        except JwksUnavailableError:
            raise
        except Exception:  # noqa: BLE001 - normalize all external fetch/import failures
            raise JwksUnavailableError("Could not retrieve or parse JWKS") from None

        return _CachedJwks(
            keys=keys, expires_at=received_monotonic + JWKS_CACHE_TTL_SECONDS
        )

    def get_key(self, kid: str) -> jwk.JWK:
        keys = self.get_keys()
        try:
            selected = keys.get_key(kid)
            if selected is None:
                raise InvalidSignedPseudonymError(
                    "JWS signing key is not present in JWKS"
                )
            if (
                selected.get("kty") != EXPECTED_KTY
                or selected.get("use") != EXPECTED_USE
                or selected.get("alg") != EXPECTED_ALG
            ):
                raise ValueError("Unsuitable signing key")
            if "key_ops" in selected:
                operations = selected["key_ops"]
                if (
                    not isinstance(operations, list)
                    or not all(isinstance(operation, str) for operation in operations)
                    or EXPECTED_OPERATION not in operations
                ):
                    raise ValueError("Key does not permit verification")
            public_key = selected.get_op_key(EXPECTED_OPERATION)
            if (
                not isinstance(public_key, RSAPublicKey)
                or public_key.key_size < EXPECTED_MINIMUM_KEY_SIZE
            ):
                raise ValueError("RSA signing key too small")
            return selected
        except InvalidSignedPseudonymError:
            raise
        except Exception:  # noqa: BLE001 - reject all malformed external key data
            with self._lock:
                if self._cache is not None and self._cache.keys is keys:
                    self._cache = None
            raise JwksUnavailableError(
                "JWKS signing key is invalid or unsuitable"
            ) from None
