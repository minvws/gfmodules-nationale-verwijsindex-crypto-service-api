import base64
import json
from typing import Any

import pytest
from jwcrypto import jwe, jwk

from app.exceptions.exception import CryptoError, InvalidJweError
from app.services.crypto.crypto_service import CryptoService
from app.services.crypto.mock_crypto_service import MockCryptoService


class _MockCryptoService(MockCryptoService):
    def __init__(self, plaintext: bytes | Exception | None = None) -> None:
        self._plaintext = plaintext

    def decrypt_jwe(self, jwe_token: str, key_id: str) -> bytes:
        if isinstance(self._plaintext, Exception):
            raise self._plaintext
        assert self._plaintext is not None
        return self._plaintext

    def decrypt_jwe_payload(self, jwe_token: str) -> Any:
        return CryptoService.decrypt_jwe_payload(self, jwe_token)


class LocalCryptoService(CryptoService):
    def __init__(self, keys: dict[str, jwk.JWK]) -> None:
        self._keys = keys

    def health_check(self) -> bool:
        return True

    def get_public_key(self, key_id: str) -> str:
        return (
            self._keys[key_id].export_to_pem(private_key=False, password=None).decode()
        )

    def decrypt_jwe(self, jwe_token: str, key_id: str) -> bytes:
        key = self._keys[key_id]
        token = jwe.JWE()
        token.deserialize(jwe_token)
        token.decrypt(key)
        return token.payload

    def hash(self, data: bytes) -> bytes:
        return data

    def encrypt_aes(self, data: bytes, iv: bytes, label: str, mechanism: str) -> str:
        return base64.b64encode(data).decode()

    def decrypt_aes(self, data: str, iv: str, label: str, mechanism: str) -> str:
        return data


def _make_test_jwe(
    payload: bytes, kid: str | None = "k1", key: jwk.JWK | None = None
) -> str:
    key = key or jwk.JWK.generate(kty="RSA", size=2048)
    header: dict[str, str] = {"alg": "RSA-OAEP-256", "enc": "A256GCM"}
    if kid is not None:
        header["kid"] = kid
    token = jwe.JWE(payload, json.dumps(header))
    token.add_recipient(key)
    return token.serialize(compact=True)


def test_decrypt_jwe_payload_returns_parsed_json() -> None:
    plaintext = json.dumps({"subject": "pseudonym:eval:abc"}).encode()
    svc = _MockCryptoService(plaintext=plaintext)

    out = svc.decrypt_jwe_payload(_make_test_jwe(plaintext))

    assert out == {"subject": "pseudonym:eval:abc"}


def test_decrypt_jwe_payload_raises_on_missing_kid() -> None:
    svc = _MockCryptoService(plaintext=b'{"subject": "x"}')
    token = _make_test_jwe(b'{"subject": "x"}', kid=None)
    with pytest.raises(InvalidJweError):
        svc.decrypt_jwe_payload(token)


def test_decrypt_jwe_payload_wraps_invalid_compact_serialization() -> None:
    svc = _MockCryptoService(plaintext=b"")
    with pytest.raises(InvalidJweError):
        svc.decrypt_jwe_payload("not-a-jwe")


def test_decrypt_jwe_payload_propagates_crypto_error() -> None:
    svc = _MockCryptoService(plaintext=CryptoError("bad"))
    token = _make_test_jwe(b'{"x":1}')
    with pytest.raises(CryptoError):
        svc.decrypt_jwe_payload(token)


def test_decrypt_jwe_payload_wraps_unexpected_errors() -> None:
    svc = _MockCryptoService(plaintext=RuntimeError("boom"))
    token = _make_test_jwe(b'{"x":1}')
    with pytest.raises(CryptoError):
        svc.decrypt_jwe_payload(token)


def test_decrypt_jwe_payload_with_real_decryption_round_trip() -> None:
    kid = "k1"
    key = jwk.JWK.generate(kty="RSA", size=2048)
    plaintext = json.dumps({"subject": "pseudonym:eval:real"}).encode()
    token = _make_test_jwe(plaintext, kid=kid, key=key.public())
    svc = LocalCryptoService(keys={kid: key})

    out = svc.decrypt_jwe_payload(token)

    assert out == {"subject": "pseudonym:eval:real"}
