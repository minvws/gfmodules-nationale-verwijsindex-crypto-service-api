import base64
import json
from collections.abc import Collection
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

    def decrypt_jwe_payload(
        self, jwe_token: str, expected_content_types: Collection[str]
    ) -> bytes:
        return CryptoService.decrypt_jwe_payload(
            self, jwe_token, expected_content_types=expected_content_types
        )


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
    payload: bytes,
    kid: str | None = "k1",
    key: jwk.JWK | None = None,
    cty: Any = "application/json",
) -> str:
    key = key or jwk.JWK.generate(kty="RSA", size=2048)
    header: dict[str, str] = {"alg": "RSA-OAEP-256", "enc": "A256GCM"}
    if kid is not None:
        header["kid"] = kid
    if cty is not ...:
        header["cty"] = cty
    token = jwe.JWE(payload, json.dumps(header))
    token.add_recipient(key)
    return token.serialize(compact=True)


def test_decrypt_jwe_payload_returns_plaintext_bytes() -> None:
    plaintext = json.dumps({"subject": "pseudonym:eval:abc"}).encode()
    svc = _MockCryptoService(plaintext=plaintext)

    out = svc.decrypt_jwe_payload(_make_test_jwe(plaintext), {"application/json"})

    assert out == plaintext


def test_decrypt_jwe_payload_raises_on_missing_kid() -> None:
    svc = _MockCryptoService(plaintext=b'{"subject": "x"}')
    token = _make_test_jwe(b'{"subject": "x"}', kid=None)
    with pytest.raises(InvalidJweError):
        svc.decrypt_jwe_payload(token, expected_content_types={"application/json"})


def test_decrypt_jwe_payload_rejects_non_object_jose_header() -> None:
    key = jwk.JWK.generate(kty="RSA", size=2048)
    token = jwe.JWE(
        b"payload", json.dumps({"alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": "k1"})
    )
    token.add_recipient(key)
    token.add_recipient(key)
    svc = _MockCryptoService(plaintext=b"payload")

    with pytest.raises(InvalidJweError):
        svc.decrypt_jwe_payload(token.serialize(compact=False), {"application/json"})


def test_decrypt_jwe_payload_wraps_invalid_compact_serialization() -> None:
    svc = _MockCryptoService(plaintext=b"")
    with pytest.raises(InvalidJweError):
        svc.decrypt_jwe_payload(
            "not-a-jwe", expected_content_types={"application/json"}
        )


def test_decrypt_jwe_payload_rejects_empty_protected_header() -> None:
    svc = _MockCryptoService(plaintext=b"")
    with pytest.raises(InvalidJweError):
        svc.decrypt_jwe_payload(
            "e30.AA.AA.AA.AA", expected_content_types={"application/json"}
        )


def test_decrypt_jwe_payload_propagates_crypto_error() -> None:
    svc = _MockCryptoService(plaintext=CryptoError("bad"))
    token = _make_test_jwe(b'{"x":1}')
    with pytest.raises(CryptoError):
        svc.decrypt_jwe_payload(token, expected_content_types={"application/json"})


def test_decrypt_jwe_payload_wraps_unexpected_errors() -> None:
    svc = _MockCryptoService(plaintext=RuntimeError("boom"))
    token = _make_test_jwe(b'{"x":1}')
    with pytest.raises(CryptoError):
        svc.decrypt_jwe_payload(token, expected_content_types={"application/json"})


def test_decrypt_jwe_payload_with_real_decryption_round_trip() -> None:
    kid = "k1"
    key = jwk.JWK.generate(kty="RSA", size=2048)
    plaintext = json.dumps({"subject": "pseudonym:eval:real"}).encode()
    token = _make_test_jwe(plaintext, kid=kid, key=key.public())
    svc = LocalCryptoService(keys={kid: key})

    out = svc.decrypt_jwe_payload(token, {"application/json"})

    assert out == plaintext


def test_signed_mode_requires_jwt_content_type() -> None:
    svc = _MockCryptoService(plaintext=b"header.payload.signature")
    token = _make_test_jwe(b"payload", cty="JWT")
    assert (
        svc.decrypt_jwe_payload(token, expected_content_types={"JWT"})
        == b"header.payload.signature"
    )


@pytest.mark.parametrize("cty", [..., "application/json", None])
def test_signed_mode_rejects_other_or_missing_content_type(cty: Any) -> None:
    svc = _MockCryptoService(plaintext=b"payload")
    token = _make_test_jwe(b"payload", cty=cty)
    with pytest.raises(InvalidJweError):
        svc.decrypt_jwe_payload(token, expected_content_types={"JWT"})


@pytest.mark.parametrize("cty", [..., "JWT", None])
def test_json_mode_rejects_other_or_invalid_content_type(cty: Any) -> None:
    svc = _MockCryptoService(plaintext=b"{}")
    token = _make_test_jwe(b"{}", cty=cty)
    with pytest.raises(InvalidJweError):
        svc.decrypt_jwe_payload(token, expected_content_types={"application/json"})
