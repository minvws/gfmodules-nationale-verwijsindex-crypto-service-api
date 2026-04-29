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


def _make_real_jwe(payload: bytes, kid: str | None = "k1") -> Any:
    key = jwk.JWK.generate(kty="RSA", size=2048)
    header: dict[str, str] = {"alg": "RSA-OAEP-256", "enc": "A256GCM"}
    if kid is not None:
        header["kid"] = kid
    token = jwe.JWE(payload, json.dumps(header))
    token.add_recipient(key)
    return token.serialize(compact=True)


def test_decrypt_jwe_payload_returns_parsed_json() -> None:
    plaintext = json.dumps({"subject": "pseudonym:eval:abc"}).encode()
    svc = _MockCryptoService(plaintext=plaintext)

    out = svc.decrypt_jwe_payload(_make_real_jwe(plaintext))

    assert out == {"subject": "pseudonym:eval:abc"}


def test_decrypt_jwe_payload_raises_on_missing_kid() -> None:
    svc = _MockCryptoService(plaintext=b'{"subject": "x"}')
    with pytest.raises(InvalidJweError):
        svc.decrypt_jwe_payload(_make_real_jwe(b'{"subject": "x"}', kid=None))


def test_decrypt_jwe_payload_wraps_invalid_compact_serialization() -> None:
    svc = _MockCryptoService(plaintext=b"")
    with pytest.raises(InvalidJweError):
        svc.decrypt_jwe_payload("not-a-jwe")


def test_decrypt_jwe_payload_propagates_crypto_error() -> None:
    svc = _MockCryptoService(plaintext=CryptoError("bad"))
    with pytest.raises(CryptoError):
        svc.decrypt_jwe_payload(_make_real_jwe(b'{"x":1}'))


def test_decrypt_jwe_payload_wraps_unexpected_errors() -> None:
    svc = _MockCryptoService(plaintext=RuntimeError("boom"))
    with pytest.raises(CryptoError):
        svc.decrypt_jwe_payload(_make_real_jwe(b'{"x":1}'))
