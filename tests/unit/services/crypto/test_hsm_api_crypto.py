import base64
import json
import os
from typing import Any
from unittest.mock import MagicMock

import pytest
from Crypto.Cipher import AES
from pytest_mock import MockerFixture
from requests.exceptions import ConnectionError as RequestsConnectionError, Timeout

from app.exceptions.exception import CryptoError, InvalidJweError, KeyNotFoundError
from app.logging.events import SYS_CRYPTO_FAILED
from app.services.crypto import hsm_api_crypto_service as hsm_module
from app.services.crypto.hsm_api_crypto_service import HsmApiCryptoService


def _resp(status: int, body: Any = None, text: str = "") -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = text or (json.dumps(body) if isinstance(body, (dict, list)) else "")
    r.json.return_value = body if body is not None else {}
    return r


@pytest.fixture
def service(http_mock: MagicMock) -> HsmApiCryptoService:
    return HsmApiCryptoService(
        http_mock,
        module="m",
        slot="s",
        hash_key_id="hk",
        signing_key_id="sk",
        support_sha1=False,
    )


def _b64u_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwe(cek: bytes, plaintext: bytes, alg: str = "RSA-OAEP-256", enc: str = "A256GCM") -> tuple[str, bytes]:
    header = {"alg": alg, "enc": enc, "kid": "sk"}
    header_b64 = _b64u_nopad(json.dumps(header).encode())
    iv = os.urandom(12)
    cipher = AES.new(cek, AES.MODE_GCM, nonce=iv)
    cipher.update(header_b64.encode("ascii"))
    ct, tag = cipher.encrypt_and_digest(plaintext)
    encrypted_key = b"WRAPPED_KEY"
    token = ".".join(
        [header_b64, _b64u_nopad(encrypted_key), _b64u_nopad(iv), _b64u_nopad(ct), _b64u_nopad(tag)]
    )
    return token, encrypted_key


def test_health_check_returns_true_on_200(service: HsmApiCryptoService, http_mock: MagicMock) -> None:
    http_mock.do_request.return_value = _resp(200, {"message": "ok"})
    assert service.health_check() is True


@pytest.mark.parametrize(
    "side_effect_or_status",
    [500, 503, RequestsConnectionError("x"), Timeout("x")],
    ids=["500", "503", "conn", "timeout"],
)
def test_health_check_returns_false_on_failure(
    side_effect_or_status: Any, service: HsmApiCryptoService, http_mock: MagicMock
) -> None:
    if isinstance(side_effect_or_status, int):
        http_mock.do_request.return_value = _resp(side_effect_or_status, {"message": "x"})
    else:
        http_mock.do_request.side_effect = side_effect_or_status
    assert service.health_check() is False


def test_get_public_key_returns_pem(service: HsmApiCryptoService, http_mock: MagicMock) -> None:
    http_mock.do_request.return_value = _resp(200, {"objects": [{"publickey": "PEM"}]})
    assert service.get_public_key("sk") == "PEM"


def test_get_public_key_uses_cached_value_after_first_call(
    service: HsmApiCryptoService, http_mock: MagicMock
) -> None:
    http_mock.do_request.return_value = _resp(200, {"objects": [{"publickey": "PEM"}]})
    service.get_public_key("sk")
    service.get_public_key("sk")
    assert http_mock.do_request.call_count == 1


def test_get_public_key_raises_when_not_found(service: HsmApiCryptoService, http_mock: MagicMock) -> None:
    http_mock.do_request.return_value = _resp(404, text="missing")
    with pytest.raises(KeyNotFoundError):
        service.get_public_key("sk")


@pytest.mark.parametrize(
    "body",
    [{"objects": []}, {"objects": [{}]}, {"wrong": "shape"}],
    ids=["empty", "no-publickey", "wrong-shape"],
)
def test_get_public_key_raises_on_malformed_response(
    body: Any, service: HsmApiCryptoService, http_mock: MagicMock
) -> None:
    http_mock.do_request.return_value = _resp(200, body, text=json.dumps(body))
    with pytest.raises(CryptoError):
        service.get_public_key("sk")


def test_decrypt_jwe_round_trip(service: HsmApiCryptoService, http_mock: MagicMock) -> None:
    cek = os.urandom(32)
    token, _encrypted_key = _make_jwe(cek, b"plaintext")
    http_mock.do_request.return_value = _resp(
        200, {"result": base64.b64encode(cek).decode()}
    )

    assert service.decrypt_jwe(token, "sk") == b"plaintext"
    call = http_mock.do_request.call_args
    assert call.kwargs["sub_route"] == "hsm/m/s/decrypt"
    assert call.kwargs["data"]["mechanism"] == "RSA_PKCS_OAEP"
    assert call.kwargs["data"]["hashmethod"] == "sha256"


def test_decrypt_jwe_rejects_malformed_compact_serialization(service: HsmApiCryptoService) -> None:
    with pytest.raises(InvalidJweError):
        service.decrypt_jwe("only.three.parts", "sk")


@pytest.mark.parametrize(
    "alg,enc,support_sha1,err",
    [
        ("none", "A256GCM", False, InvalidJweError),
        ("RSA-OAEP", "A256GCM", False, InvalidJweError),
        ("RSA-OAEP-256", "A128GCM", False, InvalidJweError),
        ("RSA-OAEP-256", "", False, InvalidJweError),
    ],
    ids=["bad-alg", "sha1-not-supported", "bad-enc", "missing-enc"],
)
def test_decrypt_jwe_validates_header_fields(
    alg: str, enc: str, support_sha1: bool, err: type[Exception], http_mock: MagicMock
) -> None:
    svc = HsmApiCryptoService(
        http_mock, module="m", slot="s", hash_key_id="h", signing_key_id="s", support_sha1=support_sha1
    )
    cek = os.urandom(32)
    token, _ = _make_jwe(cek, b"plain", alg=alg, enc=enc)
    with pytest.raises(err):
        svc.decrypt_jwe(token, "sk")


def test_decrypt_jwe_supports_sha1_when_enabled(http_mock: MagicMock) -> None:
    svc = HsmApiCryptoService(
        http_mock, module="m", slot="s", hash_key_id="h", signing_key_id="s", support_sha1=True
    )
    cek = os.urandom(32)
    token, _ = _make_jwe(cek, b"plain", alg="RSA-OAEP")
    http_mock.do_request.return_value = _resp(200, {"result": base64.b64encode(cek).decode()})
    assert svc.decrypt_jwe(token, "sk") == b"plain"


def test_decrypt_jwe_rejects_wrong_cek_length(service: HsmApiCryptoService, http_mock: MagicMock) -> None:
    cek = os.urandom(32)
    token, _ = _make_jwe(cek, b"x")
    http_mock.do_request.return_value = _resp(200, {"result": base64.b64encode(b"short").decode()})
    with pytest.raises(CryptoError):
        service.decrypt_jwe(token, "sk")


def test_decrypt_jwe_unwrap_failure_raises(service: HsmApiCryptoService, http_mock: MagicMock) -> None:
    cek = os.urandom(32)
    token, _ = _make_jwe(cek, b"x")
    http_mock.do_request.return_value = _resp(500, text="boom")
    with pytest.raises(CryptoError):
        service.decrypt_jwe(token, "sk")


def test_generate_keys_calls_rsa_and_secret_endpoints(
    service: HsmApiCryptoService, http_mock: MagicMock
) -> None:
    http_mock.do_request.side_effect = [
        _resp(200, {"result": [{"LABEL": "sk", "CLASS": "PUBLIC_KEY", "publickey": "PEM"}]}),
        _resp(200, {"result": "ok"}),
    ]
    service.generate_keys()
    sub_routes = [c.kwargs["sub_route"] for c in http_mock.do_request.call_args_list]
    assert sub_routes == ["hsm/m/s/generate/rsa", "hsm/m/s/generate/secret"]


def test_generate_signing_key_409_falls_back_to_get_public_key(
    service: HsmApiCryptoService, http_mock: MagicMock
) -> None:
    http_mock.do_request.side_effect = [
        _resp(409, text="already exists"),
        _resp(200, {"objects": [{"publickey": "PEM"}]}),
        _resp(200, {"result": "ok"}),
    ]
    service.generate_keys()
    assert http_mock.do_request.call_count == 3


def test_generate_signing_key_5xx_raises(service: HsmApiCryptoService, http_mock: MagicMock) -> None:
    http_mock.do_request.return_value = _resp(503, text="bad")
    with pytest.raises(CryptoError):
        service.generate_keys()


def test_generate_signing_key_5xx_logs_sys_crypto_failed(
    service: HsmApiCryptoService, http_mock: MagicMock, mocker: MockerFixture
) -> None:
    http_mock.do_request.return_value = _resp(503, text="bad")
    log_event = mocker.patch("app.services.crypto.hsm_api_crypto_service.log_event")

    with pytest.raises(CryptoError):
        service.generate_keys()

    log_event.assert_called_once_with(
        hsm_module.logger,
        SYS_CRYPTO_FAILED,
        "Crypto operation failed: RSA key-pair generation",
        operation_type="rsa_keypair_generate",
        error_reason="hsm_status_503",
        retry_attempt=0,
    )


def test_hash_returns_decoded_hmac(service: HsmApiCryptoService, http_mock: MagicMock) -> None:
    digest = b"\x10" * 32
    http_mock.do_request.return_value = _resp(
        200, {"result": {"data": base64.b64encode(digest).decode()}}
    )
    assert service.hash(b"input") == digest
    call = http_mock.do_request.call_args
    assert call.kwargs["sub_route"] == "hsm/m/s/sign"
    assert call.kwargs["data"]["mechanism"] == "SHA256_HMAC"


def test_hash_raises_on_error_status(service: HsmApiCryptoService, http_mock: MagicMock) -> None:
    http_mock.do_request.return_value = _resp(500, text="bad")
    with pytest.raises(CryptoError):
        service.hash(b"input")


def test_hash_raises_on_malformed_response(service: HsmApiCryptoService, http_mock: MagicMock) -> None:
    http_mock.do_request.return_value = _resp(200, {"wrong": "shape"})
    with pytest.raises(CryptoError):
        service.hash(b"input")
