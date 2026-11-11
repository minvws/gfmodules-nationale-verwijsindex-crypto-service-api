import base64
import hashlib
import json
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from email.utils import formatdate
from typing import Any
from unittest.mock import MagicMock

import inject
import pyoprf
import pytest
import requests
from fastapi.testclient import TestClient
from jwcrypto import jwe, jwk, jws
from pytest_mock import MockerFixture

from app import application, container
from app.config import Config, ConfigPseudonym
from app.data import Pkc11Mechanism
from app.exceptions.exception import InvalidJweError
from app.services.crypto.crypto_service import CryptoService

ISSUER = "https://prs.test"
AUDIENCE = "oin:00000099000000001000"
JWKS_URL = "https://prs.test/.well-known/jwks"


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode()


def public_signing_key(key: jwk.JWK, kid: str) -> dict[str, Any]:
    return {**key.export_public(as_dict=True), "kid": kid, "use": "sig", "alg": "PS256"}


def jwks_response(keys: list[dict[str, Any]]) -> requests.Response:
    result = requests.Response()
    result.status_code = 200
    result._content = json.dumps({"keys": keys}).encode()
    result.headers.update(
        {
            "Cache-Control": "public, max-age=900",
            "Date": formatdate(time.time(), usegmt=True),
        }
    )
    return result


class LocalCryptoService(CryptoService):
    def __init__(self, key: jwk.JWK) -> None:
        self.key = key

    def health_check(self) -> bool:
        return True

    def get_public_key(self, key_id: str) -> str:
        return self.key.export_to_pem().decode()

    def decrypt_jwe(self, jwe_token: str, key_id: str) -> bytes:
        if key_id != "local-jwe":
            raise InvalidJweError("Invalid JWE")
        token = jwe.JWE()
        token.deserialize(jwe_token)
        token.decrypt(self.key)
        return token.payload

    def hash(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def encrypt_aes(
        self, data: bytes, iv: bytes, label: str, mechanism: Pkc11Mechanism
    ) -> str:
        return b64(data)

    def decrypt_aes(
        self, data: str, iv: str, label: str, mechanism: Pkc11Mechanism
    ) -> str:
        raise NotImplementedError


@dataclass
class Flow:
    client: TestClient
    crypto: LocalCryptoService
    encryption_key: jwk.JWK
    http: MagicMock

    def wrap(self, plaintext: bytes, content_type: str | None) -> str:
        headers = {"alg": "RSA-OAEP", "enc": "A256GCM", "kid": "local-jwe"}
        if content_type is not None:
            headers["cty"] = content_type
        encrypted = jwe.JWE(plaintext, json.dumps(headers))
        encrypted.add_recipient(self.encryption_key.public())
        return str(encrypted.serialize(compact=True))

    def post(
        self, plaintext: bytes, content_type: str | None, blind_factor: bytes
    ) -> Any:
        return self.client.post(
            "/process",
            json={
                "jwe": self.wrap(plaintext, content_type),
                "blind_factor": b64(blind_factor),
                "label": "aes-key",
                "mechanism": "AES_CBC",
            },
        )


@pytest.fixture(scope="module")
def signing_key() -> jwk.JWK:
    return jwk.JWK.generate(kty="RSA", size=3072)


@pytest.fixture(scope="module")
def encryption_key() -> jwk.JWK:
    return jwk.JWK.generate(kty="RSA", size=2048)


@pytest.fixture
def oprf_claims() -> tuple[dict[str, Any], bytes]:
    blind_factor, blinded = pyoprf.blind(b"integration-test-pseudonym")
    evaluated = pyoprf.evaluate(pyoprf.keygen(), blinded)
    now = int(time.time())
    return (
        {
            "subject": f"pseudonym:eval:{b64(evaluated)}",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "scope": "test",
            "version": "1.1",
            "iat": now,
            "exp": now + 300,
        },
        blind_factor,
    )


def sign(key: jwk.JWK, claims: dict[str, Any], kid: str = "old-key") -> bytes:
    token = jws.JWS(json.dumps(claims).encode())
    token.add_signature(
        key, protected=json.dumps({"alg": "PS256", "typ": "JWT", "kid": kid})
    )
    return str(token.serialize(compact=True)).encode("ascii")


@pytest.fixture
def make_flow(
    use_config: Config,
    mocker: MockerFixture,
    encryption_key: jwk.JWK,
    signing_key: jwk.JWK,
) -> Iterator[Callable[..., Flow]]:
    http = mocker.patch(
        "app.services.http.request",
        return_value=jwks_response([public_signing_key(signing_key, "old-key")]),
    )
    crypto = LocalCryptoService(encryption_key)
    mocker.patch("app.container.MockCryptoService", return_value=crypto)

    def create(signing_expected: bool, configure_jwks: bool = True) -> Flow:
        settings: dict[str, Any] = {"signing_expected": signing_expected}
        if configure_jwks:
            settings.update(
                jwks_url=JWKS_URL, expected_issuer=ISSUER, expected_audience=AUDIENCE
            )
        use_config.pseudonym = ConfigPseudonym.model_validate(settings)
        inject.clear_and_configure(container.container_config)
        return Flow(
            TestClient(application.setup_fastapi()), crypto, encryption_key, http
        )

    yield create
    inject.clear()


@pytest.mark.parametrize(
    "signed, content_type", [(True, "JWT"), (False, "application/json")]
)
def test_process_accepts_the_configured_format(
    make_flow: Callable[..., Flow],
    signing_key: jwk.JWK,
    oprf_claims: tuple[dict[str, Any], bytes],
    signed: bool,
    content_type: str | None,
) -> None:
    claims, blind_factor = oprf_claims
    flow = make_flow(signed, signed)
    plaintext = sign(signing_key, claims) if signed else json.dumps(claims).encode()

    result = flow.post(plaintext, content_type, blind_factor)

    assert result.status_code == 200
    assert set(result.json()) == {"encrypted_pseudonym", "iv"}
    assert result.json()["encrypted_pseudonym"]
    assert result.json()["iv"]
    assert flow.http.call_count == (1 if signed else 0)


def test_unsigned_json_without_content_type_is_rejected_before_unblinding(
    make_flow: Callable[..., Flow],
    oprf_claims: tuple[dict[str, Any], bytes],
    mocker: MockerFixture,
) -> None:
    claims, blind_factor = oprf_claims
    flow = make_flow(signing_expected=False, configure_jwks=False)
    unblind = mocker.spy(pyoprf, "unblind")

    result = flow.post(json.dumps(claims).encode(), None, blind_factor)

    assert result.status_code == 400
    assert result.json() == {"error": "Invalid JWE"}
    unblind.assert_not_called()


@pytest.mark.parametrize(
    "signed, payload_type, cty",
    [
        (True, "json", "application/json"),
        (True, "json", "JWT"),
        (False, "jwt", "JWT"),
        (False, "jwt", "application/json"),
        (True, "tampered", "JWT"),
    ],
)
def test_wrong_format_never_reaches_unblind_hash_or_encrypt(
    make_flow: Callable[..., Flow],
    signing_key: jwk.JWK,
    oprf_claims: tuple[dict[str, Any], bytes],
    mocker: MockerFixture,
    signed: bool,
    payload_type: str,
    cty: str | None,
) -> None:
    claims, blind_factor = oprf_claims
    flow = make_flow(signing_expected=signed, configure_jwks=signed)
    if payload_type == "json":
        plaintext = json.dumps(claims).encode()
    else:
        plaintext = sign(signing_key, claims)
        if payload_type == "tampered":
            header, _, signature = plaintext.decode().split(".")
            changed = (
                base64.urlsafe_b64encode(b'{"subject":"modified"}')
                .rstrip(b"=")
                .decode()
            )
            plaintext = f"{header}.{changed}.{signature}".encode()
    unblind = mocker.spy(pyoprf, "unblind")
    hash_spy = mocker.spy(flow.crypto, "hash")
    encrypt_spy = mocker.spy(flow.crypto, "encrypt_aes")

    result = flow.post(plaintext, cty, blind_factor)

    assert result.status_code == 400
    unblind.assert_not_called()
    hash_spy.assert_not_called()
    encrypt_spy.assert_not_called()


def test_unexpected_content_type_returns_invalid_jwe_without_fetching_jwks(
    make_flow: Callable[..., Flow],
) -> None:
    flow = make_flow(signing_expected=True)
    encrypted = flow.wrap(b"payload", "unsupported/content-type")

    result = flow.client.post(
        "/process",
        json={
            "jwe": encrypted,
            "blind_factor": b64(b"blind-factor"),
            "label": "aes-key",
            "mechanism": "AES_CBC",
        },
    )

    assert result.status_code == 400
    assert result.json() == {"error": "Invalid JWE"}
    flow.http.assert_not_called()


def test_unknown_signing_key_returns_invalid_jwe(
    make_flow: Callable[..., Flow],
    signing_key: jwk.JWK,
    oprf_claims: tuple[dict[str, Any], bytes],
) -> None:
    claims, blind_factor = oprf_claims
    flow = make_flow(signing_expected=True)
    token = sign(signing_key, claims, "unknown-key")
    encrypted = flow.wrap(token, "JWT")

    result = flow.client.post(
        "/process",
        json={
            "jwe": encrypted,
            "blind_factor": b64(blind_factor),
            "label": "aes-key",
            "mechanism": "AES_CBC",
        },
    )

    assert result.status_code == 400
    assert result.json() == {"error": "Invalid JWE"}


def test_jwks_timeout_returns_503_without_further_processing(
    make_flow: Callable[..., Flow],
    signing_key: jwk.JWK,
    oprf_claims: tuple[dict[str, Any], bytes],
    mocker: MockerFixture,
) -> None:
    claims, blind_factor = oprf_claims
    flow = make_flow(signing_expected=True)
    token = sign(signing_key, claims)
    flow.http.side_effect = requests.Timeout("JWKS request timed out")
    unblind = mocker.spy(pyoprf, "unblind")
    hash_spy = mocker.spy(flow.crypto, "hash")
    encrypt_spy = mocker.spy(flow.crypto, "encrypt_aes")
    encrypted = flow.wrap(token, "JWT")

    result = flow.client.post(
        "/process",
        json={
            "jwe": encrypted,
            "blind_factor": b64(blind_factor),
            "label": "aes-key",
            "mechanism": "AES_CBC",
        },
    )

    assert result.status_code == 503
    assert result.json() == {"error": "Pseudonym verification unavailable"}
    unblind.assert_not_called()
    hash_spy.assert_not_called()
    encrypt_spy.assert_not_called()


def test_process_requires_label(
    make_flow: Callable[..., Flow],
) -> None:
    flow = make_flow(signing_expected=False, configure_jwks=False)
    body = {
        "jwe": "JWE",
        "blind_factor": "BF",
        "mechanism": "AES_CBC",
    }

    result = flow.client.post("/process", json=body)

    assert result.status_code == 422
    assert result.json()["detail"][0]["loc"] == ["body", "label"]


def test_unsigned_mode_never_contacts_jwks(
    make_flow: Callable[..., Flow],
    oprf_claims: tuple[dict[str, Any], bytes],
) -> None:
    claims, blind_factor = oprf_claims
    flow = make_flow(signing_expected=False, configure_jwks=True)
    flow.http.side_effect = requests.Timeout()

    health = flow.client.get("/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok", "components": {"hsm_api": "ok"}}
    assert (
        flow.post(
            json.dumps(claims).encode(), "application/json", blind_factor
        ).status_code
        == 200
    )
    flow.http.assert_not_called()


def test_health_populates_the_jwks_cache_used_by_process(
    make_flow: Callable[..., Flow],
    signing_key: jwk.JWK,
    oprf_claims: tuple[dict[str, Any], bytes],
) -> None:
    claims, blind_factor = oprf_claims
    flow = make_flow(signing_expected=True)

    health = flow.client.get("/health")
    assert health.status_code == 200
    assert health.json() == {
        "status": "ok",
        "components": {"hsm_api": "ok", "jwks": "ok"},
    }
    assert flow.http.call_count == 1
    assert flow.post(sign(signing_key, claims), "JWT", blind_factor).status_code == 200
    assert flow.http.call_count == 1


def test_health_reports_jwks_network_failure(
    make_flow: Callable[..., Flow],
) -> None:
    flow = make_flow(signing_expected=True)
    flow.http.side_effect = requests.Timeout()

    health = flow.client.get("/health")
    assert health.status_code == 503
    assert health.json() == {
        "status": "error",
        "components": {"hsm_api": "ok", "jwks": "error"},
    }
    assert flow.http.call_count == 1
