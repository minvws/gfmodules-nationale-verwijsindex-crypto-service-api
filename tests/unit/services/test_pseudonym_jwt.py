import base64
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from email.utils import formatdate
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests
from jwcrypto import jwk, jws
from pytest_mock import MockerFixture

from app.config import ConfigPseudonym
from app.exceptions.exception import InvalidSignedPseudonymError, JwksUnavailableError
from app.services.pseudonym_jwks import PseudonymJwksService
from app.services.pseudonym_jwt import PseudonymJwtVerifier

NOW = 1_750_000_000
ISSUER = "https://prs.example"
AUDIENCE = "oin:00000099000000001000"
JWKS_URL = "https://prs.example/.well-known/jwks"


@pytest.fixture(scope="module")
def signing_key() -> jwk.JWK:
    return jwk.JWK.generate(kty="RSA", size=3072)


@pytest.fixture(scope="module")
def rotated_key() -> jwk.JWK:
    return jwk.JWK.generate(kty="RSA", size=3072)


def public_key(key: jwk.JWK, kid: str = "key-1") -> dict[str, Any]:
    return {**key.export_public(as_dict=True), "kid": kid, "use": "sig", "alg": "PS256"}


@pytest.fixture
def claims() -> dict[str, Any]:
    return {
        "subject": "pseudonym:eval:YWJj",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "scope": "test",
        "version": "1.1",
        "iat": NOW - 120,
        "exp": NOW + 300,
    }


def sign(
    key: jwk.JWK, claims: dict[str, Any], header: dict[str, Any] | None = None
) -> str:
    protected = {"alg": "PS256", "typ": "JWT", "kid": "key-1"}
    if header:
        protected.update(header)
    protected = {name: value for name, value in protected.items() if value is not None}
    token = jws.JWS(json.dumps(claims).encode())
    token.add_signature(key, protected=json.dumps(protected))
    return str(token.serialize(compact=True))


def response(
    document: Any,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> requests.Response:
    result = requests.Response()
    result.status_code = status
    result._content = (
        document if isinstance(document, bytes) else json.dumps(document).encode()
    )
    result.headers.update(headers or {})
    return result


def cached_response(document: Any, max_age: int = 900) -> requests.Response:
    return response(
        document,
        headers={
            "Cache-Control": f"public, max-age={max_age}",
            "Date": formatdate(NOW, usegmt=True),
        },
    )


@pytest.fixture
def clock(mocker: MockerFixture) -> SimpleNamespace:
    clock = SimpleNamespace(now=float(NOW))
    mocker.patch(
        "jwcrypto.jwt.time",
        SimpleNamespace(time=lambda: clock.now),
    )
    mocker.patch(
        "app.services.pseudonym_jwks.time",
        SimpleNamespace(time=lambda: clock.now, monotonic=lambda: clock.now),
    )
    return clock


@pytest.fixture
def http(mocker: MockerFixture, signing_key: jwk.JWK) -> MagicMock:
    return mocker.patch(
        "app.services.http.request",
        return_value=cached_response({"keys": [public_key(signing_key)]}),
    )


@pytest.fixture
def jwks_service(clock: SimpleNamespace) -> PseudonymJwksService:
    return PseudonymJwksService(
        ConfigPseudonym(
            jwks_url=JWKS_URL, expected_issuer=ISSUER, expected_audience=AUDIENCE
        )
    )


@pytest.fixture
def verifier(
    clock: SimpleNamespace, jwks_service: PseudonymJwksService
) -> PseudonymJwtVerifier:
    config = ConfigPseudonym(
        jwks_url=JWKS_URL, expected_issuer=ISSUER, expected_audience=AUDIENCE
    )
    return PseudonymJwtVerifier(config, jwks_service)


def test_verifies_signed_prs_claims(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
) -> None:
    assert verifier.verify(sign(signing_key, claims)) == claims
    assert http.call_args.kwargs["url"] == JWKS_URL
    assert http.call_args.kwargs["method"] == "GET"
    assert http.call_args.kwargs["timeout"] == 5
    assert http.call_args.kwargs["allow_redirects"] is False
    assert http.call_args.kwargs.get("verify", True) is True


def test_verifier_uses_injected_jwks_service(
    clock: SimpleNamespace, signing_key: jwk.JWK, claims: dict[str, Any]
) -> None:
    jwks_service = MagicMock(spec=PseudonymJwksService)
    jwks_service.get_key.return_value = signing_key.public()
    config = ConfigPseudonym(
        jwks_url=JWKS_URL, expected_issuer=ISSUER, expected_audience=AUDIENCE
    )

    verifier = PseudonymJwtVerifier(config, jwks_service)
    assert verifier.verify(sign(signing_key, claims)) == claims
    jwks_service.get_key.assert_called_once_with("key-1")


@pytest.mark.parametrize(
    "tls_settings, expected_verify, expected_cert",
    [
        ({}, True, None),
        ({"verify_ca": False}, False, None),
        ({"verify_ca": "/tls/ca.pem"}, "/tls/ca.pem", None),
        ({"cert_path": "/tls/combined.pem"}, True, "/tls/combined.pem"),
        (
            {
                "verify_ca": "/tls/ca.pem",
                "cert_path": "/tls/client.crt",
                "key_path": "/tls/client.key",
            },
            "/tls/ca.pem",
            ("/tls/client.crt", "/tls/client.key"),
        ),
    ],
)
def test_jwks_request_uses_its_own_tls_settings(
    clock: SimpleNamespace,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    tls_settings: dict[str, Any],
    expected_verify: str | bool,
    expected_cert: str | tuple[str, str] | None,
) -> None:
    config = ConfigPseudonym.model_validate(
        {
            "jwks_url": JWKS_URL,
            "expected_issuer": ISSUER,
            "expected_audience": AUDIENCE,
            **tls_settings,
        }
    )

    verifier = PseudonymJwtVerifier(config, PseudonymJwksService(config))
    assert verifier.verify(sign(signing_key, claims)) == claims
    assert http.call_args.kwargs.get("verify", True) == expected_verify
    assert http.call_args.kwargs.get("cert") == expected_cert
    assert http.call_args.kwargs["allow_redirects"] is False


def test_rejects_tampered_signature_without_an_extra_fetch(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
) -> None:
    token = sign(signing_key, claims)
    verifier.verify(token)
    header, payload, signature = token.split(".")
    modified = base64.urlsafe_b64encode(b'{"subject":"altered"}').rstrip(b"=").decode()
    assert modified != payload

    with pytest.raises(
        InvalidSignedPseudonymError,
        match="^Signed pseudonym has an invalid signature or claims$",
    ):
        verifier.verify(f"{header}.{modified}.{signature}")
    assert http.call_count == 1


@pytest.mark.parametrize(
    "header",
    [
        {"kid": None},
        {"kid": ""},
        {"alg": "RS256"},
    ],
)
def test_rejects_missing_keys_and_disallowed_algorithms(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    header: dict[str, Any],
) -> None:
    token = sign(signing_key, claims, header)
    with pytest.raises(InvalidSignedPseudonymError):
        verifier.verify(token)


@pytest.mark.parametrize(
    "header",
    [
        {"jku": "https://attacker.test/jwks"},
        {"jwk": {"kty": "oct", "k": "YWJj"}},
    ],
)
def test_uses_configured_jwks_without_custom_header_policy(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    header: dict[str, Any],
) -> None:
    assert verifier.verify(sign(signing_key, claims, header)) == claims
    assert http.call_count == 1
    assert http.call_args.kwargs["url"] == JWKS_URL


def test_rejects_hs256_even_if_cryptographically_valid(
    verifier: PseudonymJwtVerifier, claims: dict[str, Any], http: MagicMock
) -> None:
    key = jwk.JWK.generate(kty="oct", size=256)
    token = sign(key, claims, {"alg": "HS256"})
    with pytest.raises(InvalidSignedPseudonymError):
        verifier.verify(token)


@pytest.mark.parametrize(
    "token",
    ["not-a-jws", "eyJhbGciOiJub25lIn0.e30.", ""],
)
def test_rejects_invalid_compact_serialization(
    verifier: PseudonymJwtVerifier, http: MagicMock, token: str
) -> None:
    with pytest.raises(InvalidSignedPseudonymError):
        verifier.verify(token)


@pytest.mark.parametrize(
    "field,value",
    [
        ("iss", "other"),
        ("iss", None),
        ("aud", "other"),
        ("aud", None),
        ("iat", None),
        ("exp", None),
        ("exp", NOW - 61),
    ],
)
def test_rejects_invalid_claims(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    field: str,
    value: Any,
) -> None:
    if value is None:
        claims.pop(field, None)
    else:
        claims[field] = value
    token = sign(signing_key, claims)
    with pytest.raises(
        InvalidSignedPseudonymError,
        match="^Signed pseudonym has an invalid signature or claims$",
    ):
        verifier.verify(token)


@pytest.mark.parametrize("audience", [AUDIENCE, ["other", AUDIENCE]])
def test_accepts_audience_and_clock_skew(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    audience: Any,
) -> None:
    claims.update(aud=audience, iat=NOW - 300, exp=NOW - 59, nbf=NOW + 60)
    assert verifier.verify(sign(signing_key, claims)) == claims


@pytest.mark.parametrize(
    "field,value,expected_error",
    [
        ("kty", "EC", "Could not retrieve or parse JWKS"),
        ("use", "enc", "JWKS signing key is invalid or unsuitable"),
        ("alg", "RS256", "JWKS signing key is invalid or unsuitable"),
        ("n", None, "Could not retrieve or parse JWKS"),
    ],
)
def test_incompatible_selected_key_is_a_service_error(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    field: str,
    value: Any,
    expected_error: str,
) -> None:
    key = public_key(signing_key)
    if value is None:
        key.pop(field)
    else:
        key[field] = value
    http.return_value = cached_response({"keys": [key]})
    token = sign(signing_key, claims)
    with pytest.raises(JwksUnavailableError, match=f"^{expected_error}$"):
        verifier.verify(token)


def test_selected_rsa_key_must_be_at_least_3072_bits(
    verifier: PseudonymJwtVerifier,
    claims: dict[str, Any],
    http: MagicMock,
) -> None:
    key = jwk.JWK.generate(kty="RSA", size=2048)
    http.return_value = cached_response({"keys": [public_key(key)]})
    token = sign(key, claims)
    with pytest.raises(JwksUnavailableError):
        verifier.verify(token)


@pytest.mark.parametrize("operations", [["sign"], "verify", ["verify", 1]])
def test_selected_key_must_allow_verification(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    operations: Any,
) -> None:
    key = public_key(signing_key)
    key["key_ops"] = operations
    http.return_value = cached_response({"keys": [key]})
    token = sign(signing_key, claims)
    with pytest.raises(JwksUnavailableError):
        verifier.verify(token)


def test_selected_key_can_explicitly_permit_verification(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
) -> None:
    key = public_key(signing_key)
    key["key_ops"] = ["verify"]
    http.return_value = cached_response({"keys": [key]})
    assert verifier.verify(sign(signing_key, claims)) == claims


def test_unusable_selected_key_is_not_cached(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
) -> None:
    bad_key = public_key(signing_key)
    bad_key["use"] = "enc"
    http.side_effect = [
        cached_response({"keys": [bad_key]}),
        cached_response({"keys": [public_key(signing_key)]}),
    ]
    token = sign(signing_key, claims)
    with pytest.raises(JwksUnavailableError):
        verifier.verify(token)
    assert verifier.verify(token) == claims
    assert http.call_count == 2


def test_invalid_jwks_after_expiration_is_not_cached(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    rotated_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    clock: SimpleNamespace,
) -> None:
    old_key = public_key(signing_key)
    new_key = public_key(rotated_key, "key-2")
    claims["exp"] = NOW + 5000
    http.side_effect = [
        cached_response({"keys": [old_key]}),
        cached_response({"keys": [new_key, public_key(signing_key, "key-2")]}),
        cached_response({"keys": [old_key, new_key]}),
    ]
    old_token = sign(signing_key, claims)
    verifier.verify(old_token)
    clock.now += 300
    new_token = sign(rotated_key, claims, {"kid": "key-2"})
    with pytest.raises(JwksUnavailableError):
        verifier.verify(new_token)
    assert verifier.verify(new_token) == claims
    assert http.call_count == 3


@pytest.mark.parametrize(
    "document",
    [b"not-json", {}, {"keys": [42]}, {"keys": [{"kty": "RSA", "kid": "key-1"}]}],
)
def test_invalid_jwks_is_not_cached(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    document: Any,
) -> None:
    http.side_effect = [
        cached_response(document),
        cached_response({"keys": [public_key(signing_key)]}),
    ]
    token = sign(signing_key, claims)
    with pytest.raises(JwksUnavailableError):
        verifier.verify(token)
    assert verifier.verify(token) == claims
    assert http.call_count == 2


@pytest.mark.parametrize("status", [302, 404, 503])
def test_http_errors_and_redirects_are_service_errors(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    status: int,
) -> None:
    http.return_value = response({}, status=status)
    token = sign(signing_key, claims)
    with pytest.raises(JwksUnavailableError):
        verifier.verify(token)


@pytest.mark.parametrize(
    "error",
    [requests.Timeout(), requests.ConnectionError(), requests.exceptions.SSLError()],
)
def test_jwks_network_failure_is_a_service_error(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    error: Exception,
) -> None:
    http.side_effect = error
    token = sign(signing_key, claims)
    with pytest.raises(JwksUnavailableError):
        verifier.verify(token)


def test_empty_keys_and_unknown_kid_are_client_errors(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
) -> None:
    http.return_value = cached_response({"keys": []})
    token = sign(signing_key, claims)
    with pytest.raises(
        InvalidSignedPseudonymError, match="^JWS signing key is not present in JWKS$"
    ) as exc:
        verifier.verify(token)
    assert exc.value.error_message == "Invalid JWE"
    assert http.call_count == 1


def test_reuses_fresh_jwks_and_fetches_after_expiration(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    clock: SimpleNamespace,
) -> None:
    claims["exp"] = NOW + 5000
    token = sign(signing_key, claims)
    verifier.verify(token)
    clock.now += 299
    verifier.verify(token)
    assert http.call_count == 1
    clock.now += 1
    verifier.verify(token)
    assert http.call_count == 2


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Cache-Control": "no-store, max-age=900"},
        {"Cache-Control": "max-age=86400"},
    ],
)
def test_jwks_cache_ignores_http_freshness_headers(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    headers: dict[str, str],
    clock: SimpleNamespace,
) -> None:
    http.return_value = response({"keys": [public_key(signing_key)]}, headers=headers)
    claims["exp"] = NOW + 5000
    token = sign(signing_key, claims)
    assert verifier.verify(token) == claims
    clock.now += 299
    assert verifier.verify(token) == claims
    assert http.call_count == 1
    clock.now += 1
    assert verifier.verify(token) == claims
    assert http.call_count == 2


def test_new_kid_is_rejected_until_the_cache_expires(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    rotated_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    clock: SimpleNamespace,
) -> None:
    old = public_key(signing_key)
    new = public_key(rotated_key, "key-2")
    claims["exp"] = NOW + 5000
    http.side_effect = [
        cached_response({"keys": [old]}),
        cached_response({"keys": [old, new]}),
    ]
    old_token = sign(signing_key, claims)
    new_token = sign(rotated_key, claims, {"kid": "key-2"})
    assert verifier.verify(old_token) == claims

    with pytest.raises(InvalidSignedPseudonymError):
        verifier.verify(new_token)
    assert verifier.verify(old_token) == claims
    assert http.call_count == 1

    clock.now += 300
    assert verifier.verify(new_token) == claims
    assert verifier.verify(old_token) == claims
    assert http.call_count == 2


def test_concurrent_requests_share_a_jwks_fetch(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    rotated_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
) -> None:
    old_key = public_key(signing_key)
    entered = threading.Event()
    release = threading.Event()

    def fetch(*args: Any, **kwargs: Any) -> requests.Response:
        entered.set()
        if not release.wait(5):
            raise requests.Timeout()
        return cached_response({"keys": [old_key]})

    http.side_effect = fetch
    old_token = sign(signing_key, claims)
    new_token = sign(rotated_key, claims, {"kid": "key-2"})
    with ThreadPoolExecutor(max_workers=2) as executor:
        unknown_request = executor.submit(verifier.verify, new_token)
        try:
            assert entered.wait(2)
            cached_verification = executor.submit(verifier.verify, old_token)
        finally:
            release.set()
        with pytest.raises(InvalidSignedPseudonymError):
            unknown_request.result(timeout=2)
        assert cached_verification.result(timeout=2) == claims
    assert http.call_count == 1


def test_unknown_kid_on_initial_fetch_still_populates_the_cache(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
) -> None:
    unknown = sign(signing_key, claims, {"kid": "unknown"})
    with pytest.raises(InvalidSignedPseudonymError):
        verifier.verify(unknown)
    with pytest.raises(InvalidSignedPseudonymError):
        verifier.verify(unknown)
    assert verifier.verify(sign(signing_key, claims)) == claims
    assert http.call_count == 1


def test_expired_jwks_is_not_used_on_network_error(
    verifier: PseudonymJwtVerifier,
    signing_key: jwk.JWK,
    claims: dict[str, Any],
    http: MagicMock,
    clock: SimpleNamespace,
) -> None:
    http.side_effect = [
        cached_response({"keys": [public_key(signing_key)]}),
        requests.Timeout(),
    ]
    claims["exp"] = NOW + 5000
    token = sign(signing_key, claims)
    verifier.verify(token)
    clock.now += 300
    with pytest.raises(JwksUnavailableError):
        verifier.verify(token)


def test_health_uses_a_fresh_cache_when_endpoint_is_unreachable(
    jwks_service: PseudonymJwksService, http: MagicMock
) -> None:
    assert jwks_service.health_check() is True
    http.side_effect = requests.Timeout()
    assert jwks_service.health_check() is True
    assert http.call_count == 1


def test_health_does_not_use_expired_cache_on_fetch_failure(
    jwks_service: PseudonymJwksService, http: MagicMock, clock: SimpleNamespace
) -> None:
    assert jwks_service.health_check() is True
    clock.now += 300
    http.side_effect = requests.Timeout()
    assert jwks_service.health_check() is False
    assert http.call_count == 2


def test_health_fetch_uses_jwks_tls_and_timeout_settings(
    clock: SimpleNamespace, http: MagicMock
) -> None:
    jwks_service = PseudonymJwksService(
        ConfigPseudonym(
            jwks_url=JWKS_URL,
            expected_issuer=ISSUER,
            expected_audience=AUDIENCE,
            timeout=12,
            verify_ca="/tls/ca.pem",
            cert_path="/tls/client.crt",
            key_path="/tls/client.key",
        )
    )
    assert jwks_service.health_check() is True
    http.assert_called_once_with(
        method="GET",
        url=JWKS_URL,
        params=None,
        headers={},
        timeout=12,
        allow_redirects=False,
        verify="/tls/ca.pem",
        cert=("/tls/client.crt", "/tls/client.key"),
    )
