import json
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests
from jwcrypto import jwk
from pytest_mock import MockerFixture

from app.config import ConfigPseudonym
from app.exceptions.exception import InvalidSignedPseudonymError, JwksUnavailableError
from app.services.pseudonym_jwks import PseudonymJwksService

JWKS_URL = "https://prs.example/.well-known/jwks"


@pytest.fixture(scope="module")
def generated_jwks() -> dict[str, Any]:
    keys = []
    for kid in ("key-1", "key-2"):
        public = jwk.JWK.generate(kty="RSA", size=3072).export_public(as_dict=True)
        keys.append({**public, "kid": kid, "alg": "PS256", "use": "sig"})
    return {"keys": keys}


def jwks_response(document: Any) -> requests.Response:
    result = requests.Response()
    result.status_code = 200
    result._content = (
        document if isinstance(document, bytes) else json.dumps(document).encode()
    )
    result.headers["Cache-Control"] = "public, max-age=900"
    return result


@pytest.fixture
def http(mocker: MockerFixture, generated_jwks: dict[str, Any]) -> MagicMock:
    return mocker.patch(
        "app.services.http.request", return_value=jwks_response(generated_jwks)
    )


def make_service() -> PseudonymJwksService:
    return PseudonymJwksService(
        ConfigPseudonym(
            jwks_url=JWKS_URL,
            expected_issuer="https://prs.example",
            expected_audience="oin:00000099000000001000",
        )
    )


def test_get_keys_shares_cache_with_health_and_key_selection(
    generated_jwks: dict[str, Any], http: MagicMock
) -> None:
    service = make_service()

    keys = service.get_keys()

    assert isinstance(keys, jwk.JWKSet)
    assert service.get_keys() is keys
    assert service.health_check() is True
    assert (
        service.get_key("key-1").export_public(as_dict=True)
        == generated_jwks["keys"][0]
    )
    assert http.call_count == 1


def test_unknown_kid_does_not_refresh_or_discard_a_fresh_cache(
    generated_jwks: dict[str, Any], http: MagicMock
) -> None:
    service = make_service()
    kid = generated_jwks["keys"][0]["kid"]
    assert service.get_key(kid).get("kid") == kid

    with pytest.raises(InvalidSignedPseudonymError):
        service.get_key("unknown")

    assert service.get_key(kid).get("kid") == kid
    assert http.call_count == 1


def test_identical_duplicate_keys_are_deduplicated(
    generated_jwks: dict[str, Any], http: MagicMock
) -> None:
    key = generated_jwks["keys"][0]
    http.return_value = jwks_response({"keys": [key, key]})

    service = make_service()
    assert len(service.get_keys()["keys"]) == 1
    assert service.get_key(key["kid"]).get("kid") == key["kid"]


@pytest.mark.parametrize(
    "identifier",
    [{}, {"kid": "  "}, {"kid": []}],
)
def test_keys_without_valid_kid_are_skipped_before_import(
    generated_jwks: dict[str, Any], http: MagicMock, identifier: dict[str, Any]
) -> None:
    key = generated_jwks["keys"][0]
    # The unusable key material must not be imported when there is no valid kid.
    http.return_value = jwks_response({"keys": [key, {"kty": "RSA", **identifier}]})
    service = make_service()

    keys = service.get_keys()

    assert {entry.get("kid") for entry in keys["keys"]} == {"key-1"}
    assert service.get_key("key-1").export_public(as_dict=True) == key
    assert service.health_check() is True
    assert http.call_count == 1


def test_same_kid_and_key_material_with_conflicting_metadata_is_rejected(
    generated_jwks: dict[str, Any], http: MagicMock
) -> None:
    key = generated_jwks["keys"][0]
    http.return_value = jwks_response({"keys": [key, {**key, "use": "enc"}]})

    with pytest.raises(JwksUnavailableError, match="duplicate signing key IDs"):
        make_service().get_keys()


def test_conflicting_kids_fail_health_and_are_not_cached(
    generated_jwks: dict[str, Any], http: MagicMock
) -> None:
    key = generated_jwks["keys"][0]
    other = {**generated_jwks["keys"][1], "kid": key["kid"]}
    http.side_effect = [
        jwks_response({"keys": [key, other]}),
        jwks_response({"keys": [key]}),
    ]
    service = make_service()

    assert service.health_check() is False
    assert service.get_key(key["kid"]).export_public(as_dict=True) == key
    assert http.call_count == 2


def test_unexpected_fetch_errors_are_normalized(
    http: MagicMock,
) -> None:
    http.side_effect = RuntimeError("transport failure")
    service = make_service()

    with pytest.raises(
        JwksUnavailableError, match="^Could not retrieve or parse JWKS$"
    ):
        service.get_keys()

    assert service.health_check() is False


def test_only_unidentified_keys_produce_an_empty_cached_set(http: MagicMock) -> None:
    http.return_value = jwks_response({"keys": [{}, {"kid": "  ", "kty": "RSA"}]})
    service = make_service()

    assert not service.get_keys()["keys"]
    assert service.health_check() is True
    with pytest.raises(InvalidSignedPseudonymError):
        service.get_key("missing")
    assert http.call_count == 1
