from collections.abc import Iterator
from unittest.mock import MagicMock

import inject
import pytest
from fastapi.testclient import TestClient

from app import application
from app.config import Config
from app.exceptions.exception import KeyNotFoundError
from app.services.crypto.crypto_service import CryptoService
from app.services.pseudonym_service import PseudonymService


def _client(crypto_stub: MagicMock) -> Iterator[TestClient]:
    def _bind(binder: inject.Binder) -> None:
        binder.bind(CryptoService, crypto_stub)
        binder.bind(PseudonymService, PseudonymService(crypto_stub))

    inject.clear_and_configure(_bind)
    yield TestClient(application.setup_fastapi())
    inject.clear()


@pytest.fixture
def enabled_client(use_config: Config, crypto_stub: MagicMock) -> Iterator[TestClient]:
    use_config.app.test_endpoints_enabled = True
    yield from _client(crypto_stub)


def test_test_endpoints_are_disabled_by_default(
    use_config: Config, client: TestClient
) -> None:
    assert use_config.app.test_endpoints_enabled is False

    response = client.get("/test/public_key/sk")

    assert response.status_code == 404
    assert "/test/public_key/{key_id}" not in client.app.openapi()["paths"]  # type: ignore[attr-defined]


def test_public_key_returned_for_configured_jwe_key(
    enabled_client: TestClient, crypto_stub: MagicMock
) -> None:
    crypto_stub.get_public_key.return_value = "PEM"

    response = enabled_client.get("/test/public_key/sk")

    assert response.status_code == 200
    assert response.json() == {"kid": "sk", "pem": "PEM"}


@pytest.mark.parametrize("key_id", ["hashing-key", "some-aes-label"])
def test_public_key_refused_for_other_labels(
    enabled_client: TestClient, crypto_stub: MagicMock, key_id: str
) -> None:
    # The crypto service decides which keys are allowed; the endpoint maps its refusal to 404
    crypto_stub.get_public_key.side_effect = KeyNotFoundError()

    response = enabled_client.get(f"/test/public_key/{key_id}")

    assert response.status_code == 404
    assert response.json() == {"error": "Key not found"}
    crypto_stub.get_public_key.assert_called_once_with(key_id)
