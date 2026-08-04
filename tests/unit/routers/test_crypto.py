from collections.abc import Iterator
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import container
from app.config import Config
from app.exceptions.exception import CryptoError, InvalidJweError, KeyNotFoundError
from app.models.pseudonym import PseudonymResponse
from app.routers.crypto import router as crypto_router


@pytest.fixture
def client(
    crypto_mock: MagicMock, pseudonym_mock: MagicMock, use_config: Config
) -> Iterator[TestClient]:
    app = FastAPI()
    app.include_router(crypto_router)
    app.dependency_overrides[container.get_crypto_service] = lambda: crypto_mock
    app.dependency_overrides[container.get_pseudonym_service] = lambda: pseudonym_mock
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_process_returns_encrypted_pseudonym_with_iv(
    client: TestClient, pseudonym_mock: MagicMock
) -> None:
    pseudonym_mock.decrypt_and_unblind.return_value = b"unblinded"
    pseudonym_mock.hash.return_value = "HASHED"
    pseudonym_mock.encrypt_pseudonym.return_value = PseudonymResponse(
        encrypted_pseudonym="encrypted_data",
        iv="valid_iv",
    )

    response = client.post(
        "/process",
        json={
            "jwe": "JWE",
            "blind_factor": "BF",
            "label": "label-1",
            "mechanism": "AES_CBC",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "encrypted_pseudonym": "encrypted_data",
        "iv": "valid_iv",
    }
    pseudonym_mock.decrypt_and_unblind.assert_called_once_with("JWE", "BF")
    pseudonym_mock.hash.assert_called_once_with(b"unblinded")


@pytest.mark.parametrize(
    "exc,status",
    [
        (CryptoError(), 500),
        (KeyNotFoundError(), 404),
        (InvalidJweError(), 400),
    ],
    ids=["crypto", "key-not-found", "invalid-jwe"],
)
def test_process_maps_crypto_errors(
    client: TestClient, pseudonym_mock: MagicMock, exc: CryptoError, status: int
) -> None:
    pseudonym_mock.decrypt_and_unblind.side_effect = exc

    response = client.post(
        "/process",
        json={
            "jwe": "X",
            "blind_factor": "Y",
            "label": "label-1",
            "mechanism": "AES_CBC",
        },
    )

    assert response.status_code == status
    assert response.json() == {"error": exc.error_message}


def test_process_requires_query_params(client: TestClient) -> None:
    response = client.post("/process")
    assert response.status_code == 422
