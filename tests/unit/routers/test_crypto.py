from typing import Iterator
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import container
from app.config import Config
from app.exceptions.exception import CryptoError, InvalidJweError, KeyNotFoundError
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


def test_decrypt_and_hash_returns_hashed_pseudonym(
    client: TestClient, pseudonym_mock: MagicMock
) -> None:
    pseudonym_mock.decrypt_and_unblind.return_value = b"unblinded"
    pseudonym_mock.hash.return_value = "HASHED"

    response = client.get("/decrypt_and_hash", params={"jwe": "JWE", "blind_factor": "BF"})

    assert response.status_code == 200
    assert response.json() == {"hashed_pseudonym": "HASHED"}
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
def test_decrypt_and_hash_maps_crypto_errors(
    client: TestClient, pseudonym_mock: MagicMock, exc: CryptoError, status: int
) -> None:
    pseudonym_mock.decrypt_and_unblind.side_effect = exc

    response = client.get("/decrypt_and_hash", params={"jwe": "X", "blind_factor": "Y"})

    assert response.status_code == status
    assert response.json() == {"error": exc.error_message}


def test_decrypt_and_hash_requires_query_params(client: TestClient) -> None:
    response = client.get("/decrypt_and_hash")
    assert response.status_code == 422
