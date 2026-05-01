from unittest.mock import mock_open

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pytest_mock import MockerFixture

from app.routers.default import router as default_router


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(default_router)
    return TestClient(app)


def test_index_returns_logo_and_version(client: TestClient, mocker: MockerFixture) -> None:
    mocker.patch("builtins.open", mock_open(read_data='{"version": "1.2.3", "git_ref": "abcd"}'))

    response = client.get("/")

    assert response.status_code == 200
    assert "NVI Crypto Service" in response.text
    assert "Version: 1.2.3" in response.text
    assert "Commit: abcd" in response.text


def test_index_handles_missing_version_file(client: TestClient, mocker: MockerFixture) -> None:
    mocker.patch("builtins.open", side_effect=FileNotFoundError)

    response = client.get("/")

    assert response.status_code == 200
    assert "No version information found" in response.text


def test_version_json_returns_payload(client: TestClient, mocker: MockerFixture) -> None:
    mocker.patch("builtins.open", mock_open(read_data='{"version": "1.0.0", "git_ref": "xyz"}'))
    response = client.get("/version.json")
    assert response.status_code == 200
    assert response.json() == {"version": "1.0.0", "git_ref": "xyz"}


def test_version_json_returns_404_when_missing(client: TestClient, mocker: MockerFixture) -> None:
    mocker.patch("builtins.open", side_effect=FileNotFoundError)
    response = client.get("/version.json")
    assert response.status_code == 404
    assert response.json() == {"detail": "Version info could not be loaded."}
