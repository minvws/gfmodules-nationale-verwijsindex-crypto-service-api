from typing import Iterator
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pytest_mock import MockerFixture

from app.container import get_crypto_service
from app.logging.events import HEALTH_UNHEALTHY
from app.routers import health as health_module
from app.routers.health import router as health_router


@pytest.fixture
def client(crypto_mock: MagicMock) -> Iterator[TestClient]:
    app = FastAPI()
    app.include_router(health_router)
    app.dependency_overrides[get_crypto_service] = lambda: crypto_mock
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_health_returns_ok_when_crypto_healthy(client: TestClient, crypto_mock: MagicMock) -> None:
    crypto_mock.health_check.return_value = True

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "components": {"hsm_api": "ok"}}


def test_health_returns_503_when_crypto_unhealthy(client: TestClient, crypto_mock: MagicMock) -> None:
    crypto_mock.health_check.return_value = False

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json() == {"status": "error", "components": {"hsm_api": "error"}}


def test_health_logs_health_unhealthy_when_crypto_unhealthy(
    client: TestClient, crypto_mock: MagicMock, mocker: MockerFixture
) -> None:
    crypto_mock.health_check.return_value = False
    log_event = mocker.patch("app.routers.health.log_event")

    client.get("/health")

    log_event.assert_called_once_with(
        health_module.logger,
        HEALTH_UNHEALTHY,
        "Health check unhealthy",
        unhealthy_component="hsm_api",
        status="error",
        error_detail="",
    )


def test_health_does_not_log_when_healthy(
    client: TestClient, crypto_mock: MagicMock, mocker: MockerFixture
) -> None:
    crypto_mock.health_check.return_value = True
    log_event = mocker.patch("app.routers.health.log_event")

    client.get("/health")

    log_event.assert_not_called()
