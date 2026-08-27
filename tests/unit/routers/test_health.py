from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from gfmodules.logging.testing import capture_records
from pytest_mock import MockerFixture

from app.container import get_crypto_service
from app.logging.events import Log
from app.routers import health as health_module
from app.routers.health import router as health_router


@pytest.fixture
def client(crypto_mock: MagicMock) -> Iterator[TestClient]:
    app = FastAPI()
    app.include_router(health_router)
    app.dependency_overrides[get_crypto_service] = lambda: crypto_mock
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_health_returns_ok_when_crypto_healthy(
    client: TestClient, crypto_mock: MagicMock
) -> None:
    crypto_mock.health_check.return_value = True

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "components": {"hsm_api": "ok"}}


def test_health_returns_503_when_crypto_unhealthy(
    client: TestClient, crypto_mock: MagicMock
) -> None:
    crypto_mock.health_check.return_value = False

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json() == {"status": "error", "components": {"hsm_api": "error"}}


def test_health_logs_health_unhealthy_when_crypto_unhealthy(
    client: TestClient, crypto_mock: MagicMock, mocker: MockerFixture
) -> None:
    crypto_mock.health_check.return_value = False

    with capture_records(health_module.logger.name) as captured:
        client.get("/health")

    unhealthy: list[Any] = [
        entry.record
        for entry in captured.entries
        if getattr(entry.record, "event_id", None) == Log.HEALTH_UNHEALTHY.event_id
    ]
    assert len(unhealthy) == 1
    record = unhealthy[0]
    assert record.unhealthy_component == "hsm_api"
    assert record.status == "error"


def test_health_does_not_log_when_healthy(
    client: TestClient, crypto_mock: MagicMock, mocker: MockerFixture
) -> None:
    crypto_mock.health_check.return_value = True

    with capture_records(health_module.logger.name) as captured:
        client.get("/health")

    assert [
        entry for entry in captured.entries if hasattr(entry.record, "event_id")
    ] == []
