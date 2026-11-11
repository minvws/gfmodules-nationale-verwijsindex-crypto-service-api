from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from gfmodules.logging.testing import capture_records
from pytest_mock import MockerFixture

from app.container import get_crypto_service, get_pseudonym_jwks_service
from app.logging.events import Log
from app.routers import health as health_module
from app.routers.health import router as health_router
from app.services.pseudonym_jwks import PseudonymJwksService


@pytest.fixture
def client(crypto_mock: MagicMock) -> Iterator[TestClient]:
    app = FastAPI()
    app.include_router(health_router)
    app.dependency_overrides[get_crypto_service] = lambda: crypto_mock
    app.dependency_overrides[get_pseudonym_jwks_service] = lambda: None
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


@pytest.mark.parametrize(
    "hsm_ok,jwks_ok,expected_status,expected_components",
    [
        (True, True, 200, {"hsm_api": "ok", "jwks": "ok"}),
        (True, False, 503, {"hsm_api": "ok", "jwks": "error"}),
        (False, True, 503, {"hsm_api": "error", "jwks": "ok"}),
    ],
)
def test_health_reports_hsm_and_jwks_status(
    crypto_mock: MagicMock,
    hsm_ok: bool,
    jwks_ok: bool,
    expected_status: int,
    expected_components: dict[str, str],
) -> None:
    jwks_service = MagicMock(spec=PseudonymJwksService)
    jwks_service.health_check.return_value = jwks_ok
    crypto_mock.health_check.return_value = hsm_ok
    app = FastAPI()
    app.include_router(health_router)
    app.dependency_overrides[get_crypto_service] = lambda: crypto_mock
    app.dependency_overrides[get_pseudonym_jwks_service] = lambda: jwks_service

    response = TestClient(app).get("/health")

    assert response.status_code == expected_status
    assert response.json() == {
        "status": "ok" if expected_status == 200 else "error",
        "components": expected_components,
    }
