from typing import Dict
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient


@pytest.mark.parametrize(
    "healthy,expected_status,expected_body",
    [
        (True, 200, {"status": "ok", "components": {"hsm_api": "ok"}}),
        (False, 503, {"status": "error", "components": {"hsm_api": "error"}}),
    ],
    ids=["healthy", "unhealthy"],
)
def test_health_endpoint_reflects_crypto_status(
    client: TestClient,
    crypto_stub: MagicMock,
    healthy: bool,
    expected_status: int,
    expected_body: Dict[str, object],
) -> None:
    crypto_stub.health_check.return_value = healthy

    response = client.get("/health")

    assert response.status_code == expected_status
    assert response.json() == expected_body


def test_root_returns_logo_through_full_app(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "NVI Crypto Service" in response.text
