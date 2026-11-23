from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient


@pytest.mark.parametrize(
    "health_error,expected_status,expected_body",
    [
        (None, 200, {"status": "ok", "components": {"hsm_api": "ok"}}),
        (
            "HSM API unreachable: Timeout",
            503,
            {"status": "error", "components": {"hsm_api": "error"}},
        ),
    ],
    ids=["healthy", "unhealthy"],
)
def test_health_endpoint_reflects_crypto_status(
    client: TestClient,
    crypto_stub: MagicMock,
    health_error: str | None,
    expected_status: int,
    expected_body: dict[str, object],
) -> None:
    crypto_stub.health_error.return_value = health_error

    response = client.get("/health")

    assert response.status_code == expected_status
    assert response.json() == expected_body


def test_root_returns_logo_through_full_app(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "NVI Crypto Service" in response.text
