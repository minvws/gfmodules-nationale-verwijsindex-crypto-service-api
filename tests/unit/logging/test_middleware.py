from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.logging.context import client_trace_id_var, ip_var, request_id_var
from app.logging.middleware import (
    CLIENT_TRACE_ID_HEADER,
    REQUEST_ID_HEADER,
    RequestContextMiddleware,
)


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.add_middleware(RequestContextMiddleware)

    @app.get("/ping")
    def _ping() -> dict[str, bool]:
        return {"ok": True}

    return TestClient(app)


def test_request_id_header_is_uuid(client: TestClient) -> None:
    response = client.get("/ping")
    assert REQUEST_ID_HEADER in response.headers
    UUID(response.headers[REQUEST_ID_HEADER])


def test_client_trace_id_echoed_when_provided(client: TestClient) -> None:
    response = client.get("/ping", headers={CLIENT_TRACE_ID_HEADER: "trace-1"})
    assert response.headers[CLIENT_TRACE_ID_HEADER] == "trace-1"


def test_client_trace_id_not_set_when_absent(client: TestClient) -> None:
    response = client.get("/ping")
    assert CLIENT_TRACE_ID_HEADER not in response.headers


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("bad<>chars!!", "badchars"),
        ("a" * 100, "a" * 64),
        ("ok-id_1", "ok-id_1"),
    ],
    ids=["sanitize", "truncate", "passthrough"],
)
def test_client_trace_id_is_sanitized(client: TestClient, raw: str, expected: str) -> None:
    response = client.get("/ping", headers={CLIENT_TRACE_ID_HEADER: raw})
    assert response.headers[CLIENT_TRACE_ID_HEADER] == expected


def test_context_vars_reset_after_request(client: TestClient) -> None:
    client.get("/ping")
    assert request_id_var.get() == "-"
    assert ip_var.get() == "-"
    assert client_trace_id_var.get() == "-"


def test_access_log_emitted_with_required_fields(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    with caplog.at_level(logging.INFO, logger="app.access"):
        client.get("/ping")

    record = next(r for r in caplog.records if r.name == "app.access")
    assert record.event_id == "001000" # type: ignore
    assert record.method == "GET" # type: ignore
    assert record.path == "/ping" # type: ignore
    assert record.status_code == 200 # type: ignore
    assert isinstance(record.duration_ms, int) # type: ignore
