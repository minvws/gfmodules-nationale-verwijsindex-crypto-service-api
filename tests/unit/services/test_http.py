from typing import Any

import pytest
from pytest_mock import MockerFixture
from requests.exceptions import ConnectionError as RequestsConnectionError, Timeout

from app.services.http import HttpService

PATCH_TARGET = "app.services.http.request"


@pytest.fixture
def request_mock(mocker: MockerFixture) -> Any:
    mock = mocker.patch(PATCH_TARGET)
    mock.return_value.status_code = 200
    return mock


def test_do_request_calls_requests_with_full_url(
    request_mock: Any, http_service: HttpService, mock_url: str
) -> None:
    http_service.do_request("GET", sub_route="things")

    assert request_mock.call_args.kwargs["url"] == f"{mock_url}/things"
    assert request_mock.call_args.kwargs["method"] == "GET"


def test_do_request_omits_sub_route_when_empty(
    request_mock: Any, http_service: HttpService, mock_url: str
) -> None:
    http_service.do_request("GET")
    assert request_mock.call_args.kwargs["url"] == mock_url


@pytest.mark.parametrize(
    "kwargs,expected_key,expected_value",
    [
        ({"data": {"a": 1}}, "json", {"a": 1}),
        ({"form_data": {"a": 1}}, "data", {"a": 1}),
        ({"params": {"q": "x"}}, "params", {"q": "x"}),
        ({"headers": {"H": "v"}}, "headers", {"H": "v"}),
    ],
    ids=["json-body", "form-body", "query-params", "headers"],
)
def test_do_request_forwards_payload_kwargs(
    request_mock: Any,
    http_service: HttpService,
    kwargs: dict[str, Any],
    expected_key: str,
    expected_value: Any,
) -> None:
    http_service.do_request("POST", **kwargs)
    assert request_mock.call_args.kwargs[expected_key] == expected_value


def test_do_request_rejects_data_and_form_data_together(
    request_mock: Any, http_service: HttpService
) -> None:
    with pytest.raises(ValueError, match="both 'data' and 'form_data'"):
        http_service.do_request("POST", data={"a": 1}, form_data={"b": 2})
    request_mock.assert_not_called()


@pytest.mark.parametrize(
    "cert,key,expected_cert",
    [
        ("a.crt", "a.key", ("a.crt", "a.key")),
        (None, None, None),
        ("a.crt", None, None),
        (None, "a.key", None),
    ],
    ids=["mtls-on", "mtls-off", "missing-key", "missing-cert"],
)
def test_do_request_mtls_cert_arg(
    request_mock: Any,
    mock_url: str,
    cert: str | None,
    key: str | None,
    expected_cert: Any,
) -> None:
    svc = HttpService(
        endpoint=mock_url, timeout=5, mtls_cert=cert, mtls_key=key, verify_ca=True
    )
    svc.do_request("GET")
    assert request_mock.call_args.kwargs["cert"] == expected_cert


@pytest.mark.parametrize("verify_ca", [True, False, "/path/ca.pem"])
def test_do_request_passes_verify_ca_through(
    request_mock: Any, mock_url: str, verify_ca: Any
) -> None:
    svc = HttpService(
        endpoint=mock_url,
        timeout=5,
        mtls_cert=None,
        mtls_key=None,
        verify_ca=verify_ca,
    )
    svc.do_request("GET")
    assert request_mock.call_args.kwargs["verify"] == verify_ca


@pytest.mark.parametrize("exc", [Timeout("t"), RequestsConnectionError("c")])
def test_do_request_propagates_transport_errors(
    request_mock: Any, http_service: HttpService, exc: Exception
) -> None:
    request_mock.side_effect = exc
    with pytest.raises(type(exc)):
        http_service.do_request("GET")
