from unittest.mock import MagicMock

import pytest
from requests.exceptions import ConnectionError as RequestsConnectionError, HTTPError, Timeout

from app.config import ConfigPseudonymApi
from app.exceptions.exception import PrsRegisterError
from app.services.prs_registration_service import PrsRegistrationService


@pytest.fixture
def prs_config() -> ConfigPseudonymApi:
    return ConfigPseudonymApi(endpoint="https://example.com/prs")



@pytest.fixture
def prs_service(prs_config: ConfigPseudonymApi, http_mock: MagicMock) -> PrsRegistrationService:
    svc = PrsRegistrationService(nvi_ura_number="ura-1", config=prs_config, register_app=True)
    svc._http_service = http_mock
    return svc


def _ok(status: int) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.raise_for_status = MagicMock()
    return r


@pytest.mark.parametrize("status", [200, 201], ids=["200", "201"])
def test_register_organization_succeeds_on_2xx(
    status: int, prs_service: PrsRegistrationService, http_mock: MagicMock
) -> None:
    http_mock.do_request.return_value = _ok(status)

    prs_service._register_organization()

    http_mock.do_request.assert_called_once_with(
        method="POST",
        sub_route="orgs",
        data={"ura": "ura-1", "name": "nationale-verwijsindex", "max_key_usage": "bsn"},
    )


def test_register_organization_409_is_idempotent_no_raise(
    prs_service: PrsRegistrationService, http_mock: MagicMock
) -> None:
    http_mock.do_request.return_value = _ok(409)
    prs_service._register_organization()


@pytest.mark.parametrize(
    "exc",
    [HTTPError("x"), RequestsConnectionError("x"), Timeout("x")],
    ids=["http", "conn", "timeout"],
)
def test_register_organization_wraps_transport_errors(
    exc: Exception, prs_service: PrsRegistrationService, http_mock: MagicMock
) -> None:
    http_mock.do_request.side_effect = exc
    with pytest.raises(PrsRegisterError):
        prs_service._register_organization()


def test_register_organization_5xx_raises_prs_error(
    prs_service: PrsRegistrationService, http_mock: MagicMock
) -> None:
    response = MagicMock()
    response.status_code = 503
    response.raise_for_status.side_effect = HTTPError("boom")
    http_mock.do_request.return_value = response
    with pytest.raises(PrsRegisterError):
        prs_service._register_organization()


@pytest.mark.parametrize("status", [200, 201], ids=["200", "201"])
def test_register_certificate_succeeds_on_2xx(
    status: int, prs_service: PrsRegistrationService, http_mock: MagicMock
) -> None:
    http_mock.do_request.return_value = _ok(status)

    prs_service._register_certificate("PEM-PUBLIC-KEY")

    http_mock.do_request.assert_called_once_with(
        method="POST",
        sub_route="register/certificate",
        data={"scope": ["nationale-verwijsindex"], "public_key": "PEM-PUBLIC-KEY"},
    )


def test_register_certificate_409_is_idempotent(
    prs_service: PrsRegistrationService, http_mock: MagicMock
) -> None:
    http_mock.do_request.return_value = _ok(409)
    prs_service._register_certificate("k")


@pytest.mark.parametrize(
    "exc",
    [HTTPError("x"), RequestsConnectionError("x"), Timeout("x")],
    ids=["http", "conn", "timeout"],
)
def test_register_certificate_wraps_transport_errors(
    exc: Exception, prs_service: PrsRegistrationService, http_mock: MagicMock
) -> None:
    http_mock.do_request.side_effect = exc
    with pytest.raises(PrsRegisterError):
        prs_service._register_certificate("k")


def test_register_nvi_at_prs_skips_when_register_app_false(
    prs_config: ConfigPseudonymApi, http_mock: MagicMock
) -> None:
    svc = PrsRegistrationService(nvi_ura_number="u", config=prs_config, register_app=False)
    svc._http_service = http_mock
    svc.register_nvi_at_prs("k")
    http_mock.do_request.assert_not_called()


def test_register_nvi_at_prs_calls_both_when_enabled(
    prs_service: PrsRegistrationService, http_mock: MagicMock
) -> None:
    http_mock.do_request.return_value = _ok(200)
    prs_service.register_nvi_at_prs("PEM")
    assert http_mock.do_request.call_count == 2
    sub_routes = [c.kwargs["sub_route"] for c in http_mock.do_request.call_args_list]
    assert sub_routes == ["orgs", "register/certificate"]
