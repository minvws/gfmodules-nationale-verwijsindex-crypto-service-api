from requests import HTTPError
import pytest
from unittest.mock import patch, MagicMock

from fastapi import HTTPException

from app.config import ConfigPrsOAuth
from app.services.client_oauth import PrsOAuthService

PATCHED_MODULE = "app.services.client_oauth.HttpService.do_request"


@pytest.fixture()
def mock_client_oauth_service() -> PrsOAuthService:
    config = ConfigPrsOAuth(
        enabled=True,
        issuer="http://example.com",
    )
    return PrsOAuthService(config=config)


@patch(PATCHED_MODULE)
def test_get_access_token_should_succeed(
    mock_res: MagicMock, mock_client_oauth_service: PrsOAuthService
) -> None:
    mock_req = MagicMock()
    mock_req.json.return_value = {"access_token": "some-token"}
    mock_req.status_code = 200
    mock_res.return_value = mock_req

    actual = mock_client_oauth_service.get_access_token(
        scope="some-scope", audience="some-audienc"
    )

    assert actual == "some-token"


@patch(PATCHED_MODULE)
def test_get_access_token_should_panic_when_error_occurs(
    mock_res: MagicMock, mock_client_oauth_service: PrsOAuthService
) -> None:
    mock_res.statsu_code = 503
    mock_res.side_effect = HTTPError

    with pytest.raises(HTTPException):
        mock_client_oauth_service.get_access_token("some-token", "some-audience")
