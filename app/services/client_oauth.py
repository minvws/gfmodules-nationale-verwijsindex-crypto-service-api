import logging

from fastapi import HTTPException

from app.config import ConfigPrsOAuth
from app.services.http import HttpService

logger = logging.getLogger(__name__)


class PrsOAuthService:
    """
    Service that will connect to an OAuth2 provider to fetch access tokens for using external services.
    """

    def __init__(self, config: ConfigPrsOAuth) -> None:
        self.config = config
        if self.config.enabled:
            if config.issuer is None:
                raise ValueError("Client OAuth2 issuer must be set if enabled")

            self._http_service = HttpService(
                endpoint=config.issuer,
                timeout=10,
                mtls_cert=config.mtls_cert,
                mtls_key=config.mtls_key,
                verify_ca=config.verify_ca,
            )

    def enabled(self) -> bool:
        """
        Check if the OAuth2 client is enabled.
        """
        return self.config.enabled

    def get_access_token(self, scope: str, audience: str) -> str:
        """
        Get an access token from the OAuth2 provider using client credentials.
        """
        if not self.config.enabled:
            raise ValueError("Client OAuth2 is not enabled")

        try:
            response = self._http_service.do_request(
                method="POST",
                sub_route="/oauth/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                form_data={
                    "grant_type": "client_credentials",
                    "scope": scope,
                    "target_audience": audience,
                    "authorized_role": "source",
                },
            )
            data = response.json()
            token = data["access_token"]
        except Exception as e:
            logger.error(f"Failed to obtain access token: {e}")
            raise HTTPException(status_code=500, detail="Failed to obtain access token")

        return str(token)
