import logging

from requests.exceptions import ConnectionError, HTTPError, Timeout

from app.config import ConfigPseudonymApi
from app.exceptions.exception import PrsRegisterError
from app.services.client_oauth import PrsOAuthService
from app.services.http import HttpService

logger = logging.getLogger(__name__)


class PrsRegistrationService:
    def __init__(
        self,
        nvi_ura_number: str,
        config: ConfigPseudonymApi,
        client_oauth_service: PrsOAuthService,
        register_app: bool = False,
    ) -> None:
        self._config = config
        self._http_service = HttpService(
            endpoint=self._config.endpoint,
            timeout=self._config.timeout,
            mtls_cert=self._config.mtls_cert,
            mtls_key=self._config.mtls_key,
            verify_ca=self._config.verify_ca,
        )
        self._nvi_ura_number = nvi_ura_number
        self._register_app = register_app
        self._prs_oauth_service = client_oauth_service
        self._access_token: str | None = None

    def register_nvi_at_prs(self, public_key: str) -> None:
        logger.debug("Registering NVI at PRS")
        if self._register_app:
            self._register_organization()
            self._register_certificate(public_key)

    def _register_organization(self) -> None:
        try:
            headers = {}
            if self._prs_oauth_service.enabled():
                headers["Authorization"] = "Bearer " + self.fetch_oauth_token()

            response = self._http_service.do_request(
                method="POST",
                sub_route="orgs",
                headers=headers,
                data={
                    "ura": self._nvi_ura_number,
                    "name": "nationale-verwijsindex",
                    "max_key_usage": "bsn",
                },
            )
            logger.debug("Response status code: %d", response.status_code)

            if response.status_code == 409:
                logger.debug("Organization already registered at PRS")
                return

            response.raise_for_status()

        except (HTTPError, ConnectionError, Timeout) as e:
            logger.error(f"Failed to register organization: {e}")
            raise PrsRegisterError("Failed to register organization")

    def _register_certificate(self, public_key: str) -> None:
        try:
            headers = {}
            if self._prs_oauth_service.enabled():
                headers["Authorization"] = "Bearer " + self.fetch_oauth_token()

            response = self._http_service.do_request(
                method="POST",
                sub_route="register/certificate",
                headers=headers,
                data={
                    "scope": ["nationale-verwijsindex"],
                    "public_key": public_key,
                },
            )

            if response.status_code == 409:
                logger.debug("Certificate already registered at PRS")
                return

            response.raise_for_status()

        except (HTTPError, ConnectionError, Timeout) as e:
            logger.error(f"Failed to register certificate: {e}")
            raise PrsRegisterError("Failed to register certificate")

    def fetch_oauth_token(self) -> str:
        if self._access_token is None:
            self._access_token = self._prs_oauth_service.get_access_token(
                "prs:read", self._config.endpoint
            )

        return self._access_token
