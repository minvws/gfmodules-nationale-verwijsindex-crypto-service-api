import logging

from requests.exceptions import ConnectionError, HTTPError, Timeout

from app.config import ConfigPseudonymApi
from app.exceptions.exception import PrsRegisterError
from app.services.http import HttpService


logger = logging.getLogger(__name__)


class PrsRegistrationService:
    def __init__(
        self,
        nvi_ura_number: str,
        config: ConfigPseudonymApi,
        public_key: str,
        register_app: bool = False,
    ) -> None:
        self._config = config
        self._public_key = public_key
        self._http_service = HttpService(
            endpoint=self._config.endpoint,
            timeout=self._config.timeout,
            mtls_cert=self._config.mtls_cert,
            mtls_key=self._config.mtls_key,
            verify_ca=self._config.verify_ca,
        )
        self._nvi_ura_number = nvi_ura_number
        self._register_app = register_app

    def register_nvi_at_prs(self) -> None:
        logger.debug("Registering NVI at PRS")
        if self._register_app:
            self._register_organization()
            self._register_certificate()

    def _register_organization(self) -> None:
        try:
            response = self._http_service.do_request(
                method="POST",
                sub_route="orgs",
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

    def _register_certificate(self) -> None:
        try:
            response = self._http_service.do_request(
                method="POST",
                sub_route="register/certificate",
                data={
                    "scope": ["nationale-verwijsindex"],
                    "public_key": self._public_key,
                },
            )

            if response.status_code == 409:
                logger.debug("Certificate already registered at PRS")
                return

            response.raise_for_status()

        except (HTTPError, ConnectionError, Timeout) as e:
            logger.error(f"Failed to register certificate: {e}")
            raise PrsRegisterError("Failed to register certificate")
