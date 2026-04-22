import logging

import inject

from app.config import get_config
from app.services.crypto.crypto_service import CryptoService
from app.services.crypto.hsm_api_crypto_service import HsmApiCryptoService
from app.services.crypto.mock_crypto_service import MockCryptoService
from app.services.http import HttpService
from app.services.prs_registration_service import PrsRegistrationService
from app.services.pseudonym_service import PseudonymService

logger = logging.getLogger(__name__)


def container_config(binder: inject.Binder) -> None:
    config = get_config()

    crypto_service: CryptoService
    if config.hsm_api.mock:
        logger.debug("Initializing mock crypto service")
        crypto_service = MockCryptoService()
    else:
        logger.debug(f"Initializing HSM API at {config.hsm_api.url}")
        http = HttpService(
            endpoint=config.hsm_api.url,
            timeout=config.hsm_api.timeout,
            mtls_cert=config.hsm_api.cert_path,
            mtls_key=config.hsm_api.key_path,
            verify_ca=config.hsm_api.verify_ca,
        )
        crypto_service = HsmApiCryptoService(
            http,
            config.hsm_api.module,
            config.hsm_api.slot,
            hash_key_id=config.app.hashing_key_id,
            signing_key_id=config.app.key_id,
        )

    binder.bind(CryptoService, crypto_service)

    prs_registration_service = PrsRegistrationService(
        nvi_ura_number=config.app.nvi_ura_number,
        config=config.pseudonym_api,
        register_app=config.app.register_prs_on_startup
    )
    binder.bind(PrsRegistrationService, prs_registration_service)

    pseudonym_service = PseudonymService(crypto_service)
    binder.bind(PseudonymService, pseudonym_service)


def get_crypto_service() -> CryptoService:
    return inject.instance(CryptoService)


def get_prs_registration_service() -> PrsRegistrationService:
    return inject.instance(PrsRegistrationService)


def get_pseudonym_service() -> PseudonymService:
    return inject.instance(PseudonymService)


inject.configure(container_config)
