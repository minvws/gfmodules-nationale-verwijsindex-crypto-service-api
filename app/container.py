import logging

from app.services.crypto.crypto_service import CryptoService
from app.services.crypto.factory import create_crypto_service
import inject
from app.services.prs_registration_service import PrsRegistrationService
from app.services.pseudonym_service import PseudonymService
from app.config import get_config

logger = logging.getLogger(__name__)


def container_config(binder: inject.Binder) -> None:
    config = get_config()

    crypto_service = create_crypto_service(config)

    public_key = crypto_service.get_public_key(config.app.key_id)
    if public_key is None:
        logger.error(f"Failed to obtain public key for key ID '{config.app.key_id}'")
        raise RuntimeError(
            f"Failed to obtain public key for key ID '{config.app.key_id}'"
        )

    binder.bind(CryptoService, crypto_service)

    prs_registration_service = PrsRegistrationService(
        nvi_ura_number=config.app.nvi_ura_number,
        config=config.pseudonym_api,
        public_key=public_key,
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
