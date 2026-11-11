import logging
from typing import cast

import inject

from app.config import get_config
from app.services.crypto.crypto_service import CryptoService
from app.services.crypto.hsm_api_crypto_service import HsmApiCryptoService
from app.services.crypto.mock_crypto_service import MockCryptoService
from app.services.http import HttpService
from app.services.pseudonym_jwks import PseudonymJwksService
from app.services.pseudonym_jwt import PseudonymJwtVerifier
from app.services.pseudonym_service import PseudonymService

logger = logging.getLogger(__name__)


def container_config(binder: inject.Binder) -> None:
    config = get_config()

    crypto_service: CryptoService
    if config.hsm_api.mock:
        logger.debug("Initializing mock crypto service")
        crypto_service = MockCryptoService()
    else:
        logger.debug("Initializing HSM API at %s", config.hsm_api.url)
        http = HttpService(
            endpoint=config.hsm_api.url,
            timeout=config.hsm_api.timeout,
            mtls_cert=config.hsm_api.cert_path,
            mtls_key=config.hsm_api.key_path,
            verify_ca=config.hsm_api.verify_ca,
        )
        crypto_service = HsmApiCryptoService(
            http,
            module=config.hsm_api.module,
            slot=config.hsm_api.slot,
            hash_key_id=config.app.hashing_key_id,
            allowed_jwe_key_ids=config.app.allowed_jwe_key_ids,
        )

    binder.bind(CryptoService, crypto_service)

    verifier = None
    if config.pseudonym.signing_expected:
        jwks_service = PseudonymJwksService(config.pseudonym)
        verifier = PseudonymJwtVerifier(config.pseudonym, jwks_service)
        binder.bind(PseudonymJwksService, jwks_service)
        binder.bind(PseudonymJwtVerifier, verifier)

    pseudonym_service = PseudonymService(
        crypto_service=crypto_service,
        verifier=verifier,
        reserved_labels={config.app.hashing_key_id, *config.app.allowed_jwe_key_ids},
    )
    binder.bind(PseudonymService, pseudonym_service)


def get_crypto_service() -> CryptoService:
    return cast(CryptoService, inject.instance(CryptoService))


def get_pseudonym_service() -> PseudonymService:
    return inject.instance(PseudonymService)


def get_pseudonym_jwt_verifier() -> PseudonymJwtVerifier | None:
    if not get_config().pseudonym.signing_expected:
        return None
    return inject.instance(PseudonymJwtVerifier)


def get_pseudonym_jwks_service() -> PseudonymJwksService | None:
    if not get_config().pseudonym.signing_expected:
        return None
    return inject.instance(PseudonymJwksService)


inject.configure(container_config)
