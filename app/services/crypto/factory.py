import logging

from app.config import Config, KeyStorageType
from app.services.crypto.crypto_service import CryptoService
from app.services.crypto.hsm_api_crypto_service import HsmApiCryptoService
from app.services.crypto.hsm_crypto_service import HsmCryptoService
from app.services.crypto.json_keystore import JsonKeyStorage
from app.services.crypto.memory_crypto_service import MemoryCryptoService
from app.services.http import HttpService

logger = logging.getLogger(__name__)


def create_crypto_service(config: Config) -> CryptoService:
    crypto_service: CryptoService
    key_id = config.app.key_id
    hash_key_id = config.app.hashing_key_id
    keystore_type = config.app.keystore.value

    logger.debug(f"Creating crypto service: type={keystore_type}")

    try:
        match config.app.keystore:
            case KeyStorageType.json:
                logger.debug(f"Initializing JSON keystore at {config.json_keystore.path}")
                store = JsonKeyStorage(config.json_keystore.path)
                crypto_service = MemoryCryptoService(
                    store,
                    signing_key_id=key_id,
                    hashing_key_id=hash_key_id,
                )
            case KeyStorageType.hsm_local:
                logger.debug(f"Initializing HSM (local) on slot {config.hsm_keystore.slot}")
                crypto_service = HsmCryptoService(
                    config.hsm_keystore.library,
                    config.hsm_keystore.slot,
                    config.hsm_keystore.slot_pin,
                    signing_key_id=key_id,
                    hashing_key_id=hash_key_id,
                    softhsm_oaep_sha256_fallback=config.hsm_keystore.softhsm_oaep_sha256_fallback,
                )
            case KeyStorageType.hsm_api:
                logger.debug(f"Initializing HSM API at {config.hsm_api_keystore.url}")
                http = HttpService(
                    endpoint=config.hsm_api_keystore.url,
                    timeout=config.hsm_api_keystore.timeout,
                    mtls_cert=config.hsm_api_keystore.cert_path,
                    mtls_key=config.hsm_api_keystore.key_path,
                    verify_ca=config.hsm_api_keystore.verify_ca,
                )
                crypto_service = HsmApiCryptoService(
                    http,
                    config.hsm_api_keystore.module,
                    config.hsm_api_keystore.slot,
                    hash_key_id=hash_key_id,
                    signing_key_id=key_id,
                )
            case _:
                logger.error(f"Unknown keystore type: {config.app.keystore}")
                raise ValueError(f"Unknown keystore type {config.app.keystore}")
        return crypto_service
    except ValueError:
        raise
    except Exception as e:
        logger.error(f"Failed to create crypto service: {e}")
        raise
