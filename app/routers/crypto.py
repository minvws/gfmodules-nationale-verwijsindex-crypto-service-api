import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app import container
from app.config import get_config
from app.exceptions.exception import CryptoError, KeyNotFoundError, InvalidJweError
from app.services.crypto.crypto_service import CryptoService
from app.services.pseudonym_service import PseudonymService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/test/public_key", summary="Return the NVI public key as PEM")
def public_key(
    crypto_service: Annotated[CryptoService, Depends(container.get_crypto_service)],
) -> JSONResponse:
    key_id = get_config().app.key_id
    return JSONResponse(
        content={"kid": key_id, "pem": crypto_service.get_public_key(key_id)}
    )


@router.get(
    "/decrypt_and_hash",
    summary="Decrypt and hash a pseudonym",
    description="Decrypt JWE, unblind, hash via HSM, and return hashed pseudonym",
)
def decrypt_and_hash(
    jwe: str,
    blind_factor: str,
    pseudonym_service: Annotated[
        PseudonymService, Depends(container.get_pseudonym_service)
    ],
) -> JSONResponse:
    try:
        pseudonym = pseudonym_service.decrypt_and_unblind(jwe, blind_factor)
        hashed_pseudonym = pseudonym_service.hash(pseudonym)
        return JSONResponse(
            content={"hashed_pseudonym": hashed_pseudonym}, status_code=200
        )
    except InvalidJweError as e:
        logger.error(f"Invalid JWE: {e}")
        return JSONResponse(
            content={"error": "Invalid JWE"}, status_code=400
        )
    except KeyNotFoundError as e:
        logger.error(f"Key not found: {e}")
        return JSONResponse(
            content={"error": "Key not found"}, status_code=404
        )
    except CryptoError as e:
        logger.error(f"Crypto operation failed: {e}")
        return JSONResponse(
            content={"error": "Crypto operation failed"}, status_code=500
        )
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return JSONResponse(
            content={"error": "Operation failed"}, status_code=500
        )
