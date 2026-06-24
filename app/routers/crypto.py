import logging
from typing import Annotated

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse

from app import container
from app.exceptions.exception import CryptoError
from app.models.pseudonym import PseudonymRequest
from app.services.crypto.crypto_service import CryptoService
from app.services.pseudonym_service import PseudonymService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/test/public_key/{key_id}", summary="Return the NVI public key as PEM")
def public_key(
    key_id: str,
    crypto_service: Annotated[CryptoService, Depends(container.get_crypto_service)],
) -> JSONResponse:
    try:
        pem = crypto_service.get_public_key(key_id)
    except CryptoError as e:
        logger.error(f"CryptoError occurred: {e.error_message}")
        return JSONResponse(
            content={"error": e.error_message}, status_code=e.status_code
        )

    return JSONResponse(
        content={"kid": key_id, "pem": pem}
    )


@router.post(
    "/decrypt_and_hash",
    summary="Decrypt and hash a pseudonym",
    description="Decrypt JWE, unblind, hash via HSM, and return hashed pseudonym",
)
def decrypt_and_hash(
    data: Annotated[PseudonymRequest, Body()],
    pseudonym_service: Annotated[
        PseudonymService, Depends(container.get_pseudonym_service)
    ],
) -> JSONResponse:
    try:
        pseudonym = pseudonym_service.decrypt_and_unblind(data.jwe, data.blind_factor)
        hashed_pseudonym = pseudonym_service.hash(pseudonym)
        return JSONResponse(
            content={"hashed_pseudonym": hashed_pseudonym}, status_code=200
        )
    except CryptoError as e:
        logger.error(f"CryptoError occurred: {e.error_message}")
        return JSONResponse(
            content={"error": e.error_message}, status_code=e.status_code
        )
