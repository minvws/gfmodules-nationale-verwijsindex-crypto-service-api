import logging
from typing import Annotated

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse

from app import container
from app.data import Pkc11Mechanism
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

    return JSONResponse(content={"kid": key_id, "pem": pem})


@router.post(
    "/process",
    summary="Process incoming JWE and returns an encrypted Pseudonym with an IV",
    description="Decrypt JWE, unblind, and encrypt the pseudonym with an IV (first 16 byte of the HMAC hash of the pseudonym). All done via HSM",
)
def process(
    data: Annotated[PseudonymRequest, Body()],
    pseudonym_service: Annotated[
        PseudonymService, Depends(container.get_pseudonym_service)
    ],
) -> JSONResponse:
    try:
        pseudonym = pseudonym_service.decrypt_and_unblind(data.jwe, data.blind_factor)
        hashed_pseudonym = pseudonym_service.hash(pseudonym)

        results = pseudonym_service.encrypt_pseudonym(
            pseudonym=pseudonym,
            hmac_hash=hashed_pseudonym,
            label=data.label,
            mechanism=Pkc11Mechanism(data.mechanism),
        )
        return JSONResponse(
            content=results.model_dump(),
            status_code=200,
        )
    except CryptoError as e:
        logger.error(f"CryptoError occurred: {e.error_message}")
        return JSONResponse(
            content={"error": e.error_message}, status_code=e.status_code
        )
