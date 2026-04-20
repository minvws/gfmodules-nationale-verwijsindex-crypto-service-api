import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.container import get_crypto_service
from app.services.crypto.crypto_service import CryptoService


logger = logging.getLogger(__name__)
router = APIRouter()


def ok_or_error(value: bool) -> str:
    return "ok" if value else "error"


@router.get("/health")
def health(
    crypto_service: Annotated[CryptoService, Depends(get_crypto_service)],
) -> JSONResponse:
    logger.debug("Checking application health")

    components = {
        "HSM API": ok_or_error(crypto_service.health_check()),
    }
    healthy = ok_or_error(all(value == "ok" for value in components.values()))

    return JSONResponse(
        status_code=200 if healthy == "ok" else 503,
        content={
            "status": healthy,
            "components": components,
        }
    )
