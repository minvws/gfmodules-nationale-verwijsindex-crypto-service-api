import logging
from typing import Annotated

import gfmodules.logging as gflog
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.container import get_crypto_service, get_pseudonym_jwks_service
from app.logging.events import Log
from app.services.crypto.crypto_service import CryptoService
from app.services.pseudonym_jwks import PseudonymJwksService

logger = logging.getLogger(__name__)
router = APIRouter()


def ok_or_error(value: bool) -> str:
    return "ok" if value else "error"


@router.get("/health")
def health(
    crypto_service: Annotated[CryptoService, Depends(get_crypto_service)],
    jwks: Annotated[PseudonymJwksService | None, Depends(get_pseudonym_jwks_service)],
) -> JSONResponse:
    logger.debug("Checking application health")

    errors = {"hsm_api": crypto_service.health_error()}
    if jwks is not None:
        errors["jwks"] = jwks.health_error()
    components = {name: ok_or_error(error is None) for name, error in errors.items()}
    healthy = all(error is None for error in errors.values())

    for name, error in errors.items():
        if error is not None:
            gflog.emit(
                logger,
                Log.HEALTH_UNHEALTHY,
                "Health check unhealthy",
                fields={"component": name, "status": "error", "error_detail": error},
            )

    return JSONResponse(
        status_code=200 if healthy else 503,
        content={
            "status": ok_or_error(healthy),
            "components": components,
        },
    )
