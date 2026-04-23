import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.container import get_crypto_service
from app.logging.events import HEALTH_UNHEALTHY, log_event
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
        "hsm_api": ok_or_error(crypto_service.health_check()),
    }
    healthy = all(status == "ok" for status in components.values())

    if not healthy:
        unhealthy = [name for name, status in components.items() if status != "ok"]
        log_event(
            logger,
            HEALTH_UNHEALTHY,
            "Health check unhealthy",
            unhealthy_component=",".join(unhealthy),
            status="error",
            error_detail="",
        )

    return JSONResponse(
        status_code=200 if healthy else 503,
        content={
            "status": ok_or_error(healthy),
            "components": components,
        },
    )
