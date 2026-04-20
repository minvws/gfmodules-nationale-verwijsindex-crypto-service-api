import logging

from typing import Any

from fastapi import FastAPI
import uvicorn

from app.config import get_config
from app.stats import StatsdMiddleware
from app.routers.default import router as default_router
from app.routers.health import router as health_router
from app.routers.crypto import router as crypto_router
from app.container import get_crypto_service, get_prs_registration_service

logger = logging.getLogger(__name__)

def get_uvicorn_params() -> dict[str, Any]:
    config = get_config()

    kwargs = {
        "host": config.uvicorn.host,
        "port": config.uvicorn.port,
        "reload": config.uvicorn.reload,
    }
    if (
        config.uvicorn.use_ssl
        and config.uvicorn.ssl_base_dir is not None
        and config.uvicorn.ssl_cert_file is not None
        and config.uvicorn.ssl_key_file is not None
    ):
        kwargs["ssl_keyfile"] = (
            config.uvicorn.ssl_base_dir + "/" + config.uvicorn.ssl_key_file
        )
        kwargs["ssl_certfile"] = (
            config.uvicorn.ssl_base_dir + "/" + config.uvicorn.ssl_cert_file
        )
    return kwargs


def run() -> None:
    uvicorn.run("app.application:create_fastapi_app", **get_uvicorn_params())


def create_fastapi_app() -> FastAPI:
    application_init()
    fastapi = setup_fastapi()
    register_at_prs()
    generate_keys_on_startup()

    return fastapi


def register_at_prs() -> None:
    prs_registration_service = get_prs_registration_service()
    prs_registration_service.register_nvi_at_prs()

def generate_keys_on_startup() -> None:
    if get_config().app.generate_keys_on_startup:
        crypto_service = get_crypto_service()
        if not crypto_service.health_check():
            logger.error("Crypto service health check failed")
        logger.debug("Generating keys on startup")
        crypto_service.generate_keys()

def application_init() -> None:
    setup_logging()


def setup_logging() -> None:
    loglevel = logging.getLevelName(get_config().app.loglevel.upper())

    if isinstance(loglevel, str):
        raise ValueError(f"Invalid loglevel {loglevel.upper()}")
    logging.basicConfig(
        level=loglevel,
        datefmt="%m/%d/%Y %I:%M:%S %p",
    )


def setup_fastapi() -> FastAPI:
    config = get_config()

    fastapi = (
        FastAPI(
            docs_url=config.uvicorn.docs_url,
            redoc_url=config.uvicorn.redoc_url,
        )
        if config.uvicorn.swagger_enabled
        else FastAPI(docs_url=None, redoc_url=None)
    )

    routers = [default_router, health_router, crypto_router]
    for router in routers:
        fastapi.include_router(router)

    if config.stats.enabled:
        fastapi.add_middleware(
            StatsdMiddleware, module_name=config.stats.module_name or "default"
        )

    return fastapi
