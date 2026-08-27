import json
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import gfmodules.logging as gflog
import urllib3
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from gfmodules.logging.exceptions import log_unhandled_exception
from gfmodules.logging.middleware import (
    RequestContextMiddleware,
    restore_request_context,
)

from app.config import get_config
from app.logging.events import Log
from app.routers.crypto import router as crypto_router
from app.routers.default import router as default_router
from app.routers.health import router as health_router
from app.stats import StatsdMiddleware

logger = logging.getLogger(__name__)

_CONFIG_ENV = "FASTAPI_CONFIG_PATH"
_DEFAULT_CONFIG_PATH = "app.conf"


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
    try:
        return setup_fastapi()
    except Exception as exc:
        gflog.emit(logger, Log.SYS_UNHANDLED_EXCEPTION, "Unhandled exception during application startup", fields={"exception_type": type(exc).__name__}, exc_info=exc)
        raise


def application_init() -> None:
    setup_logging()
    if get_config().app.allow_insecure_requests:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    gflog.install_excepthook(logger)
    gflog.install_signal_handlers()


def setup_logging() -> None:
    config = get_config()
    gflog.configure(config=config.logging, loglevel=config.app.loglevel, catalogue=Log)


def _read_version() -> str:
    path = Path(__file__).parent.parent / "version.json"
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
            return str(data.get("version", "unknown"))
    except (FileNotFoundError, json.JSONDecodeError):
        return "unknown"


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    config = get_config()
    async with gflog.lifespan_logging(
        logger,
        version=_read_version(),
        config_path=os.environ.get(_CONFIG_ENV, _DEFAULT_CONFIG_PATH),
        started_fields={
            "mock_hsm": config.hsm_api.mock,
            "telemetry_enabled": config.telemetry.enabled,
            "stats_enabled": config.stats.enabled,
        },
    ):
        yield


@restore_request_context
def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log_unhandled_exception(logger, request, exc)
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


def setup_fastapi() -> FastAPI:
    config = get_config()

    fastapi = (
        FastAPI(
            docs_url=config.uvicorn.docs_url,
            redoc_url=config.uvicorn.redoc_url,
            lifespan=_lifespan,
        )
        if config.uvicorn.swagger_enabled
        else FastAPI(docs_url=None, redoc_url=None, lifespan=_lifespan)
    )

    routers = [default_router, health_router, crypto_router]
    for router in routers:
        fastapi.include_router(router)

    if config.stats.enabled:
        fastapi.add_middleware(
            StatsdMiddleware, module_name=config.stats.module_name or "default"
        )

    fastapi.add_middleware(
        RequestContextMiddleware,
        correlation_id_expected=config.logging.correlation_id_expected,
        trust_forwarded_for=config.logging.trust_forwarded_for,
    )

    fastapi.add_exception_handler(Exception, _unhandled_exception_handler)

    return fastapi
