import json
import logging
import os
import signal
import sys
from contextlib import asynccontextmanager
from logging.config import dictConfig
from pathlib import Path
from types import TracebackType
from typing import Any, AsyncIterator

import urllib3
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import ConfigApp, get_config
from app.container import get_crypto_service, get_prs_registration_service
from app.logging.config_builder import LogConfigBuilder
from app.logging.events import (
    HEALTH_UNHEALTHY,
    SYS_APP_CRASHED,
    SYS_APP_STARTED,
    SYS_APP_STOPPED,
    SYS_CRYPTO_FAILED,
    SYS_UNHANDLED_EXCEPTION,
    log_event,
)
from app.logging.middleware import RequestContextMiddleware
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
        fastapi = setup_fastapi()
        conf = get_config().app
        pub_key = generate_keys_on_startup(conf)
        if pub_key:
            register_at_prs(conf, pub_key)
        _emit_app_started(conf)
        return fastapi
    except Exception as exc:
        log_event(
            logger,
            SYS_UNHANDLED_EXCEPTION,
            "Unhandled exception during application startup",
            exc_info=exc,
            exception_type=type(exc).__name__,
            startup_phase="create_fastapi_app",
        )
        raise


def register_at_prs(conf: ConfigApp, pub_key: str) -> None:
    if conf.register_at_prs_on_startup:
        prs_registration_service = get_prs_registration_service()
        prs_registration_service.register_nvi_at_prs(pub_key)


def generate_keys_on_startup(conf: ConfigApp) -> str:
    crypto_service = get_crypto_service()
    try:
        if conf.generate_keys_on_startup:
            if not crypto_service.health_check():
                log_event(
                    logger,
                    HEALTH_UNHEALTHY,
                    "HSM unhealthy at startup, skipping key generation",
                    unhealthy_component="hsm_api",
                    status="error",
                    error_detail="health_check returned false",
                )
                return ""
            logger.debug("Generating keys on startup")
            crypto_service.generate_keys()
        return crypto_service.get_public_key(conf.key_id)
    except Exception as e:
        logger.debug("Startup crypto operation failed", exc_info=e)
        log_event(
            logger,
            SYS_CRYPTO_FAILED,
            "Startup crypto operation failed, app will serve but is unhealthy",
            operation_type="startup_key_setup",
            error_reason=type(e).__name__,
            retry_attempt=0,
        )
        return ""


_shutdown_reason: str = "graceful"


def _install_excepthook() -> None:
    """Route uncaught exceptions through our own logging so the traceback stays in the
    debug stream only. Without this, Python prints the traceback to stderr and
    it leaks into stdout logs."""

    def _hook(
        exc_type: type[BaseException],
        exc_value: BaseException,
        exc_tb: TracebackType | None,
    ) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        global _shutdown_reason
        _shutdown_reason = "crash"
        log_event(
            logger,
            SYS_APP_CRASHED,
            "Application crashed: uncaught exception",
            exc_info=(exc_type, exc_value, exc_tb),
            exception_type=exc_type.__name__,
            version=_read_version(),
        )

    sys.excepthook = _hook


def _install_signal_handlers() -> None:
    """Record the shutdown reason then delegate to the previously-installed
    handler (typically uvicorn's), so we don't disrupt graceful shutdown."""

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            previous = signal.getsignal(sig)
        except (ValueError, OSError):
            continue

        def _make_handler(signum: int, prev: Any) -> Any:
            def _handler(s: int, frame: Any) -> None:
                global _shutdown_reason
                _shutdown_reason = f"signal:{signal.Signals(signum).name}"
                if callable(prev):
                    prev(s, frame)
            return _handler

        try:
            signal.signal(sig, _make_handler(sig, previous))
        except (ValueError, OSError):
            pass


def application_init() -> None:
    setup_logging()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _install_excepthook()
    _install_signal_handlers()


def setup_logging() -> None:
    config = get_config()
    loglevel = config.app.loglevel.upper()
    if loglevel not in logging.getLevelNamesMapping():
        raise ValueError(f"Invalid loglevel {loglevel}")

    log_config = LogConfigBuilder(
        loglevel=loglevel,
        logging_config=config.logging,
    ).build()
    dictConfig(log_config)


def _read_version() -> str:
    path = Path(__file__).parent.parent / "version.json"
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
            return str(data.get("version", "unknown"))
    except (FileNotFoundError, json.JSONDecodeError):
        return "unknown"


def _emit_app_started(conf: ConfigApp) -> None:
    cfg = get_config()
    log_event(
        logger,
        SYS_APP_STARTED,
        "Application started",
        version=_read_version(),
        config_path=os.environ.get(_CONFIG_ENV, _DEFAULT_CONFIG_PATH),
        mock_hsm=cfg.hsm_api.mock,
        generate_keys_on_startup=conf.generate_keys_on_startup,
        register_at_prs_on_startup=conf.register_at_prs_on_startup,
        telemetry_enabled=cfg.telemetry.enabled,
        stats_enabled=cfg.stats.enabled,
    )


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    global _shutdown_reason
    try:
        yield
    finally:
        if _shutdown_reason != "crash":
            log_event(
                logger,
                SYS_APP_STOPPED,
                "Application stopped",
                shutdown_reason=_shutdown_reason,
                version=_read_version(),
            )


def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log_event(
        logger,
        SYS_UNHANDLED_EXCEPTION,
        "Unhandled exception",
        exc_info=exc,
        exception_type=type(exc).__name__,
        endpoint=request.url.path,
        method=request.method,
    )
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

    fastapi.add_middleware(RequestContextMiddleware)

    routers = [default_router, health_router, crypto_router]
    for router in routers:
        fastapi.include_router(router)

    if config.stats.enabled:
        fastapi.add_middleware(
            StatsdMiddleware, module_name=config.stats.module_name or "default"
        )

    fastapi.add_exception_handler(Exception, _unhandled_exception_handler)

    return fastapi
