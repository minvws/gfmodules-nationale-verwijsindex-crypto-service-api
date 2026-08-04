import asyncio
import json
import sys
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from app import application
from app.config import Config
from app.logging.events import (
    SYS_APP_CRASHED,
    SYS_APP_STARTED,
    SYS_APP_STOPPED,
    SYS_UNHANDLED_EXCEPTION,
)


def test_unhandled_exception_handler_logs_and_returns_500(
    mocker: MockerFixture,
) -> None:
    request = MagicMock()
    request.url.path = "/boom"
    request.method = "GET"
    exc = RuntimeError("explode")
    log_event = mocker.patch("app.application.log_event")

    response = application._unhandled_exception_handler(request, exc)

    assert response.status_code == 500
    assert json.loads(response.body) == {"error": "Internal server error"}  # type: ignore
    log_event.assert_called_once_with(
        application.logger,
        SYS_UNHANDLED_EXCEPTION,
        "Unhandled exception",
        exc_info=exc,
        exception_type="RuntimeError",
        endpoint="/boom",
        method="GET",
    )


def test_lifespan_logs_shutdown_reason_on_exit(
    mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_event = mocker.patch("app.application.log_event")
    mocker.patch("app.application._read_version", return_value="9.9.9")
    monkeypatch.setattr(application, "_shutdown_reason", "graceful")

    async def _exercise() -> None:
        async with application._lifespan(MagicMock()):
            pass

    asyncio.run(_exercise())

    log_event.assert_called_once_with(
        application.logger,
        SYS_APP_STOPPED,
        "Application stopped",
        shutdown_reason="graceful",
        version="9.9.9",
    )


def test_emit_app_started_logs_sys_app_started(
    use_config: Config, mocker: MockerFixture
) -> None:
    mocker.patch("app.application._read_version", return_value="1.2.3")
    log_event = mocker.patch("app.application.log_event")

    application._emit_app_started(use_config)

    log_event.assert_called_once_with(
        application.logger,
        SYS_APP_STARTED,
        "Application started",
        version="1.2.3",
        config_path=mocker.ANY,
        mock_hsm=use_config.hsm_api.mock,
        telemetry_enabled=use_config.telemetry.enabled,
        stats_enabled=use_config.stats.enabled,
    )


def test_excepthook_logs_sys_app_crashed_for_uncaught_exception(
    mocker: MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mocker.patch("app.application._read_version", return_value="9.9.9")
    log_event = mocker.patch("app.application.log_event")
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    application._install_excepthook()
    try:
        raise RuntimeError("boom")
    except RuntimeError as exc:
        sys.excepthook(type(exc), exc, exc.__traceback__)

    assert application._shutdown_reason == "crash"
    assert log_event.call_count == 1
    args, kwargs = log_event.call_args
    assert args[0] is application.logger
    assert args[1] is SYS_APP_CRASHED
    assert args[2] == "Application crashed: uncaught exception"
    assert kwargs["exception_type"] == "RuntimeError"
    assert kwargs["version"] == "9.9.9"
    assert kwargs["exc_info"] is not None


def test_create_fastapi_app_logs_sys_unhandled_exception_on_startup_failure(
    mocker: MockerFixture,
) -> None:
    mocker.patch("app.application.application_init")
    exc = RuntimeError("startup boom")
    mocker.patch("app.application.setup_fastapi", side_effect=exc)
    log_event = mocker.patch("app.application.log_event")

    with pytest.raises(RuntimeError):
        application.create_fastapi_app()

    log_event.assert_called_once_with(
        application.logger,
        SYS_UNHANDLED_EXCEPTION,
        "Unhandled exception during application startup",
        exc_info=exc,
        exception_type="RuntimeError",
        startup_phase="create_fastapi_app",
    )


def test_excepthook_skips_keyboard_interrupt(
    mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_event = mocker.patch("app.application.log_event")
    default_hook = mocker.patch("sys.__excepthook__")
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    application._install_excepthook()
    try:
        raise KeyboardInterrupt()
    except KeyboardInterrupt as exc:
        sys.excepthook(type(exc), exc, exc.__traceback__)

    log_event.assert_not_called()
    default_hook.assert_called_once()
