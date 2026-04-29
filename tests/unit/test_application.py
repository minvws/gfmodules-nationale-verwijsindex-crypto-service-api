import asyncio
import json
import sys
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from app import application
from app.config import Config
from app.logging.events import (
    HEALTH_UNHEALTHY,
    SYS_APP_CRASHED,
    SYS_APP_STARTED,
    SYS_APP_STOPPED,
    SYS_CRYPTO_FAILED,
    SYS_UNHANDLED_EXCEPTION,
)


def test_register_at_prs_skips_when_disabled(
    use_config: Config, mocker: MockerFixture
) -> None:
    use_config.app.register_at_prs_on_startup = False

    factory = mocker.patch("app.application.get_prs_registration_service")

    application.register_at_prs(use_config.app, "PEM")

    factory.assert_not_called()


def test_register_at_prs_calls_service_when_enabled(
    use_config: Config, mocker: MockerFixture
) -> None:
    use_config.app.register_at_prs_on_startup = True
    prs = MagicMock()
    mocker.patch("app.application.get_prs_registration_service", return_value=prs)

    application.register_at_prs(use_config.app, "PEM")

    prs.register_nvi_at_prs.assert_called_once_with("PEM")


def test_generate_keys_on_startup_generates_keys_and_returns_pubkey(
    use_config: Config, mocker: MockerFixture
) -> None:
    use_config.app.generate_keys_on_startup = True
    crypto = MagicMock()
    crypto.health_check.return_value = True
    crypto.get_public_key.return_value = "PEM"
    mocker.patch("app.application.get_crypto_service", return_value=crypto)

    result = application.generate_keys_on_startup(use_config.app)

    assert result == "PEM"
    crypto.generate_keys.assert_called_once_with()
    crypto.get_public_key.assert_called_once_with(use_config.app.key_id)


def test_generate_keys_on_startup_returns_pubkey_without_generating(
    use_config: Config, mocker: MockerFixture
) -> None:
    use_config.app.generate_keys_on_startup = False
    crypto = MagicMock()
    crypto.get_public_key.return_value = "PEM"
    mocker.patch("app.application.get_crypto_service", return_value=crypto)

    result = application.generate_keys_on_startup(use_config.app)

    assert result == "PEM"
    crypto.health_check.assert_not_called()
    crypto.generate_keys.assert_not_called()
    crypto.get_public_key.assert_called_once_with(use_config.app.key_id)


def test_generate_keys_on_startup_logs_and_returns_empty_when_unhealthy(
    use_config: Config, mocker: MockerFixture
) -> None:
    use_config.app.generate_keys_on_startup = True
    crypto = MagicMock()
    crypto.health_check.return_value = False
    mocker.patch("app.application.get_crypto_service", return_value=crypto)
    log_event = mocker.patch("app.application.log_event")

    result = application.generate_keys_on_startup(use_config.app)

    assert result == ""
    crypto.generate_keys.assert_not_called()
    crypto.get_public_key.assert_not_called()
    log_event.assert_called_once_with(
        application.logger,
        HEALTH_UNHEALTHY,
        "HSM unhealthy at startup, skipping key generation",
        unhealthy_component="hsm_api",
        status="error",
        error_detail="health_check returned false",
    )


def test_generate_keys_on_startup_logs_and_returns_empty_on_exception(
    use_config: Config, mocker: MockerFixture
) -> None:
    use_config.app.generate_keys_on_startup = True
    crypto = MagicMock()
    crypto.health_check.return_value = True
    crypto.generate_keys.side_effect = RuntimeError("boom")
    mocker.patch("app.application.get_crypto_service", return_value=crypto)
    log_event = mocker.patch("app.application.log_event")

    result = application.generate_keys_on_startup(use_config.app)

    assert result == ""
    log_event.assert_called_once_with(
        application.logger,
        SYS_CRYPTO_FAILED,
        "Startup crypto operation failed, app will serve but is unhealthy",
        operation_type="startup_key_setup",
        error_reason="RuntimeError",
        retry_attempt=0,
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
    assert json.loads(response.body) == {"error": "Internal server error"} # type: ignore
    log_event.assert_called_once_with(
        application.logger,
        SYS_UNHANDLED_EXCEPTION,
        "Unhandled exception",
        exc_info=exc,
        exception_type="RuntimeError",
        endpoint="/boom",
        method="GET",
    )


def test_lifespan_logs_shutdown_reason_on_exit(mocker: MockerFixture) -> None:
    log_event = mocker.patch("app.application.log_event")
    mocker.patch("app.application._read_version", return_value="9.9.9")
    application._shutdown_reason = "graceful"

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
    use_config.app.generate_keys_on_startup = True
    use_config.app.register_at_prs_on_startup = False
    mocker.patch("app.application._read_version", return_value="1.2.3")
    log_event = mocker.patch("app.application.log_event")

    application._emit_app_started(use_config.app)

    log_event.assert_called_once_with(
        application.logger,
        SYS_APP_STARTED,
        "Application started",
        version="1.2.3",
        config_path=mocker.ANY,
        mock_hsm=use_config.hsm_api.mock,
        generate_keys_on_startup=True,
        register_at_prs_on_startup=False,
        telemetry_enabled=use_config.telemetry.enabled,
        stats_enabled=use_config.stats.enabled,
    )


def test_excepthook_logs_sys_app_crashed_for_uncaught_exception(
    mocker: MockerFixture,
) -> None:
    mocker.patch("app.application._read_version", return_value="9.9.9")
    log_event = mocker.patch("app.application.log_event")
    previous_excepthook = sys.excepthook
    try:
        application._install_excepthook()
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            sys.excepthook(*sys.exc_info())
    finally:
        sys.excepthook = previous_excepthook

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


def test_excepthook_skips_keyboard_interrupt(mocker: MockerFixture) -> None:
    log_event = mocker.patch("app.application.log_event")
    previous_excepthook = sys.excepthook
    default_hook = mocker.patch("sys.__excepthook__")
    try:
        application._install_excepthook()
        try:
            raise KeyboardInterrupt()
        except KeyboardInterrupt:
            sys.excepthook(*sys.exc_info())
    finally:
        sys.excepthook = previous_excepthook

    log_event.assert_not_called()
    default_hook.assert_called_once()
