import asyncio
import json
import sys
from typing import Any
from unittest.mock import MagicMock

import gfmodules.logging as gflog
import pytest
from gfmodules.logging import LoggingStreams
from gfmodules.logging.testing import (
    capture_records,
    capture_stream,
    recorded_shutdown_reason,
)
from pytest_mock import MockerFixture

from app import application
from app.config import Config
from app.logging.events import Log


def _run_lifespan() -> list[Any]:
    with capture_records(application.logger.name) as captured:

        async def _exercise() -> None:
            async with application._lifespan(MagicMock()):
                pass

        asyncio.run(_exercise())
    return [entry.record for entry in captured.entries]


def _records_for(event_id: str) -> list[Any]:
    return [record for record in _run_lifespan() if record.event_id == event_id]


def _emitted(captured: Any) -> list[Any]:
    return [
        entry.record for entry in captured.entries if hasattr(entry.record, "event_id")
    ]


def _with_event_id(captured: Any, event_id: str) -> list[Any]:
    return [record for record in _emitted(captured) if record.event_id == event_id]


class TestLifespan:
    def test_reports_a_graceful_shutdown_on_exit(
        self, use_config: Config, mocker: MockerFixture
    ) -> None:
        mocker.patch("app.application._read_version", return_value="9.9.9")

        stopped = _records_for(Log.SYS_APP_STOPPED.event_id)

        assert [record.shutdown_reason for record in stopped] == ["graceful"]

    def test_reports_the_signal_that_triggered_the_shutdown(
        self, use_config: Config, mocker: MockerFixture
    ) -> None:
        mocker.patch("app.application._read_version", return_value="9.9.9")

        with recorded_shutdown_reason("signal:SIGTERM"):
            stopped = _records_for(Log.SYS_APP_STOPPED.event_id)

        assert [record.shutdown_reason for record in stopped] == ["signal:SIGTERM"]

    def test_emits_no_stopped_event_after_a_crash(
        self, use_config: Config, mocker: MockerFixture
    ) -> None:
        mocker.patch("app.application._read_version", return_value="9.9.9")

        with recorded_shutdown_reason("crash"):
            assert _records_for(Log.SYS_APP_STOPPED.event_id) == []

    def test_the_started_event_reports_the_version_and_the_switches(
        self, use_config: Config, mocker: MockerFixture
    ) -> None:
        mocker.patch("app.application._read_version", return_value="1.2.3")

        started = _records_for(Log.SYS_APP_STARTED.event_id)

        assert len(started) == 1
        assert started[0].version == "1.2.3"
        assert started[0].config_path is not None
        assert started[0].mock_hsm is use_config.hsm_api.mock
        assert started[0].telemetry_enabled is use_config.telemetry.enabled
        assert started[0].stats_enabled is use_config.stats.enabled

    def test_the_added_switches_reach_the_app_stream(
        self, use_config: Config, mocker: MockerFixture
    ) -> None:
        mocker.patch("app.application._read_version", return_value="1.2.3")

        with capture_stream(LoggingStreams.APP, application.logger.name) as messages:

            async def _exercise() -> None:
                async with application._lifespan(MagicMock()):
                    pass

            asyncio.run(_exercise())

        started = [message for message in messages if "mock_hsm" in message]
        assert started and started[0]["mock_hsm"] is use_config.hsm_api.mock


class TestExcepthook:
    def test_reports_a_crash_for_an_uncaught_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "excepthook", sys.excepthook)
        gflog.install_excepthook(application.logger)

        with capture_records(application.logger.name) as captured:
            try:
                raise RuntimeError("boom")
            except RuntimeError as exc:
                sys.excepthook(type(exc), exc, exc.__traceback__)

        crashed = _with_event_id(captured, Log.SYS_APP_CRASHED.event_id)
        assert len(crashed) == 1
        assert crashed[0].last_exception_type == "RuntimeError"
        assert crashed[0].shutdown_reason == "crash"
        assert crashed[0].exc_info is not None

    def test_leaves_a_keyboard_interrupt_to_the_default_hook(
        self, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        default_hook = mocker.patch("sys.__excepthook__")
        monkeypatch.setattr(sys, "excepthook", sys.excepthook)
        gflog.install_excepthook(application.logger)

        with capture_records(application.logger.name) as captured:
            try:
                raise KeyboardInterrupt()
            except KeyboardInterrupt as exc:
                sys.excepthook(type(exc), exc, exc.__traceback__)

        assert default_hook.called
        assert captured.entries == []


class TestStartupFailure:
    def test_reports_an_unhandled_exception_and_re_raises(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch("app.application.application_init")
        mocker.patch(
            "app.application.setup_fastapi", side_effect=RuntimeError("startup boom")
        )

        with (
            capture_records(application.logger.name) as captured,
            pytest.raises(RuntimeError),
        ):
            application.create_fastapi_app()

        assert _with_event_id(captured, Log.SYS_UNHANDLED_EXCEPTION.event_id)
        assert _emitted(captured)[0].exception_type == "RuntimeError"


class TestUnhandledExceptionHandler:
    def test_returns_500_and_reports_the_exception(self) -> None:
        request = MagicMock()
        request.url.path = "/boom"
        request.method = "GET"

        with capture_records(application.logger.name) as captured:
            response = application._unhandled_exception_handler(
                request, RuntimeError("explode")
            )

        assert response.status_code == 500
        assert json.loads(response.body) == {"error": "Internal server error"}  # type: ignore[arg-type]
        assert _emitted(captured)[-1].exception_type == "RuntimeError"
