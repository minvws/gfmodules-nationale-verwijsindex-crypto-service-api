import logging

import gfmodules.logging as gflog
import pytest
from gfmodules.logging import (
    DefaultEventCatalogue,
    LogEvent,
    LoggingStreams,
    declared_events,
)
from gfmodules.logging.testing import (
    assert_catalogue_complete,
    capture_records,
    capture_stream,
)

from app.logging.events import Log

_APP = LoggingStreams.APP
_SIEM = LoggingStreams.SIEM


class TestCatalogue:
    def test_defines_every_required_event(self) -> None:
        assert_catalogue_complete(Log, access_logs=False)

    @pytest.mark.parametrize(
        "name,event_id",
        [
            ("HEALTH_UNHEALTHY", "100600"),
            ("SYS_APP_STARTED", "100601"),
            ("SYS_APP_STOPPED", "100602"),
            ("SYS_APP_CRASHED", "100602"),
            ("SYS_UNHANDLED_EXCEPTION", "100604"),
            ("SYS_MISSING_CORRELATION_ID", "100606"),
            ("SYS_CRYPTO_FAILED", "100607"),
            ("PSE_EXCHANGE_FAILED", "900700"),
            ("PSE_EXCHANGE_OK", "900701"),
        ],
    )
    def test_carries_the_event_id_the_spec_assigns(
        self, name: str, event_id: str
    ) -> None:
        assert getattr(Log, name).event_id == event_id

    def test_every_declared_event_routes_at_least_one_stream(self) -> None:
        for name, event in declared_events(Log):
            assert event.streams, f"{name} declares no stream"


class TestTheOverriddenSlots:
    def test_the_started_event_reports_the_switches_this_service_runs_with(
        self,
    ) -> None:
        added = set(Log.SYS_APP_STARTED.fields[_APP]) - set(
            DefaultEventCatalogue.SYS_APP_STARTED.fields[_APP]
        )

        assert added == {"mock_hsm", "telemetry_enabled", "stats_enabled"}


class TestEmitting:
    @pytest.mark.parametrize(
        "event,expected_level",
        [
            (Log.SYS_APP_STARTED, logging.INFO),
            (Log.HEALTH_UNHEALTHY, logging.ERROR),
            (Log.PSE_EXCHANGE_OK, logging.DEBUG),
            (Log.SYS_UNHANDLED_EXCEPTION, logging.ERROR),
        ],
    )
    def test_uses_the_event_level(self, event: LogEvent, expected_level: int) -> None:
        logger = logging.getLogger("app.test_events_levels")
        with capture_records("app.test_events_levels") as records:
            gflog.emit(logger, event, "msg")

        assert records.entries[-1].record.levelno == expected_level

    def test_attaches_the_event_id_and_streams(self) -> None:
        logger = logging.getLogger("app.test_events")
        with capture_records("app.test_events") as records:
            gflog.emit(logger, Log.SYS_APP_STARTED, "started", fields={"version": "1.0"})

        record = records.entries[-1].record
        assert record.event_id == Log.SYS_APP_STARTED.event_id  # type: ignore[attr-defined]
        assert LoggingStreams.APP in record.stream  # type: ignore[attr-defined]
        assert record.version == "1.0"  # type: ignore[attr-defined]

    def test_includes_the_exception_when_one_is_passed(self) -> None:
        logger = logging.getLogger("app.test_events_exc")
        try:
            raise ValueError("boom")
        except ValueError as e:
            with capture_records("app.test_events_exc") as records:
                gflog.emit(logger, Log.SYS_UNHANDLED_EXCEPTION, "fail", exc_info=e)

        assert records.entries[-1].record.exc_info is not None


class TestStreamRouting:
    def test_the_started_event_reaches_the_app_stream_only(self) -> None:
        logger = logging.getLogger("app.test_routing")
        with (
            capture_stream(_APP, "app.test_routing") as app_stream,
            capture_stream(_SIEM, "app.test_routing") as siem_stream,
        ):
            gflog.emit(logger, Log.SYS_APP_STARTED, "started", fields={"version": "1.0", "mock_hsm": True})

        assert app_stream[0]["mock_hsm"] is True
        assert siem_stream == []

    def test_a_stopped_event_gives_siem_the_reason_but_not_the_exception(self) -> None:
        logger = logging.getLogger("app.test_routing")
        with capture_stream(_SIEM, "app.test_routing") as siem_stream:
            gflog.emit(logger, Log.SYS_APP_STOPPED, "stopped", fields={"shutdown_reason": "signal:SIGTERM", "last_exception_type": "RuntimeError"})

        assert siem_stream[0]["shutdown_reason"] == "signal:SIGTERM"
        assert "last_exception_type" not in siem_stream[0]
