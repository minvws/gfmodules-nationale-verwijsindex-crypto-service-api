import logging

import pytest

from app.logging.events import (
    HEALTH_UNHEALTHY,
    PSE_EXCHANGE_OK,
    SYS_APP_STARTED,
    SYS_UNHANDLED_EXCEPTION,
    log_event,
)
from app.logging.filters import LoggingStreams


def test_log_event_attaches_event_id_and_streams(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("app.test_events")
    logger.setLevel(logging.DEBUG)
    with caplog.at_level(logging.DEBUG, logger="app.test_events"):
        log_event(logger, SYS_APP_STARTED, "started", version="1.0")

    record = caplog.records[-1]
    assert record.event_id == SYS_APP_STARTED.event_id # type: ignore
    assert LoggingStreams.APP in record.stream # type: ignore
    assert record.version == "1.0" # type: ignore
    assert record.levelno == logging.INFO


@pytest.mark.parametrize(
    "event,expected_level",
    [
        (SYS_APP_STARTED, logging.INFO),
        (HEALTH_UNHEALTHY, logging.ERROR),
        (PSE_EXCHANGE_OK, logging.DEBUG),
        (SYS_UNHANDLED_EXCEPTION, logging.ERROR),
    ],
)
def test_log_event_uses_event_level(
    caplog: pytest.LogCaptureFixture, event: object, expected_level: int
) -> None:
    logger = logging.getLogger("app.test_events_levels")
    logger.setLevel(logging.DEBUG)
    with caplog.at_level(logging.DEBUG, logger="app.test_events_levels"):
        log_event(logger, event, "msg")  # type: ignore[arg-type]
    assert caplog.records[-1].levelno == expected_level


def test_log_event_includes_exc_info(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("app.test_events_exc")
    logger.setLevel(logging.DEBUG)
    try:
        raise ValueError("boom")
    except ValueError as e:
        with caplog.at_level(logging.DEBUG, logger="app.test_events_exc"):
            log_event(logger, SYS_UNHANDLED_EXCEPTION, "fail", exc_info=e)

    assert caplog.records[-1].exc_info is not None
