import logging
from typing import List

import pytest

from app.logging.filters import (
    _LOGGER_ACCESS,
    AppFilter,
    LoggingStreams,
    PublicInspectFilter,
    SiemFilter,
)


def _record(name: str = "app.test", **extra: object) -> logging.LogRecord:
    record = logging.LogRecord(
        name=name, level=logging.INFO, pathname=__file__, lineno=1, msg="m", args=(), exc_info=None
    )
    for k, v in extra.items():
        setattr(record, k, v)
    return record


@pytest.mark.parametrize(
    "filter_cls,stream,expected",
    [
        (AppFilter, [LoggingStreams.APP], True),
        (AppFilter, [LoggingStreams.SIEM], False),
        (AppFilter, None, False),
        (PublicInspectFilter, [LoggingStreams.PUBLIC_INSPECT], True),
        (PublicInspectFilter, [LoggingStreams.SIEM], False),
        (PublicInspectFilter, None, False),
        (SiemFilter, [LoggingStreams.SIEM], True),
        (SiemFilter, [LoggingStreams.APP], False),
        (SiemFilter, None, False),
    ],
    ids=[
        "app-pass", "app-block-siem", "app-block-none",
        "public-pass", "public-block-siem", "public-block-none",
        "siem-pass", "siem-block-app", "siem-block-none",
    ],
)
def test_stream_filters(filter_cls: type, stream: List[LoggingStreams] | None, expected: bool) -> None:
    record = _record() if stream is None else _record(stream=stream)
    assert filter_cls().filter(record) is expected


@pytest.mark.parametrize(
    "name,expected",
    [
        ("uvicorn", True),
        ("uvicorn.error", True),
        (_LOGGER_ACCESS, True),
        ("app.other", False),
    ],
)
def test_app_filter_passes_known_loggers_without_stream(name: str, expected: bool) -> None:
    assert AppFilter().filter(_record(name=name)) is expected
