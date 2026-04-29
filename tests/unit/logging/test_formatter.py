import json
import logging
import sys
from typing import Any, Iterator

import pytest

from app.logging.context import client_trace_id_var, ip_var, request_id_var
from app.logging.formatter import JsonFormatter, PlainTextFormatter


def _record(msg: str = "hello", level: int = logging.INFO, **extra: Any) -> logging.LogRecord:
    record = logging.LogRecord(
        name="app.test", level=level, pathname=__file__, lineno=1, msg=msg, args=(), exc_info=None
    )
    for k, v in extra.items():
        setattr(record, k, v)
    return record


def _exc_record() -> logging.LogRecord:
    try:
        raise ValueError("boom")
    except ValueError:
        record = _record()
        record.exc_info = sys.exc_info()
        return record


@pytest.fixture
def context_vars() -> Iterator[None]:
    t1 = request_id_var.set("req-1")
    t2 = ip_var.set("10.0.0.1")
    t3 = client_trace_id_var.set("trace-1")
    try:
        yield
    finally:
        request_id_var.reset(t1)
        ip_var.reset(t2)
        client_trace_id_var.reset(t3)


def _format_json(record: logging.LogRecord, include_traces: bool = True) -> Any:
    return json.loads(JsonFormatter(include_traces=include_traces).format(record))


def test_json_formatter_required_fields() -> None:
    out = _format_json(_record("hi", event_id="100600"))
    assert {"event_id", "timestamp", "level", "event_description", "source", "message"} <= out.keys()
    assert out["event_id"] == "100600"
    assert out["event_description"] == "hi"
    assert out["level"] == "INFO"


def test_json_formatter_strips_control_characters() -> None:
    assert _format_json(_record("a\x00b\x1fc"))["event_description"] == "abc"


def test_json_formatter_includes_exception_when_traces_on() -> None:
    out = _format_json(_exc_record(), include_traces=True)
    assert "ValueError" in str(out["message"]["exception"])


def test_json_formatter_omits_exception_when_traces_off() -> None:
    out = _format_json(_exc_record(), include_traces=False)
    assert "exception" not in out["message"]


def test_json_formatter_includes_stack_info_when_traces_on() -> None:
    record = _record()
    record.stack_info = "stack"
    assert "stack_info" in _format_json(record, include_traces=True)["message"]


def test_json_formatter_includes_extras(context_vars: None) -> None:
    out = _format_json(_record(custom="x", another=42))
    msg = out["message"]
    assert msg["custom"] == "x"
    assert msg["another"] == 42
    assert msg["request_id"] == "req-1"
    assert msg["ip"] == "10.0.0.1"


def test_plaintext_formatter_includes_basic_fields(context_vars: None) -> None:
    out = PlainTextFormatter().format(_record("hello", event_id="100600", custom="x"))
    assert "INFO" in out
    assert "[100600]" in out
    assert "hello" in out
    assert "custom=x" in out
    assert "request_id=req-1" in out


def test_plaintext_formatter_appends_exception() -> None:
    out = PlainTextFormatter().format(_exc_record())
    assert "ValueError" in out
