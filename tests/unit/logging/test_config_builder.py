from typing import Any

import pytest

from app.config import ConfigLogging
from app.logging.config_builder import LogConfigBuilder


def _build(loglevel: str = "DEBUG", **logging_overrides: Any) -> dict[str, Any]:
    cfg = ConfigLogging(**logging_overrides)
    return LogConfigBuilder(logging_config=cfg, loglevel=loglevel).build()


def test_build_returns_valid_logging_dict() -> None:
    conf = _build()
    assert conf["version"] == 1
    assert conf["disable_existing_loggers"] is False


def test_build_default_only_has_console_handler() -> None:
    assert list(_build()["handlers"].keys()) == ["console"]


def test_build_console_handler_uses_loglevel() -> None:
    conf = _build()
    assert conf["handlers"]["console"]["level"] == "DEBUG"
    assert conf["loggers"]["app"]["level"] == "DEBUG"
    conf = _build(loglevel="INFO")
    assert conf["handlers"]["console"]["level"] == "INFO"
    assert conf["loggers"]["app"]["level"] == "INFO"


def test_build_debug_logs_in_console_uses_plain_formatter() -> None:
    conf = _build(debug_logs_in_console=True)
    assert conf["handlers"]["console"]["formatter"] == "plain"
    assert conf["handlers"]["console"]["level"] == "DEBUG"


def test_build_console_uses_json_traces_when_traces_included() -> None:
    conf = _build(include_traces=True)
    assert conf["handlers"]["console"]["formatter"] == "json_traces"


def test_build_console_uses_json_when_traces_excluded() -> None:
    conf = _build(include_traces=False)
    assert conf["handlers"]["console"]["formatter"] == "json"


@pytest.mark.parametrize(
    "field,handler_name,filter_name",
    [
        ("app_path", "app_syslog", "app_filter"),
        ("siem_path", "siem", "siem_filter"),
        ("public_inspect_path", "public_inspect", "public_inspect_filter"),
    ],
)
def test_build_path_adds_handler_with_filter(field: str, handler_name: str, filter_name: str) -> None:
    conf = _build(**{field: "host:514"})
    assert handler_name in conf["handlers"]
    handler = conf["handlers"][handler_name]
    assert handler["address"] == ("host", 514)
    assert filter_name in handler["filters"]


def test_build_debug_path_adds_handler_to_root_and_app() -> None:
    conf = _build(debug_path="host:516")
    assert "debug" in conf["handlers"]
    assert "debug" in conf["loggers"]["app"]["handlers"]
    assert "debug" in conf["root"]["handlers"]
    assert conf["handlers"]["debug"]["formatter"] == "json_traces"


def test_build_all_paths_configured() -> None:
    conf = _build(
        app_path="h:514",
        siem_path="h:515",
        public_inspect_path="h:516",
        debug_path="h:517",
    )
    assert {"console", "app_syslog", "siem", "public_inspect", "debug"} == set(conf["handlers"].keys())


def test_syslog_handler_parses_host_port_and_filters() -> None:
    builder = LogConfigBuilder(logging_config=ConfigLogging())
    handler = builder._syslog_handler("host:9000", formatter="json", filters=["f1"])
    assert handler["address"] == ("host", 9000)
    assert handler["formatter"] == "json"
    assert handler["filters"] == ["f1"]


def test_syslog_handler_omits_filters_when_none() -> None:
    builder = LogConfigBuilder(logging_config=ConfigLogging())
    handler = builder._syslog_handler("host:9000", formatter="json")
    assert "filters" not in handler
