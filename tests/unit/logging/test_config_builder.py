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


_SYSLOG_HANDLERS = (
    "syslog_app",
    "syslog_siem",
    "syslog_public_inspect",
    "syslog_debug",
)


@pytest.mark.parametrize(
    "handler_name,filter_name",
    [
        ("syslog_app", "app_filter"),
        ("syslog_siem", "siem_filter"),
        ("syslog_public_inspect", "public_inspect_filter"),
    ],
)
def test_build_syslog_path_adds_handler_with_filter(
    handler_name: str, filter_name: str
) -> None:
    conf = _build(syslog_path="host:514")
    assert handler_name in conf["handlers"]
    handler = conf["handlers"][handler_name]
    assert handler["address"] == ("host", 514)
    assert filter_name in handler["filters"]


def test_build_syslog_debug_handler_added_to_root_and_app() -> None:
    conf = _build(syslog_path="host:516")
    assert "syslog_debug" in conf["handlers"]
    assert "syslog_debug" in conf["loggers"]["app"]["handlers"]
    assert "syslog_debug" in conf["root"]["handlers"]
    assert conf["handlers"]["syslog_debug"]["formatter"] == "json_debug"


def test_all_streams_share_the_single_syslog_channel() -> None:
    conf = _build(syslog_path="logserver:514")

    assert set(conf["handlers"].keys()) == {"console", *_SYSLOG_HANDLERS}
    for name in _SYSLOG_HANDLERS:
        assert conf["handlers"][name]["address"] == ("logserver", 514)

    formatters = {conf["handlers"][name]["formatter"] for name in _SYSLOG_HANDLERS}
    stream_ids = {
        conf["formatters"][formatter].get("stream_id") for formatter in formatters
    }
    assert stream_ids == {"app", "siem", "public_inspect", "debug"}


def test_application_id_is_stamped_on_all_json_formatters() -> None:
    conf = _build(
        syslog_path="logserver:514",
        application_id="nationale-verwijsindex-crypto-service-api",
    )

    for name, formatter in conf["formatters"].items():
        if name == "plain":
            assert "application_id" not in formatter
        else:
            assert (
                formatter["application_id"]
                == "nationale-verwijsindex-crypto-service-api"
            )


def test_no_application_id_without_config() -> None:
    conf = _build(syslog_path="logserver:514")
    for formatter in conf["formatters"].values():
        assert "application_id" not in formatter


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
