import pytest
from pydantic import ValidationError

from app.config import ConfigApp, ConfigLogging, read_ini_file


def test_allowed_jwe_key_ids_parsed_from_space_or_comma_separated_string() -> None:
    config = ConfigApp(hashing_key_id="hk", allowed_jwe_key_ids="key-1 key-2,key-3")  # type: ignore[arg-type]

    assert config.allowed_jwe_key_ids == ["key-1", "key-2", "key-3"]


@pytest.mark.parametrize("value", ["", "   ", []])
def test_allowed_jwe_key_ids_must_not_be_empty(value: object) -> None:
    with pytest.raises(ValidationError):
        ConfigApp(hashing_key_id="hk", allowed_jwe_key_ids=value)  # type: ignore[arg-type]


def test_allowed_jwe_key_ids_is_required() -> None:
    with pytest.raises(ValidationError):
        ConfigApp(hashing_key_id="hk")  # type: ignore[call-arg]


def test_the_example_config_reads_the_logging_streams() -> None:
    logging = ConfigLogging.model_validate(read_ini_file("app.conf.example")["logging"])

    assert logging.syslog_streams == ["app", "siem", "public_inspect"]
    assert logging.console_streams == ["debug"]
