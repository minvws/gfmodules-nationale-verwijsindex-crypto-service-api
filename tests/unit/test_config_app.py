import pytest
from pydantic import ValidationError

from app.config import ConfigApp


def test_jwe_key_ids_parsed_from_space_or_comma_separated_string() -> None:
    config = ConfigApp(hashing_key_id="hk", jwe_key_ids="key-1 key-2,key-3")  # type: ignore[arg-type]

    assert config.jwe_key_ids == ["key-1", "key-2", "key-3"]


@pytest.mark.parametrize("value", ["", "   ", []])
def test_jwe_key_ids_must_not_be_empty(value: object) -> None:
    with pytest.raises(ValidationError):
        ConfigApp(hashing_key_id="hk", jwe_key_ids=value)  # type: ignore[arg-type]


def test_jwe_key_ids_is_required() -> None:
    with pytest.raises(ValidationError):
        ConfigApp(hashing_key_id="hk")  # type: ignore[call-arg]
