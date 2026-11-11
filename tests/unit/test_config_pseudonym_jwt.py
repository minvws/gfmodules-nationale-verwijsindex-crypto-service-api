from typing import Any

import pytest
from pydantic import ValidationError

from app.config import Config, ConfigPseudonym, read_ini_file


@pytest.fixture
def config_data() -> dict[str, Any]:
    return {
        "app": {"hashing_key_id": "hmac", "allowed_jwe_key_ids": ["jwe"]},
        "uvicorn": {},
        "telemetry": {},
        "stats": {},
        "hsm_api": {"url": "https://hsm.test", "module": "m", "slot": "s"},
    }


@pytest.fixture
def jwt_settings() -> dict[str, Any]:
    return {
        "jwks_url": "https://prs.example/.well-known/jwks",
        "expected_issuer": "https://prs.example",
        "expected_audience": "oin:00000099000000001000",
    }


def test_pseudonym_signing_settings_load_from_ini(
    tmp_path: Any, config_data: dict[str, Any]
) -> None:
    path = tmp_path / "pseudonym.ini"
    path.write_text(
        "[pseudonym]\nsigning_expected = True\n"
        "jwks_url = https://prs.example/jwks\n"
        "expected_issuer = https://prs.example\n"
        "expected_audience = audience\n"
    )
    config_data.update(read_ini_file(str(path)))

    config = Config.model_validate(config_data)

    assert config.pseudonym.jwks_url == "https://prs.example/jwks"
    assert config.pseudonym.expected_audience == "audience"


def test_unsigned_mode_allows_explicit_none_jwks_url(
    config_data: dict[str, Any],
) -> None:
    config_data["pseudonym"] = {"signing_expected": False, "jwks_url": None}

    config = Config.model_validate(config_data)

    assert config.pseudonym.jwks_url is None


def test_signing_is_required_when_setting_is_absent(
    config_data: dict[str, Any], jwt_settings: dict[str, Any]
) -> None:
    config_data["pseudonym"] = jwt_settings

    config = Config.model_validate(config_data)

    assert config.pseudonym.signing_expected is True
    assert config.pseudonym.timeout == 5


@pytest.mark.parametrize("setting", [None, {"signing_expected": True}])
def test_signed_mode_requires_jwks_settings(
    config_data: dict[str, Any], setting: Any
) -> None:
    if setting is not None:
        config_data["pseudonym"] = setting

    with pytest.raises(ValidationError):
        Config.model_validate(config_data)


def test_unsigned_mode_does_not_require_jwks_settings(
    config_data: dict[str, Any],
) -> None:
    config_data["pseudonym"] = {"signing_expected": False}

    config = Config.model_validate(config_data)

    assert config.pseudonym.signing_expected is False
    assert config.pseudonym.jwks_url is None


@pytest.mark.parametrize("setting, expected", [("True", True), ("False", False)])
def test_ini_boolean_selects_expected_mode(
    tmp_path: Any,
    config_data: dict[str, Any],
    jwt_settings: dict[str, Any],
    setting: str,
    expected: bool,
) -> None:
    path = tmp_path / "pseudonym.ini"
    path.write_text(f"[pseudonym]\nsigning_expected = {setting}\n")
    config_data.update(read_ini_file(str(path)))
    config_data["pseudonym"].update(jwt_settings)

    assert Config.model_validate(config_data).pseudonym.signing_expected is expected


def test_unsigned_mode_accepts_partial_jwks_settings(
    config_data: dict[str, Any],
) -> None:
    config_data["pseudonym"] = {
        "signing_expected": False,
        "jwks_url": "https://prs.example",
    }

    assert Config.model_validate(config_data).pseudonym.signing_expected is False


@pytest.mark.parametrize("field", ["jwks_url", "expected_issuer", "expected_audience"])
@pytest.mark.parametrize("value", [None, "", "   "])
def test_signed_settings_require_nonempty_fields(
    config_data: dict[str, Any], jwt_settings: dict[str, Any], field: str, value: Any
) -> None:
    if value is None:
        jwt_settings.pop(field)
    else:
        jwt_settings[field] = value
    config_data["pseudonym"] = jwt_settings

    with pytest.raises(ValidationError):
        Config.model_validate(config_data)


@pytest.mark.parametrize(
    "url",
    ["ftp://prs.example/jwks", "https:///jwks", "jwks", "https://bad%zz.example/jwks"],
)
def test_jwks_url_must_be_http_with_host(
    config_data: dict[str, Any], jwt_settings: dict[str, Any], url: str
) -> None:
    jwt_settings["jwks_url"] = url
    config_data["pseudonym"] = jwt_settings

    with pytest.raises(ValidationError):
        Config.model_validate(config_data)


@pytest.mark.parametrize(
    "url", ["http://localhost:8000/jwks", "https://prs.example/jwks"]
)
def test_accepts_http_and_https_jwks_urls(
    config_data: dict[str, Any], jwt_settings: dict[str, Any], url: str
) -> None:
    jwt_settings["jwks_url"] = url
    jwt_settings["timeout"] = 8
    config_data["pseudonym"] = jwt_settings

    config = Config.model_validate(config_data)

    assert config.pseudonym.jwks_url == url
    assert config.pseudonym.timeout == 8


def test_jwks_timeout_must_be_positive(
    config_data: dict[str, Any], jwt_settings: dict[str, Any]
) -> None:
    jwt_settings["timeout"] = 0
    config_data["pseudonym"] = jwt_settings

    with pytest.raises(ValidationError):
        Config.model_validate(config_data)


def test_jwks_tls_defaults_to_standard_ca_and_no_client_certificate(
    jwt_settings: dict[str, Any],
) -> None:
    settings = ConfigPseudonym.model_validate(jwt_settings)

    assert settings.verify_ca is True
    assert settings.cert_path is None
    assert settings.key_path is None


@pytest.mark.parametrize(
    "value,expected",
    [
        ("True", True),
        ("false", False),
        ("", True),
        ("/etc/ssl/prs-ca.pem", "/etc/ssl/prs-ca.pem"),
    ],
)
def test_jwks_verify_ca_supports_ini_boolean_or_ca_path(
    tmp_path: Any, jwt_settings: dict[str, Any], value: str, expected: str | bool
) -> None:
    path = tmp_path / "tls.ini"
    path.write_text(f"[pseudonym]\nverify_ca = {value}\n")
    jwt_settings.update(read_ini_file(str(path))["pseudonym"])

    assert ConfigPseudonym.model_validate(jwt_settings).verify_ca == expected


@pytest.mark.parametrize(
    "cert,key,expected_cert,expected_key",
    [
        ("", "", None, None),
        ("/certs/client.pem", "", "/certs/client.pem", None),
        (
            "/certs/client.crt",
            "/certs/client.key",
            "/certs/client.crt",
            "/certs/client.key",
        ),
    ],
)
def test_jwks_client_certificate_settings_are_optional(
    jwt_settings: dict[str, Any],
    cert: str,
    key: str,
    expected_cert: str | None,
    expected_key: str | None,
) -> None:
    jwt_settings.update(cert_path=cert, key_path=key)

    settings = ConfigPseudonym.model_validate(jwt_settings)

    assert settings.cert_path == expected_cert
    assert settings.key_path == expected_key


def test_jwks_private_key_requires_a_client_certificate(
    jwt_settings: dict[str, Any],
) -> None:
    jwt_settings.update(key_path="/certs/client.key")

    with pytest.raises(ValidationError, match="key_path requires cert_path"):
        ConfigPseudonym.model_validate(jwt_settings)


@pytest.mark.parametrize(
    "tls_settings",
    [
        {"verify_ca": "/certs/ca.pem"},
        {"cert_path": "/certs/combined.pem"},
    ],
)
def test_jwks_tls_settings_require_https(
    jwt_settings: dict[str, Any], tls_settings: dict[str, str]
) -> None:
    jwt_settings.update(jwks_url="http://localhost:8000/jwks", **tls_settings)

    with pytest.raises(ValidationError, match="TLS settings require an HTTPS JWKS URL"):
        ConfigPseudonym.model_validate(jwt_settings)
