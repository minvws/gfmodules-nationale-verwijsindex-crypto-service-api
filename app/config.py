import configparser
import logging
import os
from enum import Enum
from typing import Any, Self
from urllib.parse import urlsplit

import requests
from gfmodules.logging import ConfigLogging as GFConfigLogging
from gfmodules.logging.ini import split_comma_separated
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

logger = logging.getLogger(__name__)

_PATH = "app.conf"
_ENVIRONMENT_CONFIG_PATH_NAME = "FASTAPI_CONFIG_PATH"
_CONFIG = None


class LogLevel(str, Enum):
    debug = "debug"
    info = "info"
    warning = "warning"
    error = "error"
    critical = "critical"


class ConfigApp(BaseModel):
    loglevel: LogLevel = Field(default=LogLevel.info)
    hashing_key_id: str
    # HSM labels of the private keys an incoming JWE may be encrypted for (the JWE "kid").
    # Anything else is rejected, so a caller cannot make the HSM use an arbitrary private key.
    allowed_jwe_key_ids: list[str] = Field(min_length=1)
    allow_insecure_requests: bool = Field(default=False)
    # Mounts development-only /test endpoints. Never enable outside development.
    test_endpoints_enabled: bool = Field(default=False)

    @field_validator("allowed_jwe_key_ids", mode="before")
    @classmethod
    def split_allowed_jwe_key_ids(cls, v: Any) -> Any:
        if isinstance(v, str):
            return [item for item in v.replace(",", " ").split() if item]
        return v


class ConfigHsmApi(BaseModel):
    mock: bool = Field(default=False)
    url: str
    module: str
    slot: str
    cert_path: str | None = None
    key_path: str | None = None
    timeout: int = Field(default=30, gt=0)
    verify_ca: str | bool = Field(default=True)


class ConfigPseudonym(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    signing_expected: bool = True
    jwks_url: str | None = Field(default=None, min_length=1)
    expected_issuer: str | None = Field(default=None, min_length=1)
    expected_audience: str | None = Field(default=None, min_length=1)
    timeout: int = Field(default=5, gt=0)
    verify_ca: str | bool = True
    cert_path: str | None = None
    key_path: str | None = None

    @field_validator("verify_ca", mode="before")
    @classmethod
    def parse_verify_ca(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return True
            booleans = configparser.ConfigParser.BOOLEAN_STATES
            if value.lower() in booleans:
                return booleans[value.lower()]
        return value

    @field_validator("cert_path", "key_path", mode="before")
    @classmethod
    def empty_path_is_unset(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip() or None
        return value

    @model_validator(mode="after")
    def validate_signing_settings(self) -> Self:
        if self.key_path and not self.cert_path:
            raise ValueError("key_path requires cert_path")
        if (
            self.jwks_url
            and urlsplit(self.jwks_url).scheme != "https"
            and (self.cert_path or isinstance(self.verify_ca, str))
        ):
            raise ValueError("TLS settings require an HTTPS JWKS URL")
        if self.signing_expected and not all(
            (self.jwks_url, self.expected_issuer, self.expected_audience)
        ):
            raise ValueError("Signing settings require JWKS URL, issuer and audience")
        return self

    @field_validator("jwks_url")
    @classmethod
    def validate_jwks_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("JWKS URL must be an HTTP(S) URL with a host")
            _ = parsed.port
            requests.Request("GET", value).prepare()
        except (ValueError, requests.RequestException) as exc:
            raise ValueError("JWKS URL must be an HTTP(S) URL with a host") from exc
        return value


class ConfigTelemetry(BaseModel):
    enabled: bool = Field(default=False)
    endpoint: str | None = None
    service_name: str | None = None
    tracer_name: str | None = None


class ConfigStats(BaseModel):
    enabled: bool = Field(default=False)
    host: str | None = None
    port: int | None = None
    module_name: str | None = None


class ConfigLogging(GFConfigLogging):
    _split_console_streams = field_validator("console_streams", mode="before")(
        split_comma_separated()
    )


class ConfigUvicorn(BaseModel):
    swagger_enabled: bool = Field(default=False)
    docs_url: str = Field(default="/docs")
    redoc_url: str = Field(default="/redoc")
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8009, gt=0, lt=65535)
    reload: bool = Field(default=True)
    use_ssl: bool = Field(default=False)
    ssl_base_dir: str | None = None
    ssl_cert_file: str | None = None
    ssl_key_file: str | None = None


class Config(BaseModel):
    app: ConfigApp
    uvicorn: ConfigUvicorn
    telemetry: ConfigTelemetry
    stats: ConfigStats
    hsm_api: ConfigHsmApi
    logging: ConfigLogging = Field(default_factory=ConfigLogging)
    pseudonym: ConfigPseudonym = Field(default_factory=ConfigPseudonym)


def read_ini_file(path: str) -> Any:
    ini_data = configparser.ConfigParser()
    ini_data.read(path)

    ret = {}
    for section in ini_data.sections():
        ret[section] = dict(ini_data[section])

    return ret


def reset_config() -> None:
    global _CONFIG
    _CONFIG = None


def get_config(path: str | None = None) -> Config:
    global _CONFIG

    if _CONFIG is not None:
        return _CONFIG

    if path is None:
        path = os.environ.get(_ENVIRONMENT_CONFIG_PATH_NAME) or _PATH

    # To be inline with other python code, we use INI-type files for configuration. Since this isn't
    # a standard format for pydantic, we need to do some manual parsing first.
    ini_data = read_ini_file(path)

    try:
        _CONFIG = Config(**ini_data)
    except ValidationError as e:
        print(f"Configuration validation error: {e}")
        raise

    return _CONFIG
