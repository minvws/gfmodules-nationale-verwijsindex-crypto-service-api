import configparser
import logging
import os
from enum import Enum
from typing import Any

from pydantic import BaseModel, ValidationError, Field

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
    nvi_ura_number: str
    key_id: str
    hashing_key_id: str
    generate_keys_on_startup: bool = Field(default=False)
    register_prs_on_startup: bool = Field(default=False)


class ConfigHsmApi(BaseModel):
    mock: bool = Field(default=False)
    url: str
    module: str
    slot: str
    cert_path: str | None = None
    key_path: str | None = None
    timeout: int = Field(default=30, gt=0)
    verify_ca: str | bool = Field(default=False)


class ConfigPseudonymApi(BaseModel):
    endpoint: str
    timeout: int = Field(default=30, gt=0)
    mtls_cert: str | None = None
    mtls_key: str | None = None
    verify_ca: str | bool = Field(default=True)


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
    pseudonym_api: ConfigPseudonymApi
    hsm_api: ConfigHsmApi


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
    global _PATH

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
        raise e

    return _CONFIG
