from collections.abc import Generator, Iterator
from typing import Any
from unittest.mock import MagicMock

import gfmodules.logging as gflog
import pytest
from gfmodules.logging import ConfigLogging
from gfmodules.logging.testing import reset_for_tests

from app import config as config_module
from app.config import (
    Config,
)
from app.logging.events import Log
from app.services.crypto.crypto_service import CryptoService
from app.services.http import HttpService
from app.services.pseudonym_service import PseudonymService
from tests.unit.test_config import get_test_config

config_module._CONFIG = get_test_config()


@pytest.fixture(autouse=True)
def logging_catalogue() -> Generator[None, Any, None]:
    gflog.configure(
        config=ConfigLogging(debug_logs_in_console=True, access_logs=False),
        loglevel="DEBUG",
        catalogue=Log,
    )
    try:
        yield
    finally:
        reset_for_tests()


@pytest.fixture
def mock_url() -> str:
    return "https://example.com/test"


@pytest.fixture
def http_service(mock_url: str) -> HttpService:
    return HttpService(
        endpoint=mock_url,
        timeout=10,
        mtls_cert=None,
        mtls_key=None,
        verify_ca=False,
    )


@pytest.fixture
def crypto_mock() -> MagicMock:
    return MagicMock(spec=CryptoService)


@pytest.fixture
def pseudonym_mock() -> MagicMock:
    return MagicMock(spec=PseudonymService)


@pytest.fixture(autouse=True)
def use_config() -> Iterator[Config]:
    previous = config_module._CONFIG
    config_module._CONFIG = get_test_config()
    try:
        yield config_module._CONFIG
    finally:
        config_module._CONFIG = previous


@pytest.fixture
def http_mock() -> MagicMock:
    return MagicMock(spec=HttpService)


@pytest.fixture
def crypto_service_mock() -> MagicMock:
    return MagicMock(spec=CryptoService)
