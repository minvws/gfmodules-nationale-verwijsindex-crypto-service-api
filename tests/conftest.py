from collections.abc import Iterator
from unittest.mock import MagicMock

import pytest

from app import config as config_module
from app.config import (
    Config,
)
from tests.unit.test_config import get_test_config

config_module._CONFIG = get_test_config()

from app.services.crypto.crypto_service import CryptoService  # noqa: E402
from app.services.http import HttpService  # noqa: E402
from app.services.pseudonym_service import PseudonymService  # noqa: E402


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
