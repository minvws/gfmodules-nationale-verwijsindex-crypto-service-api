from collections.abc import Iterator
from unittest.mock import MagicMock

import inject
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import application
from app.config import Config
from app.services.crypto.crypto_service import CryptoService
from app.services.prs_registration_service import PrsRegistrationService
from app.services.pseudonym_service import PseudonymService


@pytest.fixture
def crypto_stub() -> MagicMock:
    return MagicMock(spec=CryptoService)


@pytest.fixture
def prs_stub() -> MagicMock:
    return MagicMock(spec=PrsRegistrationService)


@pytest.fixture
def app(
    use_config: Config, crypto_stub: MagicMock, prs_stub: MagicMock
) -> Iterator[FastAPI]:
    """A real FastAPI app with the production routers, talking to stubbed services."""

    def _bind(binder: inject.Binder) -> None:
        binder.bind(CryptoService, crypto_stub)
        binder.bind(PrsRegistrationService, prs_stub)
        binder.bind(PseudonymService, PseudonymService(crypto_stub, "ura-1"))

    inject.clear_and_configure(_bind)
    fastapi_app = application.setup_fastapi()
    yield fastapi_app
    inject.clear()


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)
