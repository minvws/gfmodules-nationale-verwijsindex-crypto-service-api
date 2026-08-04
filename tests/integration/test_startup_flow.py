import pytest
from fastapi import FastAPI
from pytest_mock import MockerFixture

from app import application
from app.config import Config


@pytest.fixture
def app_init(mocker: MockerFixture) -> None:
    mocker.patch("app.application.application_init")


def test_startup_builds_app_without_key_generation_or_registration(
    use_config: Config, app_init: None
) -> None:
    app = application.create_fastapi_app()

    assert isinstance(app, FastAPI)
