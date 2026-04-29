from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from app import application
from app.config import Config


@pytest.fixture
def app_init(mocker: MockerFixture) -> None:
    mocker.patch("app.application.application_init")


def test_startup_with_keys_and_prs_registration(
    use_config: Config, mocker: MockerFixture, app_init: None
) -> None:
    use_config.app.generate_keys_on_startup = True
    use_config.app.register_at_prs_on_startup = True

    crypto = MagicMock()
    crypto.health_check.return_value = True
    crypto.get_public_key.return_value = "PEM"
    prs = MagicMock()
    mocker.patch("app.application.get_crypto_service", return_value=crypto)
    mocker.patch("app.application.get_prs_registration_service", return_value=prs)

    application.create_fastapi_app()

    crypto.generate_keys.assert_called_once()
    prs.register_nvi_at_prs.assert_called_once_with("PEM")


def test_startup_skips_prs_when_keys_unavailable(
    use_config: Config, mocker: MockerFixture, app_init: None
) -> None:
    use_config.app.generate_keys_on_startup = True
    use_config.app.register_at_prs_on_startup = True

    crypto = MagicMock()
    crypto.health_check.return_value = False
    prs = MagicMock()
    mocker.patch("app.application.get_crypto_service", return_value=crypto)
    mocker.patch("app.application.get_prs_registration_service", return_value=prs)

    application.create_fastapi_app()

    prs.register_nvi_at_prs.assert_not_called()


def test_startup_no_register_when_flag_off(
    use_config: Config, mocker: MockerFixture, app_init: None
) -> None:
    use_config.app.generate_keys_on_startup = False
    use_config.app.register_at_prs_on_startup = False

    crypto = MagicMock()
    crypto.get_public_key.return_value = "PEM"
    prs = MagicMock()
    mocker.patch("app.application.get_crypto_service", return_value=crypto)
    mocker.patch("app.application.get_prs_registration_service", return_value=prs)

    application.create_fastapi_app()

    crypto.generate_keys.assert_not_called()
    prs.register_nvi_at_prs.assert_not_called()
