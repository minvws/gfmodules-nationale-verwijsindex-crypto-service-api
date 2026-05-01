import base64
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from app.exceptions.exception import CryptoError, InvalidJweError
from app.logging.events import PSE_EXCHANGE_FAILED, PSE_EXCHANGE_OK
from app.services import pseudonym_service as pseudonym_service_module
from app.services.pseudonym_service import PseudonymService


@pytest.fixture
def pseudonym_service(crypto_service_mock: MagicMock) -> PseudonymService:
    return PseudonymService(crypto_service=crypto_service_mock, nvi_ura_number="u")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")


def test_decrypt_and_unblind_returns_unblinded_bytes(
    pseudonym_service: PseudonymService,
    crypto_service_mock: MagicMock,
    mocker: MockerFixture,
) -> None:
    subject_bytes = b"subject-bytes"
    blind_factor = b"blind-factor"
    crypto_service_mock.decrypt_jwe_payload.return_value = {
        "subject": f"pseudonym:eval:{_b64(subject_bytes)}"
    }
    unblind = mocker.patch("app.services.pseudonym_service.pyoprf.unblind", return_value=b"plain")

    result = pseudonym_service.decrypt_and_unblind("JWE", _b64(blind_factor))

    assert result == b"plain"
    unblind.assert_called_once_with(blind_factor, subject_bytes)


def test_decrypt_and_unblind_propagates_crypto_error(
    pseudonym_service: PseudonymService, crypto_service_mock: MagicMock
) -> None:
    crypto_service_mock.decrypt_jwe_payload.side_effect = CryptoError("nope")
    with pytest.raises(CryptoError):
        pseudonym_service.decrypt_and_unblind("JWE", "AAAA")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"subject": None},
        {"subject": 123},
        {"subject": "wrong-prefix:abc"},
        {"subject": "pseudonym:other:abc"},
        "not-a-dict",
        None,
    ],
    ids=["empty-dict", "none-subj", "int-subj", "wrong-prefix", "wrong-namespace", "string", "none"],
)
def test_decrypt_and_unblind_rejects_invalid_subject(
    payload: Any,
    pseudonym_service: PseudonymService,
    crypto_service_mock: MagicMock,
) -> None:
    crypto_service_mock.decrypt_jwe_payload.return_value = payload
    with pytest.raises(InvalidJweError):
        pseudonym_service.decrypt_and_unblind("JWE", _b64(b"blind-factor"))


def test_hash_returns_urlsafe_b64(
    pseudonym_service: PseudonymService, crypto_service_mock: MagicMock
) -> None:
    crypto_service_mock.hash.return_value = b"hash-out"

    result = pseudonym_service.hash(b"in")

    assert result == _b64(b"hash-out")
    crypto_service_mock.hash.assert_called_once_with(b"in")


def test_decrypt_and_unblind_logs_pse_exchange_failed_on_crypto_error(
    pseudonym_service: PseudonymService,
    crypto_service_mock: MagicMock,
    mocker: MockerFixture,
) -> None:
    crypto_service_mock.decrypt_jwe_payload.side_effect = CryptoError("nope")
    log_event = mocker.patch("app.services.pseudonym_service.log_event")

    with pytest.raises(CryptoError):
        pseudonym_service.decrypt_and_unblind("JWE", "AAAA")

    log_event.assert_called_once_with(
        pseudonym_service_module.logger,
        PSE_EXCHANGE_FAILED,
        "OPRF exchange failed: JWE decrypt failed",
        ura_number="u",
        endpoint="/decrypt_and_hash",
        error_type="CryptoError",
    )


def test_decrypt_and_unblind_logs_pse_exchange_failed_on_invalid_subject(
    pseudonym_service: PseudonymService,
    crypto_service_mock: MagicMock,
    mocker: MockerFixture,
) -> None:
    crypto_service_mock.decrypt_jwe_payload.return_value = {"subject": "wrong-prefix:abc"}
    log_event = mocker.patch("app.services.pseudonym_service.log_event")

    with pytest.raises(InvalidJweError):
        pseudonym_service.decrypt_and_unblind("JWE", _b64(b"\x00" * 32))

    log_event.assert_called_once_with(
        pseudonym_service_module.logger,
        PSE_EXCHANGE_FAILED,
        "OPRF exchange failed: invalid JWE subject",
        ura_number="u",
        endpoint="/decrypt_and_hash",
        error_type="invalid_subject",
    )


def test_decrypt_and_unblind_logs_pse_exchange_ok_on_success(
    pseudonym_service: PseudonymService,
    crypto_service_mock: MagicMock,
    mocker: MockerFixture,
) -> None:
    crypto_service_mock.decrypt_jwe_payload.return_value = {
        "subject": f"pseudonym:eval:{_b64(b'subject-bytes')}"
    }
    mocker.patch("app.services.pseudonym_service.pyoprf.unblind", return_value=b"plain")
    log_event = mocker.patch("app.services.pseudonym_service.log_event")

    pseudonym_service.decrypt_and_unblind("JWE", _b64(b"blind-factor"))

    log_event.assert_called_once_with(
        pseudonym_service_module.logger,
        PSE_EXCHANGE_OK,
        "OPRF exchange succeeded",
        ura_number="u",
        endpoint="/decrypt_and_hash",
    )
