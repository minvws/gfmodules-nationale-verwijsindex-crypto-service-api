import base64
from typing import Any
from unittest.mock import MagicMock

import pytest
from gfmodules.logging.testing import capture_records
from pytest_mock import MockerFixture

from app.exceptions.exception import CryptoError, InvalidJweError
from app.logging.events import Log
from app.services import pseudonym_service as pseudonym_service_module
from app.services.pseudonym_service import PseudonymService


@pytest.fixture
def pseudonym_service(crypto_service_mock: MagicMock) -> PseudonymService:
    return PseudonymService(crypto_service=crypto_service_mock)


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
    unblind = mocker.patch(
        "app.services.pseudonym_service.pyoprf.unblind", return_value=b"plain"
    )

    result = pseudonym_service.decrypt_and_unblind("JWE", _b64(blind_factor))

    assert result == b"plain"
    unblind.assert_called_once_with(blind_factor, subject_bytes)


def test_decrypt_and_unblind_propagates_crypto_error(
    pseudonym_service: PseudonymService, crypto_service_mock: MagicMock
) -> None:
    crypto_service_mock.decrypt_jwe_payload.side_effect = CryptoError("nope")
    encrypted_jwe = "JWE"
    blind_factor = "AAAA"
    with pytest.raises(CryptoError):
        pseudonym_service.decrypt_and_unblind(encrypted_jwe, blind_factor)


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
    ids=[
        "empty-dict",
        "none-subj",
        "int-subj",
        "wrong-prefix",
        "wrong-namespace",
        "string",
        "none",
    ],
)
def test_decrypt_and_unblind_rejects_invalid_subject(
    payload: Any,
    pseudonym_service: PseudonymService,
    crypto_service_mock: MagicMock,
) -> None:
    crypto_service_mock.decrypt_jwe_payload.return_value = payload
    encrypted_jwe = "JWE"
    blind_factor = _b64(b"blind-factor")
    with pytest.raises(InvalidJweError):
        pseudonym_service.decrypt_and_unblind(encrypted_jwe, blind_factor)


def test_hash_returns_urlsafe_b64(
    pseudonym_service: PseudonymService, crypto_service_mock: MagicMock
) -> None:
    crypto_service_mock.hash.return_value = b"hash-out"

    result = pseudonym_service.hash(b"in")

    assert result == b"hash-out"
    crypto_service_mock.hash.assert_called_once_with(b"in")


def _events(captured: Any, event_id: str) -> list[Any]:
    return [
        entry.record
        for entry in captured.entries
        if getattr(entry.record, "event_id", None) == event_id
    ]


def test_decrypt_and_unblind_logs_pse_exchange_failed_on_crypto_error(
    pseudonym_service: PseudonymService,
    crypto_service_mock: MagicMock,
    mocker: MockerFixture,
) -> None:
    crypto_service_mock.decrypt_jwe_payload.side_effect = CryptoError("nope")

    with (
        capture_records(pseudonym_service_module.logger.name) as captured,
        pytest.raises(CryptoError),
    ):
        pseudonym_service.decrypt_and_unblind("JWE", "AAAA")

    record = _events(captured, Log.PSE_EXCHANGE_FAILED.event_id)[0]
    assert record.endpoint == "/decrypt_and_hash"
    assert record.error_type == "CryptoError"


def test_decrypt_and_unblind_logs_pse_exchange_failed_on_invalid_subject(
    pseudonym_service: PseudonymService,
    crypto_service_mock: MagicMock,
    mocker: MockerFixture,
) -> None:
    crypto_service_mock.decrypt_jwe_payload.return_value = {
        "subject": "wrong-prefix:abc"
    }
    with (
        capture_records(pseudonym_service_module.logger.name) as captured,
        pytest.raises(InvalidJweError),
    ):
        pseudonym_service.decrypt_and_unblind("JWE", _b64(b"\x00" * 32))

    record = _events(captured, Log.PSE_EXCHANGE_FAILED.event_id)[0]
    assert record.endpoint == "/decrypt_and_hash"
    assert record.error_type == "invalid_subject"


def test_decrypt_and_unblind_logs_pse_exchange_ok_on_success(
    pseudonym_service: PseudonymService,
    crypto_service_mock: MagicMock,
    mocker: MockerFixture,
) -> None:
    crypto_service_mock.decrypt_jwe_payload.return_value = {
        "subject": f"pseudonym:eval:{_b64(b'subject-bytes')}"
    }
    mocker.patch("app.services.pseudonym_service.pyoprf.unblind", return_value=b"plain")

    with capture_records(pseudonym_service_module.logger.name) as captured:
        pseudonym_service.decrypt_and_unblind("JWE", _b64(b"blind-factor"))

    record = _events(captured, Log.PSE_EXCHANGE_OK.event_id)[0]
    assert record.endpoint == "/decrypt_and_hash"
