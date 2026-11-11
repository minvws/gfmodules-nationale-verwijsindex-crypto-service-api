import base64
import json
from unittest.mock import MagicMock, call

import pytest
from pytest_mock import MockerFixture

from app.config import ConfigPseudonym
from app.exceptions.exception import (
    InvalidJweError,
    InvalidSignedPseudonymError,
    JwksUnavailableError,
)
from app.services.crypto.mock_crypto_service import MockCryptoService
from app.services.pseudonym_jwks import PseudonymJwksService
from app.services.pseudonym_jwt import PseudonymJwtVerifier
from app.services.pseudonym_service import PseudonymService


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode()


def test_signed_mode_verifies_before_unblinding(
    crypto_service_mock: MagicMock, mocker: MockerFixture
) -> None:
    order = MagicMock()
    verifier = MagicMock(spec=PseudonymJwtVerifier)
    verifier.verify.return_value = {"subject": f"pseudonym:eval:{_b64(b'subject')}"}
    order.attach_mock(verifier.verify, "verify")
    unblind = mocker.patch(
        "app.services.pseudonym_service.pyoprf.unblind", return_value=b"plain"
    )
    order.attach_mock(unblind, "unblind")
    crypto_service_mock.decrypt_jwe_payload.return_value = b"header.payload.signature"
    service = PseudonymService(crypto_service_mock, verifier=verifier)

    assert service.decrypt_and_unblind("outer-jwe", _b64(b"blind")) == b"plain"
    crypto_service_mock.decrypt_jwe_payload.assert_called_once_with(
        "outer-jwe", expected_content_types={"JWT"}
    )
    assert order.mock_calls == [
        call.verify("header.payload.signature"),
        call.unblind(b"blind", b"subject"),
    ]


@pytest.mark.parametrize(
    "error", [InvalidSignedPseudonymError(), JwksUnavailableError()]
)
def test_signed_mode_never_unblinds_after_verification_failure(
    crypto_service_mock: MagicMock, mocker: MockerFixture, error: Exception
) -> None:
    verifier = MagicMock(spec=PseudonymJwtVerifier)
    verifier.verify.side_effect = error
    crypto_service_mock.decrypt_jwe_payload.return_value = b"header.payload.signature"
    unblind = mocker.patch("app.services.pseudonym_service.pyoprf.unblind")
    service = PseudonymService(crypto_service_mock, verifier=verifier)

    with pytest.raises(type(error)):
        service.decrypt_and_unblind("outer-jwe", _b64(b"blind"))
    unblind.assert_not_called()


def test_signed_mode_rejects_non_ascii_payload_before_verification(
    crypto_service_mock: MagicMock,
) -> None:
    verifier = MagicMock(spec=PseudonymJwtVerifier)
    crypto_service_mock.decrypt_jwe_payload.return_value = b"\xff"
    service = PseudonymService(crypto_service_mock, verifier=verifier)

    with pytest.raises(InvalidSignedPseudonymError):
        service.decrypt_and_unblind("outer-jwe", _b64(b"blind"))

    verifier.verify.assert_not_called()


def test_unsigned_mode_parses_json_without_using_a_verifier(
    crypto_service_mock: MagicMock, mocker: MockerFixture
) -> None:
    crypto_service_mock.decrypt_jwe_payload.return_value = json.dumps(
        {"subject": f"pseudonym:eval:{_b64(b'subject')}"}
    ).encode()
    unblind = mocker.patch(
        "app.services.pseudonym_service.pyoprf.unblind", return_value=b"plain"
    )
    service = PseudonymService(crypto_service_mock, verifier=None)

    assert service.decrypt_and_unblind("outer-jwe", _b64(b"blind")) == b"plain"
    crypto_service_mock.decrypt_jwe_payload.assert_called_once_with(
        "outer-jwe", expected_content_types={"application/json"}
    )
    unblind.assert_called_once_with(b"blind", b"subject")


@pytest.mark.parametrize(
    "payload", [b"header.payload.signature", b"\xff", b"{", b"[]", b"null"]
)
def test_unsigned_mode_rejects_wrong_payload_before_unblinding(
    crypto_service_mock: MagicMock, mocker: MockerFixture, payload: bytes
) -> None:
    crypto_service_mock.decrypt_jwe_payload.return_value = payload
    unblind = mocker.patch("app.services.pseudonym_service.pyoprf.unblind")
    service = PseudonymService(crypto_service_mock, verifier=None)

    with pytest.raises(InvalidJweError):
        service.decrypt_and_unblind("outer-jwe", _b64(b"blind"))
    unblind.assert_not_called()


@pytest.mark.parametrize(
    "subject", ["pseudonym:eval:!!!", "pseudonym:eval:a", "pseudonym:eval:a:b"]
)
def test_invalid_subject_encoding_is_rejected_before_unblinding(
    crypto_service_mock: MagicMock, mocker: MockerFixture, subject: str
) -> None:
    crypto_service_mock.decrypt_jwe_payload.return_value = json.dumps(
        {"subject": subject}
    ).encode()
    unblind = mocker.patch("app.services.pseudonym_service.pyoprf.unblind")
    service = PseudonymService(crypto_service_mock, verifier=None)

    with pytest.raises(
        InvalidJweError, match="^OPRF subject or blind factor is invalid$"
    ):
        service.decrypt_and_unblind("outer-jwe", _b64(b"blind"))
    unblind.assert_not_called()


def test_invalid_oprf_input_is_a_safe_client_error(
    crypto_service_mock: MagicMock,
) -> None:
    crypto_service_mock.decrypt_jwe_payload.return_value = json.dumps(
        {"subject": f"pseudonym:eval:{_b64(b'short')}"}
    ).encode()
    service = PseudonymService(crypto_service_mock, verifier=None)

    with pytest.raises(InvalidJweError):
        service.decrypt_and_unblind("outer-jwe", _b64(b"short"))


def test_mock_hsm_does_not_bypass_signature_verification(mocker: MockerFixture) -> None:
    config = ConfigPseudonym(
        jwks_url="https://prs.example/jwks",
        expected_issuer="https://prs.example",
        expected_audience="audience",
    )
    verifier = PseudonymJwtVerifier(config, PseudonymJwksService(config))
    service = PseudonymService(MockCryptoService(), verifier=verifier)
    unblind = mocker.patch("app.services.pseudonym_service.pyoprf.unblind")

    with pytest.raises(InvalidSignedPseudonymError):
        service.decrypt_and_unblind('{"subject":"pseudonym:eval:YWJj"}', _b64(b"blind"))
    unblind.assert_not_called()


def test_mock_hsm_accepts_json_plaintext_only_in_unsigned_mode(
    mocker: MockerFixture,
) -> None:
    service = PseudonymService(MockCryptoService(), verifier=None)
    mocker.patch("app.services.pseudonym_service.pyoprf.unblind", return_value=b"plain")
    payload = json.dumps({"subject": f"pseudonym:eval:{_b64(b'subject')}"})
    assert service.decrypt_and_unblind(payload, _b64(b"blind")) == b"plain"
