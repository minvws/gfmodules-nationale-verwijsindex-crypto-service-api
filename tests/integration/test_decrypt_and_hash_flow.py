import base64
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from pytest_mock import MockerFixture



def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def test_process_full_flow(
    client: TestClient, crypto_stub: MagicMock, mocker: MockerFixture
) -> None:
    subject = b"subject-bytes"
    hmac_value = b"hash-out-with-a-long-text"
    crypto_stub.decrypt_jwe_payload.return_value = {
        "subject": f"pseudonym:eval:{_b64u(subject)}"
    }
    crypto_stub.hash.return_value = hmac_value
    mocker.patch(
        "app.services.pseudonym_service.pyoprf.unblind", return_value=b"unblinded"
    )
    crypto_stub.encrypt_aes.return_value = "some-encrypted_data"
    crypto_stub.aes_key_id = "label-1"
    crypto_stub.aes_mechanism = "AES_CBC"

    response = client.post(
        "/process",
        json={"jwe": "JWE-TOKEN", "blind_factor": _b64u(b"blind-factor")},
    )

    assert response.status_code == 200
    assert response.json() == {
        "encrypted_pseudonym": "some-encrypted_data",
        "iv": _b64u(hmac_value[:16]),
        "label": "label-1",
        "mechanism": "AES_CBC",
    }
    crypto_stub.decrypt_jwe_payload.assert_called_once_with("JWE-TOKEN")
    crypto_stub.hash.assert_called_once_with(b"unblinded")


def test_process_returns_400_when_subject_invalid(
    client: TestClient, crypto_stub: MagicMock
) -> None:
    crypto_stub.decrypt_jwe_payload.return_value = {"subject": "wrong"}

    response = client.post(
        "/process",
        json={"jwe": "X", "blind_factor": _b64u(b"blind-factor")},
    )

    assert response.status_code == 400
