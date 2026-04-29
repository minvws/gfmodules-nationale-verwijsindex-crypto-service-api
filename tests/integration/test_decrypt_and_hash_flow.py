import base64
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from pytest_mock import MockerFixture


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def test_decrypt_and_hash_full_flow(
    client: TestClient, crypto_stub: MagicMock, mocker: MockerFixture
) -> None:
    subject = b"subject-bytes"
    crypto_stub.decrypt_jwe_payload.return_value = {
        "subject": f"pseudonym:eval:{_b64u(subject)}"
    }
    crypto_stub.hash.return_value = b"hash-out"
    mocker.patch("app.services.pseudonym_service.pyoprf.unblind", return_value=b"unblinded")

    response = client.get(
        "/decrypt_and_hash",
        params={"jwe": "JWE-TOKEN", "blind_factor": _b64u(b"blind-factor")},
    )

    assert response.status_code == 200
    assert response.json() == {"hashed_pseudonym": _b64u(b"hash-out")}
    crypto_stub.decrypt_jwe_payload.assert_called_once_with("JWE-TOKEN")
    crypto_stub.hash.assert_called_once_with(b"unblinded")


def test_decrypt_and_hash_returns_400_when_subject_invalid(
    client: TestClient, crypto_stub: MagicMock
) -> None:
    crypto_stub.decrypt_jwe_payload.return_value = {"subject": "wrong"}

    response = client.get(
        "/decrypt_and_hash", params={"jwe": "X", "blind_factor": _b64u(b"blind-factor")}
    )

    assert response.status_code == 400
