import base64
import logging
from typing import Any

from app.data import Pkc11Mechanism
from app.services.crypto.crypto_service import CryptoService

logger = logging.getLogger(__name__)

_CANNED_BLINDED_PSEUDONYM = base64.urlsafe_b64encode(b"mock-blinded-pseudonym").decode(
    "utf-8"
)
_CANNED_PAYLOAD = {"subject": f"pseudonym:eval:{_CANNED_BLINDED_PSEUDONYM}"}


class MockCryptoService(CryptoService):
    """
    Pass-through crypto service: no keys, no crypto.
    Intended for local development and wiring smoke tests.
    """

    def __init__(self, aes_key_id: str, aes_mechanism: Pkc11Mechanism) -> None:
        super().__init__(aes_key_id, aes_mechanism)

    def health_check(self) -> bool:
        return True

    def get_public_key(self, key_id: str) -> str:
        return "no-key"

    def decrypt_jwe(self, jwe_token: str, key_id: str) -> bytes:
        return jwe_token.encode("utf-8")

    def decrypt_jwe_payload(self, jwe_token: str) -> Any:
        logger.debug("Mock decrypt_jwe_payload: returning canned payload")
        return _CANNED_PAYLOAD

    def hash(self, data: bytes) -> bytes:
        return data

    def encrypt_aes(self, data: bytes, iv: bytes) -> str:
        return base64.b64encode(data).decode()

    def decrypt_aes(self, data: str, iv: str) -> str:
        return data
