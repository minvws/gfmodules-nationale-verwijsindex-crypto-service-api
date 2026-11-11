import base64
import logging
from collections.abc import Collection

from app.data import Pkc11Mechanism
from app.services.crypto.crypto_service import CryptoService

logger = logging.getLogger(__name__)


class MockCryptoService(CryptoService):
    """
    Pass-through crypto service: no keys, no crypto.
    Intended for local development and wiring smoke tests.
    """

    def health_check(self) -> bool:
        return True

    def get_public_key(self, key_id: str) -> str:
        return "no-key"

    def decrypt_jwe(self, jwe_token: str, key_id: str) -> bytes:
        return jwe_token.encode("utf-8")

    def decrypt_jwe_payload(
        self, jwe_token: str, expected_content_types: Collection[str]
    ) -> bytes:
        logger.debug("Mock decrypt_jwe_payload: returning plaintext input")
        return jwe_token.encode("utf-8")

    def hash(self, data: bytes) -> bytes:
        return data

    def encrypt_aes(
        self, data: bytes, iv: bytes, label: str, mechanism: Pkc11Mechanism
    ) -> str:
        return base64.b64encode(data).decode()

    def decrypt_aes(
        self, data: str, iv: str, label: str, mechanism: Pkc11Mechanism
    ) -> str:
        return data
