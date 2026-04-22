import base64
import logging
from typing import Any

from app.services.crypto.crypto_service import CryptoService

logger = logging.getLogger(__name__)

_CANNED_BLINDED_PSEUDONYM = base64.urlsafe_b64encode(b"mock-blinded-pseudonym").decode("utf-8")
_CANNED_PAYLOAD = {"subject": f"pseudonym:eval:{_CANNED_BLINDED_PSEUDONYM}"}


class MockCryptoService(CryptoService):
    """
    Pass-through crypto service: no keys, no crypto.
    Intended for local development and wiring smoke tests.
    """

    def health_check(self) -> bool:
        return True

    def generate_keys(self) -> None:
        return None

    def decrypt_jwe(self, jwe_token: str, key_id: str) -> bytes:
        return jwe_token.encode("utf-8")

    def decrypt_jwe_payload(self, jwe_token: str) -> Any:
        logger.debug("Mock decrypt_jwe_payload: returning canned payload")
        return _CANNED_PAYLOAD

    def hash(self, data: bytes) -> bytes:
        return data
