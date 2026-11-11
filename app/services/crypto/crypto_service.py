import logging
from abc import ABC, abstractmethod
from collections.abc import Collection

from jwcrypto import jwe

from app.data import Pkc11Mechanism
from app.exceptions.exception import CryptoError, InvalidJweError

logger = logging.getLogger(__name__)


class CryptoService(ABC):
    """
    Interface for a cryptographic service that provides RSA key management, JWE decryption, and hashing.
    """

    @abstractmethod
    def health_check(self) -> bool:
        """
        Perform a health check to verify the crypto service is operational.
        Returns True if healthy, False otherwise.
        """

    @abstractmethod
    def get_public_key(self, key_id: str) -> str:
        """
        Retrieve the public key for an existing key pair identified by key_id.
        Returns the public key as PEM-encoded string.
        """

    @abstractmethod
    def decrypt_jwe(self, jwe_token: str, key_id: str) -> bytes:
        """
        Decrypt a JWE using the RSA private key identified by key_id.
        Returns the plaintext payload as raw bytes.
        """

    @abstractmethod
    def hash(self, data: bytes) -> bytes:
        """
        Compute a hash of data. Returns raw bytes.
        """

    @abstractmethod
    def encrypt_aes(
        self, data: bytes, iv: bytes, label: str, mechanism: Pkc11Mechanism
    ) -> str:
        """
        Encrypts a piece of data in combination with an iv.
        """

    @abstractmethod
    def decrypt_aes(
        self, data: str, iv: str, label: str, mechanism: Pkc11Mechanism
    ) -> str:
        """
        Decrypts a piece of data with a give IV. Function expects the params
        to be already encoded.
        """

    def decrypt_jwe_payload(
        self, jwe_token: str, expected_content_types: Collection[str]
    ) -> bytes:
        """
        Validate the JWE header and return its decrypted plaintext bytes.
        The content type must be a string in the allowed set.
        """
        try:
            token = jwe.JWE()
            token.deserialize(jwe_token)
            header = token.jose_header
            if not isinstance(header, dict):
                raise InvalidJweError("JWE header is not an object")
            kid = header.get("kid")
            if not isinstance(kid, str) or not kid:
                raise InvalidJweError("JWE header is missing a valid key ID")
            content_type = header.get("cty")
            if (
                not isinstance(content_type, str)
                or content_type not in expected_content_types
            ):
                raise InvalidJweError("JWE does not have the expected content type")

            return self.decrypt_jwe(jwe_token, kid)
        except (jwe.InvalidJWEData, jwe.InvalidJWEOperation, InvalidJweError) as e:
            logger.exception("JWE decrypt failed: invalid JWE")
            raise InvalidJweError("Invalid JWE format") from e
        except CryptoError:
            logger.exception("JWE decrypt failed: crypto error")
            raise
        except Exception as e:
            logger.exception("JWE decrypt failed: unexpected error")
            raise CryptoError("Failed to decrypt JWE") from e
