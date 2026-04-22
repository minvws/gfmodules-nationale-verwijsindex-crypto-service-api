import json
import logging
from abc import ABC, abstractmethod
from typing import Any

from jwcrypto import jwe

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
    def generate_keys(self) -> None:
        """
        Generate the signing and hashing keys if they do not already exist.
        """

    @abstractmethod
    def hash(self, data: bytes) -> bytes:
        """
        Compute a hash of data. Returns raw bytes.
        """

    def decrypt_jwe_payload(self, jwe_token: str) -> Any:
        """
        Decrypt a JWE and return the parsed JSON payload.
        Extracts the key ID (kid) from the JWE header and uses it to decrypt.
        """
        try:
            # Extract kid from JWE header
            token = jwe.JWE()
            token.deserialize(jwe_token)
            kid = token.jose_header.get("kid")
            if not kid:
                raise InvalidJweError("Invalid JWE: missing kid in header")

            # Decrypt and parse
            payload = self.decrypt_jwe(jwe_token, kid)
            return json.loads(payload.decode("utf-8"))
        except (jwe.InvalidJWEData, InvalidJweError) as e:
            logger.error(f"Invalid JWE: {e}")
            raise InvalidJweError("Invalid JWE format") from e
        except CryptoError:
            raise
        except Exception as e:
            raise CryptoError("Failed to decrypt JWE") from e