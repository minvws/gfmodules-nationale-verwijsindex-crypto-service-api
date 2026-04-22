import hashlib
import hmac
import logging

from jwcrypto import jwe

from app.exceptions.exception import KeyNotFoundError
from app.services.crypto.crypto_service import CryptoService
from app.services.crypto.json_keystore import JsonKeyStorage

logger = logging.getLogger(__name__)


class MemoryCryptoService(CryptoService):
    """
    Cryptographic service that stores RSA key pairs in a JSON file and performs
    operations in-memory using jwcrypto.

    Not safe for production use.
    """

    def __init__(
        self,
        keystore: JsonKeyStorage,
        signing_key_id: str,
        hashing_key_id: str,
    ):
        self.keystore = keystore
        self.signing_key_id = signing_key_id
        self.hashing_key_id = hashing_key_id
        self.public_key: str | None = None


    def health_check(self) -> bool:
        return True

    def get_public_key(self, key_id: str) -> str:
        """Retrieve the public key for an existing key pair."""
        if self.public_key:
            return self.public_key
        logger.debug(f"Getting public key for {key_id}")
        rsa_jwk = self.keystore.get_jwk(key_id)
        self.public_key = rsa_jwk.export_to_pem(private_key=False).decode("utf-8")
        if not self.public_key:
            raise KeyNotFoundError(f"Public key not found for key ID '{key_id}'")
        return self.public_key

    def decrypt_jwe(self, jwe_token: str, key_id: str) -> bytes:
        logger.debug(f"Decrypting JWE with key {key_id}")
        rsa_jwk = self.keystore.get_jwk(key_id)
        token = jwe.JWE()
        token.deserialize(jwe_token, key=rsa_jwk)
        return token.payload  # type: ignore
    
    def generate_keys(self) -> None:
        logger.debug(f"Generating keys: signing_key_id={self.signing_key_id}, hashing_key_id={self.hashing_key_id}")
        if not self.keystore.has_key(self.signing_key_id):
            self._generate_signing_key()
        if not self.keystore.has_key(self.hashing_key_id):
            self._generate_hashing_key()

    def hash(self, data: bytes) -> bytes:
        """Compute HMAC-SHA256 using the hashing secret key."""
        logger.debug(f"Hashing {len(data)} bytes")
        secret_key = self.keystore.get_symmetric_key(self.hashing_key_id)
        return hmac.new(secret_key, data, hashlib.sha256).digest()

    def _generate_signing_key(self) -> str:
        """Generate the signing key and return its public key."""
        logger.debug(f"Generating signing key: {self.signing_key_id}")
        self.keystore.generate_key(self.signing_key_id)
        return self.get_public_key(self.signing_key_id)

    def _generate_hashing_key(self) -> None:
        """Generate the hashing symmetric key for HMAC-SHA256."""
        logger.debug(f"Generating hashing key: {self.hashing_key_id}")
        self.keystore.generate_symmetric_key(self.hashing_key_id, bits=256)
