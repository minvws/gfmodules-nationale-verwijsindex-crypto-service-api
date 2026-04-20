import base64
import json
import logging

from Crypto.Cipher import AES

from app.exceptions.exception import CryptoError, InvalidJweError, KeyNotFoundError
from app.services.crypto.crypto_service import CryptoService
from app.services.http import HttpService

logger = logging.getLogger(__name__)


class HsmApiCryptoService(CryptoService):
    def __init__(
        self,
        http: HttpService,
        module: str,
        slot: str,
        hash_key_id: str,
        signing_key_id: str,
    ):
        logger.debug(f"Initializing HSM API service: module={module}, slot={slot}")
        self._http = http
        self.module = module
        self.slot = slot
        self.hash_key_id = hash_key_id
        self.signing_key_id = signing_key_id

    def health_check(self) -> bool:
        r = self._http.do_request("GET")
        if r.status_code != 200:
            logger.debug(
                f"HSM API health check failed with status {r.status_code}: {r.text}"
            )
            return False
        logger.debug(f"HSM API health check response: {r.json().get('message')}")
        return r.status_code == 200

    def get_public_key(self, key_id: str) -> str:
        """Retrieve the public key for an existing key pair."""
        r = self._http.do_request(
            "POST",
            sub_route=f"hsm/{self.module}/{self.slot}",
            data={"label": key_id, "objtype": "PUBLIC_KEY"},
        )
        if r.status_code != 200:
            raise KeyNotFoundError(f"Failed to retrieve public key: {r.text}")
        try:
            return r.json()["objects"][0]["publickey"]  # type: ignore
        except (KeyError, IndexError):
            raise CryptoError(f"Unexpected object details response: {r.text}")

    def decrypt_jwe(self, jwe_token: str, key_id: str) -> bytes:
        """Decrypt RSA-OAEP(+A256GCM) JWE: unwrap CEK in HSM, decrypt locally."""
        logger.debug(f"Decrypting JWE with key {key_id} using HSM API")
        parts = jwe_token.split(".")
        if len(parts) != 5:
            raise InvalidJweError("Invalid JWE compact serialization")

        header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64 = parts
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))

        enc = header.get("enc", None)
        if not enc or enc != "A256GCM":
            raise InvalidJweError(f"Unsupported encryption algorithm: {enc}")
        alg = header.get("alg", None)
        if not alg or alg != "RSA-OAEP-256":
            raise InvalidJweError(f"Unsupported key management algorithm: {alg}")
        encrypted_key = base64.urlsafe_b64decode(encrypted_key_b64 + "==")
        cek = self._rsa_oaep_unwrap(key_id, encrypted_key)

        if len(cek) != 32:  # 256 bits for A256GCM
            raise CryptoError(f"Unwrapped CEK length {len(cek)} does not match {enc}")

        iv = base64.urlsafe_b64decode(iv_b64 + "==")
        ciphertext = base64.urlsafe_b64decode(ciphertext_b64 + "==")
        tag = base64.urlsafe_b64decode(tag_b64 + "==")
        aad = header_b64.encode("ascii")

        cipher = AES.new(cek, AES.MODE_GCM, nonce=iv)
        cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def generate_keys(self) -> None:
        logger.debug(f"Generating keys: signing_key_id={self.signing_key_id}, hashing_key_id={self.hash_key_id}")
        self._generate_signing_key()
        self._generate_hashing_key()

    def hash(self, data: bytes) -> bytes:
        logger.debug(f"Hashing {len(data)} bytes using HSM API")
        r = self._http.do_request(
            "POST",
            sub_route=f"hsm/{self.module}/{self.slot}/sign",
            data={
                "label": self.hash_key_id,
                "data": base64.b64encode(data).decode("utf-8"),
                "mechanism": "SHA256_HMAC",
            },
        )
        if r.status_code != 200:
            raise CryptoError(f"HMAC operation failed: {r.text}")
        try:
            return base64.b64decode(r.json()["result"]["data"])
        except (KeyError, TypeError):
            raise CryptoError(f"Unexpected HMAC response: {r.text}")

    def _generate_signing_key(self) -> str:
        """Generate the signing RSA key and return its public key."""
        logger.debug(f"Generating signing key: {self.signing_key_id}")
        r = self._http.do_request(
            "POST",
            sub_route=f"hsm/{self.module}/{self.slot}/generate/rsa",
            data={"label": self.signing_key_id, "bits": 2048},
        )
        if r.status_code == 409:
            return self.get_public_key(self.signing_key_id)
        if r.status_code != 200:
            try:
                error_msg = r.json().get("error_description")
                if error_msg and "already exists" in error_msg:
                    return self.get_public_key(self.signing_key_id)
            except (ValueError, KeyError):
                logger.error(f"Failed to parse error response: {r.text}")
            raise CryptoError(f"Failed to generate RSA key pair: {r.text}")
        try:
            return r.json()["result"]["publickey"]  # type: ignore
        except (KeyError, TypeError):
            raise CryptoError(f"Unexpected response from generate/rsa: {r.text}")

    def _generate_hashing_key(self) -> None:
        """Generate the hashing secret key for HMAC operations."""
        logger.debug(f"Generating hashing key: {self.hash_key_id}")
        r = self._http.do_request(
            "POST",
            sub_route=f"hsm/{self.module}/{self.slot}/generate/secret",
            data={"label": self.hash_key_id, "bits": 256},
        )
        if r.status_code not in (200, 409) and "already exists" not in r.text:
            raise CryptoError(f"Failed to generate hashing key: {r.text}")


    def _rsa_oaep_unwrap(self, key_id: str, encrypted_key: bytes) -> bytes:
        logger.debug(f"Unwrapping CEK with RSA-OAEP using key {key_id}")
        r = self._http.do_request(
            "POST",
            sub_route=f"hsm/{self.module}/{self.slot}/decrypt",
            data={
                "label": key_id,
                "objtype": "PRIVATE_KEY",
                "mechanism": "RSA_PKCS_OAEP",
                "hashmethod": "sha256",
                "data": base64.b64encode(encrypted_key).decode("utf-8"),
            },
        )
        if r.status_code != 200:
            raise CryptoError(f"RSA-OAEP unwrap failed: {r.text}")
        try:
            return base64.b64decode(r.json()["result"])
        except (KeyError, TypeError):
            raise CryptoError(f"Unexpected decrypt response: {r.text}")
        
