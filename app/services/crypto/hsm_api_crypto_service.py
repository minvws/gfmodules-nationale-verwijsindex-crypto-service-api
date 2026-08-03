import base64
import json
import logging

from Crypto.Cipher import AES
from requests import JSONDecodeError
from requests.exceptions import ConnectionError as RequestsConnectionError, Timeout

from app.data import Pkc11Mechanism
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
    ):
        logger.debug(f"Initializing HSM API service: module={module}, slot={slot}")
        self._http = http
        self.module = module
        self.slot = slot
        self.hash_key_id = hash_key_id

    def health_check(self) -> bool:
        try:
            r = self._http.do_request("GET")
        except (RequestsConnectionError, Timeout) as e:
            logger.debug(f"HSM API unreachable: {e}")
            return False
        if r.status_code != 200:
            logger.debug(
                f"HSM API health check failed with status {r.status_code}: {r.text}"
            )
            return False
        logger.debug(f"HSM API health check response: {r.json().get('message')}")
        return True

    def get_public_key(self, key_id: str) -> str:
        """Retrieve the public key for an existing key pair identified by key_id."""
        r = self._http.do_request(
            "POST",
            sub_route=f"hsm/{self.module}/{self.slot}",
            data={"label": key_id, "objtype": "PUBLIC_KEY"},
        )
        if r.status_code != 200:
            raise KeyNotFoundError(f"Failed to retrieve public key: {r.text}")
        try:
            public_key = r.json()["objects"][0].get("publickey")
        except (KeyError, IndexError):
            raise CryptoError(f"Unexpected object details response: {r.text}")
        if not public_key:
            raise KeyNotFoundError(f"Public key not found in response: {r.text}")
        return str(public_key)

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
        if not alg:
            raise InvalidJweError("Missing 'alg' in JWE header")

        alg_map = {
            "RSA-OAEP": "sha1",
        }

        hash_method = alg_map.get(alg, None)
        if not hash_method:
            raise InvalidJweError(f"Unsupported key management algorithm: {alg}")

        encrypted_key = base64.urlsafe_b64decode(encrypted_key_b64 + "==")
        cek = self._rsa_oaep_unwrap(key_id, encrypted_key, hash_method)
        if len(cek) != 32:  # 256 bits for A256GCM
            raise CryptoError(f"Unwrapped CEK length {len(cek)} does not match {enc}")

        iv = base64.urlsafe_b64decode(iv_b64 + "==")
        ciphertext = base64.urlsafe_b64decode(ciphertext_b64 + "==")
        tag = base64.urlsafe_b64decode(tag_b64 + "==")
        aad = header_b64.encode("ascii")

        cipher = AES.new(cek, AES.MODE_GCM, nonce=iv)
        cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def hash(self, data: bytes) -> bytes:
        logger.debug(f"Hashing {len(data)} bytes using HSM API")
        r = self._http.do_request(
            "POST",
            sub_route=f"hsm/{self.module}/{self.slot}/sign",
            data={
                "label": self.hash_key_id,
                "data": base64.b64encode(data).decode("utf-8"),
                "mechanism": Pkc11Mechanism.SHA256_HMAC,
            },
        )
        if r.status_code != 200:
            raise CryptoError(f"HMAC operation failed: {r.text}")
        try:
            return base64.b64decode(r.json()["result"]["data"])
        except (KeyError, TypeError, JSONDecodeError):
            raise CryptoError(f"Unexpected HMAC response: {r.text}")

    def _rsa_oaep_unwrap(
        self, key_id: str, encrypted_key: bytes, hash_method: str
    ) -> bytes:
        logger.debug(f"Unwrapping CEK with RSA-OAEP using key {key_id}")
        r = self._http.do_request(
            "POST",
            sub_route=f"hsm/{self.module}/{self.slot}/decrypt",
            data={
                "label": key_id,
                "objtype": "PRIVATE_KEY",
                "mechanism": Pkc11Mechanism.RSA_PKCS_OAEP,
                "hashmethod": hash_method,
                "data": base64.b64encode(encrypted_key).decode("utf-8"),
            },
        )
        if r.status_code != 200:
            raise CryptoError(f"RSA-OAEP unwrap failed: {r.text}")

        try:
            return base64.b64decode(r.json()["result"])
        except (KeyError, TypeError, JSONDecodeError):
            raise CryptoError(f"Unexpected decrypt response: {r.text}")

    def encrypt_aes(
        self, data: bytes, iv: bytes, label: str, mechanism: Pkc11Mechanism
    ) -> str:
        if len(iv) != 16:
            raise CryptoError("IV for AES_CBC must be 16 bytes length")

        target = base64.b64encode(data)
        r = self._http.do_request(
            "POST",
            sub_route=f"hsm/{self.module}/{self.slot}/encrypt",
            data={
                "data": target.decode(),
                "objtype": "SECRET_KEY",
                "mechanism": mechanism.value,
                "iv": base64.b64encode(iv).decode(),
                "label": label,
            },
        )

        if r.status_code != 200:
            raise CryptoError(f"AES_CBC operation failed {r.text}")
        try:
            resp = r.json()
            results: str = resp["result"]["data"]
            return results
        except (KeyError, TypeError, JSONDecodeError) as e:
            raise CryptoError(f"Unexpected encrypt response: {e}")

    def decrypt_aes(
        self, data: str, iv: str, label: str, mechanism: Pkc11Mechanism
    ) -> str:
        if len(iv) != 16:
            raise CryptoError("IV for AES_CBC must be 16 bytes length")
        r = self._http.do_request(
            "POST",
            sub_route=f"hsm/{self.module}/{self.slot}/decrypt",
            data={
                "data": data,
                "objtype": "SECRET_KEY",
                "mechanism": mechanism.value,
                "iv": iv,
                "label": label,
            },
        )
        try:
            response = r.json()
            results: str = response["result"]["data"]
            return results

        except (KeyError, TypeError, JSONDecodeError) as e:
            raise CryptoError(f"Unexpected decrypt response: {e}")
