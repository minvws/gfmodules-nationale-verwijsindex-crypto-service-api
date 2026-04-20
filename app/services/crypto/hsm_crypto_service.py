import base64
import hashlib
import json
from typing import Any

import PyKCS11
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PyKCS11.LowLevel import CKF_SERIAL_SESSION, CKF_RW_SESSION

from app.exceptions.exception import CryptoError, KeyNotFoundError
from app.services.crypto.crypto_service import CryptoService
import logging


logger = logging.getLogger(__name__)


class HsmCryptoService(CryptoService):
    """
    Cryptographic service backed by a PKCS#11 HSM (e.g. SoftHSM2).
    """

    def __init__(
        self,
        module_path: str,
        slot: int,
        slot_pin: str,
        signing_key_id: str,
        hashing_key_id: str,
        softhsm_oaep_sha256_fallback: bool = False,
    ):
        self.session = None

        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(module_path)

        if slot not in self.pkcs11.getSlotList():
            logger.error(f"Slot {slot} not found")
            raise CryptoError(f"Slot {slot} not found. Please configure the slot first")

        self.slot = slot
        self.slot_pin = slot_pin
        self.signing_key_id = signing_key_id
        self.hashing_key_id = hashing_key_id
        self.softhsm_oaep_sha256_fallback = softhsm_oaep_sha256_fallback
        if softhsm_oaep_sha256_fallback:
            logger.warning(
                "SoftHSM OAEP-SHA256 fallback enabled: RSA-OAEP-256 will use raw RSA "
                "in the HSM with software-side OAEP unpadding. Not for production."
            )

    def health_check(self) -> bool:
        try:
            sess = self._open_session()
            sess.closeSession()
            self.session = None
            return True
        except Exception as e:
            logger.debug(f"HSM health check failed: {e}")
            return False

    def get_public_key(self, key_id: str) -> str:
        """Retrieve the public key for an existing key pair."""
        logger.debug(f"Getting public key for {key_id}")
        sess = self._open_session()
        pub_objects = self._key_exists(sess, key_id, PyKCS11.LowLevel.CKO_PUBLIC_KEY)
        if len(pub_objects) == 0:
            logger.error(f"Public key '{key_id}' not found in HSM")
            raise KeyNotFoundError(f"Public key '{key_id}' not found in HSM")
        return self._public_key(sess, pub_objects[0])

    def decrypt_jwe(self, jwe_token: str, key_id: str) -> bytes:
        """Decrypt JWE: RSA key-unwrap in HSM, AES-GCM locally."""
        logger.debug(f"Decrypting JWE with key {key_id}")
        parts = jwe_token.split(".")
        if len(parts) != 5:
            logger.error(f"Invalid JWE: expected 5 segments, got {len(parts)}")
            raise CryptoError(
                "Invalid JWE: expected 5 segments in compact serialization"
            )
        header_b64, enc_key_b64, iv_b64, ct_b64, tag_b64 = parts

        try:
            header = json.loads(self._b64url_decode(header_b64))
        except Exception as e:
            logger.error(f"Invalid JWE header: {e}")
            raise CryptoError(f"Invalid JWE header: {e}")

        alg = header.get("alg")
        enc = header.get("enc")
        if enc != "A256GCM":
            logger.error(f"Unsupported JWE enc: {enc}")
            raise CryptoError(f"Unsupported JWE 'enc': {enc} (only A256GCM supported)")

        encrypted_key = self._b64url_decode(enc_key_b64)
        iv = self._b64url_decode(iv_b64)
        ciphertext = self._b64url_decode(ct_b64)
        tag = self._b64url_decode(tag_b64)

        cek = self._unwrap_cek(key_id, encrypted_key, alg)

        aad = header_b64.encode("ascii")
        try:
            return AESGCM(cek).decrypt(iv, ciphertext + tag, aad)
        except Exception as e:
            logger.error(f"AES-GCM decryption failed: {e}")
            raise CryptoError(f"AES-GCM decryption failed: {e}")

    def generate_keys(self) -> None:
        logger.debug(f"Generating keys: signing_key_id={self.signing_key_id}, hashing_key_id={self.hashing_key_id}")
        sess = self._open_session()
        if len(self._key_exists(sess, self.signing_key_id, PyKCS11.LowLevel.CKO_PRIVATE_KEY)) == 0:
            self._generate_signing_key()
        if len(self._key_exists(sess, self.hashing_key_id, PyKCS11.LowLevel.CKO_SECRET_KEY)) == 0:
            self._generate_hashing_key()

    def hash(self, data: bytes) -> bytes:
        """Compute HMAC-SHA256 using the hashing secret key."""
        logger.debug(f"Hashing {len(data)} bytes")
        sess = self._open_session()

        secret_objs = self._key_exists(sess, self.hashing_key_id, PyKCS11.LowLevel.CKO_SECRET_KEY)
        if len(secret_objs) == 0:
            logger.error(f"Hashing secret key '{self.hashing_key_id}' not found in HSM")
            raise KeyNotFoundError(
                f"Hashing secret key '{self.hashing_key_id}' not found in HSM"
            )

        hmac_result = bytes(
            sess.sign(
                secret_objs[0],
                data,
                mecha=PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_SHA256_HMAC),
            )
        )
        return hmac_result

    def _generate_signing_key(self) -> str:
        """Generate the signing key and return its public key."""
        logger.debug(f"Generating signing key: {self.signing_key_id}")
        sess = self._open_session()

        pub_template = [
            (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_PUBLIC_KEY),
            (PyKCS11.LowLevel.CKA_KEY_TYPE, PyKCS11.LowLevel.CKK_RSA),
            (PyKCS11.LowLevel.CKA_TOKEN, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_LABEL, self.signing_key_id),
            (PyKCS11.LowLevel.CKA_MODULUS_BITS, 2048),
            (PyKCS11.LowLevel.CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (PyKCS11.LowLevel.CKA_ENCRYPT, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_VERIFY, PyKCS11.LowLevel.CK_TRUE),
        ]
        priv_template = [
            (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_PRIVATE_KEY),
            (PyKCS11.LowLevel.CKA_KEY_TYPE, PyKCS11.LowLevel.CKK_RSA),
            (PyKCS11.LowLevel.CKA_TOKEN, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_LABEL, self.signing_key_id),
            (PyKCS11.LowLevel.CKA_SENSITIVE, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_EXTRACTABLE, PyKCS11.LowLevel.CK_FALSE),
            (PyKCS11.LowLevel.CKA_DECRYPT, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_SIGN, PyKCS11.LowLevel.CK_TRUE),
        ]
        pub_obj, _ = sess.generateKeyPair(
            pub_template,
            priv_template,
            mecha=PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_RSA_PKCS_KEY_PAIR_GEN),
        )
        logger.debug("Signing key generated successfully")
        return self._public_key(sess, pub_obj)

    def _generate_hashing_key(self) -> None:
        """Generate the hashing secret key for HMAC-SHA256."""
        logger.debug(f"Generating hashing key: {self.hashing_key_id}")
        sess = self._open_session()

        secret_template = [
            (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_SECRET_KEY),
            (PyKCS11.LowLevel.CKA_KEY_TYPE, PyKCS11.LowLevel.CKK_GENERIC_SECRET),
            (PyKCS11.LowLevel.CKA_TOKEN, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_LABEL, self.hashing_key_id),
            (PyKCS11.LowLevel.CKA_VALUE_LEN, 32),  # 256-bit secret
            (PyKCS11.LowLevel.CKA_SIGN, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_SENSITIVE, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_EXTRACTABLE, PyKCS11.LowLevel.CK_FALSE),
        ]
        sess.generateKey(
            secret_template,
            mecha=PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_GENERIC_SECRET_KEY_GEN),
        )
        logger.debug("Hashing key generated successfully") 

    def _key_exists(self, sess: PyKCS11.Session, key_id: str, low_level: Any) -> Any:
        priv_objs = sess.findObjects(
            [
                (PyKCS11.LowLevel.CKA_CLASS, low_level),
                (PyKCS11.LowLevel.CKA_LABEL, key_id),
            ]
        )
        return priv_objs

    def _unwrap_cek(self, key_id: str, encrypted_key: bytes, alg: str) -> bytes:
        logger.debug(f"Unwrapping CEK with key {key_id}, alg={alg}")
        sess = self._open_session()
        priv_objs = sess.findObjects(
            [
                (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_PRIVATE_KEY),
                (PyKCS11.LowLevel.CKA_LABEL, key_id),
            ]
        )
        if not priv_objs:
            logger.error(f"Private key '{key_id}' not found in HSM")
            raise KeyNotFoundError(f"Private key '{key_id}' not found in HSM")

        if alg == "RSA-OAEP":
            hash_alg = PyKCS11.LowLevel.CKM_SHA_1
            mgf = PyKCS11.LowLevel.CKG_MGF1_SHA1
        elif alg == "RSA-OAEP-256":
            if self.softhsm_oaep_sha256_fallback:
                return self._unwrap_cek_oaep_sha256_raw(sess, priv_objs[0], encrypted_key)
            hash_alg = PyKCS11.LowLevel.CKM_SHA256
            mgf = PyKCS11.LowLevel.CKG_MGF1_SHA256
        else:
            logger.error(f"Unsupported JWE alg: {alg}")
            raise CryptoError(f"Unsupported JWE 'alg': {alg}")

        oaep_params = PyKCS11.RSAOAEPMechanism(hash_alg, mgf)
        try:
            cek = bytes(sess.decrypt(priv_objs[0], encrypted_key, oaep_params))
        except Exception as e:
            logger.error(f"HSM RSA-OAEP unwrap failed: {e}")
            raise CryptoError(f"HSM RSA-OAEP unwrap failed: {e}")
        return cek

    def _unwrap_cek_oaep_sha256_raw(
        self, sess: PyKCS11.Session, priv_obj: Any, encrypted_key: bytes
    ) -> bytes:
        # SoftHSMv2 workaround: raw RSA in the HSM, EME-OAEP-SHA256 unpad in software.
        try:
            em = bytes(
                sess.decrypt(
                    priv_obj,
                    encrypted_key,
                    PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_RSA_X_509),
                )
            )
        except Exception as e:
            logger.error(f"HSM raw RSA decrypt failed: {e}")
            raise CryptoError(f"HSM raw RSA decrypt failed: {e}")

        k = len(encrypted_key)
        if len(em) < k:
            em = b"\x00" * (k - len(em)) + em
        try:
            return _eme_oaep_sha256_decode(em, k)
        except Exception as e:
            logger.error(f"Software OAEP-SHA256 unpadding failed: {e}")
            raise CryptoError(f"Software OAEP-SHA256 unpadding failed: {e}")

    def _public_key(self, sess: PyKCS11.Session, pub_key_obj: Any) -> str:
        n = int.from_bytes(
            self._attr_bytes(sess, pub_key_obj, PyKCS11.LowLevel.CKA_MODULUS), "big"
        )
        e = int.from_bytes(
            self._attr_bytes(sess, pub_key_obj, PyKCS11.LowLevel.CKA_PUBLIC_EXPONENT),
            "big",
        )
        key = RSA.construct((n, e))
        return key.export_key(format="PEM").decode("utf-8")

    def _open_session(self) -> PyKCS11.Session:
        if self.session is None:
            try:
                logger.debug(f"Opening HSM session on slot {self.slot}")
                session = self.pkcs11.openSession(
                    self.slot, CKF_SERIAL_SESSION | CKF_RW_SESSION
                )
                session.login(self.slot_pin)
                self.session = session
            except Exception as e:
                logger.error(f"Could not open HSM session: {e}")
                raise CryptoError("Could not open HSM session: " + str(e))
        return self.session

    def _b64url_decode(self, data: str) -> bytes:
        pad = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + pad)

    def _attr_bytes(self, sess: PyKCS11.Session, obj: Any, attr: int) -> bytes:
        return bytes(sess.getAttributeValue(obj, [attr])[0])


def _mgf1_sha256(seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _eme_oaep_sha256_decode(em: bytes, k: int) -> bytes:
    # RFC 8017 §7.1.2 with SHA-256 and empty label.
    h_len = 32
    if len(em) != k or k < 2 * h_len + 2:
        raise ValueError("invalid encoded-message length")
    if em[0] != 0x00:
        raise ValueError("invalid leading byte")
    masked_seed = em[1 : 1 + h_len]
    masked_db = em[1 + h_len :]
    seed = bytes(a ^ b for a, b in zip(masked_seed, _mgf1_sha256(masked_db, h_len)))
    db = bytes(a ^ b for a, b in zip(masked_db, _mgf1_sha256(seed, k - h_len - 1)))
    if db[:h_len] != hashlib.sha256(b"").digest():
        raise ValueError("lHash mismatch")
    i = h_len
    while i < len(db) and db[i] == 0x00:
        i += 1
    if i >= len(db) or db[i] != 0x01:
        raise ValueError("missing 0x01 separator")
    return db[i + 1 :]
