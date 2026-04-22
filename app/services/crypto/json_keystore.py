import json
import logging
import base64
import os
from typing import Dict

from jwcrypto import jwk

from app.exceptions.exception import KeyNotFoundError

logger = logging.getLogger(__name__)


class JsonKeyStorage:
    """
    Key storage that persists RSA key pairs as JWKs in a JSON file.
    Also stores symmetric secret keys as base64-encoded strings.
    For development/testing only, do not use in production.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._store: Dict[str, str] = self._init_store()

        logger.debug(f"Loaded {len(self._store)} key(s) from disk")

    def _init_store(self) -> Dict[str, str]:
        try:
            with open(self.path, "r") as f:
                store: Dict[str, str] = json.load(f)
        except Exception:
            logger.warning(
                f"Could not load keystore from {self.path}, starting with empty store"
            )
            store = {}
        return store

    def generate_key(self, key_id: str) -> None:
        if key_id in self._store:
            logger.debug(f"Key {key_id} already exists, skipping generation")
            return

        jwk_obj = jwk.JWK.generate(kty="RSA", size=2048)
        self._store[key_id] = jwk_obj.export(private_key=True)

        try:
            with open(self.path, "w") as f:
                json.dump(self._store, f, indent=4)
        except Exception as e:
            logger.warning(f"Could not save keystore to {self.path}: {e}")

        logger.debug(f"Generated RSA key pair for {key_id}")

    def generate_symmetric_key(self, key_id: str, bits: int = 256) -> None:
        if key_id in self._store:
            logger.debug(f"Key {key_id} already exists, skipping generation")
            return

        secret_bytes = os.urandom(bits // 8)
        self._store[key_id] = base64.b64encode(secret_bytes).decode("utf-8")

        try:
            with open(self.path, "w") as f:
                json.dump(self._store, f, indent=4)
        except Exception as e:
            logger.warning(f"Could not save keystore to {self.path}: {e}")

        logger.debug(f"Generated symmetric key for {key_id}")

    def get_symmetric_key(self, key_id: str) -> bytes:
        """Retrieve a symmetric secret key."""
        if key_id not in self._store:
            raise KeyNotFoundError(f"Key {key_id} not found in keystore")
        return base64.b64decode(self._store[key_id])

    def has_key(self, key_id: str) -> bool:
        return key_id in self._store

    def get_jwk(self, key_id: str) -> jwk.JWK:
        if key_id not in self._store:
            raise KeyNotFoundError(f"Key {key_id} not found in keystore")
        return jwk.JWK.from_json(self._store[key_id])
