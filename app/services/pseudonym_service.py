import base64
import logging

import pyoprf

from app.exceptions.exception import InvalidJweError
from app.services.crypto.crypto_service import CryptoService

logger = logging.getLogger(__name__)


class PseudonymService:
    def __init__(self, crypto_service: CryptoService):
        self._crypto_service = crypto_service

    def decrypt_and_unblind(self, oprf_jwe: str, blind_factor: str) -> bytes:
        """
        Decrypt the OPRF-JWE and unblind the pseudonym using the blind factor.
        """
        logger.debug("Decrypting OPRF JWE")

        jwe_data = self._crypto_service.decrypt_jwe_payload(oprf_jwe)

        subject = jwe_data["subject"]
        if not subject.startswith("pseudonym:eval:"):
            logger.error("JWE is invalid: subject does not start with pseudonym:eval:")
            raise InvalidJweError("JWE is invalid: subject does not start with pseudonym:eval:")

        subj = base64.urlsafe_b64decode(subject.split(":")[-1])
        bf = base64.urlsafe_b64decode(blind_factor)
        return pyoprf.unblind(bf, subj)  # type: ignore

    def hash(self, pseudonym: bytes) -> str:
        logger.debug("Hashing pseudonym")
        hashed = self._crypto_service.hash(pseudonym)
        res = base64.urlsafe_b64encode(hashed).decode("utf-8")
        logger.debug("Hashed pseudonym: %s", res)
        return res
