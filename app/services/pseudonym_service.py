import base64
import logging

import gfmodules.logging as gflog
import pyoprf

from app.data import Pkc11Mechanism
from app.exceptions.exception import CryptoError, InvalidJweError
from app.logging.events import Log
from app.models.pseudonym import PseudonymResponse
from app.services.crypto.crypto_service import CryptoService

logger = logging.getLogger(__name__)

_ENDPOINT = "/decrypt_and_hash"


class PseudonymService:
    def __init__(self, crypto_service: CryptoService):
        self._crypto_service = crypto_service

    def decrypt_and_unblind(self, oprf_jwe: str, blind_factor: str) -> bytes:
        """
        Decrypt the OPRF-JWE and unblind the pseudonym using the blind factor.
        """
        logger.debug("Decrypting OPRF JWE")

        try:
            jwe_data = self._crypto_service.decrypt_jwe_payload(oprf_jwe)
        except CryptoError as e:
            gflog.emit(logger, Log.PSE_EXCHANGE_FAILED, "OPRF exchange failed: JWE decrypt failed", fields={"endpoint": _ENDPOINT, "error_type": type(e).__name__})
            raise

        subject = jwe_data.get("subject") if isinstance(jwe_data, dict) else None
        if not isinstance(subject, str) or not subject.startswith("pseudonym:eval:"):
            gflog.emit(logger, Log.PSE_EXCHANGE_FAILED, "OPRF exchange failed: invalid JWE subject", fields={"endpoint": _ENDPOINT, "error_type": "invalid_subject"})
            raise InvalidJweError(
                "JWE is invalid: subject does not start with pseudonym:eval:"
            )

        subj = base64.urlsafe_b64decode(subject.split(":")[-1])
        bf = base64.urlsafe_b64decode(blind_factor)
        result: bytes = pyoprf.unblind(bf, subj)

        gflog.emit(logger, Log.PSE_EXCHANGE_OK, "OPRF exchange succeeded", fields={"endpoint": _ENDPOINT})
        return result

    def encrypt_pseudonym(
        self,
        pseudonym: bytes,
        hmac_hash: bytes,
        label: str,
        mechanism: Pkc11Mechanism,
    ) -> PseudonymResponse:
        iv = hmac_hash[:16]
        logger.debug("encrypting pseudonym")
        encrypted_data = self._crypto_service.encrypt_aes(
            data=pseudonym, iv=iv, label=label, mechanism=mechanism
        )
        logger.debug("Pseudonym encrypted successfully")

        return PseudonymResponse(
            encrypted_pseudonym=encrypted_data,
            iv=base64.urlsafe_b64encode(iv).decode(),
        )

    def hash(self, pseudonym: bytes) -> bytes:
        logger.debug("Hashing pseudonym")
        hashed = self._crypto_service.hash(pseudonym)
        logger.debug("Pseudonym hashed successfully")
        return hashed
