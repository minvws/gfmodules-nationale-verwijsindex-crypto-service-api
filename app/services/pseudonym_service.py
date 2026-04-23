import base64
import logging

import pyoprf

from app.exceptions.exception import CryptoError, InvalidJweError
from app.logging.events import PSE_EXCHANGE_FAILED, PSE_EXCHANGE_OK, log_event
from app.services.crypto.crypto_service import CryptoService

logger = logging.getLogger(__name__)

_ENDPOINT = "/decrypt_and_hash"


class PseudonymService:
    def __init__(self, crypto_service: CryptoService, nvi_ura_number: str):
        self._crypto_service = crypto_service
        self._nvi_ura_number = nvi_ura_number

    def decrypt_and_unblind(self, oprf_jwe: str, blind_factor: str) -> bytes:
        """
        Decrypt the OPRF-JWE and unblind the pseudonym using the blind factor.
        """
        logger.debug("Decrypting OPRF JWE")

        try:
            jwe_data = self._crypto_service.decrypt_jwe_payload(oprf_jwe)
        except CryptoError as e:
            log_event(
                logger,
                PSE_EXCHANGE_FAILED,
                "OPRF exchange failed: JWE decrypt failed",
                ura_number=self._nvi_ura_number,
                endpoint=_ENDPOINT,
                error_type=type(e).__name__,
            )
            raise

        subject = jwe_data.get("subject") if isinstance(jwe_data, dict) else None
        if not isinstance(subject, str) or not subject.startswith("pseudonym:eval:"):
            log_event(
                logger,
                PSE_EXCHANGE_FAILED,
                "OPRF exchange failed: invalid JWE subject",
                ura_number=self._nvi_ura_number,
                endpoint=_ENDPOINT,
                error_type="invalid_subject",
            )
            raise InvalidJweError("JWE is invalid: subject does not start with pseudonym:eval:")

        subj = base64.urlsafe_b64decode(subject.split(":")[-1])
        bf = base64.urlsafe_b64decode(blind_factor)
        result: bytes = pyoprf.unblind(bf, subj)

        log_event(
            logger,
            PSE_EXCHANGE_OK,
            "OPRF exchange succeeded",
            ura_number=self._nvi_ura_number,
            endpoint=_ENDPOINT,
        )
        return result

    def hash(self, pseudonym: bytes) -> str:
        logger.debug("Hashing pseudonym")
        hashed = self._crypto_service.hash(pseudonym)
        res = base64.urlsafe_b64encode(hashed).decode("utf-8")
        logger.debug("Pseudonym hashed successfully")
        return res
