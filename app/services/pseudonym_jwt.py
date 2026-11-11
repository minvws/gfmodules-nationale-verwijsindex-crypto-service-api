import json
from typing import Any, cast

from jwcrypto import jwt

from app.config import ConfigPseudonym
from app.exceptions.exception import InvalidSignedPseudonymError
from app.services.pseudonym_constants import EXPECTED_ALG
from app.services.pseudonym_jwks import PseudonymJwksService


class PseudonymJwtVerifier:
    def __init__(
        self, config: ConfigPseudonym, jwks_service: PseudonymJwksService
    ) -> None:
        self._config = config
        self._jwks_service = jwks_service

    def verify(self, token: str) -> dict[str, Any]:
        try:
            signed = jwt.JWT(
                jwt=token,
                algs=[EXPECTED_ALG],
                check_claims={
                    "iss": self._config.expected_issuer,
                    "aud": self._config.expected_audience,
                    "iat": None,
                    "exp": None,
                },
                expected_type="JWS",
                strict_serialization=True,
            )
            kid = signed.token.jose_header["kid"]
        except Exception:  # noqa: BLE001 - do not expose untrusted JWS data
            raise InvalidSignedPseudonymError(
                "Signed pseudonym has an invalid JWS format or header"
            ) from None

        key = self._jwks_service.get_key(kid)
        try:
            signed.validate(key)
            return cast(dict[str, Any], json.loads(signed.claims))
        except Exception:  # noqa: BLE001 - normalize cryptographic parsing failures
            raise InvalidSignedPseudonymError(
                "Signed pseudonym has an invalid signature or claims"
            ) from None
