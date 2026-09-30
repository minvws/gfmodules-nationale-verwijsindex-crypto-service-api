from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel

from app.config import Config


class FeatureInfo(BaseModel):
    id: str
    title: str
    description: str


@dataclass(frozen=True)
class Feature:
    info: FeatureInfo
    enabled: Callable[[Config], bool]


FEATURES: list[Feature] = [
    Feature(
        info=FeatureInfo(
            id="pseudonym_processing",
            title="Pseudonym processing",
            description=(
                "Decrypt a JWE from the NVI, unblind the pseudonym and encrypt it "
                "with an IV"
            ),
        ),
        enabled=lambda _: True,
    ),
    Feature(
        info=FeatureInfo(
            id="hsm",
            title="HSM",
            description="Cryptographic operations run in the HSM instead of a mock",
        ),
        enabled=lambda config: not config.hsm_api.mock,
    ),
    Feature(
        info=FeatureInfo(
            id="public_key_test_endpoint",
            title="Public key test endpoint",
            description="Helper endpoint that returns the NVI public key as PEM",
        ),
        enabled=lambda _: True,
    ),
]


def enabled_features(config: Config) -> list[FeatureInfo]:
    return [feature.info for feature in FEATURES if feature.enabled(config)]
