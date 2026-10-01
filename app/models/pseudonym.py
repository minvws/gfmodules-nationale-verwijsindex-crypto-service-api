from typing import Literal

from pydantic import BaseModel, Field


class PseudonymRequest(BaseModel):
    jwe: str
    blind_factor: str
    label: str = Field(min_length=1)
    # Pseudonyms are only ever encrypted with AES_CBC
    mechanism: Literal["AES_CBC"]


class PseudonymResponse(BaseModel):
    encrypted_pseudonym: str
    iv: str
