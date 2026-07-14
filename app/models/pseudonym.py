from pydantic import BaseModel


class PseudonymRequest(BaseModel):
    jwe: str
    blind_factor: str


class PseudonymResponse(BaseModel):
    encrypted_pseudonym: str
    iv: str
    label: str
    mechanism: str
