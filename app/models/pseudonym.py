from pydantic import BaseModel


class PseudonymRequest(BaseModel):
    jwe: str
    blind_factor: str
