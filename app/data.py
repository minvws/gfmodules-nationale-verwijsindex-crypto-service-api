from enum import StrEnum


class Pkc11Mechanism(StrEnum):
    AES_CBC = "AES_CBC"
    SHA256_HMAC = "SHA256_HMAC"
    RSA_PKCS_OAEP = "RSA_PKCS_OAEP"
