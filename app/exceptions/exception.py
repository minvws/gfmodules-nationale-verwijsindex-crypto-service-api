class PrsRegisterError(Exception):
    pass


class CryptoError(Exception):
    status_code = 500
    error_message = "Crypto operation failed"


class KeyNotFoundError(CryptoError):
    status_code = 404
    error_message = "Key not found"


class InvalidJweError(CryptoError):
    status_code = 400
    error_message = "Invalid JWE"
