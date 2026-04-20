class PrsRegisterError(Exception):
    pass

class CryptoError(Exception):
    pass

class KeyNotFoundError(CryptoError):
    pass

class InvalidJweError(Exception):
    pass