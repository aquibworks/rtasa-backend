class RTASAException(Exception):
    """Base domain exception class for all custom errors."""
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

class CryptoEngineError(RTASAException):
    """Raised during cryptographic operation failures."""
    pass

class ShamirEngineError(RTASAException):
    """Raised during secret sharing algorithm failures."""
    pass

class StegoEngineError(RTASAException):
    """Raised during steganography embedding/extraction failures."""
    pass

class EntityNotFoundError(RTASAException):
    """Raised when a DB record cannot be found."""
    def __init__(self, entity_name: str, identifier: str):
        super().__init__(f"{entity_name} '{identifier}' was not found.", status_code=404)

class AuthenticationError(RTASAException):
    """Raised during credential and token validation failures."""
    def __init__(self, message: str = "Invalid credentials"):
        super().__init__(message, status_code=401)

class ConflictError(RTASAException):
    """Raised when a unique resource constraint is violated."""
    def __init__(self, message: str):
        super().__init__(message, status_code=409)