"""Core application domain exceptions."""


class AegisSOCException(Exception):
    """Base AegisSOC domain exception."""

    def __init__(self, message: str = "An internal error occurred.") -> None:
        self.message = message
        super().__init__(self.message)


class NotFoundException(AegisSOCException):
    """Raised when a requested resource is not found."""

    pass


class ValidationException(AegisSOCException):
    """Raised when an operation fails business logic or security validation."""

    pass


class ForbiddenException(AegisSOCException):
    """Raised when an action is prohibited by RBAC, scope, or safety policy."""

    pass


class UnauthorizedException(AegisSOCException):
    """Raised when authentication credentials or token are missing or invalid."""

    pass
