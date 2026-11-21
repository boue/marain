"""Errors the wrapper returns instead of calling out."""


class IdempotencyError(Exception):
    """Base error. `code` is the stable name callers match on."""

    code = "idempotency"

    def __init__(self, message: str = "", *, reason: str = ""):
        super().__init__(message or reason or self.code)
        self.reason = reason or self.code


class MissingScope(IdempotencyError):
    code = "missing_scope"


class StaleScope(IdempotencyError):
    code = "stale_scope"


class RedisUnavailable(IdempotencyError):
    code = "redis_unavailable"


class Blocked(IdempotencyError):
    code = "blocked"

    def __init__(self, reason: str, message: str = ""):
        super().__init__(message or reason, reason=reason)
        self.reason = reason


class WaiterTimeout(IdempotencyError):
    code = "waiter_timeout"


class InProgressCleared(IdempotencyError):
    code = "in_progress_cleared"


class StaleOwner(IdempotencyError):
    code = "stale_owner"


class NotApplied(IdempotencyError):
    """The external call was not applied. The key may be released."""

    code = "not_applied"


class ConfirmedRollback(IdempotencyError):
    code = "rolled_back"


class UncertainOutcome(IdempotencyError):
    code = "uncertain"

    def __init__(self, reason: str):
        super().__init__(reason, reason=reason)
        self.reason = reason


class OversizedResult(IdempotencyError):
    code = "oversized_result"


class NonserializableResult(IdempotencyError):
    code = "nonserializable_result"


class CanonicalError(IdempotencyError):
    code = "canonical"


class ReplayError(IdempotencyError):
    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code, reason=code)
        self.code = code


class ConfigError(IdempotencyError):
    code = "config"


class TransactionBoundary(IdempotencyError):
    code = "transaction_boundary"


class IdentityError(IdempotencyError):
    code = "identity"
