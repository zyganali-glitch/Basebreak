"""Deterministic retry and idempotency policy without duplicating external actions.

Authority:
- Section 4 / P-05.05: Owns retry/idempotency policy for Nebius Token Factory adapters.
- Core Invariant: A retry MUST NOT cause an externally visible operation to execute twice
  unless the provider contract supplies a proven idempotency mechanism that makes the repeat safe.
- Unproven provider idempotency guarantees MUST NOT be assumed.
- Non-idempotent mutating actions (spawning sandbox VMs, running non-disposable commands,
  chat completions) fail closed on ambiguous or transient failure to prevent duplication.
- Read-only queries (whoami, inspect_operation) and proven idempotent commands (cancel_operation)
  may be retried with strictly bounded attempts and deterministic backoff.
- Secret safety: credentials and bearer tokens are never exposed in attempt records or errors.
"""

from __future__ import annotations

import datetime
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, TypeVar

from basebreak.security.secret_policy import redact_log_text

from .client import (
    MissingCredentialError,
    ModelConfigError,
    ModelIdentityMismatchError,
    ModelNetworkError,
    ModelResponseFormatError,
    ModelTimeoutError,
)
from .materialization import (
    MalformedSourceIdentityError,
    SourceCommitMismatchError,
    SourceTreeMismatchError,
    SourceVerificationError,
)
from .sandbox import (
    MissingSandboxCredentialError,
    SandboxConfigError,
    SandboxLifecycleError,
    SandboxResponseFormatError,
    SandboxTimeoutError,
    SandboxTransportError,
)

T = TypeVar("T")

# --- Constants & Operational Ceilings ---

DEFAULT_MAX_ATTEMPTS: int = 3
MIN_MAX_ATTEMPTS: int = 1
CEILING_MAX_ATTEMPTS: int = 5

DEFAULT_INITIAL_BACKOFF_SECONDS: float = 0.5
DEFAULT_MAX_BACKOFF_SECONDS: float = 10.0
DEFAULT_BACKOFF_MULTIPLIER: float = 2.0


class OperationEffect(str, Enum):
    """Classification of external side-effects for provider operations."""

    READ_ONLY = "READ_ONLY"
    """Queries that read provider state without allocating compute or mutating data."""

    IDEMPOTENT_MUTATION = "IDEMPOTENT_MUTATION"
    """Mutating operations proven idempotent by design or targeting a specific resource."""

    NON_IDEMPOTENT_MUTATION = "NON_IDEMPOTENT_MUTATION"
    """Mutating operations that allocate compute or consume resources without idempotency keys."""


# --- Exceptions ---


class RetryPolicyError(Exception):
    """Base exception for retry policy violations and terminal failures."""


class NonRetryableOperationError(RetryPolicyError):
    """Raised when an operation cannot be retried to avoid duplicating external actions."""

    def __init__(
        self,
        operation_name: str,
        operation_effect: OperationEffect,
        reason: str,
    ) -> None:
        self.operation_name = operation_name
        self.operation_effect = operation_effect
        self.reason = reason
        super().__init__(
            f"Operation {operation_name!r} [{operation_effect.value}] is non-retryable: {reason}"
        )


class MaxAttemptsExceededError(RetryPolicyError):
    """Raised when bounded attempts are exhausted without success."""

    def __init__(
        self,
        operation_name: str,
        total_attempts: int,
        last_error_message: str,
        audit_trail: RetryAuditTrail,
    ) -> None:
        self.operation_name = operation_name
        self.total_attempts = total_attempts
        self.last_error_message = redact_log_text(last_error_message)
        self.audit_trail = audit_trail
        super().__init__(
            f"Operation {operation_name!r} exhausted maximum attempts ({total_attempts}): "
            f"{self.last_error_message}"
        )


# --- Configuration ---


@dataclass(frozen=True, slots=True)
class RetryPolicyConfig:
    """Bounded, deterministic configuration for retry execution."""

    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    initial_backoff_seconds: float = DEFAULT_INITIAL_BACKOFF_SECONDS
    max_backoff_seconds: float = DEFAULT_MAX_BACKOFF_SECONDS
    backoff_multiplier: float = DEFAULT_BACKOFF_MULTIPLIER
    sleep_callable: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        if not (MIN_MAX_ATTEMPTS <= self.max_attempts <= CEILING_MAX_ATTEMPTS):
            raise RetryPolicyError(
                f"max_attempts must be between {MIN_MAX_ATTEMPTS} and {CEILING_MAX_ATTEMPTS}, "
                f"got {self.max_attempts}"
            )
        if self.initial_backoff_seconds <= 0:
            raise RetryPolicyError("initial_backoff_seconds must be positive")
        if self.max_backoff_seconds < self.initial_backoff_seconds:
            raise RetryPolicyError("max_backoff_seconds must be >= initial_backoff_seconds")
        if self.backoff_multiplier < 1.0:
            raise RetryPolicyError("backoff_multiplier must be >= 1.0")


# --- Attempt Records & Audit Trail ---


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    """Immutable audit record for a single execution attempt."""

    attempt_number: int
    timestamp_utc: str
    operation_name: str
    operation_effect: OperationEffect
    status: str
    status_code: int | None
    error_message: str | None
    duration_seconds: float
    is_retryable: bool
    delay_before_next_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_number": self.attempt_number,
            "timestamp_utc": self.timestamp_utc,
            "operation_name": self.operation_name,
            "operation_effect": self.operation_effect.value,
            "status": self.status,
            "status_code": self.status_code,
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
            "is_retryable": self.is_retryable,
            "delay_before_next_seconds": self.delay_before_next_seconds,
        }


@dataclass(frozen=True, slots=True)
class RetryAuditTrail:
    """Complete, immutable audit trail of attempts executed under retry policy."""

    operation_name: str
    operation_effect: OperationEffect
    total_attempts: int
    is_terminal_success: bool
    attempts: tuple[AttemptRecord, ...]
    final_error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_name": self.operation_name,
            "operation_effect": self.operation_effect.value,
            "total_attempts": self.total_attempts,
            "is_terminal_success": self.is_terminal_success,
            "attempts": [a.to_dict() for a in self.attempts],
            "final_error_message": self.final_error_message,
        }


# --- Error Classification ---

_PERMANENT_HTTP_STATUSES: frozenset[int] = frozenset({400, 401, 403, 404, 405, 413, 422})
_TRANSIENT_HTTP_STATUSES: frozenset[int] = frozenset({429, 502, 503, 504})


def is_permanent_failure(exc: BaseException) -> bool:
    """Determine whether an exception represents a definitive permanent failure."""
    if isinstance(
        exc,
        (
            ModelIdentityMismatchError,
            ModelConfigError,
            MissingCredentialError,
            ModelResponseFormatError,
            SandboxConfigError,
            MissingSandboxCredentialError,
            SandboxLifecycleError,
            SandboxResponseFormatError,
            MalformedSourceIdentityError,
            SourceCommitMismatchError,
            SourceTreeMismatchError,
            SourceVerificationError,
        ),
    ):
        return True

    status_code: int | None = getattr(exc, "status_code", None)
    if status_code is not None and status_code in _PERMANENT_HTTP_STATUSES:
        return True

    return False


def is_transient_failure(exc: BaseException) -> bool:
    """Determine whether an exception represents a known transient server condition."""
    if is_permanent_failure(exc):
        return False

    if isinstance(
        exc,
        (
            ModelNetworkError,
            ModelTimeoutError,
            SandboxTransportError,
            SandboxTimeoutError,
        ),
    ):
        return True

    status_code: int | None = getattr(exc, "status_code", None)
    if status_code is not None and status_code in _TRANSIENT_HTTP_STATUSES:
        return True

    # Generic network/transport errors (connection reset, DNS timeout)
    exc_name = type(exc).__name__
    if any(k in exc_name for k in ("Transport", "URLError", "Connection", "Timeout", "Network")):
        return True

    return False


def is_operation_retryable(
    operation_effect: OperationEffect,
    exc: BaseException,
) -> tuple[bool, str]:
    """Evaluate whether an operation is eligible for retry under Basebreak law.

    Returns:
        (is_retryable, rationale_string)
    """
    if is_permanent_failure(exc):
        return False, "Permanent failure: error is not transient"

    if operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION:
        # Core Invariant: mutating actions without idempotency keys MUST NOT retry on failure
        return (
            False,
            f"Non-idempotent operation risks duplicating external action upon repeat "
            f"({operation_effect.value})",
        )

    if not is_transient_failure(exc):
        return False, f"Unknown or unclassified failure type: {type(exc).__name__}"

    return True, "Safe retryable failure on read-only or idempotent operation"


# --- Deterministic Backoff Calculation ---


def compute_backoff_seconds(
    attempt_number: int,
    config: RetryPolicyConfig,
) -> float:
    """Compute bounded exponential backoff delay for the given attempt index (1-based)."""
    if attempt_number <= 0:
        return 0.0
    factor = config.backoff_multiplier ** (attempt_number - 1)
    delay = config.initial_backoff_seconds * factor
    return min(delay, config.max_backoff_seconds)


# --- Policy Executor ---


class NebiusRetryExecutor:
    """Executes callables under explicit Basebreak retry/idempotency policy.

    Ensures:
    - Bounded attempt count;
    - Bounded exponential backoff;
    - Zero duplication of non-idempotent actions;
    - Full deterministic attempt audit trail;
    - Zero secret leakage in logs or exceptions.
    """

    def __init__(self, config: RetryPolicyConfig | None = None) -> None:
        self._config = config or RetryPolicyConfig()

    @property
    def config(self) -> RetryPolicyConfig:
        return self._config

    def execute(
        self,
        operation_name: str,
        operation_effect: OperationEffect,
        action: Callable[[], T],
    ) -> tuple[T, RetryAuditTrail]:
        """Execute action under retry policy.

        Args:
            operation_name: Human-readable name for logging and auditing.
            operation_effect: Classification (READ_ONLY, IDEMPOTENT_MUTATION,
                NON_IDEMPOTENT_MUTATION).
            action: Zero-argument callable to execute.

        Returns:
            (result, audit_trail)

        Raises:
            NonRetryableOperationError: If a non-idempotent mutation fails and cannot be retried.
            MaxAttemptsExceededError: If retryable attempts exceed config.max_attempts.
            Original Exception: If a permanent failure occurs.
        """
        attempts_list: list[AttemptRecord] = []
        max_attempts = (
            1
            if operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION
            else self._config.max_attempts
        )

        for attempt_idx in range(1, max_attempts + 1):
            start_time = time.time()
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

            try:
                result = action()
                duration = time.time() - start_time
                record = AttemptRecord(
                    attempt_number=attempt_idx,
                    timestamp_utc=now_iso,
                    operation_name=operation_name,
                    operation_effect=operation_effect,
                    status="SUCCESS",
                    status_code=200,
                    error_message=None,
                    duration_seconds=duration,
                    is_retryable=False,
                    delay_before_next_seconds=0.0,
                )
                attempts_list.append(record)
                trail = RetryAuditTrail(
                    operation_name=operation_name,
                    operation_effect=operation_effect,
                    total_attempts=len(attempts_list),
                    is_terminal_success=True,
                    attempts=tuple(attempts_list),
                )
                return result, trail

            except Exception as exc:
                duration = time.time() - start_time
                raw_err = str(exc)
                clean_err = redact_log_text(raw_err)
                code: int | None = getattr(exc, "status_code", None)

                can_retry, rationale = is_operation_retryable(operation_effect, exc)

                if can_retry and attempt_idx < max_attempts:
                    delay = compute_backoff_seconds(attempt_idx, self._config)
                    record = AttemptRecord(
                        attempt_number=attempt_idx,
                        timestamp_utc=now_iso,
                        operation_name=operation_name,
                        operation_effect=operation_effect,
                        status="TRANSIENT_FAILURE",
                        status_code=code,
                        error_message=clean_err,
                        duration_seconds=duration,
                        is_retryable=True,
                        delay_before_next_seconds=delay,
                    )
                    attempts_list.append(record)
                    self._config.sleep_callable(delay)
                    continue

                # Not retryable or exhausted
                record = AttemptRecord(
                    attempt_number=attempt_idx,
                    timestamp_utc=now_iso,
                    operation_name=operation_name,
                    operation_effect=operation_effect,
                    status="TERMINAL_FAILURE",
                    status_code=code,
                    error_message=clean_err,
                    duration_seconds=duration,
                    is_retryable=can_retry,
                    delay_before_next_seconds=0.0,
                )
                attempts_list.append(record)

                trail = RetryAuditTrail(
                    operation_name=operation_name,
                    operation_effect=operation_effect,
                    total_attempts=len(attempts_list),
                    is_terminal_success=False,
                    attempts=tuple(attempts_list),
                    final_error_message=clean_err,
                )

                if operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION:
                    # Non-idempotent mutation failure fails closed
                    raise NonRetryableOperationError(
                        operation_name=operation_name,
                        operation_effect=operation_effect,
                        reason=f"Mutating action encountered failure ({clean_err}); "
                        f"retrying is forbidden to prevent duplicate external execution.",
                    ) from exc

                if can_retry:
                    # Exhausted attempts
                    raise MaxAttemptsExceededError(
                        operation_name=operation_name,
                        total_attempts=len(attempts_list),
                        last_error_message=clean_err,
                        audit_trail=trail,
                    ) from exc

                # Permanent failure: re-raise directly
                raise

        # Should never reach here due to loop invariants
        raise RetryPolicyError(f"Unexpected termination in retry loop for {operation_name}")
