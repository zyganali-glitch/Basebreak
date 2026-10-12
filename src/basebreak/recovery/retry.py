"""Crash and retry semantics for model and provider calls.

P-25.02: Implement crash/retry semantics for model calls.
Retries transient transport and server errors with exponential backoff and jitter.
Fails closed immediately on non-retryable errors (auth, bad request, budget floor).
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

T = TypeVar("T")


class ModelCallError(Exception):
    """Base exception for model execution failures."""


class RetryableModelError(ModelCallError):
    """Transient errors that are safe to retry (e.g. rate limit, 502/503/504, timeout)."""


class NonRetryableModelError(ModelCallError):
    """Deterministic errors that must fail closed immediately (e.g. 400, 401, 403, context)."""


class BudgetFloorExceededError(NonRetryableModelError):
    """Raised when promotional safety threshold or zero-cost limit is breached."""


@dataclass(frozen=True, slots=True)
class RetryConfig:
    """Configuration for exponential backoff and retry behavior."""

    max_retries: int = 3
    initial_backoff_seconds: float = 0.1
    backoff_factor: float = 2.0
    max_backoff_seconds: float = 2.0
    jitter: bool = True

    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay in seconds for a given attempt index (0-based)."""
        delay = min(
            self.initial_backoff_seconds * (self.backoff_factor**attempt),
            self.max_backoff_seconds,
        )
        if self.jitter:
            delay = delay * (0.5 + random.random() * 0.5)
        return delay


def execute_with_retry(
    fn: Callable[[], T],
    config: RetryConfig = RetryConfig(),
    *,
    budget_check_fn: Callable[[], bool] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    on_retry: Callable[[int, Exception, float], None] | None = None,
) -> T:
    """Execute a callable with bounded retry and backoff semantics.

    Args:
        fn: Operation to execute.
        config: Retry policy configuration.
        budget_check_fn: Optional callable returning True if budget allows execution.
        sleep_fn: Function to pause execution between retries (defaults to time.sleep).
        on_retry: Optional hook called before each retry with (attempt, error, delay).

    Returns:
        Result of successful fn() call.

    Raises:
        NonRetryableModelError: Immediately upon encountering non-retryable errors.
        BudgetFloorExceededError: If budget floor check returns False.
        RetryableModelError: If max_retries is exhausted without success.
    """
    last_error: Exception | None = None

    for attempt in range(config.max_retries + 1):
        if budget_check_fn is not None and not budget_check_fn():
            raise BudgetFloorExceededError(
                "Execution aborted: Promotional safety budget floor reached"
            )

        try:
            return fn()
        except NonRetryableModelError:
            raise
        except RetryableModelError as exc:
            last_error = exc
            if attempt >= config.max_retries:
                raise RetryableModelError(
                    f"Max retries ({config.max_retries}) exhausted: {exc}"
                ) from exc

            delay = config.calculate_delay(attempt)
            if on_retry:
                on_retry(attempt + 1, exc, delay)
            sleep_fn(delay)
        except Exception as exc:
            # By default, unknown exceptions fail closed as non-retryable
            raise NonRetryableModelError(f"Unexpected unclassified error: {exc}") from exc

    if last_error:
        raise last_error
    raise RetryableModelError("Execution failed without producing a result")
