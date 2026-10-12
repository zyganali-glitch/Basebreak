"""Basebreak Recovery and Reliability subsystem.

P-25: Reliability, Recovery & Idempotency.
- P-25.01: Durable run state persistence independent of mutable workspace.
- P-25.02: Crash/retry semantics for model calls.
- P-25.03: Sandbox-loss recovery.
- P-25.04: Duplicate-run / idempotency protection.
- P-25.05: Evidence write deduplication and replay safety.
- P-25.06: Fresh-process recovery E2E.
"""

from __future__ import annotations

from basebreak.recovery.dedup import ContentAddressedEvidenceStore
from basebreak.recovery.idempotency import (
    IdempotencyDecision,
    IdempotencyEngine,
    IdempotencyKeyConflictError,
)
from basebreak.recovery.retry import (
    NonRetryableModelError,
    RetryableModelError,
    RetryConfig,
    execute_with_retry,
)
from basebreak.recovery.sandbox_recovery import (
    SandboxFailureKind,
    SandboxLossRecoveryManager,
    classify_sandbox_failure,
)
from basebreak.recovery.state import (
    DurableRunState,
    DurableStateManager,
    RunStep,
)

__all__ = [
    "ContentAddressedEvidenceStore",
    "DurableRunState",
    "DurableStateManager",
    "IdempotencyDecision",
    "IdempotencyEngine",
    "IdempotencyKeyConflictError",
    "NonRetryableModelError",
    "RetryConfig",
    "RetryableModelError",
    "RunStep",
    "SandboxFailureKind",
    "SandboxLossRecoveryManager",
    "classify_sandbox_failure",
    "execute_with_retry",
]
