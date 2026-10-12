"""Sandbox-loss recovery and failure discrimination.

P-25.03: Implement sandbox-loss recovery.
Distinguishes between test assertion failures, execution timeouts, out-of-memory
terminations, and infrastructure sandbox disconnections/crashes.
Enforces fail-closed handling: dropped sandboxes never manufacture PASS or FAIL.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

_OOM_PATTERNS = re.compile(
    r"(?i)(?:out of memory|oom-killer|killed process|cannot allocate memory)"
)
_DISCONNECT_PATTERNS = re.compile(
    r"(?i)(?:connection refused|broken pipe|connection reset by peer|sandbox agent unreachable|"
    r"daemon closed connection|transport error)"
)


class SandboxFailureKind(str, Enum):
    """Classification of sandbox execution and infrastructure outcomes."""

    SUCCESS = "SUCCESS"
    TEST_FAILURE = "TEST_FAILURE"
    TIMEOUT = "TIMEOUT"
    OOM_KILLED = "OOM_KILLED"
    CONTAINER_CRASH = "CONTAINER_CRASH"
    SANDBOX_DISCONNECT = "SANDBOX_DISCONNECT"
    UNKNOWN_INFRA_FAILURE = "UNKNOWN_INFRA_FAILURE"


@dataclass(frozen=True, slots=True)
class SandboxClassification:
    """Outcome classification with infrastructure retry recommendation."""

    kind: SandboxFailureKind
    exit_code: int | None
    is_infra_failure: bool
    can_retry_in_fresh_sandbox: bool
    summary: str


def classify_sandbox_failure(
    *,
    exit_code: int | None,
    stderr: str = "",
    is_timeout: bool = False,
    connection_lost: bool = False,
) -> SandboxClassification:
    """Classify execution outcome into deterministic failure categories."""
    if connection_lost or _DISCONNECT_PATTERNS.search(stderr):
        return SandboxClassification(
            kind=SandboxFailureKind.SANDBOX_DISCONNECT,
            exit_code=exit_code,
            is_infra_failure=True,
            can_retry_in_fresh_sandbox=True,
            summary="Sandbox daemon or transport connection lost during execution",
        )

    if is_timeout:
        return SandboxClassification(
            kind=SandboxFailureKind.TIMEOUT,
            exit_code=exit_code,
            is_infra_failure=False,
            can_retry_in_fresh_sandbox=False,
            summary="Execution exceeded time limit watchdog",
        )

    if exit_code == 0:
        return SandboxClassification(
            kind=SandboxFailureKind.SUCCESS,
            exit_code=0,
            is_infra_failure=False,
            can_retry_in_fresh_sandbox=False,
            summary="Process completed with exit code 0",
        )

    # Linux SIGKILL is exit code 137 (128 + 9), frequently OOM
    if exit_code == 137 or _OOM_PATTERNS.search(stderr):
        return SandboxClassification(
            kind=SandboxFailureKind.OOM_KILLED,
            exit_code=exit_code,
            is_infra_failure=True,
            can_retry_in_fresh_sandbox=False,  # OOM is reproducible on same resource limit
            summary="Process killed by OOM killer or SIGKILL",
        )

    # Linux SIGSEGV is exit code 139 (128 + 11)
    if exit_code == 139:
        return SandboxClassification(
            kind=SandboxFailureKind.CONTAINER_CRASH,
            exit_code=exit_code,
            is_infra_failure=True,
            can_retry_in_fresh_sandbox=True,
            summary="Process crashed with segmentation fault (SIGSEGV)",
        )

    # Ordinary non-zero exit code (e.g. 1 from pytest)
    if exit_code is not None and exit_code != 0:
        return SandboxClassification(
            kind=SandboxFailureKind.TEST_FAILURE,
            exit_code=exit_code,
            is_infra_failure=False,
            can_retry_in_fresh_sandbox=False,
            summary=f"Process exited with non-zero code {exit_code} (code under test failed)",
        )

    return SandboxClassification(
        kind=SandboxFailureKind.UNKNOWN_INFRA_FAILURE,
        exit_code=exit_code,
        is_infra_failure=True,
        can_retry_in_fresh_sandbox=True,
        summary="Execution failed due to unclassified infrastructure anomaly",
    )


class SandboxLossRecoveryManager:
    """Manages fresh sandbox recovery decisions while preserving causal invariants."""

    def __init__(self, max_infra_retries: int = 1) -> None:
        self.max_infra_retries = max_infra_retries

    def evaluate_recovery(
        self,
        classification: SandboxClassification,
        current_infra_retries: int = 0,
    ) -> bool:
        """Return True if a fresh sandbox should be created, False if verdict must conclude."""
        if not classification.can_retry_in_fresh_sandbox:
            return False
        return current_infra_retries < self.max_infra_retries
