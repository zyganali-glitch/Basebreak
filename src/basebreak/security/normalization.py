"""Deterministic provider-neutral normalization of execution outcomes.

Normalizes execution termination, failure, timeout, cancellation, and resource
conditions into deterministic classifications using proven platform semantics.
Ensures that ambiguous provider failures fail closed as UNKNOWN_PROVIDER_FAILURE
rather than being guessed as TIMEOUT or RESOURCE_FAILURE. Integrates stream
digesting and secret redaction.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.domain.execution import ExecutionResult, TerminationStatus
from basebreak.evidence.artifact import canonical_json_bytes, compute_bytes_digest
from basebreak.evidence.capture import (
    DEFAULT_MAX_CAPTURE_BYTES,
    StreamType,
    capture_stream,
)
from basebreak.security.secret_policy import (
    SecretPersistenceError,
    find_secret_findings,
    redact_log_text,
)


class NormalizedExecutionOutcome(str, Enum):
    """Authoritative normalized classification of an execution outcome."""

    SUCCESS = "SUCCESS"
    NONZERO_EXIT = "NONZERO_EXIT"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    RESOURCE_FAILURE = "RESOURCE_FAILURE"
    UNKNOWN_PROVIDER_FAILURE = "UNKNOWN_PROVIDER_FAILURE"


class ResourceFailureClass(str, Enum):
    """Specific verified class of platform resource failure."""

    CONCURRENCY_EXHAUSTED = "CONCURRENCY_EXHAUSTED"
    LAYER_QUOTA_EXCEEDED = "LAYER_QUOTA_EXCEEDED"
    OUT_OF_MEMORY = "OUT_OF_MEMORY"
    UNKNOWN_RESOURCE_FAILURE = "UNKNOWN_RESOURCE_FAILURE"


# --- Deterministic Regex Patterns for Platform Error Classification ---

_TIMEOUT_REGEX: re.Pattern[str] = re.compile(
    r"(?i)\b(timed?\s*out|deadline\s*exceeded|execution\s*timeout|operation\s*timeout)\b"
)
_CANCELLATION_REGEX: re.Pattern[str] = re.compile(
    r"(?i)\b(operation\s*cancelled|execution\s*cancelled|request\s*cancelled|"
    r"instance\s*cancelled|client\s*cancelled|cancelled\s*by\s*user)\b"
)

_CONCURRENCY_REGEX: re.Pattern[str] = re.compile(
    r"(?i)\b(concurrency\s*limit|max\s*concurrency|instance_max_concurrency|"
    r"too\s*many\s*concurrent|rate\s*limit\s*exceeded)\b"
)
_LAYER_QUOTA_REGEX: re.Pattern[str] = re.compile(
    r"(?i)\b(instance_max_layer_bytes|layer\s*bytes\s*limit|layer\s*bytes\s*exceeded|"
    r"disk\s*space\s*exceeded|layer\s*quota\s*exceeded|layer_bytes)\b"
)
_OOM_REGEX: re.Pattern[str] = re.compile(
    r"(?i)\b(out\s*of\s*memory|\boom\s*killer\b|cgroup\s*memory|memory\s*limit\s*exceeded)\b"
)


@dataclass(frozen=True, slots=True)
class NormalizedExecutionRecord:
    """Immutable, provider-neutral record of a normalized execution outcome.

    Attributes:
        outcome: Authoritative classification of execution termination.
        exit_code: Process exit code if completed.
        duration_seconds: Measured execution duration in seconds.
        stdout_digest: Full cryptographic SHA-256 digest of stdout.
        stderr_digest: Full cryptographic SHA-256 digest of stderr.
        stdout_preview: Bounded, sanitized stdout preview text.
        stderr_preview: Bounded, sanitized stderr preview text.
        is_timeout: True if outcome is TIMEOUT.
        is_cancelled: True if outcome is CANCELLED.
        is_resource_failure: True if outcome is RESOURCE_FAILURE.
        resource_failure_class: Specific resource failure category if applicable.
        provider_status: Original raw provider status string if present.
        provider_error_code: Provider HTTP or RPC error code if present.
        provider_error_message: Sanitized provider error message if present.
        raw_payload_digest: Cryptographic digest of raw provider payload if present.
    """

    outcome: NormalizedExecutionOutcome
    exit_code: int | None = None
    duration_seconds: float | None = None
    stdout_digest: str = ""
    stderr_digest: str = ""
    stdout_preview: str = ""
    stderr_preview: str = ""
    is_timeout: bool = False
    is_cancelled: bool = False
    is_resource_failure: bool = False
    resource_failure_class: ResourceFailureClass | None = None
    provider_status: str | None = None
    provider_error_code: int | None = None
    provider_error_message: str | None = None
    raw_payload_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, NormalizedExecutionOutcome):
            raise TypeError(
                f"outcome must be a NormalizedExecutionOutcome, got {type(self.outcome).__name__}"
            )

        # Invariant checks for outcome flags
        expected_timeout = self.outcome == NormalizedExecutionOutcome.TIMEOUT
        if self.is_timeout != expected_timeout:
            raise ValueError(
                f"is_timeout ({self.is_timeout}) does not match outcome ({self.outcome.value})"
            )

        expected_cancelled = self.outcome == NormalizedExecutionOutcome.CANCELLED
        if self.is_cancelled != expected_cancelled:
            raise ValueError(
                f"is_cancelled ({self.is_cancelled}) does not match outcome ({self.outcome.value})"
            )

        expected_rf = self.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        if self.is_resource_failure != expected_rf:
            raise ValueError(
                f"is_resource_failure ({self.is_resource_failure}) does not match "
                f"outcome ({self.outcome.value})"
            )

        if self.outcome == NormalizedExecutionOutcome.SUCCESS and self.exit_code != 0:
            raise ValueError(f"SUCCESS outcome requires exit_code == 0, got {self.exit_code}")

        if self.outcome == NormalizedExecutionOutcome.NONZERO_EXIT and (
            self.exit_code is None or self.exit_code == 0
        ):
            raise ValueError(
                f"NONZERO_EXIT outcome requires non-zero exit_code, got {self.exit_code}"
            )

        # Secret persistence checks: preview fields and error message must not contain raw secrets
        if self.stdout_preview:
            findings = find_secret_findings(self.stdout_preview)
            if findings:
                raise SecretPersistenceError(
                    rule_id=findings[0].rule_id,
                    path="stdout_preview",
                    category="SECRET_PERSISTENCE_FORBIDDEN",
                )
        if self.stderr_preview:
            findings = find_secret_findings(self.stderr_preview)
            if findings:
                raise SecretPersistenceError(
                    rule_id=findings[0].rule_id,
                    path="stderr_preview",
                    category="SECRET_PERSISTENCE_FORBIDDEN",
                )
        if self.provider_error_message:
            findings = find_secret_findings(self.provider_error_message)
            if findings:
                raise SecretPersistenceError(
                    rule_id=findings[0].rule_id,
                    path="provider_error_message",
                    category="SECRET_PERSISTENCE_FORBIDDEN",
                )

    def to_dict(self) -> dict[str, Any]:
        """Serialize record to a deterministic dictionary."""
        return {
            "outcome": self.outcome.value,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "stdout_digest": self.stdout_digest,
            "stderr_digest": self.stderr_digest,
            "stdout_preview": self.stdout_preview,
            "stderr_preview": self.stderr_preview,
            "is_timeout": self.is_timeout,
            "is_cancelled": self.is_cancelled,
            "is_resource_failure": self.is_resource_failure,
            "resource_failure_class": (
                self.resource_failure_class.value
                if self.resource_failure_class is not None
                else None
            ),
            "provider_status": self.provider_status,
            "provider_error_code": self.provider_error_code,
            "provider_error_message": self.provider_error_message,
            "raw_payload_digest": self.raw_payload_digest,
        }

    def canonical_digest(self) -> str:
        """Compute the content-addressed SHA-256 digest of this normalized record."""
        return compute_bytes_digest(canonical_json_bytes(self.to_dict())).value


def _extract_provider_error(
    error_data: Any,
) -> tuple[int | None, str | None]:
    """Extract (code, message) safely from provider error representation."""
    if error_data is None:
        return None, None
    if isinstance(error_data, Mapping):
        code = error_data.get("status") or error_data.get("code")
        msg = error_data.get("error") or error_data.get("message")
        int_code = int(code) if isinstance(code, (int, str)) and str(code).isdigit() else None
        str_msg = str(msg) if msg is not None else None
        return int_code, str_msg
    if isinstance(error_data, str):
        return None, error_data
    return None, str(error_data)


def normalize_execution_result(
    *,
    raw_payload: Mapping[str, Any] | None = None,
    execution_result: ExecutionResult | None = None,
    stdout: str | bytes = "",
    stderr: str | bytes = "",
    exit_code: int | None = None,
    is_timeout: bool = False,
    is_cancelled: bool = False,
    provider_status: str | None = None,
    provider_error: Mapping[str, Any] | str | None = None,
    duration_seconds: float | None = None,
    max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
) -> NormalizedExecutionRecord:
    """Normalize execution results into a deterministic NormalizedExecutionRecord.

    Accepts raw provider payloads (e.g. from Token Factory Sandboxes), domain
    ExecutionResult contracts, or raw exit/status indicators. Classifies outcomes
    fail-closed without guessing ambiguous errors as timeouts or resource limits.

    Stream outputs are cryptographically digested and sanitized using P-04.02.
    """
    raw_digest: str | None = None

    # 1. Parse raw provider payload if supplied
    if raw_payload is not None:
        try:
            raw_digest = compute_bytes_digest(canonical_json_bytes(raw_payload)).value
        except Exception:
            raw_digest = None

        # Extract platform fields (Token Factory OpenAPI schema convention)
        if provider_status is None:
            p_stat = raw_payload.get("status")
            if isinstance(p_stat, str):
                provider_status = p_stat.upper()

        if provider_error is None and "error" in raw_payload:
            provider_error = raw_payload.get("error")

        meta = raw_payload.get("metadata")
        if isinstance(meta, Mapping):
            res = meta.get("result")
            if isinstance(res, Mapping):
                if exit_code is None and "exit_code" in res:
                    ec = res.get("exit_code")
                    if isinstance(ec, int):
                        exit_code = ec
                if not stdout and "stdout" in res:
                    stdout = str(res.get("stdout") or "")
                if not stderr and "stderr" in res:
                    stderr = str(res.get("stderr") or "")
                if duration_seconds is None and "duration" in res:
                    dur = res.get("duration")
                    if isinstance(dur, (int, float)):
                        duration_seconds = float(dur)

    # 2. Reconcile domain execution result if supplied
    if execution_result is not None:
        if exit_code is None:
            exit_code = execution_result.exit_code
        if duration_seconds is None:
            duration_seconds = execution_result.duration_seconds
        if execution_result.status == TerminationStatus.TIMED_OUT:
            is_timeout = True
        elif execution_result.status == TerminationStatus.CANCELLED:
            is_cancelled = True

    # 3. Extract and sanitize provider error fields
    err_code, err_msg = _extract_provider_error(provider_error)
    sanitized_err_msg = redact_log_text(err_msg) if err_msg else None

    # 4. Stream capture, digesting, and sanitization
    stdout_captured = capture_stream(
        stdout,
        StreamType.STDOUT,
        max_bytes=max_capture_bytes,
    )
    stderr_captured = capture_stream(
        stderr,
        StreamType.STDERR,
        max_bytes=max_capture_bytes,
    )

    stdout_digest = stdout_captured.full_digest.value
    stderr_digest = stderr_captured.full_digest.value
    stdout_preview = stdout_captured.sanitized_text
    stderr_preview = stderr_captured.sanitized_text

    # 5. Deterministic Outcome Resolution (Fail-Closed Classification)

    # A. Check for TIMEOUT
    timeout_detected = (
        is_timeout
        or provider_status in ("TIMED_OUT", "TIMEOUT")
        or err_code == 408
        or (err_msg is not None and bool(_TIMEOUT_REGEX.search(err_msg)))
        or (exit_code == 124 and (is_timeout or (err_msg and bool(_TIMEOUT_REGEX.search(err_msg)))))
    )
    if timeout_detected:
        return NormalizedExecutionRecord(
            outcome=NormalizedExecutionOutcome.TIMEOUT,
            exit_code=exit_code,
            duration_seconds=duration_seconds,
            stdout_digest=stdout_digest,
            stderr_digest=stderr_digest,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            is_timeout=True,
            provider_status=provider_status,
            provider_error_code=err_code,
            provider_error_message=sanitized_err_msg,
            raw_payload_digest=raw_digest,
        )

    # B. Check for CANCELLED
    cancellation_detected = (
        is_cancelled
        or provider_status in ("CANCELLED", "CANCELED")
        or err_code == 499
        or (err_msg is not None and bool(_CANCELLATION_REGEX.search(err_msg)))
    )
    if cancellation_detected:
        return NormalizedExecutionRecord(
            outcome=NormalizedExecutionOutcome.CANCELLED,
            exit_code=exit_code,
            duration_seconds=duration_seconds,
            stdout_digest=stdout_digest,
            stderr_digest=stderr_digest,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            is_cancelled=True,
            provider_status=provider_status,
            provider_error_code=err_code,
            provider_error_message=sanitized_err_msg,
            raw_payload_digest=raw_digest,
        )

    # C. Check for RESOURCE_FAILURE (Strict deterministic matching only)
    resource_failure_class: ResourceFailureClass | None = None
    if err_msg is not None:
        if bool(_CONCURRENCY_REGEX.search(err_msg)) or (
            err_code == 429 and "concurrency" in err_msg.lower()
        ):
            resource_failure_class = ResourceFailureClass.CONCURRENCY_EXHAUSTED
        elif bool(_LAYER_QUOTA_REGEX.search(err_msg)):
            resource_failure_class = ResourceFailureClass.LAYER_QUOTA_EXCEEDED
        elif bool(_OOM_REGEX.search(err_msg)):
            resource_failure_class = ResourceFailureClass.OUT_OF_MEMORY
    elif err_code == 429:
        # Standard HTTP 429 is rate/concurrency exhaustion
        resource_failure_class = ResourceFailureClass.CONCURRENCY_EXHAUSTED

    if resource_failure_class is not None:
        return NormalizedExecutionRecord(
            outcome=NormalizedExecutionOutcome.RESOURCE_FAILURE,
            exit_code=exit_code,
            duration_seconds=duration_seconds,
            stdout_digest=stdout_digest,
            stderr_digest=stderr_digest,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            is_resource_failure=True,
            resource_failure_class=resource_failure_class,
            provider_status=provider_status,
            provider_error_code=err_code,
            provider_error_message=sanitized_err_msg,
            raw_payload_digest=raw_digest,
        )

    # D. Check for Process Completion (SUCCESS or NONZERO_EXIT)
    # Recognized when provider status is SUCCESS or COMPLETED (or omitted for direct local results)
    is_completed_status = (
        provider_status in ("SUCCESS", "COMPLETED", None) and provider_error is None
    )
    if is_completed_status and exit_code is not None:
        if exit_code == 0:
            return NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.SUCCESS,
                exit_code=0,
                duration_seconds=duration_seconds,
                stdout_digest=stdout_digest,
                stderr_digest=stderr_digest,
                stdout_preview=stdout_preview,
                stderr_preview=stderr_preview,
                provider_status=provider_status,
                raw_payload_digest=raw_digest,
            )
        return NormalizedExecutionRecord(
            outcome=NormalizedExecutionOutcome.NONZERO_EXIT,
            exit_code=exit_code,
            duration_seconds=duration_seconds,
            stdout_digest=stdout_digest,
            stderr_digest=stderr_digest,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            provider_status=provider_status,
            raw_payload_digest=raw_digest,
        )

    # E. All other cases fail closed as UNKNOWN_PROVIDER_FAILURE
    return NormalizedExecutionRecord(
        outcome=NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE,
        exit_code=exit_code,
        duration_seconds=duration_seconds,
        stdout_digest=stdout_digest,
        stderr_digest=stderr_digest,
        stdout_preview=stdout_preview,
        stderr_preview=stderr_preview,
        provider_status=provider_status,
        provider_error_code=err_code,
        provider_error_message=sanitized_err_msg,
        raw_payload_digest=raw_digest,
    )
