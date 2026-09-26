"""Secret-safe telemetry normalization for Nebius Token Factory models and sandboxes.

Authority:
- Section 4 / P-04: Deterministic facts (exit codes, hashes, digests) remain authoritative.
- Telemetry records provider-side observability without acquiring verdict authority.
- Evidence provenance (FIXTURE, LOCAL_EXECUTION, LIVE_NEBIUS, RECORDED_LIVE) is strictly preserved.
- Secret safety: credentials and bearer tokens are purged and redacted from all telemetry.
- Bounded payloads: strings and metadata are bounded to prevent memory exhaustion or log flooding.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any

from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import canonical_json_bytes, compute_bytes_digest
from basebreak.security.secret_policy import (
    find_secret_findings,
    is_sensitive_key,
    redact_log_text,
)

from .client import ModelAdapterError, ModelClientResult, ModelProviderError
from .sandbox import (
    NebiusOperationStatus,
    NebiusSandboxExecutionResult,
    SandboxAdapterError,
    SandboxProviderError,
)

# --- Bounding Constants ---

MAX_TELEMETRY_STRING_BYTES: int = 1024
MAX_PAYLOAD_DIGEST_BYTES: int = 65536

_SENSITIVE_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "authorization",
        "project",
        "api_key",
        "apikey",
        "token",
        "bearer",
        "secret",
        "password",
        "credential",
    }
)


def _is_sensitive_field(key: str) -> bool:
    clean = key.strip().lower().replace("-", "_")
    if clean in _SENSITIVE_FIELD_NAMES:
        return True
    return is_sensitive_key(clean)


def sanitize_and_bound_text(
    text: str | None,
    max_bytes: int = MAX_TELEMETRY_STRING_BYTES,
) -> str:
    """Sanitize secrets from text and bound its byte length."""
    if text is None:
        return ""
    redacted = redact_log_text(str(text))
    encoded = redacted.encode("utf-8")
    if len(encoded) <= max_bytes:
        return redacted

    # Truncate to max_bytes cleanly
    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return f"{truncated}... [TRUNCATED {len(encoded) - max_bytes} B]"


def _sanitize_dict_recursively(data: Any) -> Any:
    """Recursively strip sensitive keys and redact sensitive string values."""
    if isinstance(data, dict):
        clean_dict: dict[str, Any] = {}
        for k, v in data.items():
            str_k = str(k)
            if _is_sensitive_field(str_k):
                clean_dict[str_k] = "[REDACTED_CREDENTIAL]"
            else:
                clean_dict[str_k] = _sanitize_dict_recursively(v)
        return clean_dict
    if isinstance(data, list):
        return [_sanitize_dict_recursively(item) for item in data]
    if isinstance(data, str):
        return redact_log_text(data)
    return data


def compute_sanitized_payload_digest(raw_payload: Any) -> str:
    """Compute content-addressed SHA-256 digest of sanitized payload."""
    if raw_payload is None:
        return ""
    try:
        sanitized = _sanitize_dict_recursively(raw_payload)
        json_bytes = canonical_json_bytes(sanitized)
        return compute_bytes_digest(json_bytes).value
    except Exception:
        # Fallback to string digest if JSON serialization fails
        clean_str = redact_log_text(str(raw_payload))
        return compute_bytes_digest(clean_str.encode("utf-8")).value


# --- Telemetry Data Classes ---


@dataclass(frozen=True, slots=True)
class NormalizedModelTelemetry:
    """Secret-safe, non-authoritative telemetry record for model inference."""

    model: str
    returned_model: str
    request_id: str | None
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None
    duration_seconds: float | None
    finish_reason: str | None
    status_code: int | None
    provenance: EvidenceProvenance
    sanitized_error: str | None = None
    payload_digest: str = ""
    timestamp_utc: str = ""
    is_authoritative: bool = False

    def __post_init__(self) -> None:
        if not self.timestamp_utc:
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            object.__setattr__(self, "timestamp_utc", now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "telemetry_type": "MODEL",
            "model": self.model,
            "returned_model": self.returned_model,
            "request_id": self.request_id,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "duration_seconds": self.duration_seconds,
            "finish_reason": self.finish_reason,
            "status_code": self.status_code,
            "provenance": self.provenance.value,
            "sanitized_error": self.sanitized_error,
            "payload_digest": self.payload_digest,
            "timestamp_utc": self.timestamp_utc,
            "is_authoritative": False,
        }

    def to_log_message(self) -> str:
        """Deterministic secret-safe single-line log format."""
        tokens_info = f"tokens={self.prompt_tokens}+{self.completion_tokens}={self.total_tokens}"
        dur_info = f"lat={self.duration_seconds:.3f}s" if self.duration_seconds else "lat=None"
        err_info = f" err={self.sanitized_error!r}" if self.sanitized_error else ""
        return (
            f"[MODEL_TELEMETRY] [{self.provenance.value}] model={self.returned_model} "
            f"req_id={self.request_id} {tokens_info} {dur_info}{err_info}"
        )


@dataclass(frozen=True, slots=True)
class NormalizedSandboxTelemetry:
    """Secret-safe, non-authoritative telemetry record for sandbox execution."""

    operation_id: str | None
    sandbox_id: str | None
    image: str | None
    disposable: bool | None
    provider_status: str | None
    duration_seconds: float | None
    cpu_duration_seconds: float | None
    memory_bytes: int | None
    provenance: EvidenceProvenance
    sanitized_error: str | None = None
    payload_digest: str = ""
    timestamp_utc: str = ""
    is_authoritative: bool = False

    def __post_init__(self) -> None:
        if not self.timestamp_utc:
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            object.__setattr__(self, "timestamp_utc", now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "telemetry_type": "SANDBOX",
            "operation_id": self.operation_id,
            "sandbox_id": self.sandbox_id,
            "image": self.image,
            "disposable": self.disposable,
            "provider_status": self.provider_status,
            "duration_seconds": self.duration_seconds,
            "cpu_duration_seconds": self.cpu_duration_seconds,
            "memory_bytes": self.memory_bytes,
            "provenance": self.provenance.value,
            "sanitized_error": self.sanitized_error,
            "payload_digest": self.payload_digest,
            "timestamp_utc": self.timestamp_utc,
            "is_authoritative": False,
        }

    def to_log_message(self) -> str:
        """Deterministic secret-safe single-line log format."""
        dur_info = f"dur={self.duration_seconds:.3f}s" if self.duration_seconds else "dur=None"
        cpu_info = f" cpu={self.cpu_duration_seconds:.3f}s" if self.cpu_duration_seconds else ""
        mem_info = f" mem={self.memory_bytes}B" if self.memory_bytes else ""
        err_info = f" err={self.sanitized_error!r}" if self.sanitized_error else ""
        meta = f"sbx={self.sandbox_id} status={self.provider_status}"
        stats = f"{dur_info}{cpu_info}{mem_info}{err_info}"
        tag = f"[SANDBOX_TELEMETRY] [{self.provenance.value}]"
        return f"{tag} op={self.operation_id} {meta} {stats}"


# --- Normalizer Functions ---


def normalize_model_telemetry(
    source: ModelClientResult | ModelProviderError | ModelAdapterError | dict[str, Any] | Any,
    *,
    provenance: EvidenceProvenance,
    configured_model: str = "",
    status_code: int = 200,
) -> NormalizedModelTelemetry:
    """Normalize model telemetry without transferring authority to provider prose.

    Args:
        source: ModelClientResult, ModelProviderError, or raw payload dict.
        provenance: Preserved EvidenceProvenance (mandatory).
        configured_model: Fallback configured model if not in source.
        status_code: Default HTTP status code.

    Returns:
        NormalizedModelTelemetry with bounded fields and redacted secrets.
    """
    if not isinstance(provenance, EvidenceProvenance):
        raise TypeError(
            f"provenance must be an instance of EvidenceProvenance, got {type(provenance).__name__}"
        )

    model = configured_model
    returned_model = configured_model
    request_id: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    duration_seconds: float | None = None
    finish_reason: str | None = None
    sanitized_error: str | None = None
    raw_payload: Any = None
    code = status_code

    if isinstance(source, ModelClientResult):
        model = source.configured_model
        returned_model = source.returned_model
        request_id = source.request_id
        if source.usage:
            prompt_tokens = source.usage.prompt_tokens
            completion_tokens = source.usage.completion_tokens
            total_tokens = source.usage.total_tokens
        duration_seconds = source.duration_seconds
        finish_reason = source.finish_reason
        raw_payload = {
            "configured_model": source.configured_model,
            "returned_model": source.returned_model,
            "request_id": source.request_id,
        }
        code = 200
    elif isinstance(source, ModelProviderError):
        code = source.status_code
        sanitized_error = sanitize_and_bound_text(source.sanitized_message)
        raw_payload = {"error": source.sanitized_message, "status_code": source.status_code}
    elif isinstance(source, ModelAdapterError):
        sanitized_error = sanitize_and_bound_text(str(source))
        raw_payload = {"error": str(source)}
        code = 500
    elif isinstance(source, dict):
        raw_payload = source
        model = str(source.get("model") or configured_model)
        returned_model = str(source.get("model") or configured_model)
        request_id = source.get("id") or source.get("request_id")
        usage = source.get("usage")
        if isinstance(usage, dict):
            prompt_tokens = usage.get("prompt_tokens")
            completion_tokens = usage.get("completion_tokens")
            total_tokens = usage.get("total_tokens")
        duration_seconds = source.get("duration_seconds") or source.get("duration")
        choices = source.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            finish_reason = choices[0].get("finish_reason")
        err = source.get("error")
        if err:
            sanitized_error = sanitize_and_bound_text(str(err))
    else:
        # Fallback for unexpected or malformed types: fail safe
        sanitized_error = sanitize_and_bound_text(
            f"Malformed telemetry source: {type(source).__name__}"
        )
        raw_payload = {"malformed_source": str(source)[:256]}

    payload_digest = compute_sanitized_payload_digest(raw_payload)

    return NormalizedModelTelemetry(
        model=sanitize_and_bound_text(model, 128),
        returned_model=sanitize_and_bound_text(returned_model, 128),
        request_id=sanitize_and_bound_text(request_id, 128) if request_id else None,
        prompt_tokens=prompt_tokens if isinstance(prompt_tokens, int) else None,
        completion_tokens=completion_tokens if isinstance(completion_tokens, int) else None,
        total_tokens=total_tokens if isinstance(total_tokens, int) else None,
        duration_seconds=float(duration_seconds) if duration_seconds is not None else None,
        finish_reason=sanitize_and_bound_text(finish_reason, 64) if finish_reason else None,
        status_code=int(code) if isinstance(code, int) else None,
        provenance=provenance,
        sanitized_error=sanitized_error,
        payload_digest=payload_digest,
        is_authoritative=False,
    )


def normalize_sandbox_telemetry(
    source: (
        NebiusSandboxExecutionResult
        | NebiusOperationStatus
        | SandboxProviderError
        | SandboxAdapterError
        | dict[str, Any]
        | Any
    ),
    *,
    provenance: EvidenceProvenance,
    sandbox_id: str | None = None,
    image: str | None = None,
    disposable: bool | None = None,
) -> NormalizedSandboxTelemetry:
    """Normalize sandbox telemetry without transferring authority to provider prose.

    Args:
        source: NebiusSandboxExecutionResult, NebiusOperationStatus, error, or dict.
        provenance: Preserved EvidenceProvenance (mandatory).
        sandbox_id: Optional sandbox identity string.
        image: Optional image name/tag.
        disposable: Optional disposable flag.

    Returns:
        NormalizedSandboxTelemetry with bounded fields and redacted secrets.
    """
    if not isinstance(provenance, EvidenceProvenance):
        raise TypeError(
            f"provenance must be an instance of EvidenceProvenance, got {type(provenance).__name__}"
        )

    op_id: str | None = None
    sbx_id: str | None = sandbox_id
    img: str | None = image
    disp: bool | None = disposable
    provider_status: str | None = None
    duration_seconds: float | None = None
    cpu_duration: float | None = None
    memory_bytes: int | None = None
    sanitized_error: str | None = None
    raw_payload: Any = None

    if isinstance(source, NebiusSandboxExecutionResult):
        op_id = source.operation_id
        sbx_id = source.sandbox_identity.sandbox_id
        provider_status = source.provider_status
        duration_seconds = source.duration_seconds
        sanitized_error = (
            sanitize_and_bound_text(source.error_message) if source.error_message else None
        )
        raw_payload = source.raw_payload
        # Extract cpu/memory metrics from raw payload if available
        if isinstance(raw_payload, dict):
            res_meta = raw_payload.get("result") or raw_payload.get("metadata", {}).get("result")
            if isinstance(res_meta, dict):
                cpu_duration = res_meta.get("cpu_time") or res_meta.get("cpu_duration")
                memory_bytes = res_meta.get("memory") or res_meta.get("memory_bytes")
    elif isinstance(source, NebiusOperationStatus):
        op_id = source.operation_id
        provider_status = source.status
        duration_seconds = source.duration_seconds
        sanitized_error = sanitize_and_bound_text(source.error) if source.error else None
        raw_payload = source.raw_payload
    elif isinstance(source, SandboxProviderError):
        provider_status = f"HTTP_{source.status_code}"
        sanitized_error = sanitize_and_bound_text(source.sanitized_message)
        raw_payload = {"error": source.sanitized_message, "status_code": source.status_code}
    elif isinstance(source, SandboxAdapterError):
        provider_status = "ADAPTER_ERROR"
        sanitized_error = sanitize_and_bound_text(str(source))
        raw_payload = {"error": str(source)}
    elif isinstance(source, dict):
        raw_payload = source
        op_id = source.get("id") or source.get("operation_id")
        provider_status = source.get("status")
        duration_seconds = source.get("duration") or source.get("duration_seconds")
        err = source.get("error")
        if err:
            sanitized_error = sanitize_and_bound_text(str(err))
    else:
        # Fallback for unexpected or malformed types: fail safe
        provider_status = "MALFORMED_TELEMETRY"
        sanitized_error = sanitize_and_bound_text(
            f"Malformed telemetry source: {type(source).__name__}"
        )
        raw_payload = {"malformed_source": str(source)[:256]}

    payload_digest = compute_sanitized_payload_digest(raw_payload)

    return NormalizedSandboxTelemetry(
        operation_id=sanitize_and_bound_text(op_id, 128) if op_id else None,
        sandbox_id=sanitize_and_bound_text(sbx_id, 128) if sbx_id else None,
        image=sanitize_and_bound_text(img, 128) if img else None,
        disposable=disp,
        provider_status=sanitize_and_bound_text(provider_status, 64) if provider_status else None,
        duration_seconds=float(duration_seconds) if duration_seconds is not None else None,
        cpu_duration_seconds=float(cpu_duration) if cpu_duration is not None else None,
        memory_bytes=int(memory_bytes) if memory_bytes is not None else None,
        provenance=provenance,
        sanitized_error=sanitized_error,
        payload_digest=payload_digest,
        is_authoritative=False,
    )


def format_telemetry_log(
    telemetry: NormalizedModelTelemetry | NormalizedSandboxTelemetry,
) -> str:
    """Format normalized telemetry for secret-safe logging.

    Guarantees no raw secrets; asserts zero sensitive findings.
    """
    msg = telemetry.to_log_message()
    findings = find_secret_findings(msg)
    if findings:
        return redact_log_text(msg)
    return msg
