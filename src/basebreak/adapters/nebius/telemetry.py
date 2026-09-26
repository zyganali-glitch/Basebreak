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
import math
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
MAX_TELEMETRY_DEPTH: int = 8
MAX_COLLECTION_ITEMS: int = 128
MAX_TOTAL_NODES: int = 512

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


def _safe_object_to_str(obj: Any, max_len: int = 256) -> str:
    """Safely extract string representation from arbitrary objects without raising."""
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj[:max_len]
    try:
        raw = str(obj)
    except Exception:
        try:
            raw = repr(obj)
        except Exception:
            return f"<{type(obj).__name__}: unstringable>"
    return raw[:max_len]


def _safe_object_to_sanitized_text(
    obj: Any,
    max_bytes: int = MAX_TELEMETRY_STRING_BYTES,
) -> str:
    """Safely convert an arbitrary object to a secret-redacted, bounded text string."""
    if obj is None:
        return ""
    if isinstance(obj, str):
        return sanitize_and_bound_text(obj, max_bytes=max_bytes)

    raw: str
    try:
        raw = str(obj)
    except Exception:
        try:
            raw = repr(obj)
        except Exception:
            return f"<{type(obj).__name__}: unstringable>"

    return sanitize_and_bound_text(raw, max_bytes=max_bytes)


def sanitize_and_bound_text(
    text: Any,
    max_bytes: int = MAX_TELEMETRY_STRING_BYTES,
) -> str:
    """Sanitize secrets from text and bound its byte length safely.

    Guarantees:
    - Never raises on unstringable objects or non-string inputs.
    - All synthetic secrets are redacted before retention.
    - Output length is strictly bounded to max_bytes (plus truncation note if truncated).
    - Prevents ReDoS/unbounded scanning on megabyte-scale text.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = _safe_object_to_str(text, max_len=max_bytes * 2)

    encoded = text.encode("utf-8")
    original_len = len(encoded)
    if original_len <= max_bytes:
        return redact_log_text(text)

    # To prevent ReDoS / memory explosion on huge strings,
    # slice the prefix before regex scanning, keeping enough margin to avoid clipping tokens
    prefix_bytes = encoded[: max_bytes + 256]
    prefix_str = prefix_bytes.decode("utf-8", errors="ignore")
    redacted_prefix = redact_log_text(prefix_str)

    redacted_bytes = redacted_prefix.encode("utf-8")
    truncated = redacted_bytes[:max_bytes].decode("utf-8", errors="ignore")
    excess_bytes = original_len - max_bytes
    return f"{truncated}... [TRUNCATED {excess_bytes} B]"


class _SanitizationContext:
    __slots__ = ("is_truncated", "max_bytes", "total_nodes", "visited_ids")

    def __init__(self, max_bytes: int = MAX_PAYLOAD_DIGEST_BYTES) -> None:
        self.max_bytes = max_bytes
        self.is_truncated = False
        self.total_nodes = 0
        self.visited_ids: set[int] = set()

    def check_node_budget(self) -> bool:
        """Returns True if within node budget, False if budget exceeded."""
        self.total_nodes += 1
        if self.total_nodes > MAX_TOTAL_NODES:
            self.is_truncated = True
            return False
        return True


def _sanitize_value(
    ctx: _SanitizationContext,
    data: Any,
    depth: int = 0,
) -> Any:
    """Recursively sanitize and bound an arbitrary data structure."""
    if not ctx.check_node_budget():
        return "[PAYLOAD_NODE_LIMIT_EXCEEDED]"

    if depth > MAX_TELEMETRY_DEPTH:
        ctx.is_truncated = True
        return "[MAX_DEPTH_EXCEEDED]"

    if data is None:
        return None

    if isinstance(data, bool):
        return data

    if isinstance(data, int):
        return data

    if isinstance(data, float):
        if math.isnan(data):
            return "NaN"
        if math.isinf(data):
            return "Infinity" if data > 0 else "-Infinity"
        return data

    if isinstance(data, str):
        encoded = data.encode("utf-8")
        if len(encoded) > MAX_TELEMETRY_STRING_BYTES:
            ctx.is_truncated = True
            return sanitize_and_bound_text(data, max_bytes=MAX_TELEMETRY_STRING_BYTES)
        return redact_log_text(data)

    if isinstance(data, (bytes, bytearray)):
        ctx.is_truncated = True
        return f"<bytes: len={len(data)}>"

    if isinstance(data, dict):
        obj_id = id(data)
        if obj_id in ctx.visited_ids:
            ctx.is_truncated = True
            return "[CIRCULAR_REFERENCE]"
        ctx.visited_ids.add(obj_id)
        try:
            clean_dict: dict[str, Any] = {}
            items_to_sort: list[tuple[str, Any]] = []
            for k, v in data.items():
                safe_k = _safe_object_to_sanitized_text(k, max_bytes=128)
                items_to_sort.append((safe_k, v))
            items_to_sort.sort(key=lambda x: x[0])

            if len(items_to_sort) > MAX_COLLECTION_ITEMS:
                ctx.is_truncated = True
                omitted_count = len(items_to_sort) - MAX_COLLECTION_ITEMS
                items_to_sort = items_to_sort[:MAX_COLLECTION_ITEMS]
                truncated_marker = f"[{omitted_count} keys omitted]"
            else:
                truncated_marker = None

            for safe_k, v in items_to_sort:
                if not ctx.check_node_budget():
                    clean_dict["[TRUNCATED_KEYS]"] = "[NODE_LIMIT_EXCEEDED]"
                    break
                if _is_sensitive_field(safe_k):
                    clean_dict[safe_k] = "[REDACTED_CREDENTIAL]"
                else:
                    clean_dict[safe_k] = _sanitize_value(ctx, v, depth + 1)

            if truncated_marker is not None:
                clean_dict["[TRUNCATED_KEYS]"] = truncated_marker

            return clean_dict
        finally:
            ctx.visited_ids.remove(obj_id)

    if isinstance(data, (list, tuple, set, frozenset)):
        obj_id = id(data)
        if obj_id in ctx.visited_ids:
            ctx.is_truncated = True
            return "[CIRCULAR_REFERENCE]"
        ctx.visited_ids.add(obj_id)
        try:
            clean_list: list[Any] = []
            raw_items = list(data)
            if len(raw_items) > MAX_COLLECTION_ITEMS:
                ctx.is_truncated = True
                omitted_count = len(raw_items) - MAX_COLLECTION_ITEMS
                raw_items = raw_items[:MAX_COLLECTION_ITEMS]
                marker = f"[TRUNCATED_ITEMS: {omitted_count} omitted]"
            else:
                marker = None

            for item in raw_items:
                if not ctx.check_node_budget():
                    clean_list.append("[NODE_LIMIT_EXCEEDED]")
                    break
                clean_list.append(_sanitize_value(ctx, item, depth + 1))

            if marker is not None:
                clean_list.append(marker)

            return clean_list
        finally:
            ctx.visited_ids.remove(obj_id)

    # Fallback for custom / arbitrary object
    ctx.is_truncated = True
    return _safe_object_to_sanitized_text(data, max_bytes=MAX_TELEMETRY_STRING_BYTES)


@dataclass(frozen=True, slots=True)
class SanitizedPayloadDigest:
    """Result of computing a sanitized, bounded payload digest.

    Attributes:
        digest: 64-char lowercase hex SHA-256 digest of bounded canonical bytes (or "" if None).
        is_truncated: True if payload was truncated during bounding or serialization.
        byte_count: Number of bytes digested.
    """

    digest: str
    is_truncated: bool
    byte_count: int = 0

    def __iter__(self) -> Any:
        return iter((self.digest, self.is_truncated))

    def __str__(self) -> str:
        return self.digest

    def __bool__(self) -> bool:
        return bool(self.digest)


def sanitize_payload(
    raw_payload: Any,
    max_bytes: int = MAX_PAYLOAD_DIGEST_BYTES,
) -> tuple[Any, bool]:
    """Recursively sanitize sensitive keys/values and bound payload structures.

    Returns:
        (sanitized_bounded_data, is_truncated)
    """
    if raw_payload is None:
        return None, False
    ctx = _SanitizationContext(max_bytes=max_bytes)
    sanitized = _sanitize_value(ctx, raw_payload, depth=0)
    return sanitized, ctx.is_truncated


def compute_sanitized_payload_digest(
    raw_payload: Any,
    max_bytes: int = MAX_PAYLOAD_DIGEST_BYTES,
) -> SanitizedPayloadDigest:
    """Compute content-addressed SHA-256 digest of sanitized, bounded payload.

    Enforces MAX_PAYLOAD_DIGEST_BYTES and structural bounding (depth, collection sizes,
    string lengths, node counts). If the payload exceeds limits or requires truncation,
    is_truncated is set to True and the digest is computed strictly over the bounded representation.
    """
    if raw_payload is None:
        return SanitizedPayloadDigest(digest="", is_truncated=False, byte_count=0)

    ctx = _SanitizationContext(max_bytes=max_bytes)
    sanitized = _sanitize_value(ctx, raw_payload, depth=0)
    is_truncated = ctx.is_truncated

    try:
        json_bytes = canonical_json_bytes(sanitized)
    except Exception:
        fallback_str = _safe_object_to_sanitized_text(sanitized, max_bytes=max_bytes)
        json_bytes = fallback_str.encode("utf-8")
        is_truncated = True

    if len(json_bytes) > max_bytes:
        is_truncated = True
        json_bytes = json_bytes[:max_bytes]

    digest = compute_bytes_digest(json_bytes).value
    return SanitizedPayloadDigest(
        digest=digest,
        is_truncated=is_truncated,
        byte_count=len(json_bytes),
    )


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
    payload_truncated: bool = False
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
            "payload_truncated": self.payload_truncated,
            "timestamp_utc": self.timestamp_utc,
            "is_authoritative": False,
        }

    def to_log_message(self) -> str:
        """Deterministic secret-safe single-line log format."""
        tokens_info = f"tokens={self.prompt_tokens}+{self.completion_tokens}={self.total_tokens}"
        dur_info = f"lat={self.duration_seconds:.3f}s" if self.duration_seconds else "lat=None"
        err_info = f" err={self.sanitized_error!r}" if self.sanitized_error else ""
        trunc_info = " [PAYLOAD_TRUNCATED]" if self.payload_truncated else ""
        return (
            f"[MODEL_TELEMETRY] [{self.provenance.value}] model={self.returned_model} "
            f"req_id={self.request_id} {tokens_info} {dur_info}{err_info}{trunc_info}"
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
    payload_truncated: bool = False
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
            "payload_truncated": self.payload_truncated,
            "timestamp_utc": self.timestamp_utc,
            "is_authoritative": False,
        }

    def to_log_message(self) -> str:
        """Deterministic secret-safe single-line log format."""
        dur_info = f"dur={self.duration_seconds:.3f}s" if self.duration_seconds else "dur=None"
        cpu_info = f" cpu={self.cpu_duration_seconds:.3f}s" if self.cpu_duration_seconds else ""
        mem_info = f" mem={self.memory_bytes}B" if self.memory_bytes else ""
        err_info = f" err={self.sanitized_error!r}" if self.sanitized_error else ""
        trunc_info = " [PAYLOAD_TRUNCATED]" if self.payload_truncated else ""
        meta = f"sbx={self.sandbox_id} status={self.provider_status}"
        stats = f"{dur_info}{cpu_info}{mem_info}{err_info}{trunc_info}"
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
        raw_payload = {"error": sanitized_error}
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
            sanitized_error = sanitize_and_bound_text(err)
    else:
        # Fallback for unexpected or malformed types: fail safe
        safe_type = sanitize_and_bound_text(type(source).__name__, 64)
        sanitized_error = f"Malformed telemetry source: {safe_type}"
        safe_source_repr = sanitize_and_bound_text(
            _safe_object_to_str(source, max_len=256), max_bytes=256
        )
        raw_payload = {"malformed_source": safe_source_repr}

    digest_info = compute_sanitized_payload_digest(raw_payload)

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
        payload_digest=digest_info.digest,
        payload_truncated=digest_info.is_truncated,
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
        raw_payload = {"error": sanitized_error}
    elif isinstance(source, dict):
        raw_payload = source
        op_id = source.get("id") or source.get("operation_id")
        provider_status = source.get("status")
        duration_seconds = source.get("duration") or source.get("duration_seconds")
        err = source.get("error")
        if err:
            sanitized_error = sanitize_and_bound_text(err)
    else:
        # Fallback for unexpected or malformed types: fail safe
        provider_status = "MALFORMED_TELEMETRY"
        safe_type = sanitize_and_bound_text(type(source).__name__, 64)
        sanitized_error = f"Malformed telemetry source: {safe_type}"
        safe_source_repr = sanitize_and_bound_text(
            _safe_object_to_str(source, max_len=256), max_bytes=256
        )
        raw_payload = {"malformed_source": safe_source_repr}

    digest_info = compute_sanitized_payload_digest(raw_payload)

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
        payload_digest=digest_info.digest,
        payload_truncated=digest_info.is_truncated,
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
