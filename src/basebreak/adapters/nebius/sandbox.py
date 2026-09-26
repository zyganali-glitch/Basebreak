"""Bounded sandbox adapter for Nebius Token Factory Sandboxes.

Authority:
- Uses proven endpoint: https://api.tokenfactory.nebius.com/sandboxes/v1
- ConTree API v1.0.0 OpenAPI specification
- Live discovery facts frozen in P-01.03, P-01.04, P-01.05
- Operational ceilings frozen in P-04.03 (src/basebreak/security/sandbox_policy.py)
- Execution normalization authority in P-04.05 (src/basebreak/security/normalization.py)
- Zero verdict authority: preserves deterministic execution facts.
- Fail-closed on missing credentials, timeouts, malformed responses.
- Exactly-once transport: no silent retries or retry loops (owned by P-05.05).
- Secret safety: credentials never persisted in results, errors, or reprs.
"""

from __future__ import annotations

import json
import os
import shlex
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.domain.execution import ExecutionCommand, SandboxIdentity
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.security.normalization import (
    NormalizedExecutionRecord,
    normalize_execution_result,
)
from basebreak.security.sandbox_policy import (
    MAX_COMMAND_LENGTH_BYTES,
    MAX_SANDBOX_TIMEOUT_SECONDS,
    MIN_SANDBOX_TIMEOUT_SECONDS,
)
from basebreak.security.secret_policy import (
    find_secret_findings,
    is_sensitive_key,
    redact_log_text,
    validate_no_secrets,
)

from .client import TransportCallable, TransportResponse, default_urllib_transport
from .sandbox_constants import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    DEFAULT_SANDBOX_API_BASE_URL,
    DEFAULT_SANDBOX_IMAGE,
    DEFAULT_SANDBOX_TIMEOUT_SECONDS,
    INSTANCES_PATH,
    OPERATIONS_PATH,
    WHOAMI_PATH,
)

# --- Exceptions ---


class SandboxAdapterError(Exception):
    """Base exception for sandbox adapter failures."""


class SandboxConfigError(SandboxAdapterError):
    """Raised when client configuration or request parameters are invalid."""


class MissingSandboxCredentialError(SandboxConfigError):
    """Raised when the required API credential or project ID is missing."""


class SandboxTransportError(SandboxAdapterError):
    """Raised when transport/network failure prevents completing a request."""


class SandboxTimeoutError(SandboxAdapterError):
    """Raised when an operation times out during execution or polling."""


class SandboxProviderError(SandboxAdapterError):
    """Raised when the provider returns a non-2xx status code or error payload."""

    def __init__(
        self,
        status_code: int,
        sanitized_message: str,
        error_type: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.sanitized_message = sanitized_message
        self.error_type = error_type
        suffix = f" (type: {error_type})" if error_type else ""
        super().__init__(f"Provider error HTTP {status_code}: {sanitized_message}{suffix}")

    def __repr__(self) -> str:
        return (
            f"SandboxProviderError(status_code={self.status_code}, "
            f"sanitized_message={self.sanitized_message!r}, "
            f"error_type={self.error_type!r})"
        )


class SandboxResponseFormatError(SandboxAdapterError):
    """Raised when the provider response is malformed or missing required structure."""


class SandboxLifecycleError(SandboxAdapterError):
    """Raised when an invalid lifecycle state transition or action is attempted."""


# --- Lifecycle States ---


class SandboxLifecycleState(str, Enum):
    """Lifecycle state of a sandbox instance/handle."""

    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    DISPOSED = "DISPOSED"


# --- Configuration ---


@dataclass(frozen=True, slots=True)
class SandboxClientConfig:
    """Bounded configuration for Nebius Token Factory Sandbox client."""

    api_key: str | None = None
    project_id: str | None = None
    api_base_url: str = DEFAULT_SANDBOX_API_BASE_URL
    default_image: str = DEFAULT_SANDBOX_IMAGE
    default_timeout_seconds: int = DEFAULT_SANDBOX_TIMEOUT_SECONDS
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS
    max_poll_seconds: float = float(MAX_SANDBOX_TIMEOUT_SECONDS)

    def __post_init__(self) -> None:
        if not self.api_base_url or not self.api_base_url.strip():
            raise SandboxConfigError("api_base_url must not be empty")
        if "://" in self.api_base_url:
            rem = self.api_base_url.split("://", 1)[1]
            auth = rem.split("/", 1)[0]
            if "@" in auth:
                raise SandboxConfigError("api_base_url must not contain embedded credentials")

        if not (
            MIN_SANDBOX_TIMEOUT_SECONDS
            <= self.default_timeout_seconds
            <= MAX_SANDBOX_TIMEOUT_SECONDS
        ):
            raise SandboxConfigError(
                f"default_timeout_seconds must be between {MIN_SANDBOX_TIMEOUT_SECONDS} "
                f"and {MAX_SANDBOX_TIMEOUT_SECONDS}, got {self.default_timeout_seconds}"
            )

        if self.poll_interval_seconds <= 0:
            raise SandboxConfigError("poll_interval_seconds must be positive")

        if self.max_poll_seconds <= 0:
            raise SandboxConfigError("max_poll_seconds must be positive")

    def __repr__(self) -> str:
        masked_key = "***" if self.api_key else None
        return (
            f"SandboxClientConfig(api_key={masked_key!r}, "
            f"project_id={self.project_id!r}, "
            f"api_base_url={self.api_base_url!r}, "
            f"default_image={self.default_image!r}, "
            f"default_timeout_seconds={self.default_timeout_seconds})"
        )


# --- Handle and Result Records ---


@dataclass(slots=True)
class NebiusSandboxHandle:
    """Stateful handle tracking a sandbox instance lifecycle."""

    sandbox_identity: SandboxIdentity
    image: str
    disposable: bool
    lifecycle_state: SandboxLifecycleState = SandboxLifecycleState.CREATED
    last_operation_id: str | None = None
    result_image_uuid: str | None = None
    created_at_epoch: float = 0.0

    def __post_init__(self) -> None:
        if self.created_at_epoch == 0.0:
            self.created_at_epoch = time.time()

    def __repr__(self) -> str:
        return (
            f"NebiusSandboxHandle(sandbox_id={self.sandbox_identity.sandbox_id!r}, "
            f"image={self.image!r}, "
            f"disposable={self.disposable}, "
            f"state={self.lifecycle_state.value}, "
            f"last_operation_id={self.last_operation_id!r})"
        )


@dataclass(frozen=True, slots=True)
class NebiusOperationStatus:
    """Parsed status of a Nebius Token Factory operation."""

    operation_id: str
    status: str
    error: str | None = None
    exit_code: int | None = None
    duration_seconds: float | None = None
    stdout: str = ""
    stderr: str = ""
    result_image_uuid: str | None = None
    raw_payload: dict[str, Any] | None = None

    @property
    def is_terminal(self) -> bool:
        """True if the operation has reached a terminal status."""
        return self.status in ("SUCCESS", "FAILED", "CANCELLED", "TIMEOUT")


@dataclass(frozen=True, slots=True)
class NebiusSandboxExecutionResult:
    """Deterministic result facts from a Nebius Token Factory sandbox execution.

    Preserves exit code, duration, stdout, and stderr as authoritative facts.
    Provider prose/status metadata is recorded but does not override facts.
    """

    sandbox_identity: SandboxIdentity
    operation_id: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float | None
    result_image_uuid: str | None
    provider_status: str
    error_message: str | None = None
    is_completed: bool = False
    is_timeout: bool = False
    is_cancelled: bool = False
    raw_payload: dict[str, Any] | None = None

    @property
    def stdout_digest(self) -> str:
        """Cryptographic SHA-256 digest of captured stdout."""
        return compute_bytes_digest(self.stdout.encode("utf-8")).value

    @property
    def stderr_digest(self) -> str:
        """Cryptographic SHA-256 digest of captured stderr."""
        return compute_bytes_digest(self.stderr.encode("utf-8")).value

    def to_normalized_record(self) -> NormalizedExecutionRecord:
        """Normalize into provider-neutral NormalizedExecutionRecord using P-04 authority."""
        return normalize_execution_result(
            raw_payload=self.raw_payload,
            stdout=self.stdout,
            stderr=self.stderr,
            exit_code=self.exit_code,
            is_timeout=self.is_timeout,
            is_cancelled=self.is_cancelled,
            is_failed_to_start=(self.exit_code is None and self.provider_status == "FAILED"),
            provider_status=self.provider_status,
            provider_error=self.error_message,
            duration_seconds=self.duration_seconds,
        )

    def __repr__(self) -> str:
        return (
            f"NebiusSandboxExecutionResult(sandbox_id={self.sandbox_identity.sandbox_id!r}, "
            f"operation_id={self.operation_id!r}, "
            f"exit_code={self.exit_code}, "
            f"duration={self.duration_seconds}, "
            f"status={self.provider_status!r})"
        )


# --- NebiusSandboxAdapter ---


class NebiusSandboxAdapter:
    """Bounded adapter for Nebius Token Factory Sandboxes.

    Implements:
    - create_sandbox (session/context preparation)
    - execute_command (POST /instances with bounding and polling)
    - inspect_operation (GET /operations/{id})
    - cancel_operation (POST /operations/{id}/cancel)
    - inspect_whoami (GET /whoami)
    - teardown_sandbox (cancellation and state termination)

    Guarantees:
    - exactly-once transport call per request; no silent retry loops;
    - credentials never persist in logs, errors, or records;
    - provider metadata does not override deterministic execution facts.
    """

    def __init__(
        self,
        config: SandboxClientConfig | None = None,
        transport: TransportCallable | None = None,
    ) -> None:
        self._config = config or SandboxClientConfig()
        self._transport = transport or default_urllib_transport

    @property
    def config(self) -> SandboxClientConfig:
        return self._config

    def _resolve_credentials(self) -> tuple[str, str]:
        """Resolve and validate API key and Project ID at runtime."""
        api_key = self._config.api_key
        if not api_key:
            api_key = os.environ.get("NEBIUS_API_KEY") or os.environ.get("CONTREE_TOKEN")
        if not api_key or not api_key.strip():
            raise MissingSandboxCredentialError(
                "Nebius API key is required but was not provided in config or environment "
                "(checked NEBIUS_API_KEY and CONTREE_TOKEN)."
            )

        project_id = self._config.project_id
        if not project_id:
            project_id = (
                os.environ.get("NEBIUS_PROJECT_ID")
                or os.environ.get("NEBIUS_AI_PROJECT")
                or os.environ.get("CONTREE_PROJECT")
            )
        if not project_id or not project_id.strip():
            raise MissingSandboxCredentialError(
                "Nebius Project ID is required but was not provided in config or environment "
                "(checked NEBIUS_PROJECT_ID, NEBIUS_AI_PROJECT, and CONTREE_PROJECT)."
            )

        return api_key.strip(), project_id.strip()

    def _build_headers(self, api_key: str, project_id: str) -> dict[str, str]:
        """Construct required headers for Token Factory Sandboxes."""
        return {
            "Authorization": f"Bearer {api_key}",
            "Project": project_id,
            "Content-Type": "application/json",
            "User-Agent": "Basebreak-Adapter/0.1",
        }

    def _call_api(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        timeout: float = 30.0,
    ) -> TransportResponse:
        """Execute a single HTTP request without automatic retry."""
        api_key, project_id = self._resolve_credentials()
        url = f"{self._config.api_base_url.rstrip('/')}{path}"
        headers = self._build_headers(api_key, project_id)

        req = urllib.request.Request(
            url=url,
            data=body,
            headers=headers,
            method=method,
        )

        try:
            resp = self._transport(req, timeout)
        except urllib.error.HTTPError as exc:
            raw_body = b""
            try:
                raw_body = exc.read()
            except Exception:
                pass
            sanitized_body = redact_log_text(raw_body.decode("utf-8", errors="replace"))
            status = getattr(exc, "code", 500)
            raise SandboxProviderError(
                status_code=status,
                sanitized_message=sanitized_body or str(exc),
            ) from exc
        except urllib.error.URLError as exc:
            msg = redact_log_text(str(exc))
            raise SandboxTransportError(f"Sandbox transport error: {msg}") from exc
        except TimeoutError as exc:
            raise SandboxTimeoutError(f"Sandbox request timed out after {timeout}s") from exc
        except Exception as exc:
            if isinstance(
                exc,
                (
                    SandboxAdapterError,
                    MissingSandboxCredentialError,
                    SandboxProviderError,
                    SandboxTransportError,
                    SandboxTimeoutError,
                ),
            ):
                raise
            msg = redact_log_text(str(exc))
            raise SandboxTransportError(f"Unexpected transport error: {msg}") from exc

        # Handle non-2xx status from custom transports
        if resp.status_code >= 400:
            sanitized_body = redact_log_text(resp.body.decode("utf-8", errors="replace"))
            raise SandboxProviderError(
                status_code=resp.status_code,
                sanitized_message=sanitized_body,
            )

        return resp

    def create_sandbox(
        self,
        image: str | None = None,
        disposable: bool = True,
        description: str = "",
    ) -> NebiusSandboxHandle:
        """Create a new bounded sandbox handle ready for execution.

        Initializes a unique SandboxIdentity and tracks state. Does not create
        persistent provider compute until command execution occurs.
        """
        chosen_image = image or self._config.default_image
        if not chosen_image or not chosen_image.strip():
            raise SandboxConfigError("Sandbox image must not be empty")

        sandbox_id = f"sbx-{uuid.uuid4().hex[:16]}"
        identity = SandboxIdentity(sandbox_id=sandbox_id, description=description)

        return NebiusSandboxHandle(
            sandbox_identity=identity,
            image=chosen_image.strip(),
            disposable=disposable,
            lifecycle_state=SandboxLifecycleState.CREATED,
        )

    def _normalize_command_string(
        self,
        command: str | ExecutionCommand | Sequence[str],
    ) -> str:
        """Normalize and validate command argument into a bounded shell command string."""
        if isinstance(command, ExecutionCommand):
            if len(command.argv) == 1:
                cmd_str = command.argv[0]
            else:
                cmd_str = shlex.join(command.argv)
            if command.cwd:
                cmd_str = f"cd {shlex.quote(command.cwd)} && {cmd_str}"
        elif isinstance(command, str):
            cmd_str = command
        elif isinstance(command, Sequence) and not isinstance(command, (bytes, bytearray)):
            cmd_str = shlex.join(str(arg) for arg in command)
        else:
            raise SandboxConfigError(f"Unsupported command type: {type(command).__name__}")

        if not cmd_str or not cmd_str.strip():
            raise SandboxConfigError("Command must not be empty")

        if "\x00" in cmd_str:
            raise SandboxConfigError("Command must not contain null bytes")

        cmd_bytes = cmd_str.encode("utf-8")
        if len(cmd_bytes) > MAX_COMMAND_LENGTH_BYTES:
            raise SandboxConfigError(
                f"Command exceeds length budget: {len(cmd_bytes)} bytes "
                f"(max {MAX_COMMAND_LENGTH_BYTES} bytes)"
            )

        return cmd_str

    def _extract_operation_id(self, resp: TransportResponse) -> str:
        """Extract operation ID from Location header or response body."""
        # 1. Location header
        loc = resp.headers.get("Location") or resp.headers.get("location")
        if loc:
            op_id = loc.rstrip("/").split("/")[-1].strip()
            if op_id:
                return op_id

        # 2. JSON response body
        if resp.body:
            try:
                data = json.loads(resp.body.decode("utf-8"))
                if isinstance(data, dict):
                    extracted_id: Any = (
                        data.get("id")
                        or data.get("operation_id")
                        or data.get("uuid")
                        or (
                            data.get("operation", {}).get("id")
                            if isinstance(data.get("operation"), dict)
                            else None
                        )
                    )
                    if extracted_id and isinstance(extracted_id, str) and extracted_id.strip():
                        return extracted_id.strip()
            except Exception:
                pass

        raise SandboxResponseFormatError(
            "Could not extract operation ID from spawn response "
            "(no valid Location header or JSON id)"
        )

    def _parse_stream_output(self, stream_data: Any) -> str:
        """Parse stdout/stderr stream from provider response structure."""
        if stream_data is None:
            return ""
        if isinstance(stream_data, str):
            return stream_data
        if isinstance(stream_data, dict):
            # ConTree format: {"data": "...", "encoding": "ascii", "truncated": false}
            data_val = stream_data.get("data")
            if data_val is not None:
                return str(data_val)
        return str(stream_data)

    def inspect_operation(self, operation_id: str) -> NebiusOperationStatus:
        """Inspect the current status of an operation on Nebius Token Factory.

        Executes exactly one GET request.
        """
        if not operation_id or not operation_id.strip():
            raise SandboxConfigError("operation_id must not be empty")

        clean_op_id = operation_id.strip()
        resp = self._call_api("GET", f"{OPERATIONS_PATH}/{clean_op_id}")

        try:
            payload = json.loads(resp.body.decode("utf-8"))
        except Exception as exc:
            raise SandboxResponseFormatError(
                f"Operation status response is not valid JSON: {exc}"
            ) from exc

        if not isinstance(payload, dict):
            raise SandboxResponseFormatError(
                f"Operation status payload must be a JSON object, got {type(payload).__name__}"
            )

        status = payload.get("status")
        if not status or not isinstance(status, str):
            raise SandboxResponseFormatError(
                f"Operation status payload missing 'status' field: {payload}"
            )

        # Extract result metadata
        result_meta = (
            payload.get("result")
            or payload.get("metadata", {}).get("result")
            or payload.get("metadata")
            or {}
        )
        if not isinstance(result_meta, dict):
            result_meta = {}

        raw_exit = result_meta.get("exit_code")
        exit_code: int | None = None
        if raw_exit is not None:
            try:
                exit_code = int(raw_exit)
            except (ValueError, TypeError):
                exit_code = None

        raw_duration = (
            result_meta.get("duration")
            or result_meta.get("duration_seconds")
            or payload.get("duration")
        )
        duration: float | None = None
        if raw_duration is not None:
            try:
                duration = float(raw_duration)
            except (ValueError, TypeError):
                duration = None

        stdout = self._parse_stream_output(result_meta.get("stdout"))
        stderr = self._parse_stream_output(result_meta.get("stderr"))

        result_image = (
            result_meta.get("result_image_uuid")
            or result_meta.get("image")
            or payload.get("result_image_uuid")
        )
        image_uuid = str(result_image) if result_image else None

        raw_error = payload.get("error") or result_meta.get("error")
        error_msg = redact_log_text(str(raw_error)) if raw_error is not None else None

        return NebiusOperationStatus(
            operation_id=clean_op_id,
            status=status.upper(),
            error=error_msg,
            exit_code=exit_code,
            duration_seconds=duration,
            stdout=stdout,
            stderr=stderr,
            result_image_uuid=image_uuid,
            raw_payload=payload,
        )

    def cancel_operation(self, operation_id: str) -> bool:
        """Cancel an in-flight operation on Nebius Token Factory.

        Executes exactly one POST request.
        """
        if not operation_id or not operation_id.strip():
            raise SandboxConfigError("operation_id must not be empty")

        clean_op_id = operation_id.strip()
        resp = self._call_api("POST", f"{OPERATIONS_PATH}/{clean_op_id}/cancel")
        return resp.status_code in (200, 201, 202, 204)

    def inspect_whoami(self) -> dict[str, Any]:
        """Query sandbox account metadata and active running instances.

        Executes exactly one GET request.
        """
        resp = self._call_api("GET", WHOAMI_PATH)
        try:
            data = json.loads(resp.body.decode("utf-8"))
            if isinstance(data, dict):
                return data
            return {"raw": data}
        except Exception as exc:
            raise SandboxResponseFormatError(f"whoami response is not valid JSON: {exc}") from exc

    def execute_command(
        self,
        sandbox: NebiusSandboxHandle | str,
        command: str | ExecutionCommand | Sequence[str],
        *,
        timeout_seconds: int | None = None,
        disposable: bool | None = None,
        working_dir: str | None = None,
        env: Mapping[str, str] | None = None,
        networking_enabled: bool = True,
    ) -> NebiusSandboxExecutionResult:
        """Spawn and execute a bounded command in a Nebius Token Factory Sandbox.

        Bounds:
        - timeout bounded between 1s and 600s;
        - command validated against length budget and null bytes;
        - env checked against secret leakage;
        - single spawn request; single-pass polling with bounded timeout.
        """
        handle: NebiusSandboxHandle | None = None
        if isinstance(sandbox, NebiusSandboxHandle):
            handle = sandbox
            if handle.lifecycle_state == SandboxLifecycleState.DISPOSED:
                sid = handle.sandbox_identity.sandbox_id
                raise SandboxLifecycleError(f"Cannot execute command on disposed sandbox {sid}")
            target_image = handle.result_image_uuid or handle.image
            is_disposable = handle.disposable if disposable is None else disposable
            identity = handle.sandbox_identity
        elif isinstance(sandbox, str):
            if not sandbox.strip():
                raise SandboxConfigError("Target sandbox image must not be empty")
            target_image = sandbox.strip()
            is_disposable = True if disposable is None else disposable
            identity = SandboxIdentity(sandbox_id=f"sbx-{uuid.uuid4().hex[:16]}")
        else:
            raise SandboxConfigError(f"Unsupported sandbox parameter: {type(sandbox).__name__}")

        # Validate timeout
        effective_timeout = (
            timeout_seconds if timeout_seconds is not None else self._config.default_timeout_seconds
        )
        if not (MIN_SANDBOX_TIMEOUT_SECONDS <= effective_timeout <= MAX_SANDBOX_TIMEOUT_SECONDS):
            raise SandboxConfigError(
                f"timeout_seconds must be between {MIN_SANDBOX_TIMEOUT_SECONDS} "
                f"and {MAX_SANDBOX_TIMEOUT_SECONDS}, got {effective_timeout}"
            )

        # Normalize and validate command string
        cmd_str = self._normalize_command_string(command)

        # Handle working directory and env from ExecutionCommand if present
        if isinstance(command, ExecutionCommand):
            if working_dir is None and command.cwd:
                working_dir = command.cwd
            if env is None and command.env:
                env = dict(command.env)

        # Validate environment against secret leakage
        env_dict: dict[str, str] = {}
        if env:
            for k, v in env.items():
                if is_sensitive_key(k):
                    findings = find_secret_findings(v)
                    rule_id = findings[0].rule_id if findings else "SENSITIVE_KEY"
                    raise SandboxConfigError(
                        f"Secret-shaped or sensitive key forbidden in sandbox env: {k!r} "
                        f"(rule: {rule_id})"
                    )
            validate_no_secrets(dict(env), path="sandbox_env")
            env_dict = {str(k): str(v) for k, v in env.items()}

        # Construct request payload
        payload: dict[str, Any] = {
            "image": target_image,
            "command": cmd_str,
            "shell": True,
            "disposable": is_disposable,
            "timeout": effective_timeout,
        }
        if working_dir:
            payload["working_dir"] = working_dir
        if env_dict:
            payload["env"] = env_dict
        if not networking_enabled:
            payload["networking"] = {"enabled": False}
        else:
            payload["networking"] = {"enabled": True}

        # Transition handle to RUNNING
        if handle:
            handle.lifecycle_state = SandboxLifecycleState.RUNNING

        body_bytes = json.dumps(payload).encode("utf-8")

        # Spawn instance (exactly once)
        spawn_resp = self._call_api("POST", INSTANCES_PATH, body=body_bytes)
        operation_id = self._extract_operation_id(spawn_resp)

        if handle:
            handle.last_operation_id = operation_id

        # Poll operation until terminal status or client timeout
        start_time = time.time()
        max_duration = float(effective_timeout) + 10.0  # 10s grace period for VM spinup/teardown
        final_status: NebiusOperationStatus | None = None

        while True:
            status = self.inspect_operation(operation_id)
            if status.is_terminal:
                final_status = status
                break

            elapsed = time.time() - start_time
            if elapsed > max_duration:
                # Timed out client-side: cancel in-flight operation
                try:
                    self.cancel_operation(operation_id)
                except Exception:
                    pass
                if handle:
                    handle.lifecycle_state = SandboxLifecycleState.FAILED
                raise SandboxTimeoutError(
                    f"Sandbox operation {operation_id} timed out after {elapsed:.1f}s "
                    f"(budget: {effective_timeout}s)"
                )

            time.sleep(self._config.poll_interval_seconds)

        # Update handle state
        if handle:
            if final_status.status == "SUCCESS":
                handle.lifecycle_state = SandboxLifecycleState.COMPLETED
                if final_status.result_image_uuid:
                    handle.result_image_uuid = final_status.result_image_uuid
            else:
                handle.lifecycle_state = SandboxLifecycleState.FAILED

        # Build execution result preserving deterministic facts
        is_completed = final_status.exit_code is not None
        is_timeout = final_status.status == "TIMEOUT"
        is_cancelled = final_status.status == "CANCELLED"

        return NebiusSandboxExecutionResult(
            sandbox_identity=identity,
            operation_id=operation_id,
            exit_code=final_status.exit_code,
            stdout=final_status.stdout,
            stderr=final_status.stderr,
            duration_seconds=final_status.duration_seconds,
            result_image_uuid=final_status.result_image_uuid,
            provider_status=final_status.status,
            error_message=final_status.error,
            is_completed=is_completed,
            is_timeout=is_timeout,
            is_cancelled=is_cancelled,
            raw_payload=final_status.raw_payload,
        )

    def teardown_sandbox(
        self,
        handle: NebiusSandboxHandle,
        *,
        verify_whoami: bool = False,
    ) -> None:
        """Teardown and dispose a sandbox handle.

        Cancels any in-flight operation and transitions lifecycle state to DISPOSED.
        Subsequent execution commands on this handle will fail closed.
        """
        if handle.lifecycle_state == SandboxLifecycleState.DISPOSED:
            return

        # Cancel in-flight operation if running
        if handle.lifecycle_state == SandboxLifecycleState.RUNNING and handle.last_operation_id:
            try:
                self.cancel_operation(handle.last_operation_id)
            except Exception:
                pass

        handle.lifecycle_state = SandboxLifecycleState.DISPOSED

        # Optionally inspect whoami to observe zero running instances
        if verify_whoami:
            try:
                self.inspect_whoami()
            except Exception:
                pass
