"""Bounded model client for Nebius Token Factory chat completions.

Authority:
- Uses proven endpoint: https://api.tokenfactory.nebius.com/v1/chat/completions
- Primary live-proven model: nvidia/Nemotron-3_5-Lightning
- Zero verdict authority: returns pure model output as ModelClientResult.
- Fail-closed on missing credentials, timeouts, malformed responses, model mismatch.
- Single attempt: no automatic retries (owned by P-05.05).
- Secret safety: credentials never persisted in results, errors, or reprs.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from basebreak.security.secret_policy import redact_log_text

from .models import (
    CHAT_COMPLETIONS_PATH,
    DEFAULT_API_BASE_URL,
    DEFAULT_MAX_TOKENS,
    DEFAULT_PRIMARY_MODEL,
    DEFAULT_TEMPERATURE,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_MAX_TOKENS,
    MAX_PROMPT_CHARACTERS,
    MAX_RESPONSE_CHARACTERS,
    MAX_TEMPERATURE,
    MAX_TIMEOUT_SECONDS,
    MIN_MAX_TOKENS,
    MIN_TEMPERATURE,
    MIN_TIMEOUT_SECONDS,
)

# --- Exceptions ---


class ModelAdapterError(Exception):
    """Base exception for model adapter failures."""


class ModelConfigError(ModelAdapterError):
    """Raised when client configuration or request parameters are invalid."""


class MissingCredentialError(ModelConfigError):
    """Raised when the required API credential is not available."""


class ModelTimeoutError(ModelAdapterError):
    """Raised when the model HTTP request times out."""


class ModelNetworkError(ModelAdapterError):
    """Raised when transport/network failure prevents completing the request."""


class ModelProviderError(ModelAdapterError):
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
            f"ModelProviderError(status_code={self.status_code}, "
            f"sanitized_message={self.sanitized_message!r}, "
            f"error_type={self.error_type!r})"
        )


class ModelResponseFormatError(ModelAdapterError):
    """Raised when the provider response is malformed or missing required structure."""


class ModelIdentityMismatchError(ModelAdapterError):
    """Raised when provider returns a model identifier different from the configured model."""

    def __init__(self, configured_model: str, returned_model: str) -> None:
        self.configured_model = configured_model
        self.returned_model = returned_model
        super().__init__(
            f"Model identity mismatch: requested '{configured_model}' "
            f"but provider returned '{returned_model}'"
        )

    def __repr__(self) -> str:
        return (
            f"ModelIdentityMismatchError(configured_model={self.configured_model!r}, "
            f"returned_model={self.returned_model!r})"
        )


# --- Data Structures ---


@dataclass(frozen=True, slots=True)
class ChatMessage:
    """A single chat completion message."""

    role: str
    content: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, str) or not self.role.strip():
            raise ModelConfigError("ChatMessage role must be a non-empty string")
        if not isinstance(self.content, str):
            raise ModelConfigError("ChatMessage content must be a string")

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Token usage metrics reported by the provider."""

    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


@dataclass(frozen=True, slots=True)
class ModelClientConfig:
    """Configuration and explicit bounds for the Nebius Token Factory model client."""

    api_key: str | None = None
    api_base_url: str = DEFAULT_API_BASE_URL
    model: str = DEFAULT_PRIMARY_MODEL
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_tokens: int = DEFAULT_MAX_TOKENS
    temperature: float = DEFAULT_TEMPERATURE
    max_prompt_characters: int = MAX_PROMPT_CHARACTERS
    max_response_characters: int = MAX_RESPONSE_CHARACTERS
    env_var_name: str = "NEBIUS_API_KEY"

    def __post_init__(self) -> None:
        if not isinstance(self.model, str) or not self.model.strip():
            raise ModelConfigError("Model identifier must be a non-empty string")
        if not isinstance(self.api_base_url, str) or not (
            self.api_base_url.startswith("http://") or self.api_base_url.startswith("https://")
        ):
            raise ModelConfigError("api_base_url must start with http:// or https://")
        if not (MIN_TIMEOUT_SECONDS <= self.timeout_seconds <= MAX_TIMEOUT_SECONDS):
            raise ModelConfigError(
                f"timeout_seconds must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}, "
                f"got {self.timeout_seconds}"
            )
        if not (MIN_MAX_TOKENS <= self.max_tokens <= MAX_MAX_TOKENS):
            raise ModelConfigError(
                f"max_tokens must be between {MIN_MAX_TOKENS} and {MAX_MAX_TOKENS}, "
                f"got {self.max_tokens}"
            )
        if not (MIN_TEMPERATURE <= self.temperature <= MAX_TEMPERATURE):
            raise ModelConfigError(
                f"temperature must be between {MIN_TEMPERATURE} and {MAX_TEMPERATURE}, "
                f"got {self.temperature}"
            )
        if self.max_prompt_characters <= 0:
            raise ModelConfigError("max_prompt_characters must be positive")
        if self.max_response_characters <= 0:
            raise ModelConfigError("max_response_characters must be positive")

    def __repr__(self) -> str:
        key_repr = "[CONFIGURED]" if self.api_key else "[NOT_SET]"
        return (
            f"ModelClientConfig(model={self.model!r}, "
            f"api_base_url={self.api_base_url!r}, "
            f"timeout_seconds={self.timeout_seconds}, "
            f"max_tokens={self.max_tokens}, "
            f"temperature={self.temperature}, "
            f"api_key={key_repr!r})"
        )


@dataclass(frozen=True, slots=True)
class ModelClientResult:
    """Bounded, typed result of a model completion call.

    Contains pure model output and execution metadata.
    Contains ZERO verdict authority or causal verification logic.
    """

    configured_model: str
    returned_model: str
    content: str
    finish_reason: str | None
    request_id: str | None
    usage: TokenUsage | None
    duration_seconds: float
    raw_status: str = "COMPLETED"

    def __repr__(self) -> str:
        content_preview = self.content[:60] + "..." if len(self.content) > 60 else self.content
        return (
            f"ModelClientResult(configured_model={self.configured_model!r}, "
            f"returned_model={self.returned_model!r}, "
            f"finish_reason={self.finish_reason!r}, "
            f"request_id={self.request_id!r}, "
            f"duration_seconds={self.duration_seconds:.3f}, "
            f"content_length={len(self.content)}, "
            f"preview={content_preview!r})"
        )


# --- Transport Abstraction ---


@dataclass(frozen=True, slots=True)
class TransportResponse:
    """Raw HTTP transport response."""

    status_code: int
    body: bytes
    headers: dict[str, str]


TransportCallable = Callable[[urllib.request.Request, float], TransportResponse]


def default_urllib_transport(request: urllib.request.Request, timeout: float) -> TransportResponse:
    """Minimal deterministic HTTP transport using standard library urllib."""
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            status_code = int(response.getcode())
            headers = {k: v for k, v in response.headers.items()}
            return TransportResponse(status_code=status_code, body=body, headers=headers)
    except urllib.error.HTTPError as exc:
        body = exc.read()
        headers = {k: v for k, v in exc.headers.items()}
        return TransportResponse(status_code=int(exc.code), body=body, headers=headers)
    except urllib.error.URLError as exc:
        reason_str = str(exc.reason).lower()
        if isinstance(exc.reason, TimeoutError) or "timed out" in reason_str:
            raise ModelTimeoutError(f"Model request timed out after {timeout}s") from exc
        raise ModelNetworkError(
            f"Model request network failure: {redact_log_text(str(exc.reason))}"
        ) from exc
    except TimeoutError as exc:
        raise ModelTimeoutError(f"Model request timed out after {timeout}s") from exc
    except Exception as exc:
        raise ModelNetworkError(f"Transport failure: {redact_log_text(str(exc))}") from exc


# --- Model Client ---


class NebiusModelClient:
    """Bounded model client for Nebius Token Factory chat completions.

    Strictly bounds:
    - single attempt (ONE request, no retry);
    - timeout passed to transport;
    - token and temperature limits;
    - prompt and response character bounds;
    - runtime-only credential handling (never leaked);
    - exact model identity verification;
    - typed error classification;
    - returns ModelClientResult with zero causal verdict logic.
    """

    def __init__(
        self,
        config: ModelClientConfig | None = None,
        transport: TransportCallable | None = None,
    ) -> None:
        self.config = config or ModelClientConfig()
        self._transport = transport or default_urllib_transport

    def __repr__(self) -> str:
        return (
            f"NebiusModelClient(model={self.config.model!r}, "
            f"api_base_url={self.config.api_base_url!r})"
        )

    def _resolve_api_key(self) -> str:
        key = self.config.api_key or os.environ.get(self.config.env_var_name)
        if not key or not key.strip():
            raise MissingCredentialError(
                f"Missing API credential: environment variable '{self.config.env_var_name}' "
                "is not set or empty"
            )
        return key.strip()

    def complete(
        self,
        messages: list[ChatMessage | dict[str, str]],
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> ModelClientResult:
        """Execute exactly ONE bounded chat completion request.

        No automatic retries. Missing credential fails closed.
        """
        api_key = self._resolve_api_key()

        if not messages:
            raise ModelConfigError("Messages list must not be empty")

        normalized_messages: list[ChatMessage] = []
        for i, msg in enumerate(messages):
            if isinstance(msg, ChatMessage):
                normalized_messages.append(msg)
            elif isinstance(msg, dict):
                role = msg.get("role")
                content = msg.get("content")
                if not isinstance(role, str) or not isinstance(content, str):
                    raise ModelConfigError(
                        f"Message at index {i} must have str 'role' and 'content'"
                    )
                normalized_messages.append(ChatMessage(role=role, content=content))
            else:
                raise ModelConfigError(f"Message at index {i} must be ChatMessage or dict")

        total_prompt_chars = sum(len(m.content) for m in normalized_messages)
        if total_prompt_chars > self.config.max_prompt_characters:
            raise ModelConfigError(
                f"Total prompt characters ({total_prompt_chars}) exceeds limit "
                f"({self.config.max_prompt_characters})"
            )

        eff_max_tokens = max_tokens if max_tokens is not None else self.config.max_tokens
        if not (MIN_MAX_TOKENS <= eff_max_tokens <= MAX_MAX_TOKENS):
            raise ModelConfigError(
                f"max_tokens must be between {MIN_MAX_TOKENS} and {MAX_MAX_TOKENS}, "
                f"got {eff_max_tokens}"
            )

        eff_temperature = temperature if temperature is not None else self.config.temperature
        if not (MIN_TEMPERATURE <= eff_temperature <= MAX_TEMPERATURE):
            raise ModelConfigError(
                f"temperature must be between {MIN_TEMPERATURE} and {MAX_TEMPERATURE}, "
                f"got {eff_temperature}"
            )

        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": [m.to_dict() for m in normalized_messages],
            "max_tokens": eff_max_tokens,
            "temperature": eff_temperature,
        }

        payload_bytes = json.dumps(payload).encode("utf-8")
        url = f"{self.config.api_base_url.rstrip('/')}{CHAT_COMPLETIONS_PATH}"

        request = urllib.request.Request(
            url,
            data=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "Basebreak/0.1.0",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )

        start_time = time.monotonic()
        try:
            response = self._transport(request, self.config.timeout_seconds)
        except ModelAdapterError:
            raise
        except TimeoutError as exc:
            raise ModelTimeoutError(
                f"Model request timed out after {self.config.timeout_seconds}s"
            ) from exc
        except Exception as exc:
            raise ModelNetworkError(f"Transport failure: {redact_log_text(str(exc))}") from exc

        elapsed = time.monotonic() - start_time

        if response.status_code != 200:
            sanitized_msg = self._extract_error_message(response.body, response.status_code)
            error_type = self._extract_error_type(response.body)
            raise ModelProviderError(
                status_code=response.status_code,
                sanitized_message=sanitized_msg,
                error_type=error_type,
            )

        try:
            data = json.loads(response.body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ModelResponseFormatError(f"Model response is not valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ModelResponseFormatError("Model response root must be a JSON object")

        choices = data.get("choices")
        if not isinstance(choices, list) or len(choices) == 0:
            raise ModelResponseFormatError(
                "Model response missing required 'choices' array or choices is empty"
            )

        choice = choices[0]
        if not isinstance(choice, dict):
            raise ModelResponseFormatError("Model response choice item must be an object")

        message = choice.get("message")
        if not isinstance(message, dict):
            raise ModelResponseFormatError(
                "Model response choice missing required 'message' object"
            )

        content = message.get("content")
        if not isinstance(content, str):
            raise ModelResponseFormatError("Model response message missing 'content' string field")

        if len(content) > self.config.max_response_characters:
            content = content[: self.config.max_response_characters]

        returned_model = data.get("model")
        if not isinstance(returned_model, str) or not returned_model.strip():
            raise ModelResponseFormatError("Model response missing required 'model' string field")

        if returned_model != self.config.model:
            raise ModelIdentityMismatchError(
                configured_model=self.config.model,
                returned_model=returned_model,
            )

        finish_reason = choice.get("finish_reason")
        if finish_reason is not None and not isinstance(finish_reason, str):
            finish_reason = str(finish_reason)

        request_id = data.get("id")
        if request_id is not None and not isinstance(request_id, str):
            request_id = str(request_id)

        usage = None
        usage_data = data.get("usage")
        if isinstance(usage_data, dict):
            usage = TokenUsage(
                prompt_tokens=int(usage_data.get("prompt_tokens", 0)),
                completion_tokens=int(usage_data.get("completion_tokens", 0)),
                total_tokens=int(usage_data.get("total_tokens", 0)),
            )

        return ModelClientResult(
            configured_model=self.config.model,
            returned_model=returned_model,
            content=content,
            finish_reason=finish_reason,
            request_id=request_id,
            usage=usage,
            duration_seconds=elapsed,
        )

    def _extract_error_message(self, body: bytes, status_code: int) -> str:
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            if isinstance(data, dict):
                err = data.get("error")
                if isinstance(err, dict) and "message" in err:
                    return redact_log_text(str(err["message"]))
                if isinstance(err, str):
                    return redact_log_text(err)
                if "message" in data:
                    return redact_log_text(str(data["message"]))
        except Exception:
            pass
        raw_snippet = body[:200].decode("utf-8", errors="replace").strip()
        return redact_log_text(raw_snippet or f"HTTP {status_code}")

    def _extract_error_type(self, body: bytes) -> str | None:
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            if isinstance(data, dict):
                err = data.get("error")
                if isinstance(err, dict) and "type" in err and isinstance(err["type"], str):
                    return redact_log_text(err["type"])
        except Exception:
            pass
        return None
