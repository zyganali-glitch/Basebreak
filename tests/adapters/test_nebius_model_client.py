"""Deterministic unit tests for Nebius Token Factory bounded model client.

Provenance: FIXTURE / LOCAL_EXECUTION.
Validates all requirements of P-05.01 without requiring live Nebius network credentials.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

import pytest

from basebreak.adapters.nebius import (
    CANDIDATE_DEEP_MODEL,
    CHAT_COMPLETIONS_PATH,
    DEFAULT_API_BASE_URL,
    DEFAULT_PRIMARY_MODEL,
    MAX_MAX_TOKENS,
    MAX_TEMPERATURE,
    ChatMessage,
    MissingCredentialError,
    ModelClientConfig,
    ModelClientResult,
    ModelConfigError,
    ModelIdentityMismatchError,
    ModelProviderError,
    ModelResponseFormatError,
    ModelTimeoutError,
    ModelTruncatedResponseError,
    NebiusModelClient,
    TokenUsage,
    TransportResponse,
)


def _make_success_body(
    content: str = "BASEBREAK_LIVE_OK",
    model: str = DEFAULT_PRIMARY_MODEL,
    finish_reason: str = "stop",
    request_id: str = "req-12345",
    usage: dict[str, int] | None = None,
) -> bytes:
    payload: dict[str, Any] = {
        "id": request_id,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": finish_reason,
            }
        ],
    }
    if usage is not None:
        payload["usage"] = usage
    else:
        payload["usage"] = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    return json.dumps(payload).encode("utf-8")


class TestNebiusModelClient:
    """Test suite for P-05.01 bounded model client."""

    @pytest.fixture(autouse=True)
    def _set_project_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEBIUS_PROJECT_ID", "proj-123")

    # 1. exact default model is nvidia/Nemotron-3_5-Lightning
    def test_exact_default_model(self) -> None:
        assert DEFAULT_PRIMARY_MODEL == "nvidia/Nemotron-3_5-Lightning"
        config = ModelClientConfig()
        assert config.model == "nvidia/Nemotron-3_5-Lightning"
        client = NebiusModelClient()
        assert client.config.model == "nvidia/Nemotron-3_5-Lightning"

    # Candidate deep model is defined but not default
    def test_candidate_deep_model_not_default(self) -> None:
        assert CANDIDATE_DEEP_MODEL == "nvidia/nemotron-3-super-120b-a12b"
        config = ModelClientConfig()
        assert config.model != CANDIDATE_DEEP_MODEL

    # 2. exact Token Factory API base/endpoint construction
    def test_api_base_and_endpoint_construction(self) -> None:
        assert DEFAULT_API_BASE_URL == "https://api.tokenfactory.nebius.com/v1"
        assert CHAT_COMPLETIONS_PATH == "/chat/completions"

        captured_request: list[urllib.request.Request] = []

        def mock_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            captured_request.append(req)
            return TransportResponse(status_code=200, body=_make_success_body(), headers={})

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="test-key"),
            transport=mock_transport,
        )
        client.complete([ChatMessage(role="user", content="hello")])

        assert len(captured_request) == 1
        assert (
            captured_request[0].full_url
            == "https://api.tokenfactory.nebius.com/v1/chat/completions?ai_project_id=proj-123"
        )

    # 3. configured timeout is actually passed to transport
    def test_configured_timeout_passed_to_transport(self) -> None:
        captured_timeout: list[float] = []

        def mock_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            captured_timeout.append(timeout)
            return TransportResponse(status_code=200, body=_make_success_body(), headers={})

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="test-key", timeout_seconds=42.5),
            transport=mock_transport,
        )
        client.complete([ChatMessage(role="user", content="ping")])

        assert len(captured_timeout) == 1
        assert captured_timeout[0] == 42.5

    # 4. max token bound enforced
    def test_max_token_bound_enforced(self) -> None:
        # Config bounds
        with pytest.raises(ModelConfigError):
            ModelClientConfig(max_tokens=0)
        with pytest.raises(ModelConfigError):
            ModelClientConfig(max_tokens=MAX_MAX_TOKENS + 1)

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="test-key"),
            transport=lambda req, timeout: TransportResponse(200, _make_success_body(), {}),
        )
        # Call-time bounds
        with pytest.raises(ModelConfigError):
            client.complete([ChatMessage(role="user", content="hi")], max_tokens=0)
        with pytest.raises(ModelConfigError):
            client.complete(
                [ChatMessage(role="user", content="hi")],
                max_tokens=MAX_MAX_TOKENS + 1,
            )

    # 5. temperature bound validated
    def test_temperature_bound_validated(self) -> None:
        with pytest.raises(ModelConfigError):
            ModelClientConfig(temperature=-0.1)
        with pytest.raises(ModelConfigError):
            ModelClientConfig(temperature=MAX_TEMPERATURE + 0.1)

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="test-key"),
            transport=lambda req, timeout: TransportResponse(200, _make_success_body(), {}),
        )
        with pytest.raises(ModelConfigError):
            client.complete([ChatMessage(role="user", content="hi")], temperature=-0.5)
        with pytest.raises(ModelConfigError):
            client.complete([ChatMessage(role="user", content="hi")], temperature=2.5)

    # 6. missing credential fails closed
    def test_missing_credential_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
        transport_called = False

        def mock_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            nonlocal transport_called
            transport_called = True
            return TransportResponse(200, _make_success_body(), {})

        client = NebiusModelClient(
            config=ModelClientConfig(api_key=None),
            transport=mock_transport,
        )
        with pytest.raises(MissingCredentialError) as exc_info:
            client.complete([ChatMessage(role="user", content="hi")])

        assert "NEBIUS_API_KEY" in str(exc_info.value)
        assert not transport_called

    # 7. credential never appears in repr/error/result
    def test_credential_never_appears_in_repr_or_errors(self) -> None:
        raw_secret = "secret-nebius-token-xyz-12345678901234567890"
        config = ModelClientConfig(api_key=raw_secret)

        # Repr of config masks the secret
        config_repr = repr(config)
        assert raw_secret not in config_repr
        assert "[CONFIGURED]" in config_repr

        # Repr of client does not contain secret
        client = NebiusModelClient(
            config=config,
            transport=lambda req, timeout: TransportResponse(200, _make_success_body(), {}),
        )
        assert raw_secret not in repr(client)

        result = client.complete([ChatMessage(role="user", content="test")])
        assert raw_secret not in repr(result)

    # 8. Authorization header is constructed only at transport boundary
    def test_authorization_header_at_transport_boundary(self) -> None:
        auth_headers: list[str] = []

        def mock_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            auth_header = req.get_header("Authorization")
            if auth_header:
                auth_headers.append(auth_header)
            return TransportResponse(200, _make_success_body(), {})

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="sample-key-123"),
            transport=mock_transport,
        )
        result = client.complete([ChatMessage(role="user", content="test")])

        assert len(auth_headers) == 1
        assert auth_headers[0] == "Bearer sample-key-123"
        # Result does not store headers or auth
        assert not hasattr(result, "headers")
        assert not hasattr(result, "authorization")

    # 9. successful OpenAI-compatible response parses correctly
    def test_successful_response_parsing(self) -> None:
        def mock_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            body = _make_success_body(
                content="Deterministic model completion",
                model=DEFAULT_PRIMARY_MODEL,
                finish_reason="stop",
                request_id="req-9999",
                usage={"prompt_tokens": 15, "completion_tokens": 8, "total_tokens": 23},
            )
            return TransportResponse(200, body, {})

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=mock_transport,
        )
        result = client.complete([{"role": "user", "content": "Generate fix"}])

        assert isinstance(result, ModelClientResult)
        assert result.content == "Deterministic model completion"
        assert result.configured_model == DEFAULT_PRIMARY_MODEL
        assert result.returned_model == DEFAULT_PRIMARY_MODEL
        assert result.finish_reason == "stop"
        assert result.request_id == "req-9999"
        assert isinstance(result.usage, TokenUsage)
        assert result.usage.prompt_tokens == 15
        assert result.usage.completion_tokens == 8
        assert result.usage.total_tokens == 23
        assert result.duration_seconds >= 0.0

    # 9b. chat_template_kwargs and reasoning_effort are passed into top-level payload
    def test_chat_template_kwargs_and_reasoning_effort(self) -> None:
        captured_payload = {}

        def mock_transport(req: Any, timeout: float) -> TransportResponse:
            nonlocal captured_payload
            captured_payload = json.loads(req.data.decode("utf-8"))
            body = _make_success_body()
            return TransportResponse(200, body, {})

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=mock_transport,
        )
        result = client.complete(
            [{"role": "user", "content": "hi"}],
            chat_template_kwargs={"enable_thinking": False},
            reasoning_effort="none",
        )
        assert result.content == "BASEBREAK_LIVE_OK"
        assert captured_payload.get("chat_template_kwargs") == {"enable_thinking": False}
        assert "extra_body" not in captured_payload
        assert captured_payload.get("reasoning_effort") == "none"

    # 9c. Focused request-byte serialization regression tests
    def test_raw_http_wire_bytes_serialization(self) -> None:
        captured_raw_data = b""

        def mock_transport(req: Any, timeout: float) -> TransportResponse:
            nonlocal captured_raw_data
            captured_raw_data = req.data
            return TransportResponse(200, _make_success_body(), {})

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=mock_transport,
        )
        client.complete(
            [{"role": "user", "content": "code proposal"}],
            chat_template_kwargs={"enable_thinking": False},
        )
        assert isinstance(captured_raw_data, bytes)
        assert b'"enable_thinking": false' in captured_raw_data
        assert b'"chat_template_kwargs"' in captured_raw_data
        assert b'"extra_body"' not in captured_raw_data
        parsed = json.loads(captured_raw_data.decode("utf-8"))
        assert parsed["chat_template_kwargs"] == {"enable_thinking": False}
        assert "extra_body" not in parsed

    def test_extra_body_options_unpacked_to_top_level_over_the_wire(self) -> None:
        captured_payload = {}

        def mock_transport(req: Any, timeout: float) -> TransportResponse:
            nonlocal captured_payload
            captured_payload = json.loads(req.data.decode("utf-8"))
            return TransportResponse(200, _make_success_body(), {})

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=mock_transport,
        )
        client.complete(
            [{"role": "user", "content": "hi"}],
            extra_body={"custom_sampling_flag": "fast_mode"},
        )
        assert captured_payload.get("custom_sampling_flag") == "fast_mode"
        assert "extra_body" not in captured_payload

    def test_extra_body_with_chat_template_kwargs_merged_without_duplication(self) -> None:
        captured_payload = {}
        captured_bytes = b""

        def mock_transport(req: Any, timeout: float) -> TransportResponse:
            nonlocal captured_payload, captured_bytes
            captured_bytes = req.data
            captured_payload = json.loads(req.data.decode("utf-8"))
            return TransportResponse(200, _make_success_body(), {})

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=mock_transport,
        )
        client.complete(
            [{"role": "user", "content": "hi"}],
            extra_body={"chat_template_kwargs": {"enable_thinking": False}},
        )
        assert captured_payload.get("chat_template_kwargs") == {"enable_thinking": False}
        assert "extra_body" not in captured_payload
        assert b'"extra_body"' not in captured_bytes

    def test_context_window_vs_output_limit_distinction(self) -> None:
        from basebreak.adapters.nebius.models import (
            MODEL_CONTEXT_LENGTHS,
            MODEL_MAX_OUTPUT_TOKENS,
        )

        assert MODEL_CONTEXT_LENGTHS[DEFAULT_PRIMARY_MODEL] == 1_048_576
        assert MODEL_MAX_OUTPUT_TOKENS[DEFAULT_PRIMARY_MODEL] == 262_144
        assert MAX_MAX_TOKENS == 262_144
        assert MAX_MAX_TOKENS < MODEL_CONTEXT_LENGTHS[DEFAULT_PRIMARY_MODEL]

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=lambda req, timeout: TransportResponse(200, _make_success_body(), {}),
        )
        # Requesting context window size as output max_tokens fails closed
        with pytest.raises(ModelConfigError):
            client.complete([ChatMessage(role="user", content="hi")], max_tokens=1_048_576)

        # Requesting beyond MAX_MAX_TOKENS fails closed
        with pytest.raises(ModelConfigError):
            client.complete([ChatMessage(role="user", content="hi")], max_tokens=MAX_MAX_TOKENS + 1)

        # Genuine architectural max output limit is accepted
        result = client.complete(
            [ChatMessage(role="user", content="hi")],
            max_tokens=MAX_MAX_TOKENS,
        )
        assert isinstance(result, ModelClientResult)

    # 10. response text is bounded
    def test_response_text_bounding(self) -> None:
        long_content = "X" * 1000
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key", max_response_characters=50),
            transport=lambda req, timeout: TransportResponse(
                200, _make_success_body(content=long_content), {}
            ),
        )
        result = client.complete([ChatMessage(role="user", content="hi")])
        assert len(result.content) == 50
        assert result.content == "X" * 50

    # 11. finish reason preserved
    def test_finish_reason_preserved(self) -> None:
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=lambda req, timeout: TransportResponse(
                200, _make_success_body(finish_reason="length"), {}
            ),
        )
        result = client.complete([ChatMessage(role="user", content="hi")])
        assert result.finish_reason == "length"

    # 12. usage fields preserved if present, None if omitted
    def test_usage_fields_preserved_or_none(self) -> None:
        # Case with usage omitted
        raw_payload = {
            "id": "req-no-usage",
            "model": DEFAULT_PRIMARY_MODEL,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
        }
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=lambda req, timeout: TransportResponse(
                200, json.dumps(raw_payload).encode("utf-8"), {}
            ),
        )
        result = client.complete([ChatMessage(role="user", content="hi")])
        assert result.usage is None

    # 13. returned model mismatch fails closed
    def test_returned_model_mismatch_fails_closed(self) -> None:
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key", model="nvidia/Nemotron-3_5-Lightning"),
            transport=lambda req, timeout: TransportResponse(
                200, _make_success_body(model="unexpected-model-identifier"), {}
            ),
        )
        with pytest.raises(ModelIdentityMismatchError) as exc_info:
            client.complete([ChatMessage(role="user", content="hi")])

        assert exc_info.value.configured_model == "nvidia/Nemotron-3_5-Lightning"
        assert exc_info.value.returned_model == "unexpected-model-identifier"

    # 14. HTTP/provider error is sanitized
    def test_provider_error_sanitization(self) -> None:
        raw_secret = "secret_nebius_key_abcdef12345678901234"
        error_payload = {
            "error": {
                "message": f"Authentication failed for Bearer {raw_secret}",
                "type": "authentication_error",
            }
        }

        def mock_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return TransportResponse(
                status_code=401,
                body=json.dumps(error_payload).encode("utf-8"),
                headers={},
            )

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=mock_transport,
        )
        with pytest.raises(ModelProviderError) as exc_info:
            client.complete([ChatMessage(role="user", content="hi")])

        assert exc_info.value.status_code == 401
        assert raw_secret not in exc_info.value.sanitized_message
        assert "[REDACTED]" in exc_info.value.sanitized_message
        assert raw_secret not in repr(exc_info.value)
        assert raw_secret not in str(exc_info.value)

    # 15. malformed JSON fails closed
    def test_malformed_json_fails_closed(self) -> None:
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=lambda req, timeout: TransportResponse(200, b"<html>Not JSON</html>", {}),
        )
        with pytest.raises(ModelResponseFormatError):
            client.complete([ChatMessage(role="user", content="hi")])

    # 16. missing choices/message/content fails closed
    def test_missing_choices_or_content_fails_closed(self) -> None:
        # Missing choices
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=lambda req, timeout: TransportResponse(
                200, json.dumps({"model": DEFAULT_PRIMARY_MODEL}).encode("utf-8"), {}
            ),
        )
        with pytest.raises(ModelResponseFormatError):
            client.complete([ChatMessage(role="user", content="hi")])

        # Empty choices
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=lambda req, timeout: TransportResponse(
                200, json.dumps({"model": DEFAULT_PRIMARY_MODEL, "choices": []}).encode("utf-8"), {}
            ),
        )
        with pytest.raises(ModelResponseFormatError):
            client.complete([ChatMessage(role="user", content="hi")])

        # Missing message
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=lambda req, timeout: TransportResponse(
                200,
                json.dumps({"model": DEFAULT_PRIMARY_MODEL, "choices": [{}]}).encode("utf-8"),
                {},
            ),
        )
        with pytest.raises(ModelResponseFormatError):
            client.complete([ChatMessage(role="user", content="hi")])

        # Missing content
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=lambda req, timeout: TransportResponse(
                200,
                json.dumps({"model": DEFAULT_PRIMARY_MODEL, "choices": [{"message": {}}]}).encode(
                    "utf-8"
                ),
                {},
            ),
        )
        with pytest.raises(ModelResponseFormatError):
            client.complete([ChatMessage(role="user", content="hi")])

    # 17. timeout produces typed adapter timeout error
    def test_timeout_produces_typed_adapter_timeout_error(self) -> None:
        def timeout_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            raise TimeoutError("Socket timed out")

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=timeout_transport,
        )
        with pytest.raises(ModelTimeoutError):
            client.complete([ChatMessage(role="user", content="hi")])

    # 18. no automatic retry occurs
    def test_no_automatic_retry_occurs(self) -> None:
        call_count = 0

        def failing_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            nonlocal call_count
            call_count += 1
            return TransportResponse(
                status_code=500, body=b'{"error": "Internal Server Error"}', headers={}
            )

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=failing_transport,
        )
        with pytest.raises(ModelProviderError):
            client.complete([ChatMessage(role="user", content="hi")])

        # Must have attempted exactly once
        assert call_count == 1

    # 20. no causal verdict is produced by model client
    def test_no_causal_verdict_produced(self) -> None:
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=lambda req, timeout: TransportResponse(200, _make_success_body(), {}),
        )
        result = client.complete([ChatMessage(role="user", content="hi")])

        assert isinstance(result, ModelClientResult)
        assert not hasattr(result, "verdict")
        assert not hasattr(result, "preliminary_verdict")
        assert not hasattr(result, "is_verified")
        assert not hasattr(result, "causal_verdict")
        assert not hasattr(result, "pass_fail")

    # 21. P-27.06: opt-in truncation rejection fails closed on finish_reason='length'
    def test_reject_length_truncation_fails_closed(self) -> None:
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=lambda req, timeout: TransportResponse(
                200, _make_success_body(content='{"partial":', finish_reason="length"), {}
            ),
        )
        with pytest.raises(ModelTruncatedResponseError):
            client.complete([ChatMessage(role="user", content="hi")], reject_length_truncation=True)

    # 22. default behaviour unchanged: truncation returned for the caller to judge
    def test_truncation_without_reject_flag_preserved(self) -> None:
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=lambda req, timeout: TransportResponse(
                200, _make_success_body(content='{"partial":', finish_reason="length"), {}
            ),
        )
        result = client.complete([ChatMessage(role="user", content="hi")])
        assert result.finish_reason == "length"
        assert result.content == '{"partial":'

    # 23. P-27.06: provider-enforced response_format reaches the wire
    def test_response_format_sent_in_payload(self) -> None:
        captured_request: list[urllib.request.Request] = []

        def mock_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            captured_request.append(req)
            return TransportResponse(200, _make_success_body(), {})

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=mock_transport,
        )
        client.complete(
            [ChatMessage(role="user", content="hi")],
            response_format={"type": "json_object"},
        )
        assert len(captured_request) == 1
        payload_bytes = captured_request[0].data
        assert isinstance(payload_bytes, bytes)
        body = json.loads(payload_bytes.decode("utf-8"))
        assert body["response_format"] == {"type": "json_object"}

    # 24. P-27.06: unsupported response_format type fails closed pre-dispatch
    def test_response_format_invalid_type_fails_closed(self) -> None:
        call_count = 0

        def mock_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            nonlocal call_count
            call_count += 1
            return TransportResponse(200, _make_success_body(), {})

        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key", max_response_characters=50),
            transport=mock_transport,
        )
        with pytest.raises(ModelConfigError):
            client.complete(
                [ChatMessage(role="user", content="hi")], response_format={"type": "bogus"}
            )
        assert call_count == 0  # rejected before any provider dispatch

    # 25. P-27.06: client-bound truncation rejected when opted in
    def test_bound_truncation_rejected_when_opted_in(self) -> None:
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key", max_response_characters=5),
            transport=lambda req, timeout: TransportResponse(
                200, _make_success_body(content="X" * 100, finish_reason="stop"), {}
            ),
        )
        with pytest.raises(ModelTruncatedResponseError):
            client.complete([ChatMessage(role="user", content="hi")], reject_length_truncation=True)

    # 26. P-27.06: null content with reasoning content fails closed and retains metadata
    def test_null_content_with_reasoning_retains_metadata(self) -> None:
        payload = {
            "id": "req-null-content-1",
            "model": DEFAULT_PRIMARY_MODEL,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "reasoning_content": "Internal model reasoning steps...",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 120, "completion_tokens": 45, "total_tokens": 165},
        }
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=lambda req, timeout: TransportResponse(
                200, json.dumps(payload).encode("utf-8"), {}
            ),
        )
        with pytest.raises(ModelResponseFormatError) as exc_info:
            client.complete([ChatMessage(role="user", content="hi")])

        exc = exc_info.value
        assert "missing 'content' string field" in str(exc)
        assert exc.usage is not None
        assert exc.usage.prompt_tokens == 120
        assert exc.usage.completion_tokens == 45
        assert exc.usage.total_tokens == 165
        assert exc.finish_reason == "stop"
        assert exc.has_reasoning_content is True
        assert exc.request_id == "req-null-content-1"
        assert exc.returned_model == DEFAULT_PRIMARY_MODEL

    # 27. P-27.06: refusal fails closed and retains metadata
    def test_refusal_fails_closed_and_retains_metadata(self) -> None:
        payload = {
            "id": "req-refusal-1",
            "model": DEFAULT_PRIMARY_MODEL,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "I cannot fulfill this request.",
                        "refusal": "Policy violation.",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 50, "completion_tokens": 10, "total_tokens": 60},
        }
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key"),
            transport=lambda req, timeout: TransportResponse(
                200, json.dumps(payload).encode("utf-8"), {}
            ),
        )
        with pytest.raises(ModelResponseFormatError) as exc_info:
            client.complete([ChatMessage(role="user", content="hi")])

        exc = exc_info.value
        assert "refused" in str(exc).lower()
        assert exc.usage is not None
        assert exc.usage.total_tokens == 60
        assert exc.finish_reason == "stop"
        assert exc.request_id == "req-refusal-1"
