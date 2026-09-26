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
            == "https://api.tokenfactory.nebius.com/v1/chat/completions"
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
