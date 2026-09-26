"""Closure gate test suite for Master Plan task P-05.01.

Validates the full closure contract for:
P-05.01 — Implement bounded model client using discovered model identifiers/config
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from basebreak.adapters.nebius import (
    CANDIDATE_DEEP_MODEL,
    DEFAULT_PRIMARY_MODEL,
    ChatMessage,
    MissingCredentialError,
    ModelAdapterError,
    ModelClientConfig,
    ModelConfigError,
    ModelIdentityMismatchError,
    ModelNetworkError,
    ModelProviderError,
    ModelResponseFormatError,
    ModelTimeoutError,
    NebiusModelClient,
    default_urllib_transport,
)


def _make_dummy_response(
    content: str = "BASEBREAK_LIVE_OK",
    model: str = DEFAULT_PRIMARY_MODEL,
    status_code: int = 200,
) -> bytes:
    payload: dict[str, Any] = {
        "id": "chatcmpl-closure-test",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
    }
    return json.dumps(payload).encode("utf-8")


class TestP0501Closure:
    """Comprehensive closure verification for P-05.01."""

    def test_error_taxonomy_complete(self) -> None:
        assert issubclass(ModelConfigError, ModelAdapterError)
        assert issubclass(MissingCredentialError, ModelConfigError)
        assert issubclass(ModelTimeoutError, ModelAdapterError)
        assert issubclass(ModelNetworkError, ModelAdapterError)
        assert issubclass(ModelProviderError, ModelAdapterError)
        assert issubclass(ModelResponseFormatError, ModelAdapterError)
        assert issubclass(ModelIdentityMismatchError, ModelAdapterError)

    def test_error_boundary_independent_of_p04_execution_outcomes(self) -> None:
        from basebreak.domain.execution import ExecutionResult
        from basebreak.security.normalization import NormalizedExecutionRecord

        # ModelAdapterError must NOT be an ExecutionResult or NormalizedExecutionRecord
        assert not issubclass(ModelAdapterError, ExecutionResult)
        assert not issubclass(ModelAdapterError, NormalizedExecutionRecord)

    def test_default_urllib_transport_success(self) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = _make_dummy_response()
        mock_resp.getcode.return_value = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        with patch("urllib.request.urlopen", return_value=mock_resp):
            req = urllib.request.Request("http://test.local")
            t_resp = default_urllib_transport(req, timeout=10.0)
            assert t_resp.status_code == 200
            assert b"BASEBREAK_LIVE_OK" in t_resp.body

    def test_default_urllib_transport_http_error(self) -> None:
        error_body = b'{"error": {"message": "Unauthorized access"}}'
        http_err = urllib.error.HTTPError(
            url="http://test.local",
            code=401,
            msg="Unauthorized",
            hdrs=MagicMock(items=lambda: [("Content-Type", "application/json")]),
            fp=MagicMock(read=lambda: error_body),
        )

        with patch("urllib.request.urlopen", side_effect=http_err):
            req = urllib.request.Request("http://test.local")
            t_resp = default_urllib_transport(req, timeout=10.0)
            assert t_resp.status_code == 401
            assert t_resp.body == error_body

    def test_default_urllib_transport_timeout_error(self) -> None:
        with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            req = urllib.request.Request("http://test.local")
            with pytest.raises(ModelTimeoutError):
                default_urllib_transport(req, timeout=5.0)

    def test_default_urllib_transport_url_timeout_error(self) -> None:
        url_err = urllib.error.URLError(reason=TimeoutError("socket timed out"))
        with patch("urllib.request.urlopen", side_effect=url_err):
            req = urllib.request.Request("http://test.local")
            with pytest.raises(ModelTimeoutError):
                default_urllib_transport(req, timeout=5.0)

    def test_default_urllib_transport_generic_network_error(self) -> None:
        url_err = urllib.error.URLError(reason="Connection refused")
        with patch("urllib.request.urlopen", side_effect=url_err):
            req = urllib.request.Request("http://test.local")
            with pytest.raises(ModelNetworkError) as exc_info:
                default_urllib_transport(req, timeout=5.0)
            assert "Connection refused" in str(exc_info.value)

    def test_prompt_character_bound_enforced(self) -> None:
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="valid-key", max_prompt_characters=100),
            transport=lambda req, timeout: MagicMock(),
        )
        with pytest.raises(ModelConfigError) as exc_info:
            client.complete([ChatMessage(role="user", content="A" * 101)])
        assert "Total prompt characters (101) exceeds limit (100)" in str(exc_info.value)

    def test_whitespace_credential_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEBIUS_API_KEY", "   ")
        client = NebiusModelClient(config=ModelClientConfig(api_key=None))
        with pytest.raises(MissingCredentialError):
            client.complete([ChatMessage(role="user", content="hi")])

    def test_candidate_deep_model_can_be_configured_explicitly(self) -> None:
        client = NebiusModelClient(
            config=ModelClientConfig(api_key="test-key", model=CANDIDATE_DEEP_MODEL),
            transport=lambda req, timeout: MagicMock(
                status_code=200,
                body=_make_dummy_response(model=CANDIDATE_DEEP_MODEL),
                headers={},
            ),
        )
        result = client.complete([ChatMessage(role="user", content="deep task")])
        assert result.configured_model == CANDIDATE_DEEP_MODEL
        assert result.returned_model == CANDIDATE_DEEP_MODEL
