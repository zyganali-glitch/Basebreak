"""Tests for P-16.02: Tavily Adapter with source provenance and strict minimization."""

from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message
from typing import Any

import pytest

from basebreak.adapters.tavily.client import (
    TavilyClient,
    extract_source_claims,
)
from basebreak.adapters.tavily.models import (
    CREDIT_COST_BASIC,
    DEFAULT_SEARCH_DEPTH,
    SourceClaim,
    TavilyHttpError,
    TavilyMissingKeyError,
    TavilyQueryValidationError,
    TavilyQuotaExceededError,
    TavilySearchResponse,
    TavilyTimeoutError,
)


class MockHttpResponse:
    """Mock urllib response context manager."""

    def __init__(
        self, data: bytes, status: int = 200, headers: dict[str, str] | None = None
    ) -> None:
        self._data = data
        self.status = status
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._data

    def __enter__(self) -> MockHttpResponse:
        return self

    def __exit__(self, *args: Any) -> None:
        pass


def test_tavily_missing_key_fails_closed() -> None:
    client = TavilyClient(api_key="")
    with pytest.raises(TavilyMissingKeyError, match="TAVILY_API_KEY is not set"):
        client.search("CVE-2024-21626")


def test_tavily_repr_never_leaks_api_key() -> None:
    secret = "tvly-super-secret-test-key-123456789"
    client = TavilyClient(api_key=secret)
    rep = repr(client)
    assert secret not in rep
    assert "***" in rep


def test_query_validation_bounds_and_sanitization() -> None:
    client = TavilyClient(api_key="tvly-mock-key-12345")

    # Empty
    with pytest.raises(TavilyQueryValidationError, match="non-empty string"):
        client.validate_query("")

    # Whitespace
    with pytest.raises(TavilyQueryValidationError, match="whitespace only"):
        client.validate_query("   \t  ")

    # Overly long (>300 chars)
    long_q = "a" * 301
    with pytest.raises(TavilyQueryValidationError, match="maximum permitted length"):
        client.validate_query(long_q)

    # Valid
    assert client.validate_query("CVE-2024-21626") == "CVE-2024-21626"


def test_query_validation_rejects_secret_patterns() -> None:
    client = TavilyClient(api_key="tvly-mock-key-12345")

    with pytest.raises(TavilyQueryValidationError, match="sensitive secret pattern"):
        client.validate_query("lookup Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")

    with pytest.raises(TavilyQueryValidationError, match="sensitive secret pattern"):
        client.validate_query("search for tvly-actualkey123456789")


def test_query_validation_prevents_sealed_witness_leakage() -> None:
    client = TavilyClient(api_key="tvly-mock-key-12345")
    sealed_tokens = ["SEALED_EXPLOIT_PAYLOAD_001", "WITNESS_SECRET_NONCE_XYZ"]

    # Clean query passes
    assert (
        client.validate_query("CVE-2024-21626 advisory", sealed_witness_tokens=sealed_tokens)
        == "CVE-2024-21626 advisory"
    )

    # Query leaking sealed token fails closed
    with pytest.raises(
        TavilyQueryValidationError, match="contains protected sealed witness token"
    ) as exc_info:
        client.validate_query(
            "explain SEALED_EXPLOIT_PAYLOAD_001 crash",
            sealed_witness_tokens=sealed_tokens,
        )
    # Regression: Ensure protected token is NEVER interpolated into exception text
    assert "SEALED_EXPLOIT_PAYLOAD_001" not in str(exc_info.value)
    assert "SECRET_SIGNATURE_KEY_xyz" not in str(exc_info.value)


def test_tavily_search_request_strict_minimization() -> None:
    captured_requests: list[dict[str, Any]] = []

    def mock_opener(req: urllib.request.Request, timeout: float = 10.0) -> MockHttpResponse:
        body = json.loads(req.data.decode("utf-8"))  # type: ignore[union-attr]
        captured_requests.append(body)

        resp_payload = {
            "query": body["query"],
            "results": [
                {
                    "title": "NVD - CVE-2024-21626",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
                    "content": (
                        "runc 1.1.11 and earlier contains a file descriptor leak vulnerability."
                    ),
                    "score": 0.95,
                    "published_date": "2024-01-31T00:00:00Z",
                }
            ],
            "response_time": 0.42,
            "usage": {"credits": 1},
            "request_id": "req-tavily-test-001",
        }
        return MockHttpResponse(json.dumps(resp_payload).encode("utf-8"))

    client = TavilyClient(api_key="tvly-mock-key-12345", opener=mock_opener)
    response = client.search(
        "CVE-2024-21626",
        max_results=3,
        include_domains=["nvd.nist.gov", "cve.org"],
    )

    assert len(captured_requests) == 1
    req_body = captured_requests[0]

    # Verify strict minimization
    assert req_body["query"] == "CVE-2024-21626"
    assert req_body["search_depth"] == DEFAULT_SEARCH_DEPTH
    assert req_body["max_results"] == 3
    assert req_body["include_raw_content"] is False
    assert req_body["include_answer"] is False
    assert req_body["chunks_per_source"] == 1
    assert req_body["include_domains"] == ["nvd.nist.gov", "cve.org"]

    # Verify parsed response
    assert isinstance(response, TavilySearchResponse)
    assert response.credits_used == CREDIT_COST_BASIC
    assert response.request_id == "req-tavily-test-001"
    assert len(response.results) == 1
    item = response.results[0]
    assert item.title == "NVD - CVE-2024-21626"
    assert item.url == "https://nvd.nist.gov/vuln/detail/CVE-2024-21626"
    assert item.published_date == "2024-01-31T00:00:00Z"

    # Verify extracted source claims
    claims = extract_source_claims(response)
    assert len(claims) == 1
    claim = claims[0]
    assert isinstance(claim, SourceClaim)
    assert claim.publisher == "nvd.nist.gov"
    assert "runc 1.1.11" in claim.claim_text


def test_tavily_quota_exceeded_error_handling() -> None:
    def mock_opener(req: urllib.request.Request, timeout: float = 10.0) -> Any:
        fp = io.BytesIO(b'{"detail": {"error": "432 Plan limit exceeded"}}')
        msg = Message()
        raise urllib.error.HTTPError(
            req.full_url,
            432,
            "Plan Limit Exceeded",
            hdrs=msg,
            fp=fp,
        )

    client = TavilyClient(api_key="tvly-mock-key-12345", opener=mock_opener)
    with pytest.raises(TavilyQuotaExceededError, match="plan limit exceeded"):
        client.search("CVE-2024-21626")


def test_tavily_rate_limit_and_retry() -> None:
    attempts = 0

    def mock_opener(req: urllib.request.Request, timeout: float = 10.0) -> Any:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            msg = Message()
            msg["Retry-After"] = "0.1"
            fp = io.BytesIO(b'{"detail": {"error": "Rate limit exceeded"}}')
            raise urllib.error.HTTPError(
                req.full_url,
                429,
                "Too Many Requests",
                hdrs=msg,
                fp=fp,
            )
        resp_payload = {
            "query": "test",
            "results": [],
            "response_time": 0.1,
            "usage": {"credits": 1},
        }
        return MockHttpResponse(json.dumps(resp_payload).encode("utf-8"))

    client = TavilyClient(api_key="tvly-mock-key-12345", opener=mock_opener)
    resp = client.search("test")
    assert attempts == 2
    assert resp.credits_used == 1


def test_tavily_timeout_handling() -> None:
    def mock_opener(req: urllib.request.Request, timeout: float = 10.0) -> Any:
        raise TimeoutError("Socket timed out")

    client = TavilyClient(api_key="tvly-mock-key-12345", opener=mock_opener)
    with pytest.raises(TavilyTimeoutError, match="timed out"):
        client.search("CVE-2024-21626")


def test_tavily_secret_redaction_in_http_error() -> None:
    def mock_opener(req: urllib.request.Request, timeout: float = 10.0) -> Any:
        # Error body containing simulated secret
        fp = io.BytesIO(b'{"detail": {"error": "Failed for key tvly-super-secret-token-abcdef"}}')
        msg = Message()
        raise urllib.error.HTTPError(
            req.full_url,
            400,
            "Bad Request",
            hdrs=msg,
            fp=fp,
        )

    client = TavilyClient(api_key="tvly-mock-key-12345", opener=mock_opener)
    with pytest.raises(TavilyHttpError) as exc_info:
        client.search("CVE-2024-21626")

    err_str = str(exc_info.value)
    # The secret must be redacted
    assert "tvly-super-secret-token-abcdef" not in err_str
    assert "[REDACTED" in err_str


def test_tavily_rejects_advanced_and_unsupported_search_depth() -> None:
    """Adversarial test: caller-selected advanced or non-basic depth must be rejected."""
    from basebreak.adapters.tavily.models import TavilyConfigError

    client = TavilyClient(api_key="tvly-mock-key")
    with pytest.raises(TavilyConfigError, match="Unsupported search_depth 'advanced'"):
        client.search("CVE-2024-21626", search_depth="advanced")

    with pytest.raises(TavilyConfigError, match="Unsupported search_depth 'ultra'"):
        client.search("CVE-2024-21626", search_depth="ultra")


def test_tavily_retry_suppression_and_single_call_constraint() -> None:
    """Adversarial test: retry suppression fails on first error and blocks second call."""
    from basebreak.adapters.tavily.models import TavilyAdapterError, TavilyRateLimitError

    attempts = 0

    def mock_opener(req: urllib.request.Request, timeout: float = 10.0) -> Any:
        nonlocal attempts
        attempts += 1
        msg = Message()
        msg["Retry-After"] = "0.1"
        fp = io.BytesIO(b'{"detail": {"error": "Rate limit exceeded"}}')
        raise urllib.error.HTTPError(
            req.full_url,
            429,
            "Too Many Requests",
            hdrs=msg,
            fp=fp,
        )

    # With allow_retries=False, must fail immediately without second attempt
    client = TavilyClient(
        api_key="tvly-mock-key-12345",
        opener=mock_opener,
        allow_retries=False,
        single_call_only=True,
    )
    with pytest.raises(TavilyRateLimitError):
        client.search("CVE-2024-21626")
    assert attempts == 1

    # Second call must be rejected by single_call_only
    with pytest.raises(TavilyAdapterError, match="Single-call constraint violated"):
        client.search("CVE-2024-21626")


def test_tavily_rejects_unauthorized_and_insecure_destinations() -> None:
    """Adversarial test: live credentials must never target insecure or unauthorized hosts."""
    from basebreak.adapters.tavily.models import TavilyConfigError

    # Insecure HTTP
    with pytest.raises(TavilyConfigError, match="Insecure API destination"):
        TavilyClient(api_key="tvly-mock-key", base_url="http://api.tavily.com/search")

    # Unauthorized domain
    with pytest.raises(TavilyConfigError, match="Unauthorized API destination"):
        TavilyClient(api_key="tvly-mock-key", base_url="https://attacker.com/steal")

    with pytest.raises(TavilyConfigError, match="Unauthorized API destination"):
        TavilyClient(api_key="tvly-mock-key", base_url="https://api.tavily.com.attacker.com")


def test_tavily_secret_safe_exceptions_redacts_witness_tokens() -> None:
    """Adversarial test: witness tokens and API keys must be scrubbed from exception messages."""
    witness_token = "VERIFIER_SEALED_TOKEN_XYZ_123"

    def mock_opener(req: urllib.request.Request, timeout: float = 10.0) -> Any:
        fp = io.BytesIO(
            f'{{"detail": "{witness_token} leaked with tvly-real-secret-key-abcdef"}}'.encode()
        )
        msg = Message()
        raise urllib.error.HTTPError(
            req.full_url,
            400,
            "Bad Request",
            hdrs=msg,
            fp=fp,
        )

    client = TavilyClient(api_key="tvly-real-secret-key-abcdef", opener=mock_opener)
    with pytest.raises(TavilyHttpError) as exc_info:
        client.search("CVE-2024-21626", sealed_witness_tokens=[witness_token])

    err_msg = str(exc_info.value)
    assert witness_token not in err_msg
    assert "tvly-real-secret-key-abcdef" not in err_msg
    assert "[PROTECTED_WITNESS]" in err_msg
    assert "[REDACTED]" in err_msg


def test_credits_used_property_does_not_mask_missing_usage() -> None:
    """Validate credits_used returns None when usage is absent, never falling back to expected."""

    def mock_opener(req: urllib.request.Request, timeout: float = 10.0) -> MockHttpResponse:
        resp_payload = {
            "query": "CVE-2024-21626",
            "results": [],
            "response_time": 0.1,
            # No "usage" dictionary provided by provider!
            "request_id": "req-no-usage",
        }
        return MockHttpResponse(json.dumps(resp_payload).encode("utf-8"))

    client = TavilyClient(api_key="tvly-mock-key", opener=mock_opener)
    response = client.search("CVE-2024-21626")
    assert response.expected_credits == 1
    assert response.observed_credits is None
    assert response.credits_used is None  # Strictly None, does NOT present 1 as observed!


def test_tavily_client_properties_and_single_call_constraints() -> None:
    """Validate client properties for single-call and retry constraints."""
    c1 = TavilyClient(api_key="tvly-mock-key", single_call_only=True, allow_retries=False)
    assert c1.single_call_only is True
    assert c1.allow_retries is False
    assert c1.calls_attempted == 0

    c2 = TavilyClient(api_key="tvly-mock-key", single_call_only=False, allow_retries=True)
    assert c2.single_call_only is False
    assert c2.allow_retries is True
    assert c2.calls_attempted == 0
