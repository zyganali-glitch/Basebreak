"""Bounded Tavily search client with strict minimization and secret safety.

P-16.02: Implement Tavily adapter with source provenance and strict minimization.

Features:
- Credentials isolated to host runtime environment; never persisted or logged.
- Bounded query input validation (length limits, sealed witness token leak protection).
- Minimal request payload (search_depth='basic', max_results<=5, raw_content=False, answer=False).
- Bounded timeout and bounded single idempotent retry for transient rate limits.
- Sanitized error handling preventing credential leakage in logs or exceptions.
- Structured response parsing with SHA-256 item and response integrity digests.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any
from urllib.parse import urlparse

from basebreak.security.secret_policy import redact_log_text

from .models import (
    CREDIT_COST_BASIC,
    DEFAULT_MAX_RESULTS,
    DEFAULT_SEARCH_DEPTH,
    DEFAULT_TAVILY_API_URL,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_PERMITTED_RESULTS,
    MAX_QUERY_LENGTH,
    MAX_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS,
    SourceClaim,
    TavilyAdapterError,
    TavilyConfigError,
    TavilyHttpError,
    TavilyMissingKeyError,
    TavilyQueryValidationError,
    TavilyQuotaExceededError,
    TavilyRateLimitError,
    TavilySearchResponse,
    TavilySearchResultItem,
    TavilyTimeoutError,
    compute_tavily_digest,
)

# Known secret patterns that should NEVER appear in search queries
SENSITIVE_QUERY_PATTERNS = [
    re.compile(r"bearer\s+[a-zA-Z0-9_\-\.]{10,}", re.IGNORECASE),
    re.compile(r"api[_\-]?key\s*[:=]\s*[a-zA-Z0-9_\-\.]{10,}", re.IGNORECASE),
    re.compile(r"tvly-[a-zA-Z0-9]{15,}", re.IGNORECASE),
    re.compile(r"secret[_\-]?token\s*[:=]", re.IGNORECASE),
]


class TavilyClient:
    """Bounded, secret-safe Tavily Search client."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_TAVILY_API_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        self._api_key = api_key or os.environ.get("TAVILY_API_KEY", "")
        self._base_url = base_url
        if not (MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS):
            raise TavilyConfigError(
                f"timeout must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}s, "
                f"got {timeout}"
            )
        self._timeout = timeout
        self._opener = opener or urllib.request.urlopen

    def __repr__(self) -> str:
        # Secret safety: never expose API key in repr
        masked = "***" if self._api_key else "NONE"
        return f"TavilyClient(base_url={self._base_url!r}, timeout={self._timeout}, key={masked})"

    def validate_query(
        self,
        query: str,
        sealed_witness_tokens: Sequence[str] | None = None,
    ) -> str:
        """Validate and sanitize a query before external transmission."""
        if not query or not isinstance(query, str):
            raise TavilyQueryValidationError("Query must be a non-empty string")
        stripped = query.strip()
        if not stripped:
            raise TavilyQueryValidationError("Query must not be empty or whitespace only")
        if len(stripped) > MAX_QUERY_LENGTH:
            raise TavilyQueryValidationError(
                f"Query exceeds maximum permitted length of {MAX_QUERY_LENGTH} chars "
                f"(got {len(stripped)})"
            )

        # Check for secret patterns
        for pat in SENSITIVE_QUERY_PATTERNS:
            if pat.search(stripped):
                raise TavilyQueryValidationError(
                    "Query contains sensitive secret pattern; blocked for safety"
                )

        # Check against sealed witness tokens
        if sealed_witness_tokens:
            for token in sealed_witness_tokens:
                if token and len(token) >= 4 and token.lower() in stripped.lower():
                    raise TavilyQueryValidationError(
                        f"Query contains protected sealed witness token '{token}'; "
                        "search blocked to prevent leakage"
                    )

        return stripped

    def search(
        self,
        query: str,
        *,
        max_results: int = DEFAULT_MAX_RESULTS,
        search_depth: str = DEFAULT_SEARCH_DEPTH,
        include_domains: Sequence[str] | None = None,
        exclude_domains: Sequence[str] | None = None,
        include_published_date: bool = True,
        sealed_witness_tokens: Sequence[str] | None = None,
    ) -> TavilySearchResponse:
        """Execute a strictly bounded search query against Tavily."""
        if not self._api_key:
            raise TavilyMissingKeyError(
                "TAVILY_API_KEY is not set. Execution requires a valid key "
                "in the runtime environment."
            )

        sanitized_query = self.validate_query(query, sealed_witness_tokens=sealed_witness_tokens)
        bounded_max_results = max(1, min(max_results, MAX_PERMITTED_RESULTS))

        # Payload strict minimization
        request_data: dict[str, Any] = {
            "query": sanitized_query,
            "search_depth": search_depth,
            "max_results": bounded_max_results,
            "include_raw_content": False,
            "include_answer": False,
            "include_published_date": include_published_date,
            "chunks_per_source": 1,
        }
        if include_domains:
            request_data["include_domains"] = list(include_domains)
        if exclude_domains:
            request_data["exclude_domains"] = list(exclude_domains)

        payload_bytes = json.dumps(request_data).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key}",
            "User-Agent": "Basebreak-Causal-Runtime/0.1.0",
        }

        req = urllib.request.Request(
            self._base_url,
            data=payload_bytes,
            headers=headers,
            method="POST",
        )

        response_bytes = self._execute_http_with_bounded_retry(req)
        return self._parse_response(sanitized_query, response_bytes)

    def _execute_http_with_bounded_retry(self, req: urllib.request.Request) -> bytes:
        """Execute HTTP request with bounded retry for rate limits / transient server errors."""
        max_attempts = 2
        for attempt in range(max_attempts):
            try:
                with self._opener(req, timeout=self._timeout) as resp:
                    return resp.read()  # type: ignore[no-any-return]
            except urllib.error.HTTPError as exc:
                code = exc.code
                detail = ""
                try:
                    err_body = exc.read().decode("utf-8", errors="replace")
                    if self._api_key and self._api_key in err_body:
                        err_body = err_body.replace(self._api_key, "[REDACTED]")
                    err_body = re.sub(r"tvly-[A-Za-z0-9_\-]{10,}", "[REDACTED]", err_body)
                    detail = redact_log_text(err_body)
                except Exception:
                    detail = f"HTTP {code}"

                # 429 Too Many Requests -> check Retry-After header, retry at most once
                if code == 429:
                    if attempt < max_attempts - 1:
                        retry_after = exc.headers.get("Retry-After")
                        delay = 1.0
                        if retry_after:
                            try:
                                delay = min(5.0, max(0.5, float(retry_after)))
                            except ValueError:
                                delay = 1.0
                        time.sleep(delay)
                        continue
                    raise TavilyRateLimitError(
                        f"Tavily rate limit exceeded (HTTP 429): {detail}"
                    ) from exc

                # 432 Plan Limit or 433 PayGo Limit
                if code in (432, 433):
                    raise TavilyQuotaExceededError(
                        f"Tavily quota/plan limit exceeded (HTTP {code}): {detail}"
                    ) from exc

                # 503 / 504 -> retry at most once
                if code in (503, 504) and attempt < max_attempts - 1:
                    time.sleep(1.0)
                    continue

                if code == 401:
                    raise TavilyMissingKeyError(
                        f"Tavily authentication failed (HTTP 401): {detail}"
                    ) from exc

                raise TavilyHttpError(code, detail) from exc
            except TimeoutError as exc:
                raise TavilyTimeoutError(
                    f"Tavily search request timed out after {self._timeout}s"
                ) from exc
            except urllib.error.URLError as exc:
                if "timed out" in str(exc).lower():
                    raise TavilyTimeoutError(f"Tavily search request timed out: {exc}") from exc
                raise TavilyAdapterError(f"Tavily network connection failed: {exc}") from exc

        raise TavilyAdapterError("Unexpected exit from HTTP retry loop")

    def _parse_response(self, query: str, response_bytes: bytes) -> TavilySearchResponse:
        """Parse raw response JSON into immutable TavilySearchResponse."""
        try:
            data = json.loads(response_bytes.decode("utf-8"))
        except Exception as exc:
            raise TavilyAdapterError(f"Failed to parse Tavily JSON response: {exc}") from exc

        if not isinstance(data, dict):
            raise TavilyAdapterError(f"Expected JSON object response, got {type(data).__name__}")

        raw_results = data.get("results", [])
        if not isinstance(raw_results, list):
            raise TavilyAdapterError("Response 'results' field must be a list")

        items: list[TavilySearchResultItem] = []
        for item in raw_results:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title", "")).strip()
            url = str(item.get("url", "")).strip()
            content = str(item.get("content", "")).strip()
            try:
                score = float(item.get("score", 0.0))
            except (ValueError, TypeError):
                score = 0.0
            pub_date = item.get("published_date")
            pub_date_str = str(pub_date).strip() if pub_date else None
            raw_c = item.get("raw_content")
            raw_c_str = str(raw_c) if raw_c is not None else None

            item_digest = compute_tavily_digest(
                {
                    "title": title,
                    "url": url,
                    "content": content,
                    "score": round(score, 6),
                    "published_date": pub_date_str,
                    "raw_content": raw_c_str,
                }
            )
            items.append(
                TavilySearchResultItem(
                    title=title,
                    url=url,
                    content=content,
                    score=score,
                    published_date=pub_date_str,
                    raw_content=raw_c_str,
                    item_digest=item_digest,
                )
            )

        resp_time_val = data.get("response_time", 0.0)
        try:
            resp_time = float(resp_time_val)
        except (ValueError, TypeError):
            resp_time = 0.0

        usage_dict = data.get("usage", {})
        credits_used = CREDIT_COST_BASIC
        if isinstance(usage_dict, dict) and "credits" in usage_dict:
            try:
                credits_used = int(usage_dict["credits"])
            except (ValueError, TypeError):
                credits_used = CREDIT_COST_BASIC

        req_id = data.get("request_id")
        req_id_str = str(req_id).strip() if req_id else None

        resp_digest = compute_tavily_digest(
            {
                "query": query,
                "results": [it.item_digest for it in items],
                "response_time": round(resp_time, 4),
                "credits_used": credits_used,
                "request_id": req_id_str,
            }
        )

        return TavilySearchResponse(
            query=query,
            results=tuple(items),
            response_time=resp_time,
            credits_used=credits_used,
            request_id=req_id_str,
            response_digest=resp_digest,
        )


def extract_source_claims(response: TavilySearchResponse) -> tuple[SourceClaim, ...]:
    """Extract structured, identifiable SourceClaims from a TavilySearchResponse."""
    claims: list[SourceClaim] = []
    for item in response.results:
        parsed = urlparse(item.url)
        publisher = parsed.netloc.lower() or "unknown_publisher"
        claim_digest = compute_tavily_digest(
            {
                "url": item.url,
                "publisher": publisher,
                "claim_text": item.content,
                "published_date": item.published_date,
            }
        )
        claims.append(
            SourceClaim(
                url=item.url,
                publisher=publisher,
                claim_text=item.content,
                published_date=item.published_date,
                claim_digest=claim_digest,
            )
        )
    return tuple(claims)
