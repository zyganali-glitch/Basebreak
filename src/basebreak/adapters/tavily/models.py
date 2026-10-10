"""Tavily adapter constants, exceptions, and structured response models.

P-16.02: Tavily adapter with source provenance and strict minimization.

Official API Reference:
- Endpoint: POST https://api.tavily.com/search
- Auth: Authorization: Bearer <TAVILY_API_KEY>
- Zero Secret Persistence: Keys loaded strictly from runtime environment.
- Strict Minimization: Bounded results, basic search depth (1 credit), raw HTML disabled.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

# Official Tavily API Constants
DEFAULT_TAVILY_API_URL: str = "https://api.tavily.com/search"
DEFAULT_SEARCH_DEPTH: str = "basic"
DEFAULT_MAX_RESULTS: int = 3
MAX_PERMITTED_RESULTS: int = 5
DEFAULT_TIMEOUT_SECONDS: float = 10.0
MIN_TIMEOUT_SECONDS: float = 1.0
MAX_TIMEOUT_SECONDS: float = 30.0
MAX_QUERY_LENGTH: int = 300

CREDIT_COST_BASIC: int = 1
CREDIT_COST_ADVANCED: int = 2


# --- Exceptions ---


class TavilyAdapterError(Exception):
    """Base exception for Tavily adapter failures."""


class TavilyConfigError(TavilyAdapterError):
    """Raised when client configuration or parameters are invalid."""


class TavilyMissingKeyError(TavilyConfigError):
    """Raised when TAVILY_API_KEY is not configured in the environment."""


class TavilyTimeoutError(TavilyAdapterError):
    """Raised when the Tavily HTTP request exceeds timeout."""


class TavilyRateLimitError(TavilyAdapterError):
    """Raised on HTTP 429 Too Many Requests."""


class TavilyQuotaExceededError(TavilyAdapterError):
    """Raised on HTTP 432 / 433 Plan Limit or PayGo Limit exceeded."""


class TavilyHttpError(TavilyAdapterError):
    """Raised on non-200 HTTP responses from Tavily."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Tavily HTTP {status_code}: {detail}")


class TavilyQueryValidationError(TavilyAdapterError):
    """Raised when a query fails security or validation checks (e.g. leaks sealed tokens)."""


# --- Structured Models ---


def compute_tavily_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical JSON representation."""
    canonical = json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class TavilySearchResultItem:
    """Single search result item returned by Tavily."""

    title: str
    url: str
    content: str
    score: float
    published_date: str | None
    raw_content: str | None
    item_digest: str

    def __post_init__(self) -> None:
        if not self.url:
            raise ValueError("url must not be empty")
        expected = compute_tavily_digest(
            {
                "title": self.title,
                "url": self.url,
                "content": self.content,
                "score": round(self.score, 6),
                "published_date": self.published_date,
                "raw_content": self.raw_content,
            }
        )
        if self.item_digest != expected:
            raise ValueError(
                f"item_digest mismatch: declared '{self.item_digest}', computed '{expected}'"
            )


@dataclass(frozen=True, slots=True)
class SourceClaim:
    """Distinct record of a specific technical claim extracted from a search result item."""

    url: str
    publisher: str
    claim_text: str
    published_date: str | None
    claim_digest: str

    def __post_init__(self) -> None:
        if not self.url or not self.publisher or not self.claim_text:
            raise ValueError("url, publisher, and claim_text must not be empty")
        expected = compute_tavily_digest(
            {
                "url": self.url,
                "publisher": self.publisher,
                "claim_text": self.claim_text,
                "published_date": self.published_date,
            }
        )
        if self.claim_digest != expected:
            raise ValueError(
                f"claim_digest mismatch: declared '{self.claim_digest}', computed '{expected}'"
            )


@dataclass(frozen=True, slots=True)
class TavilySearchResponse:
    """Immutable, content-addressed response from Tavily Search."""

    query: str
    results: tuple[TavilySearchResultItem, ...]
    response_time: float
    credits_used: int
    request_id: str | None
    response_digest: str

    def __post_init__(self) -> None:
        if not self.query:
            raise ValueError("query must not be empty")
        expected = compute_tavily_digest(
            {
                "query": self.query,
                "results": [item.item_digest for item in self.results],
                "response_time": round(self.response_time, 4),
                "credits_used": self.credits_used,
                "request_id": self.request_id,
            }
        )
        if self.response_digest != expected:
            raise ValueError(
                f"response_digest mismatch: declared '{self.response_digest}', "
                f"computed '{expected}'"
            )
