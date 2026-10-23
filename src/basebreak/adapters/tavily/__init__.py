"""Tavily search provider adapter package.

P-16.02 & P-16.05: Implement Tavily adapter with source provenance and strict minimization.
"""

from typing import TYPE_CHECKING, Any

from .client import (
    TavilyClient,
    extract_source_claims,
)
from .models import (
    CREDIT_COST_ADVANCED,
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

if TYPE_CHECKING:
    from .demo import (
        GroundedEvidencePacket,
        TavilyDemonstrationPlan,
        TavilyPreflightStatus,
        check_live_tavily_preflight,
        create_cve_2024_21626_contract,
        execute_fixture_tavily_demonstration,
        execute_live_tavily_demonstration,
        run_tavily_cve_grounding_pipeline,
    )


def __getattr__(name: str) -> Any:
    if name in (
        "GroundedEvidencePacket",
        "TavilyDemonstrationPlan",
        "TavilyPreflightStatus",
        "check_live_tavily_preflight",
        "create_cve_2024_21626_contract",
        "execute_fixture_tavily_demonstration",
        "execute_live_tavily_demonstration",
        "run_tavily_cve_grounding_pipeline",
    ):
        from . import demo

        return getattr(demo, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "CREDIT_COST_ADVANCED",
    "CREDIT_COST_BASIC",
    "DEFAULT_MAX_RESULTS",
    "DEFAULT_SEARCH_DEPTH",
    "DEFAULT_TAVILY_API_URL",
    "DEFAULT_TIMEOUT_SECONDS",
    "GroundedEvidencePacket",
    "MAX_PERMITTED_RESULTS",
    "MAX_QUERY_LENGTH",
    "MAX_TIMEOUT_SECONDS",
    "MIN_TIMEOUT_SECONDS",
    "SourceClaim",
    "TavilyAdapterError",
    "TavilyClient",
    "TavilyConfigError",
    "TavilyDemonstrationPlan",
    "TavilyHttpError",
    "TavilyMissingKeyError",
    "TavilyPreflightStatus",
    "TavilyQueryValidationError",
    "TavilyQuotaExceededError",
    "TavilyRateLimitError",
    "TavilySearchResponse",
    "TavilySearchResultItem",
    "TavilyTimeoutError",
    "check_live_tavily_preflight",
    "compute_tavily_digest",
    "create_cve_2024_21626_contract",
    "execute_fixture_tavily_demonstration",
    "execute_live_tavily_demonstration",
    "extract_source_claims",
    "run_tavily_cve_grounding_pipeline",
]
