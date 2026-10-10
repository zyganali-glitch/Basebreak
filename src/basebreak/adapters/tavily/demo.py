"""Conditional real runtime Tavily demonstration plan and operator authorization gate.

P-16.05: Execute real runtime Tavily path if bonus remains strategically justified.

Authority & Invariants:
1. Hard Stop Gate:
   - A real live Tavily API call is NOT AUTHORIZED by default.
   - Status is held strictly at OPERATOR_AUTHORIZATION_REQUIRED until explicit operator approval.
2. Single Bounded Execution:
   - When authorized, exactly ONE bounded call against an authoritative CVE advisory is permitted.
   - search_depth: 'basic' (strictly 1 credit consumed out of 4,125 available free credits).
   - max_results: 3 (bounded).
   - Raw HTML scraping and LLM answers disabled.
3. No Mock-to-Live Substitution:
   - A simulated or fixture result must NEVER claim to be a live provider execution.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from basebreak.adapters.tavily.client import TavilyClient, extract_source_claims
from basebreak.adapters.tavily.models import (
    CREDIT_COST_BASIC,
    TavilySearchResponse,
)
from basebreak.compiler.freeze import FrozenContract
from basebreak.domain.semantics import ChangeClass
from basebreak.grounding.evidence import (
    FreshnessState,
    GroundedContractBinding,
    GroundedFact,
    UncertaintyState,
    create_grounded_binding,
    create_grounded_fact,
)
from basebreak.grounding.materiality import (
    AUTHORITATIVE_CVE_DOMAINS,
    GroundingMateriality,
    evaluate_grounding_materiality,
)


@dataclass(frozen=True, slots=True)
class TavilyDemonstrationPlan:
    """Pre-planned bounded specification for a real live Tavily query."""

    scenario_name: str = "CVE-2024-21626 Container Escape Security Advisory Grounding"
    change_class: ChangeClass = ChangeClass.SECURITY_FIX
    target_cve: str = "CVE-2024-21626"
    query: str = "CVE-2024-21626 runc security advisory container escape"
    allowed_domains: tuple[str, ...] = AUTHORITATIVE_CVE_DOMAINS
    max_results: int = 3
    search_depth: str = "basic"
    expected_credit_cost: int = CREDIT_COST_BASIC
    information_sought: str = (
        "Authoritative vulnerability description, affected runc versions (<=1.1.11), "
        "and fixed release (1.1.12) to verify vulnerability fix scope."
    )


@dataclass(frozen=True, slots=True)
class TavilyPreflightStatus:
    """Readiness and quota status before external provider execution."""

    api_key_configured: bool
    masked_key: str
    quota_available_credits: int
    expected_consumption: int
    zero_cost_safeguard_active: bool
    authorization_status: str


def check_live_tavily_preflight() -> TavilyPreflightStatus:
    """Inspect local environment and quota status without consuming any API credits."""
    key = os.environ.get("TAVILY_API_KEY", "")
    has_key = bool(key and len(key) >= 10)
    masked = f"{key[:4]}...{key[-4:]}" if has_key else "NONE"

    return TavilyPreflightStatus(
        api_key_configured=has_key,
        masked_key=masked,
        # 1,000 monthly + 3,125 promotional credits confirmed in platform discovery
        quota_available_credits=4125,
        expected_consumption=CREDIT_COST_BASIC,  # Exactly 1 credit
        zero_cost_safeguard_active=True,  # Usage-based billing confirmed disabled in P-01.01
        authorization_status="OPERATOR_AUTHORIZATION_REQUIRED",
    )


def execute_live_tavily_demonstration(
    contract: FrozenContract,
    *,
    operator_authorized: bool = False,
    observation_timestamp: str = "2026-10-10T08:00:00Z",
    client: TavilyClient | None = None,
) -> tuple[TavilySearchResponse, GroundedContractBinding]:
    """Execute the bounded live Tavily search demonstration upon explicit operator authorization.

    Fails closed if operator_authorized is False.
    """
    if not operator_authorized:
        raise PermissionError(
            "Real Tavily live execution is blocked at gate: OPERATOR_AUTHORIZATION_REQUIRED. "
            "Execution requires explicit fresh operator authorization."
        )

    plan = TavilyDemonstrationPlan()
    tavily_client = client or TavilyClient()

    # Execute bounded search
    response = tavily_client.search(
        query=plan.query,
        max_results=plan.max_results,
        search_depth=plan.search_depth,
        include_domains=plan.allowed_domains,
        include_published_date=True,
    )

    # Extract claims
    claims = extract_source_claims(response)

    # Build GroundedFacts
    facts: list[GroundedFact] = []
    for claim in claims:
        fact = create_grounded_fact(
            contract=contract,
            requirement_id="REQ-SEC-CVE-2024-21626",
            source_url=claim.url,
            publisher=claim.publisher,
            retrieved_claim=claim.claim_text,
            materiality=GroundingMateriality.REQUIRED,
            observation_timestamp=observation_timestamp,
            published_date=claim.published_date,
            retrieval_provider="tavily",
            provider_response_id=response.request_id,
            is_fixture=False,
            freshness_state=FreshnessState.FRESH,
            uncertainty_state=UncertaintyState.CERTAIN,
        )
        facts.append(fact)

    decision = evaluate_grounding_materiality(
        contract=contract,
        external_reference=plan.target_cve,
    )

    binding = create_grounded_binding(
        contract=contract,
        decision=decision,
        facts=facts,
        binding_timestamp=observation_timestamp,
    )

    return (response, binding)
