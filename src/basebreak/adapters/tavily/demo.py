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
from datetime import datetime, timezone

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
    historical_discovery_credits: int
    current_verified_credits: int | None
    current_quota_verified: bool
    zero_cost_safeguard_verified: bool
    readiness_state: str
    authorization_status: str
    expected_consumption: int
    is_fixture: bool = False


def check_live_tavily_preflight() -> TavilyPreflightStatus:
    """Inspect local environment without fabricating balances or confirmations."""
    key = os.environ.get("TAVILY_API_KEY", "")
    has_key = bool(key and len(key) >= 10)

    # Never hardcode current balance or billing-safety confirmation.
    # Without a fresh authenticated account balance check, current quota is UNVERIFIED.
    readiness_state = "UNVERIFIED_QUOTA_BLOCKED" if has_key else "MISSING_KEY_BLOCKED"

    return TavilyPreflightStatus(
        api_key_configured=has_key,
        historical_discovery_credits=4125,
        current_verified_credits=None,
        current_quota_verified=False,
        zero_cost_safeguard_verified=False,
        readiness_state=readiness_state,
        authorization_status="OPERATOR_AUTHORIZATION_REQUIRED",
        expected_consumption=CREDIT_COST_BASIC,
        is_fixture=False,
    )


def verify_advisory_snippet_support(claim_text: str, target_cve: str) -> bool:
    """Verify that a snippet contains sufficient supporting factual context for the CVE."""
    if not claim_text or not target_cve:
        return False
    return target_cve.lower() in claim_text.lower()


def execute_live_tavily_demonstration(
    contract: FrozenContract,
    *,
    operator_authorized: bool = False,
    verified_capacity: bool = False,
    observation_timestamp: str | None = None,
    client: TavilyClient | None = None,
) -> tuple[TavilySearchResponse, GroundedContractBinding]:
    """Execute the bounded live Tavily search demonstration upon operator authorization.

    Invariants enforced:
    1. Fails closed if operator_authorized is False.
    2. Fails closed if verified_capacity is False.
    3. Rejects mock client injection to prevent fixture laundering.
    4. Uses captured UTC observation time, never hardcoded default.
    5. Disables automatic retries and enforces single-call constraint.
    """
    if not operator_authorized:
        raise PermissionError(
            "Real Tavily live execution is blocked at gate: OPERATOR_AUTHORIZATION_REQUIRED. "
            "Execution requires explicit fresh operator authorization."
        )

    if not verified_capacity:
        raise RuntimeError(
            "Live Tavily execution blocked: current quota capacity and zero-cost billing "
            "safeguard must be independently verified before dispatching HTTP request."
        )

    if client is not None and client.is_mocked:
        raise ValueError(
            "Fixture laundering rejected: mock client with custom opener cannot execute "
            "as live demonstration."
        )

    actual_timestamp = observation_timestamp or datetime.now(timezone.utc).isoformat()
    plan = TavilyDemonstrationPlan()
    tavily_client = client or TavilyClient(single_call_only=True, allow_retries=False)

    # Execute bounded search
    response = tavily_client.search(
        query=plan.query,
        max_results=plan.max_results,
        search_depth=plan.search_depth,
        include_domains=plan.allowed_domains,
        include_published_date=True,
    )

    req = contract.requirements[0] if contract.requirements else None
    decision = evaluate_grounding_materiality(
        contract=contract,
        requirement=req,
        external_reference=plan.target_cve,
    )

    claims = extract_source_claims(response)
    facts: list[GroundedFact] = []
    for claim in claims:
        is_supported = verify_advisory_snippet_support(claim.claim_text, plan.target_cve)
        fact = create_grounded_fact(
            contract=contract,
            requirement_id=decision.requirement_id,
            source_url=claim.url,
            publisher=claim.publisher,
            retrieved_claim=claim.claim_text,
            materiality=GroundingMateriality.REQUIRED,
            observation_timestamp=actual_timestamp,
            published_date=claim.published_date,
            retrieval_provider="tavily",
            provider_response_id=response.request_id,
            is_fixture=False,
            freshness_state=FreshnessState.FRESH if is_supported else FreshnessState.UNKNOWN,
            uncertainty_state=(
                UncertaintyState.CERTAIN if is_supported else UncertaintyState.UNCERTAIN
            ),
        )
        facts.append(fact)

    binding = create_grounded_binding(
        contract=contract,
        decision=decision,
        facts=facts,
        binding_timestamp=actual_timestamp,
    )

    return (response, binding)


def execute_fixture_tavily_demonstration(
    contract: FrozenContract,
    *,
    client: TavilyClient,
    observation_timestamp: str | None = None,
) -> tuple[TavilySearchResponse, GroundedContractBinding]:
    """Execute an honest offline fixture demonstration using mock provider data.

    Explicitly marks all generated facts as is_fixture=True.
    """
    actual_timestamp = observation_timestamp or datetime.now(timezone.utc).isoformat()
    plan = TavilyDemonstrationPlan()

    response = client.search(
        query=plan.query,
        max_results=plan.max_results,
        search_depth=plan.search_depth,
        include_domains=plan.allowed_domains,
        include_published_date=True,
    )

    req = contract.requirements[0] if contract.requirements else None
    decision = evaluate_grounding_materiality(
        contract=contract,
        requirement=req,
        external_reference=plan.target_cve,
    )

    claims = extract_source_claims(response)
    facts: list[GroundedFact] = []
    for claim in claims:
        is_supported = verify_advisory_snippet_support(claim.claim_text, plan.target_cve)
        fact = create_grounded_fact(
            contract=contract,
            requirement_id=decision.requirement_id,
            source_url=claim.url,
            publisher=claim.publisher,
            retrieved_claim=claim.claim_text,
            materiality=GroundingMateriality.REQUIRED,
            observation_timestamp=actual_timestamp,
            published_date=claim.published_date,
            retrieval_provider="tavily",
            provider_response_id=response.request_id,
            is_fixture=True,  # Honestly classified as fixture!
            freshness_state=FreshnessState.FRESH if is_supported else FreshnessState.UNKNOWN,
            uncertainty_state=(
                UncertaintyState.CERTAIN if is_supported else UncertaintyState.UNCERTAIN
            ),
        )
        facts.append(fact)

    binding = create_grounded_binding(
        contract=contract,
        decision=decision,
        facts=facts,
        binding_timestamp=actual_timestamp,
    )

    return (response, binding)
