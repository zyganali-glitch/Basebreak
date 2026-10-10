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
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from basebreak.adapters.tavily.client import TavilyClient, extract_source_claims
from basebreak.adapters.tavily.models import (
    CREDIT_COST_BASIC,
    TavilySearchResponse,
)
from basebreak.compiler.freeze import FrozenContract
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.grounding.evidence import (
    FreshnessState,
    GroundedContractBinding,
    GroundedFact,
    TrustedProviderObservation,
    UncertaintyState,
    create_grounded_binding,
    create_grounded_fact,
    create_trusted_observation,
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


ADVISORY_SUBSTANTIVE_SIGNALS: tuple[str, ...] = (
    "fixed",
    "fix",
    "fixes",
    "patch",
    "patched",
    "patches",
    "vulnerability",
    "descriptor",
    "escape",
    "leak",
    "leakage",
    "1.1.12",
    "1.1.11",
)

ADVISORY_SUBSTANTIVE_PATTERN = re.compile(
    r"\b(?:fixed|fixes|fix|patched|patches|patch|vulnerability|descriptor|escape|leak|leakage|1\.1\.12|1\.1\.11)\b",
    re.IGNORECASE,
)


def verify_advisory_snippet_support(claim_text: str, target_cve: str) -> bool:
    """Screen an advisory search snippet for substantive relevance to the target CVE.

    Treats snippet matching strictly as relevance screening, NOT factual certainty.
    Requires both the exact target CVE identifier AND substantive vulnerability/fix signals.
    Generic words such as 'version' or 'release' alone do not establish advisory relevance.
    """
    if not claim_text or not target_cve:
        return False
    lower_text = claim_text.lower()
    if target_cve.lower() not in lower_text:
        return False
    return bool(ADVISORY_SUBSTANTIVE_PATTERN.search(lower_text))


def screen_advisory_claim(
    claim_text: str,
    target_cve: str,
    url: str,
    allowed_domains: tuple[str, ...],
    has_observation_metadata: bool,
    published_date: str | None = None,
) -> tuple[FreshnessState, UncertaintyState]:
    """Screen an advisory claim, preserving uncertainty unless fully validated.

    Invariants:
    1. Lexical snippet matching is relevance screening only, NOT proof of certainty or freshness.
    2. Freshness is NEVER automatically assigned FRESH solely because retrieval just occurred;
       defaults to UNKNOWN unless explicit temporal freshness is verified.
    3. Uncertainty is preserved (UNCERTAIN) unless supported by trusted observation metadata,
       authoritative publisher domain, and validated substantive advisory facts.
    4. Non-relevant snippets fail to INSUFFICIENT.
    """
    if not verify_advisory_snippet_support(claim_text, target_cve):
        return (FreshnessState.UNKNOWN, UncertaintyState.INSUFFICIENT)

    # Retrieval having just occurred does NOT establish freshness; defaults to UNKNOWN
    freshness = FreshnessState.UNKNOWN

    # Evaluate claim and source quality:
    # 1. Authoritative domain check
    parsed_domain = urlparse(url).netloc.lower()
    is_authoritative = any(
        parsed_domain == d or parsed_domain.endswith("." + d) for d in allowed_domains
    )

    # 2. Substantive advisory fact verification (vulnerability mechanism or fix/patched release)
    lower = claim_text.lower()
    has_substantive_fact = bool(
        re.search(r"\b(?:1\.1\.12|fixed|escape|descriptor|leak|patch|patched)\b", lower)
    )

    # 3. Only if authoritative domain, substantive advisory fact, and trusted observation metadata
    # are all present do we conclude CERTAIN; otherwise preserve UNCERTAIN.
    if is_authoritative and has_substantive_fact and has_observation_metadata:
        uncertainty = UncertaintyState.CERTAIN
    else:
        uncertainty = UncertaintyState.UNCERTAIN

    return (freshness, uncertainty)


def create_demonstration_observation(
    response: TavilySearchResponse,
    *,
    plan: TavilyDemonstrationPlan,
    observation_timestamp: str,
    provenance: EvidenceProvenance,
    is_live_execution: bool,
) -> TrustedProviderObservation:
    """Mint a TrustedProviderObservation from demonstration search response."""
    return create_trusted_observation(
        observation_id=response.request_id or f"obs-{response.response_digest[:16]}",
        provider_name="tavily",
        query=plan.query,
        response_digest=response.response_digest,
        observation_timestamp=observation_timestamp,
        provenance=provenance,
        is_live_execution=is_live_execution,
    )


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
    4. Rejects supplied client that permits retries or multiple calls.
    5. Uses captured UTC observation time, never hardcoded default.
    6. Disables automatic retries and enforces exactly one HTTP attempt.
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

    if client is not None:
        if client.is_mocked:
            raise ValueError(
                "Fixture laundering rejected: mock client with custom opener cannot execute "
                "as live demonstration."
            )
        if not client.single_call_only or client.allow_retries:
            raise ValueError(
                "Execution rejected: supplied TavilyClient must have single_call_only=True "
                "and allow_retries=False to strictly guarantee exactly one HTTP attempt."
            )
        if client.calls_attempted > 0:
            raise ValueError(
                "Execution rejected: supplied TavilyClient has already attempted calls; "
                "fresh single-call client required."
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
    has_obs_meta = bool(response.request_id and response.response_digest)
    for claim in claims:
        freshness_state, uncertainty_state = screen_advisory_claim(
            claim_text=claim.claim_text,
            target_cve=plan.target_cve,
            url=claim.url,
            allowed_domains=plan.allowed_domains,
            has_observation_metadata=has_obs_meta,
            published_date=claim.published_date,
        )
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
            freshness_state=freshness_state,
            uncertainty_state=uncertainty_state,
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
    Rejects normal live network clients to prevent accidental external calls.
    """
    if not client.is_mocked:
        raise ValueError(
            "Live network client rejected from fixture demonstration: "
            "execute_fixture_tavily_demonstration requires a mocked client with explicit opener."
        )

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
    has_obs_meta = bool(response.request_id and response.response_digest)
    for claim in claims:
        freshness_state, uncertainty_state = screen_advisory_claim(
            claim_text=claim.claim_text,
            target_cve=plan.target_cve,
            url=claim.url,
            allowed_domains=plan.allowed_domains,
            has_observation_metadata=has_obs_meta,
            published_date=claim.published_date,
        )
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
            freshness_state=freshness_state,
            uncertainty_state=uncertainty_state,
        )
        facts.append(fact)

    binding = create_grounded_binding(
        contract=contract,
        decision=decision,
        facts=facts,
        binding_timestamp=actual_timestamp,
    )

    return (response, binding)
