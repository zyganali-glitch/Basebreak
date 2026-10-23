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

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from basebreak.compiler.freeze import FrozenContract, freeze_review_result
from basebreak.compiler.ingestion import ingest_task
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.review import ReviewBundle, ReviewSession
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeClass,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
)
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
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
from basebreak.grounding.firewall import (
    GroundingFirewallResult,
    evaluate_grounding_firewall,
)
from basebreak.grounding.materiality import (
    AUTHORITATIVE_CVE_DOMAINS,
    GroundingMateriality,
    evaluate_grounding_materiality,
)

from .client import TavilyClient, extract_source_claims
from .models import (
    CREDIT_COST_BASIC,
    TavilyMissingKeyError,
    TavilySearchResponse,
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


def check_live_tavily_preflight(operator_authorized: bool = False) -> TavilyPreflightStatus:
    """Inspect local environment without fabricating balances or confirmations."""
    key = os.environ.get("TAVILY_API_KEY", "")
    has_key = bool(key and len(key) >= 10)

    # Never hardcode current balance or billing-safety confirmation.
    # Without a fresh authenticated account balance check, current quota is UNVERIFIED.
    readiness_state = "UNVERIFIED_QUOTA_BLOCKED" if has_key else "MISSING_KEY_BLOCKED"
    auth_status = (
        "OPERATOR_AUTHORIZED" if operator_authorized else "OPERATOR_AUTHORIZATION_REQUIRED"
    )

    return TavilyPreflightStatus(
        api_key_configured=has_key,
        historical_discovery_credits=4125,
        current_verified_credits=None,
        current_quota_verified=False,
        zero_cost_safeguard_verified=False,
        readiness_state=readiness_state,
        authorization_status=auth_status,
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


def create_cve_2024_21626_contract() -> FrozenContract:
    """Construct the canonical frozen engineering contract for CVE-2024-21626 advisory grounding."""
    task_text = "Fix CVE-2024-21626 runc file descriptor leakage on container process exec."
    task = ingest_task(task_text)
    cit = task_text
    prop = ProposedRequirement(
        statement=(
            "All file descriptors above 2 are verified closed prior to executing target process."
        ),
        citation=cit,
        citation_start=0,
        citation_end=len(cit),
        rationale="Authoritative fix for CVE-2024-21626",
    )
    fact = DeterministicClassificationFact(
        inferred_class=ChangeClass.SECURITY_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=1.0,
        alternative_classes=(),
        rationale="Security fix",
        evidence_citations=(cit,),
        matched_signals=("fix", "cve"),
    )
    semantics = ChangeSemanticsClassification(
        task_digest=task.task_digest,
        change_class=ChangeClass.SECURITY_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=1.0,
        alternative_classes=(),
        rationale="Security fix",
        evidence_citations=(cit,),
        deterministic_facts=fact,
    )
    bundle = ReviewBundle(
        task=task,
        semantics=semantics,
        requirements=(prop,),
    )
    session = ReviewSession(bundle)
    approval = session.approve()
    return freeze_review_result(approval)


@dataclass(frozen=True, slots=True)
class GroundedEvidencePacket:
    """Sanitized, verifiable real-provider or offline grounding evidence packet."""

    contract_digest: str
    requirement_id: str
    query: str
    search_parameters: dict[str, Any]
    provider_response_id: str | None
    response_digest: str
    source_items: tuple[dict[str, Any], ...]
    observation_timestamp: str
    grounded_fact_digests: tuple[str, ...]
    binding_digest: str
    firewall_status: str
    firewall_verdict: str
    uncertainty_states: tuple[str, ...]
    credit_usage: int | None
    provenance: str
    is_live: bool
    readiness_state: str
    diagnostics: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_digest": self.contract_digest,
            "requirement_id": self.requirement_id,
            "query": self.query,
            "search_parameters": self.search_parameters,
            "provider_response_id": self.provider_response_id,
            "response_digest": self.response_digest,
            "source_items": list(self.source_items),
            "observation_timestamp": self.observation_timestamp,
            "grounded_fact_digests": list(self.grounded_fact_digests),
            "binding_digest": self.binding_digest,
            "firewall_status": self.firewall_status,
            "firewall_verdict": self.firewall_verdict,
            "uncertainty_states": list(self.uncertainty_states),
            "credit_usage": self.credit_usage if self.credit_usage is not None else "UNKNOWN",
            "provenance": self.provenance,
            "is_live": self.is_live,
            "readiness_state": self.readiness_state,
            "diagnostics": list(self.diagnostics),
        }


def run_tavily_cve_grounding_pipeline(
    *,
    operator_authorized: bool = False,
    verified_capacity: bool = False,
    candidate_execution_verdict: PreliminaryVerdict = PreliminaryVerdict.VERIFIED,
    client: TavilyClient | None = None,
    persist_packet_path: str | None = None,
    observation_timestamp: str | None = None,
) -> tuple[GroundedEvidencePacket, GroundingFirewallResult]:
    """Execute the end-to-end Tavily grounding pipeline with deterministic firewall evaluation.

    Pipeline sequence:
    1. Frozen CVE security contract (create_cve_2024_21626_contract).
    2. Deterministic materiality evaluation (REQUIRED).
    3. Operator authorization and billing-capacity checks (fails closed if unverified).
    4. Bounded Tavily search execution (basic search depth, max 3, allowed domains).
    5. Source claim extraction.
    6. Advisory relevance screening against CVE and substantive fix signals.
    7. Immutable GroundedFact creation with digests.
    8. GroundedContractBinding creation bound to frozen contract digest.
    9. TrustedProviderObservation generation (for live execution).
    10. Deterministic authority firewall evaluation (enforcing causal execution primacy).
    11. Sanitized evidence packet construction and optional persistence.
    """
    contract = create_cve_2024_21626_contract()
    req = contract.requirements[0]
    decision = evaluate_grounding_materiality(
        contract=contract,
        requirement=req,
        external_reference="CVE-2024-21626",
    )

    actual_timestamp = observation_timestamp or datetime.now(timezone.utc).isoformat()
    plan = TavilyDemonstrationPlan()

    if client is not None and client.is_mocked:
        # Offline fixture demonstration
        response, binding = execute_fixture_tavily_demonstration(
            contract,
            client=client,
            observation_timestamp=actual_timestamp,
        )
        obs: TrustedProviderObservation | None = None
        provenance = EvidenceProvenance.FIXTURE
        is_live = False
        readiness_state = "OFFLINE_FIXTURE"
    else:
        # Live provider execution requires operator authorization and verified capacity
        preflight = check_live_tavily_preflight(operator_authorized=operator_authorized)
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
        if not preflight.api_key_configured:
            raise TavilyMissingKeyError(
                "TAVILY_API_KEY is not set. Execution requires a valid key "
                "in the runtime environment."
            )

        response, binding = execute_live_tavily_demonstration(
            contract,
            operator_authorized=operator_authorized,
            verified_capacity=verified_capacity,
            observation_timestamp=actual_timestamp,
            client=client,
        )
        obs = create_demonstration_observation(
            response,
            plan=plan,
            observation_timestamp=actual_timestamp,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            is_live_execution=True,
        )
        provenance = EvidenceProvenance.LOCAL_EXECUTION
        is_live = True
        readiness_state = "LIVE_EXECUTED"

    trusted_obs = [obs] if obs is not None else None
    firewall_result = evaluate_grounding_firewall(
        materiality=decision,
        binding=binding,
        execution_verdict=candidate_execution_verdict,
        trusted_observations=trusted_obs,
    )

    source_items = tuple(
        {
            "title": item.title,
            "url": item.url,
            "publisher": urlparse(item.url).netloc.lower(),
            "published_date": item.published_date,
            "item_digest": item.item_digest,
        }
        for item in response.results
    )
    fact_digests = tuple(f.evidence_digest for f in binding.facts)
    uncertainty_states = tuple(f.uncertainty_state.value for f in binding.facts)

    diagnostics: list[str] = []
    if firewall_result.adversarial_flags:
        diagnostics.extend(firewall_result.adversarial_flags)

    packet = GroundedEvidencePacket(
        contract_digest=contract.contract_digest,
        requirement_id=req.requirement_id,
        query=plan.query,
        search_parameters={
            "search_depth": plan.search_depth,
            "max_results": plan.max_results,
            "allowed_domains": list(plan.allowed_domains),
            "include_published_date": True,
            "include_raw_content": False,
            "include_answer": False,
        },
        provider_response_id=response.request_id,
        response_digest=response.response_digest,
        source_items=source_items,
        observation_timestamp=actual_timestamp,
        grounded_fact_digests=fact_digests,
        binding_digest=binding.binding_digest,
        firewall_status=firewall_result.grounding_status.value,
        firewall_verdict=firewall_result.final_verdict.value,
        uncertainty_states=uncertainty_states,
        credit_usage=response.credits_used,
        provenance=provenance.value,
        is_live=is_live,
        readiness_state=readiness_state,
        diagnostics=tuple(diagnostics),
    )

    if persist_packet_path:
        os.makedirs(os.path.dirname(os.path.abspath(persist_packet_path)), exist_ok=True)
        with open(persist_packet_path, "w", encoding="utf-8") as pf:
            json.dump(packet.to_dict(), pf, indent=2, sort_keys=True)

    return (packet, firewall_result)


def main(argv: list[str] | None = None) -> int:
    """Command-line entrypoint for Tavily grounding execution and preflight inspection."""
    parser = argparse.ArgumentParser(
        description="Basebreak Tavily Grounding Runner (P-16.05)",
    )
    parser.add_argument(
        "--check-preflight",
        action="store_true",
        help="Inspect environment and quota readiness safely without dispatching any call.",
    )
    parser.add_argument(
        "--operator-authorized",
        action="store_true",
        help="Explicit operator authorization for ONE bounded search request.",
    )
    parser.add_argument(
        "--verified-capacity",
        action="store_true",
        help=(
            "Operator confirmation that account is Researcher Free, "
            "PAYG OFF, and credits available."
        ),
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to save sanitized evidence packet JSON.",
    )
    parser.add_argument(
        "--candidate-verdict",
        type=str,
        default="VERIFIED",
        choices=["VERIFIED", "CONTRADICTED", "BLOCKED", "INCONCLUSIVE"],
        help="Candidate execution verdict under sealed witness.",
    )

    args = parser.parse_args(argv)

    if args.check_preflight:
        preflight = check_live_tavily_preflight(operator_authorized=args.operator_authorized)
        print("=" * 60)
        print("BASEBREAK TAVILY PREFLIGHT STATUS")
        print("=" * 60)
        print(f"  API Key Configured:         {preflight.api_key_configured}")
        print(f"  Readiness State:            {preflight.readiness_state}")
        print(f"  Authorization Status:       {preflight.authorization_status}")
        print(f"  Expected Credit Exposure:   {preflight.expected_consumption} credit")
        print(f"  Zero-Cost Safeguard:        {preflight.zero_cost_safeguard_verified}")
        print("=" * 60)
        if not preflight.api_key_configured:
            print("\n[TR] BILDIRIM: TAVILY_API_KEY ortami su anda bos.")
            print("Gecici olarak ortam degiskeni eklemek icin:")
            print('  $env:TAVILY_API_KEY="tvly-..."')
            print("Ardindan tekrar kontrol edebilirsiniz.\n")
        return 0

    if not args.operator_authorized:
        print(
            "ERROR: Live execution requires explicit operator authorization: --operator-authorized",
            file=sys.stderr,
        )
        return 1

    if not args.verified_capacity:
        print(
            "ERROR: Live execution requires verified zero-cost capacity confirmation: "
            "--verified-capacity",
            file=sys.stderr,
        )
        return 1

    verdict_map = {
        "VERIFIED": PreliminaryVerdict.VERIFIED,
        "CONTRADICTED": PreliminaryVerdict.CONTRADICTED,
        "BLOCKED": PreliminaryVerdict.BLOCKED,
        "INCONCLUSIVE": PreliminaryVerdict.INCONCLUSIVE,
    }
    cand_verdict = verdict_map.get(args.candidate_verdict, PreliminaryVerdict.VERIFIED)

    try:
        packet, fw_res = run_tavily_cve_grounding_pipeline(
            operator_authorized=args.operator_authorized,
            verified_capacity=args.verified_capacity,
            candidate_execution_verdict=cand_verdict,
            persist_packet_path=args.output,
        )
        print("=" * 60)
        print("TAVILY GROUNDING PIPELINE COMPLETED")
        print("=" * 60)
        print(f"  Contract Digest:    {packet.contract_digest[:16]}...")
        print(f"  Requirement ID:     {packet.requirement_id}")
        print(f"  Firewall Status:    {packet.firewall_status}")
        print(f"  Firewall Verdict:   {packet.firewall_verdict}")
        print(f"  Credits Consumed:   {packet.credit_usage}")
        print(f"  Is Live Execution:  {packet.is_live}")
        if args.output:
            print(f"  Evidence Packet:    {args.output}")
        print("=" * 60)
        return 0
    except TavilyMissingKeyError as e:
        print(f"BLOCKED: {e}", file=sys.stderr)
        print(
            "Zero-cost safeguard enforced: no request dispatched. Status: MISSING_KEY_BLOCKED.",
            file=sys.stderr,
        )
        return 2
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
