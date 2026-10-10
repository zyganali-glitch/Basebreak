"""Integrated closure test suite for P-16: External Grounding & Tavily."""

from __future__ import annotations

import json
from typing import Any

import pytest

from basebreak.adapters.tavily.client import TavilyClient
from basebreak.adapters.tavily.demo import (
    check_live_tavily_preflight,
    execute_live_tavily_demonstration,
)
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
from basebreak.domain.verdict import PreliminaryVerdict
from basebreak.grounding.evidence import (
    create_grounded_binding,
    create_grounded_fact,
    verify_grounded_binding_digest,
    verify_grounded_fact_digest,
)
from basebreak.grounding.firewall import (
    GroundingStatus,
    evaluate_grounding_firewall,
)
from basebreak.grounding.materiality import (
    GroundingCategory,
    GroundingMateriality,
    evaluate_grounding_materiality,
    verify_materiality_digest,
)


class MockHttpResponse:
    def __init__(self, data: bytes, status: int = 200) -> None:
        self._data = data
        self.status = status

    def read(self) -> bytes:
        return self._data

    def __enter__(self) -> MockHttpResponse:
        return self

    def __exit__(self, *args: Any) -> None:
        pass


def _make_frozen_cve_contract() -> FrozenContract:
    task_text = "Fix CVE-2024-21626 runc file descriptor leakage on container process exec."
    task = ingest_task(task_text)
    cit = task_text
    prop = ProposedRequirement(
        statement=(
            "All file descriptors above 2 are verified closed prior to executing target process"
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


def test_p16_end_to_end_grounding_lifecycle() -> None:
    """Validate P-16.01 -> P-16.02 -> P-16.03 -> P-16.04 full lifecycle."""
    contract = _make_frozen_cve_contract()
    req = contract.requirements[0]

    # P-16.01: Materiality evaluation
    decision = evaluate_grounding_materiality(contract, req)
    assert decision.materiality == GroundingMateriality.REQUIRED
    assert decision.category == GroundingCategory.CVE_SECURITY_ADVISORY
    assert decision.external_reference == "CVE-2024-21626"
    assert verify_materiality_digest(decision) is True

    # P-16.02: Bounded Tavily search (mocked HTTP)
    def mock_opener(req: Any, timeout: float = 10.0) -> MockHttpResponse:
        resp_data = {
            "query": "CVE-2024-21626",
            "results": [
                {
                    "title": "CVE-2024-21626 Advisory",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
                    "content": (
                        "CVE-2024-21626: runc <= 1.1.11 leaks internal file descriptors. "
                        "Fixed in runc 1.1.12."
                    ),
                    "score": 0.98,
                    "published_date": "2024-01-31",
                }
            ],
            "response_time": 0.25,
            "usage": {"credits": 1},
            "request_id": "req-p16-closure-001",
        }
        return MockHttpResponse(json.dumps(resp_data).encode("utf-8"))

    client = TavilyClient(api_key="tvly-mock-p16-key", opener=mock_opener)
    response = client.search(decision.permitted_query or "CVE-2024-21626", max_results=3)
    assert response.credits_used == 1
    assert len(response.results) == 1

    # P-16.03: Bind into GroundedContractBinding (honestly marked as fixture since mock was used)
    item = response.results[0]
    fact = create_grounded_fact(
        contract=contract,
        requirement_id=req.requirement_id,
        source_url=item.url,
        publisher="nvd.nist.gov",
        retrieved_claim=item.content,
        materiality=decision.materiality,
        observation_timestamp="2026-10-10T08:00:00Z",
        published_date=item.published_date,
        retrieval_provider="tavily",
        provider_response_id=response.request_id,
        is_fixture=True,
    )
    assert verify_grounded_fact_digest(fact) is True

    binding = create_grounded_binding(
        contract=contract,
        decision=decision,
        facts=[fact],
        binding_timestamp="2026-10-10T08:01:00Z",
    )
    assert verify_grounded_binding_digest(binding) is True

    # P-16.04: Evaluate through authority firewall
    # Offline fixture evidence CANNOT satisfy mandatory live grounding: fail-closed BLOCKED
    firewall_result = evaluate_grounding_firewall(
        materiality=decision,
        binding=binding,
        execution_verdict=PreliminaryVerdict.VERIFIED,
    )
    assert firewall_result.final_verdict == PreliminaryVerdict.BLOCKED
    assert firewall_result.grounding_status == GroundingStatus.FIXTURE_ONLY_GROUNDING
    assert firewall_result.execution_verdict_preserved is False
    assert "fixture_only:mandatory_grounding" in firewall_result.adversarial_flags


def test_p16_05_operator_authorization_gate_enforcement() -> None:
    """Validate P-16.05 hard stop gate behavior and anti-laundering rules."""
    contract = _make_frozen_cve_contract()

    # Preflight check: unverified without live account inspection
    preflight = check_live_tavily_preflight()
    assert preflight.authorization_status == "OPERATOR_AUTHORIZATION_REQUIRED"
    assert preflight.expected_consumption == 1
    assert preflight.current_verified_credits is None
    assert preflight.current_quota_verified is False
    assert preflight.zero_cost_safeguard_verified is False
    assert "BLOCKED" in preflight.readiness_state

    # 1. Without explicit operator authorization -> FAILS CLOSED
    with pytest.raises(PermissionError, match="OPERATOR_AUTHORIZATION_REQUIRED"):
        execute_live_tavily_demonstration(contract, operator_authorized=False)

    # 2. Authorized but without verified capacity -> FAILS CLOSED
    with pytest.raises(RuntimeError, match="current quota capacity"):
        execute_live_tavily_demonstration(
            contract, operator_authorized=True, verified_capacity=False
        )

    # 3. Passing injected mock client to LIVE demo -> FAILS CLOSED (anti-laundering)
    def mock_opener(req: Any, timeout: float = 10.0) -> MockHttpResponse:
        resp_data = {
            "query": "CVE-2024-21626",
            "results": [
                {
                    "title": "GHSA Advisory",
                    "url": "https://github.com/opencontainers/runc/security/advisories/GHSA-c3cr-m6c4-2r3x",
                    "content": "Fixed CVE-2024-21626 in runc 1.1.12.",
                    "score": 0.99,
                    "published_date": "2024-01-31",
                }
            ],
            "response_time": 0.20,
            "usage": {"credits": 1},
            "request_id": "req-authorized-demo",
        }
        return MockHttpResponse(json.dumps(resp_data).encode("utf-8"))

    mock_client = TavilyClient(api_key="tvly-mock-auth-key", opener=mock_opener)
    with pytest.raises(ValueError, match="Fixture laundering rejected"):
        execute_live_tavily_demonstration(
            contract,
            operator_authorized=True,
            verified_capacity=True,
            client=mock_client,
        )

    # 4. Honest offline fixture demonstration executes and marks facts as fixture
    from basebreak.adapters.tavily.demo import execute_fixture_tavily_demonstration

    resp, binding = execute_fixture_tavily_demonstration(
        contract,
        client=mock_client,
    )
    assert resp.credits_used == 1
    assert len(binding.facts) == 1
    assert binding.facts[0].is_fixture is True
    assert verify_grounded_binding_digest(binding) is True

    # 5. Reject unmocked live network client from offline fixture demonstration
    live_client = TavilyClient(api_key="tvly-mock-live-key")
    with pytest.raises(ValueError, match="Live network client rejected from fixture"):
        execute_fixture_tavily_demonstration(contract, client=live_client)

    # 6. Reject supplied client that permits retries or multiple attempts from live demo
    retry_client = TavilyClient(
        api_key="tvly-mock-live-key",
        allow_retries=True,
        single_call_only=False,
    )
    with pytest.raises(ValueError, match="single_call_only=True and allow_retries=False"):
        execute_live_tavily_demonstration(
            contract,
            operator_authorized=True,
            verified_capacity=True,
            client=retry_client,
        )

    # 7. Focused Grounding Honesty: snippet mentioning CVE without substantive fix context
    from basebreak.adapters.tavily.demo import verify_advisory_snippet_support

    unrelated_snippet = (
        "In our latest cybersecurity episode we mention CVE-2024-21626 among weekly tags."
    )
    assert verify_advisory_snippet_support(unrelated_snippet, "CVE-2024-21626") is False

    version_only_snippet = (
        "In version 4 of our weekly cybersecurity roundup, CVE-2024-21626 was listed in index."
    )
    assert verify_advisory_snippet_support(version_only_snippet, "CVE-2024-21626") is False

    supported_snippet = (
        "CVE-2024-21626 vulnerability in runc allowed container escape; fixed in version 1.1.12."
    )
    assert verify_advisory_snippet_support(supported_snippet, "CVE-2024-21626") is True

    # 8. Negative laundering test: caller-supplied is_fixture=False without verified observation
    from basebreak.grounding.evidence import create_grounded_fact

    req = contract.requirements[0]
    decision = evaluate_grounding_materiality(contract, req)
    fake_live_fact = create_grounded_fact(
        contract=contract,
        requirement_id=req.requirement_id,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
        publisher="nvd.nist.gov",
        retrieved_claim="CVE-2024-21626 fixed in runc 1.1.12.",
        materiality=GroundingMateriality.REQUIRED,
        observation_timestamp="2026-10-10T08:00:00Z",
        is_fixture=False,
    )
    fake_live_binding = create_grounded_binding(
        contract=contract,
        decision=decision,
        facts=[fake_live_fact],
        binding_timestamp="2026-10-10T08:00:00Z",
    )
    laundering_eval = evaluate_grounding_firewall(
        materiality=decision,
        binding=fake_live_binding,
        execution_verdict=PreliminaryVerdict.VERIFIED,
    )
    assert laundering_eval.final_verdict == PreliminaryVerdict.BLOCKED
    assert laundering_eval.grounding_status == GroundingStatus.INSUFFICIENT_GROUNDING
    assert any("unverified_live_claim" in f for f in laundering_eval.adversarial_flags)
