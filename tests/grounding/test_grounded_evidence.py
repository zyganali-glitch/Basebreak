"""Tests for P-16.03: Grounded Contract Evidence Records and Binding."""

from __future__ import annotations

import pytest

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
from basebreak.grounding.evidence import (
    GroundedContractBinding,
    GroundedFact,
    UncertaintyState,
    create_grounded_binding,
    create_grounded_fact,
    reconcile_fact_uncertainty,
    verify_grounded_binding_digest,
    verify_grounded_fact_digest,
)
from basebreak.grounding.materiality import (
    GroundingMateriality,
    evaluate_grounding_materiality,
)


def _make_frozen_contract() -> FrozenContract:
    task_text = "Fix CVE-2024-21626 container breakout vulnerability in runc."
    task = ingest_task(task_text)
    cit = task_text
    prop = ProposedRequirement(
        statement="runc closes leaked file descriptors before executing user process",
        citation=cit,
        citation_start=0,
        citation_end=len(cit),
        rationale="Security fix requirement",
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


def test_create_grounded_fact_and_verify_digest() -> None:
    contract = _make_frozen_contract()
    fact = create_grounded_fact(
        contract=contract,
        requirement_id=contract.requirements[0].requirement_id,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
        publisher="nvd.nist.gov",
        retrieved_claim="runc versions up to 1.1.11 suffer from an internal file descriptor leak.",
        materiality=GroundingMateriality.REQUIRED,
        observation_timestamp="2026-10-10T08:00:00Z",
        published_date="2024-01-31T00:00:00Z",
        retrieval_provider="tavily",
        provider_response_id="req-12345",
        is_fixture=False,
    )

    assert isinstance(fact, GroundedFact)
    assert fact.contract_digest == contract.contract_digest
    assert fact.publisher == "nvd.nist.gov"
    assert verify_grounded_fact_digest(fact) is True


def test_grounded_fact_tamper_detection() -> None:
    contract = _make_frozen_contract()
    fact = create_grounded_fact(
        contract=contract,
        requirement_id=contract.requirements[0].requirement_id,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
        publisher="nvd.nist.gov",
        retrieved_claim="Original valid claim.",
        materiality=GroundingMateriality.REQUIRED,
        observation_timestamp="2026-10-10T08:00:00Z",
    )

    # Tampering with claim text
    with pytest.raises(ValueError, match="evidence_digest mismatch"):
        GroundedFact(
            fact_id=fact.fact_id,
            contract_digest=fact.contract_digest,
            requirement_id=fact.requirement_id,
            source_url=fact.source_url,
            publisher=fact.publisher,
            retrieved_claim="Tampered altered claim text",
            observation_timestamp=fact.observation_timestamp,
            published_date=fact.published_date,
            retrieval_provider=fact.retrieval_provider,
            provider_response_id=fact.provider_response_id,
            materiality=fact.materiality,
            is_fixture=fact.is_fixture,
            freshness_state=fact.freshness_state,
            uncertainty_state=fact.uncertainty_state,
            evidence_digest=fact.evidence_digest,
        )


def test_grounded_contract_binding_creation_and_auditability() -> None:
    contract = _make_frozen_contract()
    decision = evaluate_grounding_materiality(contract, contract.requirements[0])
    fact1 = create_grounded_fact(
        contract=contract,
        requirement_id=contract.requirements[0].requirement_id,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
        publisher="nvd.nist.gov",
        retrieved_claim="Vulnerability advisory 1.",
        materiality=GroundingMateriality.REQUIRED,
        observation_timestamp="2026-10-10T08:00:00Z",
    )
    fact2 = create_grounded_fact(
        contract=contract,
        requirement_id=contract.requirements[0].requirement_id,
        source_url="https://github.com/opencontainers/runc/security/advisories/GHSA-c3cr-m6c4-2r3x",
        publisher="github.com",
        retrieved_claim="GitHub Security Advisory: Fixed in runc 1.1.12.",
        materiality=GroundingMateriality.REQUIRED,
        observation_timestamp="2026-10-10T08:00:00Z",
    )

    binding = create_grounded_binding(
        contract=contract,
        decision=decision,
        facts=[fact1, fact2],
        binding_timestamp="2026-10-10T08:01:00Z",
    )

    assert isinstance(binding, GroundedContractBinding)
    assert binding.contract_digest == contract.contract_digest
    assert len(binding.facts) == 2
    assert binding.overall_uncertainty == UncertaintyState.CERTAIN
    assert verify_grounded_binding_digest(binding) is True

    # Critical invariant: FrozenContract digest remains unchanged!
    assert binding.contract_digest == contract.contract_digest


def test_reconcile_fact_uncertainty_states() -> None:
    contract = _make_frozen_contract()
    # Empty -> INSUFFICIENT
    assert reconcile_fact_uncertainty([]) == UncertaintyState.INSUFFICIENT

    fact_clean = create_grounded_fact(
        contract=contract,
        requirement_id="REQ-1",
        source_url="https://example.com/1",
        publisher="example.com",
        retrieved_claim="Claim A",
        materiality=GroundingMateriality.REQUIRED,
        observation_timestamp="2026-10-10T08:00:00Z",
        uncertainty_state=UncertaintyState.CERTAIN,
    )
    fact_contradictory = create_grounded_fact(
        contract=contract,
        requirement_id="REQ-1",
        source_url="https://example.com/2",
        publisher="example.com",
        retrieved_claim="Contradicting claim B",
        materiality=GroundingMateriality.REQUIRED,
        observation_timestamp="2026-10-10T08:00:00Z",
        uncertainty_state=UncertaintyState.CONTRADICTORY,
    )

    # Clean only -> CERTAIN
    assert reconcile_fact_uncertainty([fact_clean]) == UncertaintyState.CERTAIN

    # Contradictory present -> CONTRADICTORY
    assert (
        reconcile_fact_uncertainty([fact_clean, fact_contradictory])
        == UncertaintyState.CONTRADICTORY
    )
