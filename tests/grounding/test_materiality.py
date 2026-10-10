"""Tests for P-16.01: Deterministic Grounding Materiality Policy."""

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
from basebreak.grounding.materiality import (
    AUTHORITATIVE_CVE_DOMAINS,
    AUTHORITATIVE_DEP_API_DOMAINS,
    GroundingCategory,
    GroundingMateriality,
    MaterialityDecision,
    evaluate_grounding_materiality,
    verify_materiality_digest,
)


def _make_frozen_contract(
    task_text: str,
    change_class: ChangeClass = ChangeClass.BUG_FIX,
    statement: str = "Requirement statement",
) -> FrozenContract:
    task = ingest_task(task_text)
    cit = task_text
    start = task.normalized_text.index(cit)
    end = start + len(cit)
    prop = ProposedRequirement(
        statement=statement,
        citation=cit,
        citation_start=start,
        citation_end=end,
        rationale="Test requirement",
    )
    fact = DeterministicClassificationFact(
        inferred_class=change_class,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=1.0,
        alternative_classes=(),
        rationale="Test classification",
        evidence_citations=(cit,),
        matched_signals=("test",),
    )
    semantics = ChangeSemanticsClassification(
        task_digest=task.task_digest,
        change_class=change_class,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=1.0,
        alternative_classes=(),
        rationale="Test classification",
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


def test_security_fix_with_cve_is_materially_required() -> None:
    task_text = (
        "Fix CVE-2024-21626 container escape vulnerability in runc file descriptor handling."
    )
    contract = _make_frozen_contract(task_text, ChangeClass.SECURITY_FIX)
    req = contract.requirements[0]

    decision = evaluate_grounding_materiality(contract, req)

    assert decision.materiality == GroundingMateriality.REQUIRED
    assert decision.category == GroundingCategory.CVE_SECURITY_ADVISORY
    assert decision.external_reference == "CVE-2024-21626"
    assert "CVE-2024-21626" in (decision.permitted_query or "")
    assert set(decision.allowed_domains) == set(AUTHORITATIVE_CVE_DOMAINS)
    assert verify_materiality_digest(decision) is True


def test_security_fix_self_contained_is_not_applicable() -> None:
    task_text = "Fix buffer overrun in internal image decoding routine."
    contract = _make_frozen_contract(task_text, ChangeClass.SECURITY_FIX)
    req = contract.requirements[0]

    decision = evaluate_grounding_materiality(contract, req)

    assert decision.materiality == GroundingMateriality.NOT_APPLICABLE
    assert decision.category is None
    assert decision.permitted_query is None
    assert verify_materiality_digest(decision) is True


def test_dep_api_migration_with_release_notes_is_materially_required() -> None:
    task_text = (
        "Perform library migration to urllib3>=2.0.0 handling breaking change in method signature."
    )
    contract = _make_frozen_contract(task_text, ChangeClass.DEP_API_CHANGE)
    req = contract.requirements[0]

    decision = evaluate_grounding_materiality(contract, req, external_reference="urllib3>=2.0.0")

    assert decision.materiality == GroundingMateriality.REQUIRED
    assert decision.category == GroundingCategory.DEP_API_MIGRATION
    assert decision.external_reference == "urllib3>=2.0.0"
    assert set(decision.allowed_domains) == set(AUTHORITATIVE_DEP_API_DOMAINS)
    assert verify_materiality_digest(decision) is True


def test_ordinary_bug_fix_never_triggers_web_search() -> None:
    # Mentions Python, Flask, HTTP, JSON - must NOT trigger grounding
    task_text = (
        "Fix JSON serialization error in Flask HTTP endpoint handling Python datetime objects."
    )
    contract = _make_frozen_contract(task_text, ChangeClass.BUG_FIX)
    req = contract.requirements[0]

    decision = evaluate_grounding_materiality(contract, req)

    assert decision.materiality == GroundingMateriality.NOT_APPLICABLE
    assert decision.category is None
    assert decision.permitted_query is None
    assert "prohibited and not applicable" in decision.rationale
    assert verify_materiality_digest(decision) is True


def test_refactor_and_performance_are_not_applicable() -> None:
    for cls in (ChangeClass.REFACTOR, ChangeClass.PERFORMANCE):
        contract = _make_frozen_contract(f"Optimize {cls.name} in search indexing.", cls)
        decision = evaluate_grounding_materiality(contract)
        assert decision.materiality == GroundingMateriality.NOT_APPLICABLE
        assert verify_materiality_digest(decision) is True


def test_forced_unverifiable_decision() -> None:
    contract = _make_frozen_contract("Fix impossible conflicting requirement.", ChangeClass.BUG_FIX)
    decision = evaluate_grounding_materiality(contract, forced_unverifiable=True)

    assert decision.materiality == GroundingMateriality.UNVERIFIABLE
    assert decision.category is None
    assert "contradictory" in decision.rationale
    assert verify_materiality_digest(decision) is True


def test_materiality_decision_tamper_rejection() -> None:
    contract = _make_frozen_contract(
        "Fix CVE-2024-3094 backdoor in upstream source.", ChangeClass.SECURITY_FIX
    )
    decision = evaluate_grounding_materiality(contract)

    # Valid decision verifies
    assert verify_materiality_digest(decision) is True

    # Tampered decision digest fails post_init
    with pytest.raises(ValueError, match="decision_digest mismatch"):
        MaterialityDecision(
            decision_id=decision.decision_id,
            contract_digest=decision.contract_digest,
            requirement_id=decision.requirement_id,
            materiality=decision.materiality,
            category=decision.category,
            external_reference=decision.external_reference,
            permitted_query=decision.permitted_query,
            allowed_domains=decision.allowed_domains,
            rationale="Tampered rationale",
            decision_digest=decision.decision_digest,
        )
