"""End-to-end integration tests for P-15: Risk-Adaptive Verification Budget."""

from __future__ import annotations

from basebreak.budget.accounting import (
    BudgetLedger,
    ResourceLimits,
)
from basebreak.budget.depth_policy import (
    VerificationAction,
    resolve_verification_depth,
)
from basebreak.budget.fail_closed import (
    BudgetGateStatus,
    handle_budget_exhaustion,
    preflight_budget_admission,
)
from basebreak.budget.mandatory_policy import (
    resolve_mandatory_obligations,
    validate_executed_obligations,
)
from basebreak.budget.risk_features import (
    RiskLevel,
    classify_risk,
    extract_risk_features,
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


def _create_test_frozen_contract(change_class: ChangeClass = ChangeClass.BUG_FIX) -> FrozenContract:
    task_text = "Fix boundary off-by-one error in calculator parser."
    task = ingest_task(task_text)
    cit = task_text
    start = task.normalized_text.index(cit)
    end = start + len(cit)
    prop = ProposedRequirement(
        statement="Calculator handles boundary conditions without raising IndexError",
        citation=cit,
        citation_start=start,
        citation_end=end,
        rationale="Fix defect",
    )
    fact = DeterministicClassificationFact(
        inferred_class=change_class,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=1.0,
        alternative_classes=(),
        rationale="Deterministic test classification",
        evidence_citations=(cit,),
        matched_signals=("fix", "error"),
    )
    semantics = ChangeSemanticsClassification(
        task_digest=task.task_digest,
        change_class=change_class,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=1.0,
        alternative_classes=(),
        rationale="Deterministic test classification",
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


def test_end_to_end_low_risk_workflow() -> None:
    """Full workflow: FrozenContract -> RiskFeatures -> Classification -> Depth -> Accounting."""
    contract = _create_test_frozen_contract(ChangeClass.BUG_FIX)

    # 1. Extract risk features
    features = extract_risk_features(
        change_class=contract.change_class,
        certainty=contract.certainty,
        changed_files=("src/calc.py",),
        changed_lines_count=15,
        has_contractual_obligations=True,
    )
    assert features.changed_files_count == 1

    # 2. Classify risk
    classification = classify_risk(features)
    assert classification.risk_level == RiskLevel.LOW

    # 3. Resolve verification depth
    depth = resolve_verification_depth(classification)
    assert depth.depth_name == "MINIMAL_CAUSAL"
    assert VerificationAction.BASE_EXECUTION in depth.mandatory_actions
    assert VerificationAction.CANDIDATE_EXECUTION in depth.mandatory_actions
    assert depth.min_sandboxes_required == 2

    # 4. Resolve mandatory obligations
    obligations = resolve_mandatory_obligations(classification, patch_hunk_count=1)
    assert obligations.counterrun_mandatory is False
    assert obligations.slicing_mandatory is False

    # 5. Initialize budget ledger with operator ceilings
    ledger = BudgetLedger(
        limits=ResourceLimits(
            max_sandbox_executions=6,
            max_verifier_executions=6,
            max_total_tokens=10000,
            max_elapsed_seconds=120.0,
            max_estimated_cost_usd=0.50,
        )
    )

    # 6. Preflight admission
    admission = preflight_budget_admission(ledger, depth, obligations)
    assert admission.gate_status == BudgetGateStatus.ADMITTED

    # 7. Reserve and execute operations
    ledger.reserve("run-c0", sandboxes=2, verifier_executions=2)
    ledger.record_operation(
        "base-exec", sandbox_executions=1, verifier_executions=1, elapsed_seconds=2.0
    )
    ledger.record_operation(
        "cand-exec", sandbox_executions=1, verifier_executions=1, elapsed_seconds=2.5
    )
    ledger.commit_reservation("run-c0")

    # 8. Validate executed obligations
    validate_executed_obligations(
        obligations,
        counterrun_executed=False,
        counterrun_passed=False,
        slicing_executed=False,
        slicing_passed=False,
    )

    # 9. Verify ledger state
    assert ledger.consumption.sandbox_executions == 2
    assert ledger.consumption.verifier_executions == 2
    assert ledger.consumption.elapsed_seconds == 4.5


def test_end_to_end_high_risk_multi_hunk_security_workflow() -> None:
    """Full workflow: multi-hunk SECURITY_FIX mandates counterrun/slicing and catches deficit."""
    contract = _create_test_frozen_contract(ChangeClass.SECURITY_FIX)

    # 1. Extract risk features (touches security path + 4 files)
    features = extract_risk_features(
        change_class=contract.change_class,
        certainty=contract.certainty,
        changed_files=(
            "src/auth/jwt.py",
            "src/auth/roles.py",
            "src/api/routes.py",
            "src/middleware.py",
        ),
        changed_lines_count=120,
    )
    classification = classify_risk(features)
    assert classification.risk_level == RiskLevel.HIGH

    # 2. Depth requires deep causal verification
    depth = resolve_verification_depth(classification)
    assert depth.depth_name == "DEEP_CAUSAL"
    assert VerificationAction.COUNTERFACTUAL_EXECUTION in depth.mandatory_actions
    assert VerificationAction.REGRESSION_SUITE_EXECUTION in depth.mandatory_actions

    # 3. Mandatory obligations require counterrun AND slicing
    obligations = resolve_mandatory_obligations(classification, patch_hunk_count=4)
    assert obligations.counterrun_mandatory is True
    assert obligations.slicing_mandatory is True

    # 4. Budget insufficient: operator only provided 3 sandboxes (needs at least 6)
    ledger_tight = BudgetLedger(limits=ResourceLimits(max_sandbox_executions=3))
    admission_tight = preflight_budget_admission(ledger_tight, depth, obligations)
    assert admission_tight.gate_status == BudgetGateStatus.INSUFFICIENT_RESERVATION
    assert admission_tight.preliminary_verdict == PreliminaryVerdict.BLOCKED
    assert admission_tight.grants_pass is False

    # 5. Sufficient budget: operator provides 10 sandboxes
    ledger_generous = BudgetLedger(limits=ResourceLimits(max_sandbox_executions=10))
    admission_ok = preflight_budget_admission(ledger_generous, depth, obligations)
    assert admission_ok.gate_status == BudgetGateStatus.ADMITTED

    # 6. Execute base, candidate, counterrun, slice
    ledger_generous.record_operation("base-sec", sandbox_executions=1, verifier_executions=1)
    ledger_generous.record_operation("cand-sec", sandbox_executions=1, verifier_executions=1)
    ledger_generous.record_operation(
        "cr-sec", sandbox_executions=1, verifier_executions=1, counterrun_executions=1
    )
    ledger_generous.record_operation("slice-1", sandbox_executions=1, verifier_executions=1)
    ledger_generous.record_operation("slice-2", sandbox_executions=1, verifier_executions=1)

    # All mandatory obligations pass
    validate_executed_obligations(
        obligations,
        counterrun_executed=True,
        counterrun_passed=True,
        slicing_executed=True,
        slicing_passed=True,
    )


def test_witness_failure_during_repair_loop_unmasked_by_budget() -> None:
    """Witness failure unmasked by subsequent budget exhaustion remains CONTRADICTED."""
    features = extract_risk_features(
        change_class=ChangeClass.BUG_FIX, changed_files=("src/calc.py",)
    )
    classification = classify_risk(features)
    depth = resolve_verification_depth(classification)
    obligations = resolve_mandatory_obligations(classification)

    ledger = BudgetLedger(limits=ResourceLimits(max_sandbox_executions=1))
    # Execute BASE world, which fails to break (witness failure)
    ledger.record_operation("base", sandbox_executions=1)

    # Sandbox limit reached (1 of 1 used). Exhaustion occurs!
    exhaustion_result = handle_budget_exhaustion(
        ledger,
        depth,
        obligations,
        executed_actions=[VerificationAction.BASE_EXECUTION],
        witness_failure_observed=True,  # BASE world did not break!
        exhaustion_detail="Sandbox limit reached",
    )

    # Verdict must be CONTRADICTED, never BLOCKED or INCONCLUSIVE
    assert exhaustion_result.gate_status == BudgetGateStatus.CONTRADICTED_WITNESS
    assert exhaustion_result.preliminary_verdict == PreliminaryVerdict.CONTRADICTED
    assert exhaustion_result.grants_pass is False
