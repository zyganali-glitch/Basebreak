"""Tests for P-15.03: Cost, token, and sandbox budget accounting."""

from __future__ import annotations

from typing import cast

import pytest

from basebreak.budget.accounting import (
    BudgetExhaustedError,
    BudgetLedger,
    DuplicateOperationError,
    FinancialCostEstimate,
    InvalidAccountingValueError,
    ReservationError,
    ReservationStatus,
    ResourceLimits,
)
from basebreak.repair.engine import RepairLoopBudget, RepairLoopCounters


def test_financial_cost_estimate_invariants() -> None:
    """FinancialCostEstimate must reject false zero-cost claims, negative values, and NaN."""
    # Unknown cost cannot claim verified zero cost
    with pytest.raises(
        InvalidAccountingValueError, match="Cannot declare is_verified_zero_cost=True"
    ):
        FinancialCostEstimate(estimated_usd=None, is_verified_zero_cost=True)

    # Positive cost cannot claim verified zero cost
    with pytest.raises(
        InvalidAccountingValueError, match="Cannot declare is_verified_zero_cost=True"
    ):
        FinancialCostEstimate(estimated_usd=0.05, is_verified_zero_cost=True)

    # Negative cost rejected
    with pytest.raises(InvalidAccountingValueError, match="cannot be negative"):
        FinancialCostEstimate(estimated_usd=-1.0)

    # NaN cost rejected
    with pytest.raises(InvalidAccountingValueError, match="cannot be NaN"):
        FinancialCostEstimate(estimated_usd=float("nan"))

    # Legitimate verified zero cost (e.g. local deterministic execution)
    zero_cost = FinancialCostEstimate(estimated_usd=0.0, is_verified_zero_cost=True)
    assert zero_cost.is_verified_zero_cost is True
    assert zero_cost.estimated_usd == 0.0


def test_resource_limits_validation() -> None:
    """ResourceLimits must validate positive bounds and reject negative/invalid types."""
    # Negative tokens
    with pytest.raises(InvalidAccountingValueError, match="max_total_tokens"):
        ResourceLimits(max_total_tokens=-100)

    # Zero sandboxes
    with pytest.raises(InvalidAccountingValueError, match="max_sandbox_executions"):
        ResourceLimits(max_sandbox_executions=0)

    # Boolean passed as integer
    with pytest.raises(InvalidAccountingValueError, match="max_model_invocations"):
        ResourceLimits(max_model_invocations=cast(int, True))

    # Valid limits
    limits = ResourceLimits(
        max_total_tokens=10000,
        max_sandbox_executions=5,
        max_verifier_executions=5,
        max_elapsed_seconds=120.0,
        max_estimated_cost_usd=1.0,
    )
    assert limits.max_total_tokens == 10000
    assert limits.max_sandbox_executions == 5


def test_ledger_deduplication() -> None:
    """BudgetLedger must reject duplicate operation IDs to prevent double-charging."""
    ledger = BudgetLedger()
    ledger.record_operation("op-1", input_tokens=100, output_tokens=50)

    with pytest.raises(DuplicateOperationError, match="has already been recorded"):
        ledger.record_operation("op-1", input_tokens=100, output_tokens=50)

    assert ledger.consumption.total_tokens == 150
    assert len(ledger.consumption.recorded_operation_ids) == 1


def test_reservation_lifecycle() -> None:
    """Pre-execution reservation lifecycle: reserve -> commit, reserve -> cancel."""
    ledger = BudgetLedger(
        limits=ResourceLimits(
            max_sandbox_executions=4,
            max_verifier_executions=4,
        )
    )

    # 1. Reserve 2 sandboxes
    res1 = ledger.reserve("res-a", sandboxes=2, verifier_executions=2)
    assert res1.status == ReservationStatus.PENDING
    assert ledger.get_active_reserved_sandboxes() == 2

    # 2. Attempt to reserve 3 more (exceeds total limit of 4)
    with pytest.raises(BudgetExhaustedError, match="Insufficient sandbox budget"):
        ledger.reserve("res-b", sandboxes=3)

    # 3. Commit res-a
    ledger.commit_reservation("res-a")
    assert ledger.get_active_reserved_sandboxes() == 0

    # 4. Reserve and cancel
    ledger.reserve("res-c", sandboxes=2)
    assert ledger.get_active_reserved_sandboxes() == 2
    ledger.cancel_reservation("res-c")
    assert ledger.get_active_reserved_sandboxes() == 0

    # 5. Cancelling already cancelled reservation raises error
    with pytest.raises(ReservationError, match="Cannot cancel reservation"):
        ledger.cancel_reservation("res-c")


def test_budget_exhaustion_on_limits() -> None:
    """Recording operations that exceed limits must immediately raise BudgetExhaustedError."""
    # Token ceiling
    l1 = BudgetLedger(limits=ResourceLimits(max_total_tokens=500))
    l1.record_operation("op-token-1", total_tokens=400)
    with pytest.raises(BudgetExhaustedError, match="Token limit exceeded"):
        l1.record_operation("op-token-2", total_tokens=200)

    # Model invocations ceiling
    l2 = BudgetLedger(limits=ResourceLimits(max_model_invocations=1))
    l2.record_operation("op-model-1", is_model_invocation=True)
    with pytest.raises(BudgetExhaustedError, match="Model invocation limit exceeded"):
        l2.record_operation("op-model-2", is_model_invocation=True)

    # Sandbox executions ceiling
    l3 = BudgetLedger(limits=ResourceLimits(max_sandbox_executions=2))
    l3.record_operation("op-sbx-1", sandbox_executions=2)
    with pytest.raises(BudgetExhaustedError, match="Sandbox execution limit exceeded"):
        l3.record_operation("op-sbx-2", sandbox_executions=1)

    # Financial cost ceiling
    l4 = BudgetLedger(limits=ResourceLimits(max_estimated_cost_usd=0.10))
    l4.record_operation("op-cost-1", financial_cost=FinancialCostEstimate(estimated_usd=0.08))
    with pytest.raises(BudgetExhaustedError, match="Financial cost limit exceeded"):
        l4.record_operation("op-cost-2", financial_cost=FinancialCostEstimate(estimated_usd=0.05))


def test_repair_loop_budget_composition() -> None:
    """BudgetLedger must compose cleanly with RepairLoopBudget and RepairLoopCounters."""
    orig_repair_budget = RepairLoopBudget(
        max_repair_rounds=2,
        max_builder_attempts=3,
        max_sandbox_executions=6,
        max_verifier_executions=6,
        max_token_budget=50000,
        max_clock_seconds=180.0,
    )

    ledger = BudgetLedger.from_repair_loop_budget(orig_repair_budget)
    assert ledger.limits.max_sandbox_executions == 6
    assert ledger.limits.max_verifier_executions == 6
    assert ledger.limits.max_total_tokens == 50000
    assert ledger.limits.max_elapsed_seconds == 180.0

    # Convert back to RepairLoopBudget
    converted_budget = ledger.to_repair_loop_budget()
    assert converted_budget.max_builder_attempts == 3
    assert converted_budget.max_sandbox_executions == 6
    assert converted_budget.max_token_budget == 50000

    # Synchronize consumption from RepairLoopCounters
    counters = RepairLoopCounters(
        builder_attempts_used=2,
        verifier_executions_used=4,
        sandbox_executions_used=4,
        tokens_used=12000,
    )
    ledger.sync_from_repair_loop_counters(counters)
    assert ledger.consumption.model_invocations == 2
    assert ledger.consumption.verifier_executions == 4
    assert ledger.consumption.sandbox_executions == 4
    assert ledger.consumption.total_tokens == 12000


def test_transactional_state_equality_on_rejected_financial_overspend() -> None:
    """Defect C: Denied financial overspend must leave ledger state 100% unchanged."""
    ledger = BudgetLedger(
        limits=ResourceLimits(
            max_total_tokens=1000,
            max_sandbox_executions=10,
            max_estimated_cost_usd=0.10,
        )
    )
    ledger.record_operation("op-init", total_tokens=100, sandbox_executions=1)
    snapshot_before = ledger.to_dict()

    # Attempt operation that exceeds max_estimated_cost_usd ($0.15 > $0.10)
    # but requests tokens and sandboxes that would have partially mutated the ledger if non-atomic
    with pytest.raises(BudgetExhaustedError, match="Financial cost limit exceeded"):
        ledger.record_operation(
            "op-fail",
            total_tokens=200,
            sandbox_executions=2,
            financial_cost=FinancialCostEstimate(estimated_usd=0.15),
        )

    # Invariant: Consumption, reservations, and recorded operation IDs remain strictly unchanged
    snapshot_after = ledger.to_dict()
    assert snapshot_after == snapshot_before
    assert "op-fail" not in ledger.consumption.recorded_operation_ids


def test_transactional_state_equality_on_all_rejected_ceilings() -> None:
    """Defect C: Any ceiling violation leaves ledger state strictly unchanged."""
    ledger = BudgetLedger(
        limits=ResourceLimits(
            max_input_tokens=100,
            max_output_tokens=100,
            max_total_tokens=150,
            max_sandbox_executions=2,
            max_verifier_executions=2,
            max_elapsed_seconds=10.0,
        )
    )
    ledger.record_operation("op-base", input_tokens=40, output_tokens=40, total_tokens=80)
    snapshot_before = ledger.to_dict()

    # 1. Exceed input tokens
    with pytest.raises(BudgetExhaustedError, match="Input token limit exceeded"):
        ledger.record_operation("op-fail-in", input_tokens=70, output_tokens=10)
    assert ledger.to_dict() == snapshot_before

    # 2. Exceed output tokens
    with pytest.raises(BudgetExhaustedError, match="Output token limit exceeded"):
        ledger.record_operation("op-fail-out", input_tokens=10, output_tokens=70)
    assert ledger.to_dict() == snapshot_before

    # 3. Exceed total tokens
    with pytest.raises(BudgetExhaustedError, match="Token limit exceeded"):
        ledger.record_operation("op-fail-tot", total_tokens=80)
    assert ledger.to_dict() == snapshot_before

    # 4. Exceed sandboxes
    with pytest.raises(BudgetExhaustedError, match="Sandbox execution limit exceeded"):
        ledger.record_operation("op-fail-sbx", sandbox_executions=3)
    assert ledger.to_dict() == snapshot_before

    # 5. Exceed verifiers
    with pytest.raises(BudgetExhaustedError, match="Verifier execution limit exceeded"):
        ledger.record_operation("op-fail-ver", verifier_executions=3)
    assert ledger.to_dict() == snapshot_before

    # 6. Exceed time
    with pytest.raises(BudgetExhaustedError, match="Time limit exceeded"):
        ledger.record_operation("op-fail-time", elapsed_seconds=20.0)
    assert ledger.to_dict() == snapshot_before

    # 7. Duplicate operation ID does not alter state
    with pytest.raises(DuplicateOperationError, match="already been recorded"):
        ledger.record_operation("op-base", total_tokens=10)
    assert ledger.to_dict() == snapshot_before


def test_inconsistent_token_counts_rejected() -> None:
    """Defect C: Reject inconsistent reported total_tokens vs input_tokens + output_tokens."""
    ledger = BudgetLedger()
    snapshot_before = ledger.to_dict()

    with pytest.raises(InvalidAccountingValueError, match="Inconsistent token counts"):
        ledger.record_operation("op-bad", input_tokens=100, output_tokens=50, total_tokens=200)

    assert ledger.to_dict() == snapshot_before


def test_unreserved_operation_cannot_bypass_active_reservation() -> None:
    """Defect C: Active reservations cannot be bypassed by unrelated unreserved operations."""
    ledger = BudgetLedger(
        limits=ResourceLimits(
            max_sandbox_executions=4,
            max_total_tokens=1000,
        )
    )

    # Reserve 3 sandboxes for reservation res-active
    ledger.reserve("res-active", sandboxes=3, tokens=600)
    assert ledger.get_active_reserved_sandboxes() == 3
    assert ledger.get_active_reserved_tokens() == 600

    # Unreserved operation requesting 2 sandboxes must fail (4 - 3 = 1 available for unreserved)
    with pytest.raises(BudgetExhaustedError, match="Sandbox execution limit exceeded"):
        ledger.record_operation("op-unreserved-fail", sandbox_executions=2)

    # Unreserved operation requesting 500 tokens must fail
    # (1000 - 600 = 400 available for unreserved)
    with pytest.raises(BudgetExhaustedError, match="Token limit exceeded"):
        ledger.record_operation("op-unreserved-tok-fail", total_tokens=500)

    # Unreserved operation within remaining unreserved capacity succeeds
    ledger.record_operation("op-unreserved-ok", sandbox_executions=1, total_tokens=300)
    assert ledger.consumption.sandbox_executions == 1
    assert ledger.consumption.total_tokens == 300

    # Operation associated with res-active can use its reserved capacity
    ledger.record_operation(
        "op-reserved-ok",
        reservation_id="res-active",
        sandbox_executions=3,
        total_tokens=600,
    )
    assert ledger.consumption.sandbox_executions == 4
    assert ledger.consumption.total_tokens == 900
