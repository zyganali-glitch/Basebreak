"""Bounded cost, token, and sandbox resource accounting.

P-15.03: Add cost/token/sandbox budget accounting under the
Basebreak causal verification authority model.

Authority Model & Invariants:
1. Strict Value Validation:
   Rejects negative, malformed, NaN, infinite, overflowing, or contradictory values.
2. Honest Cost & Billing Truth:
   Never present unavailable or unknown provider billing facts as verified zero cost.
   is_verified_zero_cost is True ONLY when deterministically proven (e.g. local offline execution).
3. Upper Constraint Law:
   Operator budget is an absolute upper ceiling, NEVER permission to spend beyond limits.
4. Idempotent Accounting & Deduplication:
   Operation identities prevent duplicate counting/charging for the same verified action.
5. Reservation & Reconciliation:
   Supports pre-execution reservation and post-execution commitment/cancellation.
6. Seamless Composition:
   Composes cleanly with RepairLoopBudget and RepairLoopCounters without weakening their guarantees.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from basebreak.repair.engine import RepairLoopBudget, RepairLoopCounters

ACCOUNTING_SCHEMA_VERSION: str = "1.0.0"


class AccountingError(Exception):
    """Base exception for budget accounting errors."""


class BudgetExhaustedError(AccountingError):
    """Raised when an operation or reservation exceeds configured budget limits."""


class InvalidAccountingValueError(AccountingError):
    """Raised when an accounting value is negative, NaN, infinite, or contradictory."""


class DuplicateOperationError(AccountingError):
    """Raised when an operation identity has already been recorded."""


class ReservationError(AccountingError):
    """Raised when reservation state transition is invalid."""


class ReservationStatus(str, Enum):
    """Status lifecycle of a resource reservation."""

    PENDING = "PENDING"
    COMMITTED = "COMMITTED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True, slots=True)
class FinancialCostEstimate:
    """Estimated financial cost representation.

    Invariant: If estimated_usd is None, is_verified_zero_cost MUST be False.
    """

    estimated_usd: float | None = None
    is_verified_zero_cost: bool = False
    currency: str = "USD"
    rate_basis: str = ""

    def __post_init__(self) -> None:
        if self.estimated_usd is None:
            if self.is_verified_zero_cost:
                raise InvalidAccountingValueError(
                    "Cannot declare is_verified_zero_cost=True when estimated_usd is None (unknown)"
                )
        else:
            if isinstance(self.estimated_usd, bool) or not isinstance(
                self.estimated_usd, (int, float)
            ):
                raise InvalidAccountingValueError(
                    f"estimated_usd must be numeric, got {type(self.estimated_usd).__name__}"
                )
            if math.isnan(self.estimated_usd) or math.isinf(self.estimated_usd):
                raise InvalidAccountingValueError("estimated_usd cannot be NaN or Infinite")
            if self.estimated_usd < 0.0:
                raise InvalidAccountingValueError(
                    f"estimated_usd cannot be negative, got {self.estimated_usd}"
                )
            if self.estimated_usd > 0.0 and self.is_verified_zero_cost:
                raise InvalidAccountingValueError(
                    f"Cannot declare is_verified_zero_cost=True when cost is {self.estimated_usd}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "currency": self.currency,
            "estimated_usd": round(self.estimated_usd, 6)
            if self.estimated_usd is not None
            else None,
            "is_verified_zero_cost": self.is_verified_zero_cost,
            "rate_basis": self.rate_basis,
        }


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """Configured bounded resource ceilings. None indicates unconfigured limit."""

    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    max_total_tokens: int | None = None
    max_model_invocations: int | None = None
    max_sandbox_creations: int | None = None
    max_sandbox_executions: int | None = None
    max_verifier_executions: int | None = None
    max_counterrun_executions: int | None = None
    max_elapsed_seconds: float | None = None
    max_estimated_cost_usd: float | None = None

    def __post_init__(self) -> None:
        # Validate integer limits
        for name in (
            "max_input_tokens",
            "max_output_tokens",
            "max_total_tokens",
            "max_model_invocations",
            "max_sandbox_creations",
            "max_sandbox_executions",
            "max_verifier_executions",
            "max_counterrun_executions",
        ):
            val = getattr(self, name)
            if val is not None:
                if isinstance(val, bool) or not isinstance(val, int):
                    raise InvalidAccountingValueError(
                        f"{name} must be an integer, got {type(val).__name__}"
                    )
                if val <= 0:
                    raise InvalidAccountingValueError(
                        f"{name} must be a positive integer, got {val}"
                    )

        # Validate float limits
        for name in ("max_elapsed_seconds", "max_estimated_cost_usd"):
            val = getattr(self, name)
            if val is not None:
                if isinstance(val, bool) or not isinstance(val, (int, float)):
                    raise InvalidAccountingValueError(
                        f"{name} must be numeric, got {type(val).__name__}"
                    )
                if math.isnan(val) or math.isinf(val):
                    raise InvalidAccountingValueError(f"{name} cannot be NaN or Infinite")
                if val <= 0.0:
                    raise InvalidAccountingValueError(f"{name} must be positive, got {val}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_counterrun_executions": self.max_counterrun_executions,
            "max_elapsed_seconds": self.max_elapsed_seconds,
            "max_estimated_cost_usd": self.max_estimated_cost_usd,
            "max_input_tokens": self.max_input_tokens,
            "max_model_invocations": self.max_model_invocations,
            "max_output_tokens": self.max_output_tokens,
            "max_sandbox_creations": self.max_sandbox_creations,
            "max_sandbox_executions": self.max_sandbox_executions,
            "max_total_tokens": self.max_total_tokens,
            "max_verifier_executions": self.max_verifier_executions,
        }


@dataclass(slots=True)
class ResourceConsumption:
    """Observed actual resource consumption."""

    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    model_invocations: int = 0
    sandbox_creations: int = 0
    sandbox_executions: int = 0
    verifier_executions: int = 0
    counterrun_executions: int = 0
    elapsed_seconds: float = 0.0
    estimated_cost_usd: float | None = None
    has_unknown_financial_cost: bool = False
    is_verified_zero_cost: bool = True
    recorded_operation_ids: set[str] = field(default_factory=set)

    def validate(self) -> None:
        """Validate consumption invariant consistency."""
        for name in (
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "model_invocations",
            "sandbox_creations",
            "sandbox_executions",
            "verifier_executions",
            "counterrun_executions",
        ):
            val = getattr(self, name)
            if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                raise InvalidAccountingValueError(
                    f"{name} must be a non-negative integer, got {val!r}"
                )

        if isinstance(self.elapsed_seconds, bool) or not isinstance(
            self.elapsed_seconds, (int, float)
        ):
            raise InvalidAccountingValueError("elapsed_seconds must be numeric")
        if (
            math.isnan(self.elapsed_seconds)
            or math.isinf(self.elapsed_seconds)
            or self.elapsed_seconds < 0.0
        ):
            raise InvalidAccountingValueError(f"Invalid elapsed_seconds: {self.elapsed_seconds}")

        if self.estimated_cost_usd is not None:
            if (
                math.isnan(self.estimated_cost_usd)
                or math.isinf(self.estimated_cost_usd)
                or self.estimated_cost_usd < 0.0
            ):
                raise InvalidAccountingValueError(
                    f"Invalid estimated_cost_usd: {self.estimated_cost_usd}"
                )
            if self.estimated_cost_usd > 0.0:
                self.is_verified_zero_cost = False

        if self.has_unknown_financial_cost:
            self.is_verified_zero_cost = False

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "counterrun_executions": self.counterrun_executions,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "estimated_cost_usd": round(self.estimated_cost_usd, 6)
            if self.estimated_cost_usd is not None
            else None,
            "has_unknown_financial_cost": self.has_unknown_financial_cost,
            "input_tokens": self.input_tokens,
            "is_verified_zero_cost": self.is_verified_zero_cost,
            "model_invocations": self.model_invocations,
            "output_tokens": self.output_tokens,
            "recorded_operations_count": len(self.recorded_operation_ids),
            "sandbox_creations": self.sandbox_creations,
            "sandbox_executions": self.sandbox_executions,
            "total_tokens": self.total_tokens,
            "verifier_executions": self.verifier_executions,
        }


@dataclass(frozen=True, slots=True)
class ResourceReservation:
    """Pre-execution reservation of bounded resources."""

    reservation_id: str
    reserved_tokens: int = 0
    reserved_sandboxes: int = 0
    reserved_verifier_executions: int = 0
    reserved_counterrun_executions: int = 0
    reserved_seconds: float = 0.0
    status: ReservationStatus = ReservationStatus.PENDING

    def __post_init__(self) -> None:
        if not self.reservation_id or not self.reservation_id.strip():
            raise InvalidAccountingValueError("reservation_id must be non-empty string")
        for name in (
            "reserved_tokens",
            "reserved_sandboxes",
            "reserved_verifier_executions",
            "reserved_counterrun_executions",
        ):
            val = getattr(self, name)
            if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                raise InvalidAccountingValueError(
                    f"{name} must be a non-negative integer, got {val!r}"
                )
        if (
            isinstance(self.reserved_seconds, bool)
            or not isinstance(self.reserved_seconds, (int, float))
            or self.reserved_seconds < 0.0
        ):
            raise InvalidAccountingValueError(
                f"reserved_seconds must be non-negative, got {self.reserved_seconds!r}"
            )
        if math.isnan(self.reserved_seconds) or math.isinf(self.reserved_seconds):
            raise InvalidAccountingValueError("reserved_seconds cannot be NaN or Infinite")

    def to_dict(self) -> dict[str, Any]:
        return {
            "reservation_id": self.reservation_id,
            "reserved_counterrun_executions": self.reserved_counterrun_executions,
            "reserved_sandboxes": self.reserved_sandboxes,
            "reserved_seconds": self.reserved_seconds,
            "reserved_tokens": self.reserved_tokens,
            "reserved_verifier_executions": self.reserved_verifier_executions,
            "status": self.status.value,
        }


class BudgetLedger:
    """Deterministic, bounded accounting ledger for verification execution."""

    def __init__(
        self,
        limits: ResourceLimits | None = None,
        initial_consumption: ResourceConsumption | None = None,
    ) -> None:
        self.limits: ResourceLimits = limits or ResourceLimits()
        self.consumption: ResourceConsumption = initial_consumption or ResourceConsumption()
        self.consumption.validate()
        self.reservations: dict[str, ResourceReservation] = {}
        self._start_time: float = time.perf_counter()

    @property
    def elapsed_wall_clock_seconds(self) -> float:
        return time.perf_counter() - self._start_time

    def get_active_reserved_tokens(self) -> int:
        return sum(
            r.reserved_tokens
            for r in self.reservations.values()
            if r.status == ReservationStatus.PENDING
        )

    def get_active_reserved_sandboxes(self) -> int:
        return sum(
            r.reserved_sandboxes
            for r in self.reservations.values()
            if r.status == ReservationStatus.PENDING
        )

    def get_active_reserved_verifier_executions(self) -> int:
        return sum(
            r.reserved_verifier_executions
            for r in self.reservations.values()
            if r.status == ReservationStatus.PENDING
        )

    def get_active_reserved_counterruns(self) -> int:
        return sum(
            r.reserved_counterrun_executions
            for r in self.reservations.values()
            if r.status == ReservationStatus.PENDING
        )

    def reserve(
        self,
        reservation_id: str,
        *,
        tokens: int = 0,
        sandboxes: int = 0,
        verifier_executions: int = 0,
        counterrun_executions: int = 0,
        seconds: float = 0.0,
    ) -> ResourceReservation:
        """Reserve bounded resources before starting an execution phase.

        Raises BudgetExhaustedError if available unreserved capacity is insufficient.
        """
        if reservation_id in self.reservations:
            existing = self.reservations[reservation_id]
            if existing.status == ReservationStatus.PENDING:
                raise ReservationError(
                    f"Active reservation already exists with ID {reservation_id!r}"
                )

        # Check token ceiling
        if self.limits.max_total_tokens is not None:
            available = self.limits.max_total_tokens - (
                self.consumption.total_tokens + self.get_active_reserved_tokens()
            )
            if tokens > available:
                raise BudgetExhaustedError(
                    f"Insufficient token budget: requested {tokens}, available {available}"
                )

        # Check sandbox executions ceiling
        if self.limits.max_sandbox_executions is not None:
            available_sbx = self.limits.max_sandbox_executions - (
                self.consumption.sandbox_executions + self.get_active_reserved_sandboxes()
            )
            if sandboxes > available_sbx:
                raise BudgetExhaustedError(
                    f"Insufficient sandbox budget: requested {sandboxes}, available {available_sbx}"
                )

        # Check verifier executions ceiling
        if self.limits.max_verifier_executions is not None:
            available_ver = self.limits.max_verifier_executions - (
                self.consumption.verifier_executions
                + self.get_active_reserved_verifier_executions()
            )
            if verifier_executions > available_ver:
                raise BudgetExhaustedError(
                    f"Insufficient verifier budget: requested {verifier_executions}, "
                    f"available {available_ver}"
                )

        # Check counterrun executions ceiling
        if self.limits.max_counterrun_executions is not None:
            available_cr = self.limits.max_counterrun_executions - (
                self.consumption.counterrun_executions + self.get_active_reserved_counterruns()
            )
            if counterrun_executions > available_cr:
                raise BudgetExhaustedError(
                    f"Insufficient counterrun budget: requested {counterrun_executions}, "
                    f"available {available_cr}"
                )

        # Check elapsed seconds ceiling
        if self.limits.max_elapsed_seconds is not None:
            current_elapsed = max(self.consumption.elapsed_seconds, self.elapsed_wall_clock_seconds)
            if current_elapsed + seconds > self.limits.max_elapsed_seconds:
                max_sec = self.limits.max_elapsed_seconds
                raise BudgetExhaustedError(
                    f"Insufficient time budget: requested {seconds}s, "
                    f"already elapsed {current_elapsed:.2f}s against limit {max_sec}s"
                )

        res = ResourceReservation(
            reservation_id=reservation_id,
            reserved_tokens=tokens,
            reserved_sandboxes=sandboxes,
            reserved_verifier_executions=verifier_executions,
            reserved_counterrun_executions=counterrun_executions,
            reserved_seconds=seconds,
            status=ReservationStatus.PENDING,
        )
        self.reservations[reservation_id] = res
        return res

    def commit_reservation(self, reservation_id: str) -> None:
        """Mark reservation as committed after execution completion."""
        if reservation_id not in self.reservations:
            raise ReservationError(f"No reservation found with ID {reservation_id!r}")
        res = self.reservations[reservation_id]
        if res.status != ReservationStatus.PENDING:
            raise ReservationError(f"Cannot commit reservation in status {res.status.value}")
        self.reservations[reservation_id] = ResourceReservation(
            reservation_id=res.reservation_id,
            reserved_tokens=res.reserved_tokens,
            reserved_sandboxes=res.reserved_sandboxes,
            reserved_verifier_executions=res.reserved_verifier_executions,
            reserved_counterrun_executions=res.reserved_counterrun_executions,
            reserved_seconds=res.reserved_seconds,
            status=ReservationStatus.COMMITTED,
        )

    def cancel_reservation(self, reservation_id: str) -> None:
        """Release reserved capacity upon cancellation, timeout, or failure."""
        if reservation_id not in self.reservations:
            raise ReservationError(f"No reservation found with ID {reservation_id!r}")
        res = self.reservations[reservation_id]
        if res.status != ReservationStatus.PENDING:
            raise ReservationError(f"Cannot cancel reservation in status {res.status.value}")
        self.reservations[reservation_id] = ResourceReservation(
            reservation_id=res.reservation_id,
            reserved_tokens=res.reserved_tokens,
            reserved_sandboxes=res.reserved_sandboxes,
            reserved_verifier_executions=res.reserved_verifier_executions,
            reserved_counterrun_executions=res.reserved_counterrun_executions,
            reserved_seconds=res.reserved_seconds,
            status=ReservationStatus.CANCELLED,
        )

    def record_operation(
        self,
        operation_id: str,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        total_tokens: int = 0,
        is_model_invocation: bool = False,
        sandbox_creations: int = 0,
        sandbox_executions: int = 0,
        verifier_executions: int = 0,
        counterrun_executions: int = 0,
        elapsed_seconds: float = 0.0,
        financial_cost: FinancialCostEstimate | None = None,
        has_unknown_cost: bool = False,
        reservation_id: str | None = None,
    ) -> None:
        """Record an observed execution event with transactional guarantees and limit checking.

        All inputs, limits, reservations, and projected financial costs are verified
        BEFORE mutating any ledger state. If an operation is rejected, consumption,
        reservations, and recorded operation IDs remain strictly unchanged.
        """
        if not operation_id or not operation_id.strip():
            raise InvalidAccountingValueError("operation_id must be a non-empty string")
        if operation_id in self.consumption.recorded_operation_ids:
            raise DuplicateOperationError(
                f"Operation {operation_id!r} has already been recorded in budget ledger"
            )

        # Validate non-negative numbers
        for name, val in (
            ("input_tokens", input_tokens),
            ("output_tokens", output_tokens),
            ("total_tokens", total_tokens),
            ("sandbox_creations", sandbox_creations),
            ("sandbox_executions", sandbox_executions),
            ("verifier_executions", verifier_executions),
            ("counterrun_executions", counterrun_executions),
        ):
            if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                raise InvalidAccountingValueError(f"{name} must be a non-negative int, got {val!r}")

        if (
            isinstance(elapsed_seconds, bool)
            or not isinstance(elapsed_seconds, (int, float))
            or elapsed_seconds < 0.0
        ):
            raise InvalidAccountingValueError(
                f"elapsed_seconds must be non-negative, got {elapsed_seconds!r}"
            )
        if math.isnan(elapsed_seconds) or math.isinf(elapsed_seconds):
            raise InvalidAccountingValueError("elapsed_seconds cannot be NaN or Infinite")

        if financial_cost is not None and not isinstance(financial_cost, FinancialCostEstimate):
            raise InvalidAccountingValueError(
                f"financial_cost must be FinancialCostEstimate, got {type(financial_cost).__name__}"
            )

        # Inconsistent token counts check
        if total_tokens > 0 and (input_tokens > 0 or output_tokens > 0):
            if total_tokens != input_tokens + output_tokens:
                raise InvalidAccountingValueError(
                    f"Inconsistent token counts: total_tokens ({total_tokens}) != "
                    f"input_tokens ({input_tokens}) + output_tokens ({output_tokens})"
                )

        # Resolve total tokens
        effective_tokens = total_tokens
        if effective_tokens == 0 and (input_tokens > 0 or output_tokens > 0):
            effective_tokens = input_tokens + output_tokens

        # Active reservation lookup and isolation
        rel_res_tokens = 0
        rel_res_sbx = 0
        rel_res_ver = 0
        rel_res_cr = 0
        if reservation_id is not None:
            if reservation_id not in self.reservations:
                raise ReservationError(f"No reservation found with ID {reservation_id!r}")
            res = self.reservations[reservation_id]
            if res.status != ReservationStatus.PENDING:
                raise ReservationError(
                    f"Cannot associate operation with reservation in status {res.status.value}"
                )
            rel_res_tokens = res.reserved_tokens
            rel_res_sbx = res.reserved_sandboxes
            rel_res_ver = res.reserved_verifier_executions
            rel_res_cr = res.reserved_counterrun_executions

        # Active reservations belonging to OTHER pending reservations cannot be bypassed
        other_reserved_tokens = max(0, self.get_active_reserved_tokens() - rel_res_tokens)
        other_reserved_sbx = max(0, self.get_active_reserved_sandboxes() - rel_res_sbx)
        other_reserved_ver = max(0, self.get_active_reserved_verifier_executions() - rel_res_ver)
        other_reserved_cr = max(0, self.get_active_reserved_counterruns() - rel_res_cr)

        # CHECK ALL LIMITS BEFORE APPLYING ANY MUTATIONS
        if self.limits.max_input_tokens is not None and input_tokens > 0:
            if self.consumption.input_tokens + input_tokens > self.limits.max_input_tokens:
                curr_in = self.consumption.input_tokens + input_tokens
                max_in = self.limits.max_input_tokens
                raise BudgetExhaustedError(f"Input token limit exceeded: {curr_in} > {max_in}")

        if self.limits.max_output_tokens is not None and output_tokens > 0:
            if self.consumption.output_tokens + output_tokens > self.limits.max_output_tokens:
                curr_out = self.consumption.output_tokens + output_tokens
                max_out = self.limits.max_output_tokens
                raise BudgetExhaustedError(f"Output token limit exceeded: {curr_out} > {max_out}")

        if self.limits.max_total_tokens is not None and effective_tokens > 0:
            if (
                self.consumption.total_tokens + other_reserved_tokens + effective_tokens
                > self.limits.max_total_tokens
            ):
                curr_tok = self.consumption.total_tokens + other_reserved_tokens + effective_tokens
                max_tok = self.limits.max_total_tokens
                raise BudgetExhaustedError(f"Token limit exceeded: {curr_tok} > {max_tok}")

        if self.limits.max_model_invocations is not None and is_model_invocation:
            if self.consumption.model_invocations + 1 > self.limits.max_model_invocations:
                curr_inv = self.consumption.model_invocations + 1
                max_inv = self.limits.max_model_invocations
                raise BudgetExhaustedError(
                    f"Model invocation limit exceeded: {curr_inv} > {max_inv}"
                )

        if self.limits.max_sandbox_creations is not None and sandbox_creations > 0:
            if (
                self.consumption.sandbox_creations + sandbox_creations
                > self.limits.max_sandbox_creations
            ):
                curr_sc = self.consumption.sandbox_creations + sandbox_creations
                max_sc = self.limits.max_sandbox_creations
                raise BudgetExhaustedError(f"Sandbox creation limit exceeded: {curr_sc} > {max_sc}")

        if self.limits.max_sandbox_executions is not None and sandbox_executions > 0:
            if (
                self.consumption.sandbox_executions + other_reserved_sbx + sandbox_executions
                > self.limits.max_sandbox_executions
            ):
                curr_se = (
                    self.consumption.sandbox_executions + other_reserved_sbx + sandbox_executions
                )
                max_se = self.limits.max_sandbox_executions
                raise BudgetExhaustedError(
                    f"Sandbox execution limit exceeded: {curr_se} > {max_se}"
                )

        if self.limits.max_verifier_executions is not None and verifier_executions > 0:
            if (
                self.consumption.verifier_executions + other_reserved_ver + verifier_executions
                > self.limits.max_verifier_executions
            ):
                curr_ve = (
                    self.consumption.verifier_executions + other_reserved_ver + verifier_executions
                )
                max_ve = self.limits.max_verifier_executions
                raise BudgetExhaustedError(
                    f"Verifier execution limit exceeded: {curr_ve} > {max_ve}"
                )

        if self.limits.max_counterrun_executions is not None and counterrun_executions > 0:
            if (
                self.consumption.counterrun_executions + other_reserved_cr + counterrun_executions
                > self.limits.max_counterrun_executions
            ):
                curr_ce = (
                    self.consumption.counterrun_executions
                    + other_reserved_cr
                    + counterrun_executions
                )
                max_ce = self.limits.max_counterrun_executions
                raise BudgetExhaustedError(
                    f"Counterrun execution limit exceeded: {curr_ce} > {max_ce}"
                )

        if self.limits.max_elapsed_seconds is not None and elapsed_seconds > 0:
            if self.consumption.elapsed_seconds + elapsed_seconds > self.limits.max_elapsed_seconds:
                curr_time = self.consumption.elapsed_seconds + elapsed_seconds
                max_time = self.limits.max_elapsed_seconds
                raise BudgetExhaustedError(
                    f"Time limit exceeded: {curr_time:.2f}s > {max_time:.2f}s"
                )

        if financial_cost is not None and financial_cost.estimated_usd is not None:
            current_cost = self.consumption.estimated_cost_usd or 0.0
            projected_cost = current_cost + financial_cost.estimated_usd
            if (
                self.limits.max_estimated_cost_usd is not None
                and projected_cost > self.limits.max_estimated_cost_usd
            ):
                max_usd = self.limits.max_estimated_cost_usd
                raise BudgetExhaustedError(
                    f"Financial cost limit exceeded: ${projected_cost:.4f} > ${max_usd:.4f}"
                )

        # ALL CHECKS PASSED: APPLY TRANSACTIONAL MUTATIONS
        self.consumption.input_tokens += input_tokens
        self.consumption.output_tokens += output_tokens
        self.consumption.total_tokens += effective_tokens
        if is_model_invocation:
            self.consumption.model_invocations += 1
        self.consumption.sandbox_creations += sandbox_creations
        self.consumption.sandbox_executions += sandbox_executions
        self.consumption.verifier_executions += verifier_executions
        self.consumption.counterrun_executions += counterrun_executions
        self.consumption.elapsed_seconds += elapsed_seconds

        if has_unknown_cost:
            self.consumption.has_unknown_financial_cost = True
            self.consumption.is_verified_zero_cost = False

        if financial_cost is not None:
            if financial_cost.estimated_usd is not None:
                current_cost = self.consumption.estimated_cost_usd or 0.0
                self.consumption.estimated_cost_usd = current_cost + financial_cost.estimated_usd
                if financial_cost.estimated_usd > 0.0:
                    self.consumption.is_verified_zero_cost = False
            elif not financial_cost.is_verified_zero_cost:
                self.consumption.has_unknown_financial_cost = True
                self.consumption.is_verified_zero_cost = False

        self.consumption.recorded_operation_ids.add(operation_id)
        self.consumption.validate()

    def to_repair_loop_budget(self) -> RepairLoopBudget:
        """Convert ledger limits to compatible RepairLoopBudget."""
        return RepairLoopBudget(
            max_builder_attempts=self.limits.max_model_invocations or 3,
            max_clock_seconds=self.limits.max_elapsed_seconds or 300.0,
            max_repair_rounds=min(self.limits.max_model_invocations or 2, 5),
            max_sandbox_executions=self.limits.max_sandbox_executions or 6,
            max_token_budget=self.limits.max_total_tokens,
            max_verifier_executions=self.limits.max_verifier_executions or 6,
        )

    @classmethod
    def from_repair_loop_budget(cls, budget: RepairLoopBudget) -> BudgetLedger:
        """Construct a BudgetLedger from an existing RepairLoopBudget."""
        if not isinstance(budget, RepairLoopBudget):
            raise InvalidAccountingValueError(
                f"budget must be RepairLoopBudget, got {type(budget).__name__}"
            )
        limits = ResourceLimits(
            max_elapsed_seconds=budget.max_clock_seconds,
            max_model_invocations=budget.max_builder_attempts,
            max_sandbox_executions=budget.max_sandbox_executions,
            max_total_tokens=budget.max_token_budget,
            max_verifier_executions=budget.max_verifier_executions,
        )
        return cls(limits=limits)

    def sync_from_repair_loop_counters(self, counters: RepairLoopCounters) -> None:
        """Synchronize observed consumption from RepairLoopCounters."""
        if not isinstance(counters, RepairLoopCounters):
            raise InvalidAccountingValueError(
                f"counters must be RepairLoopCounters, got {type(counters).__name__}"
            )
        self.consumption.model_invocations = max(
            self.consumption.model_invocations, counters.builder_attempts_used
        )
        self.consumption.verifier_executions = max(
            self.consumption.verifier_executions, counters.verifier_executions_used
        )
        self.consumption.sandbox_executions = max(
            self.consumption.sandbox_executions, counters.sandbox_executions_used
        )
        self.consumption.total_tokens = max(self.consumption.total_tokens, counters.tokens_used)
        self.consumption.elapsed_seconds = max(
            self.consumption.elapsed_seconds, counters.elapsed_seconds
        )
        self.consumption.validate()

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete ledger state to deterministic dictionary."""
        return {
            "consumption": self.consumption.to_dict(),
            "limits": self.limits.to_dict(),
            "reservations": {k: v.to_dict() for k, v in self.reservations.items()},
            "schema_version": ACCOUNTING_SCHEMA_VERSION,
        }
