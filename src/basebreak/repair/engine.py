"""Sealed repair loop orchestration and budget-capped termination.

P-14.06: Cap repair rounds/cost and return honest non-success.

Core Invariants:
1. Honest termination: Infinite repair loops or unbudgeted retries are strictly prohibited.
2. Explicit budget ceilings:
   - MAX_REPAIR_ROUNDS (default 2, ceiling 5)
   - MAX_BUILDER_ATTEMPTS
   - MAX_VERIFIER_EXECUTIONS
   - MAX_SANDBOX_EXECUTIONS
   - MAX_CLOCK_SECONDS
3. Honest non-success classifications:
   - REPAIR_BUDGET_EXHAUSTED
   - REPAIR_NO_PROGRESS
   - REPAIR_REGRESSED
   - REPAIR_INVALID_CANDIDATE
   - REPAIR_FEEDBACK_UNSAFE
   - REPAIR_INFRA_FAILURE
   - INCONCLUSIVE
4. Cryptographic audit trail: Every execution produces an authentic, tamper-evident
   RepairLoopReceipt binding initial candidate, all feedback digests, all lineage
   digests, all reproduction receipts, resource counters, and final verdict.
5. Zero Builder self-certification: Builder claims cannot certify repaired candidates.
   Repaired candidates must undergo fresh independent verifier reproduction in
   a freshly allocated disposable sandbox.
6. Model prose never overturns deterministic facts.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from basebreak.builder.capture import CandidateCaptureError, CandidateSnapshot
from basebreak.compiler.freeze import FrozenContract
from basebreak.domain.source import SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.repair.context import (
    BuilderRepairContextEnvelope,
    create_builder_repair_context,
    verify_builder_repair_context_integrity,
)
from basebreak.repair.feedback import (
    FailureConditionCategory,
    create_safe_repair_feedback,
    verify_repair_feedback_integrity,
)
from basebreak.repair.lineage import (
    CandidateIdentityReuseError,
    CandidateLineageError,
    CandidateLineageRecord,
    RepairedCandidateSnapshot,
    UnchangedCandidateError,
    create_candidate_lineage_record,
)
from basebreak.repair.reproduction import (
    RepairedVerificationReceipt,
    VerifierSandboxReuseError,
    execute_repaired_verifier_reproduction,
)
from basebreak.repair.sanitizer import DisclosureSanitizer, UnsafeDisclosureError
from basebreak.security.protected_surfaces import (
    get_canonical_basebreak_protected_manifest,
    is_path_protected,
)
from basebreak.verifier.sandbox import VerifierSandboxManager
from basebreak.verifier.witness_lock import ImmutableWitnessLock
from basebreak.verifier.witness_result import WitnessOutcome
from basebreak.verifier.witness_store import SealedWitnessRecord

REPAIR_LOOP_RECEIPT_SCHEMA_VERSION: str = "1.0.0"

_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class RepairLoopStatus(str, Enum):
    """Terminal classification for sealed repair loop execution."""

    VERIFIED_AFTER_REPAIR = "VERIFIED_AFTER_REPAIR"
    REPAIR_BUDGET_EXHAUSTED = "REPAIR_BUDGET_EXHAUSTED"
    REPAIR_NO_PROGRESS = "REPAIR_NO_PROGRESS"
    REPAIR_REGRESSED = "REPAIR_REGRESSED"
    REPAIR_INVALID_CANDIDATE = "REPAIR_INVALID_CANDIDATE"
    REPAIR_FEEDBACK_UNSAFE = "REPAIR_FEEDBACK_UNSAFE"
    REPAIR_INFRA_FAILURE = "REPAIR_INFRA_FAILURE"
    INCONCLUSIVE = "INCONCLUSIVE"


class RepairLoopError(Exception):
    """Base exception for repair loop errors."""


class RepairBudgetExceededError(RepairLoopError):
    """Raised when an operation exceeds configured repair budget limits."""


class RepairLoopReceiptTamperingError(RepairLoopError):
    """Raised when repair loop receipt integrity check fails."""


@dataclass(frozen=True, slots=True)
class RepairLoopBudget:
    """Bounded resource ceilings for sealed repair loop execution."""

    max_repair_rounds: int = 2
    max_builder_attempts: int = 3
    max_verifier_executions: int = 6
    max_sandbox_executions: int = 6
    max_token_budget: int | None = None
    max_clock_seconds: float = 300.0

    def __post_init__(self) -> None:
        if not isinstance(self.max_repair_rounds, int) or self.max_repair_rounds < 1:
            raise ValueError("max_repair_rounds must be a positive integer >= 1")
        if self.max_repair_rounds > 5:
            raise ValueError("max_repair_rounds cannot exceed safety ceiling of 5")
        if not isinstance(self.max_builder_attempts, int) or self.max_builder_attempts < 1:
            raise ValueError("max_builder_attempts must be a positive integer >= 1")
        if not isinstance(self.max_verifier_executions, int) or self.max_verifier_executions < 1:
            raise ValueError("max_verifier_executions must be a positive integer >= 1")
        if not isinstance(self.max_sandbox_executions, int) or self.max_sandbox_executions < 1:
            raise ValueError("max_sandbox_executions must be a positive integer >= 1")
        if self.max_token_budget is not None and self.max_token_budget <= 0:
            raise ValueError("max_token_budget must be a positive integer if specified")
        if self.max_clock_seconds <= 0.0:
            raise ValueError("max_clock_seconds must be a positive float")


@dataclass(slots=True)
class RepairLoopCounters:
    """Mutable consumption tracker for repair loop budget enforcement."""

    repair_rounds_completed: int = 0
    builder_attempts_used: int = 0
    verifier_executions_used: int = 0
    sandbox_executions_used: int = 0
    tokens_used: int = 0
    start_time: float = field(default_factory=time.perf_counter)

    @property
    def elapsed_seconds(self) -> float:
        return time.perf_counter() - self.start_time

    def to_dict(self) -> dict[str, Any]:
        return {
            "builder_attempts_used": self.builder_attempts_used,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "repair_rounds_completed": self.repair_rounds_completed,
            "sandbox_executions_used": self.sandbox_executions_used,
            "tokens_used": self.tokens_used,
            "verifier_executions_used": self.verifier_executions_used,
        }


@dataclass(frozen=True, slots=True)
class RepairLoopReceipt:
    """Tamper-evident audit receipt summarizing full sealed repair loop execution.

    Possesses zero unverified authority (is_authoritative=False).
    """

    schema_version: str
    repair_receipt_id: str
    initial_candidate_id: str
    initial_patch_digest: str
    initial_tree_digest: str
    final_candidate_id: str | None
    final_patch_digest: str | None
    final_tree_digest: str | None
    status: RepairLoopStatus
    preliminary_verdict: PreliminaryVerdict
    is_causally_verified: bool
    grants_pass: bool
    is_authoritative: bool
    total_rounds: int
    lineage_digests: tuple[str, ...]
    feedback_digests: tuple[str, ...]
    reproduction_receipt_digests: tuple[str, ...]
    counters: dict[str, Any]
    failure_reason: str | None
    provenance: EvidenceProvenance
    created_at: str
    receipt_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != REPAIR_LOOP_RECEIPT_SCHEMA_VERSION:
            raise RepairLoopReceiptTamperingError(
                f"Unsupported schema_version: {self.schema_version!r}"
            )
        if not self.repair_receipt_id.strip():
            raise RepairLoopReceiptTamperingError("repair_receipt_id must be non-empty")
        if not self.initial_candidate_id.strip():
            raise RepairLoopReceiptTamperingError("initial_candidate_id must be non-empty")
        if not _HEX_64_PATTERN.match(self.initial_patch_digest):
            raise RepairLoopReceiptTamperingError(
                "initial_patch_digest must be a 64-char hex string"
            )
        if not _HEX_40_OR_64_PATTERN.match(self.initial_tree_digest):
            raise RepairLoopReceiptTamperingError(
                "initial_tree_digest must be a 40 or 64-char hex string"
            )
        if not isinstance(self.status, RepairLoopStatus):
            raise TypeError("status must be a RepairLoopStatus instance")
        if not isinstance(self.preliminary_verdict, PreliminaryVerdict):
            raise TypeError("preliminary_verdict must be a PreliminaryVerdict instance")
        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError("provenance must be an EvidenceProvenance instance")

        # Authority boundary invariant
        if self.is_authoritative is not False:
            raise RepairLoopReceiptTamperingError("is_authoritative must be strictly False")

        # Pass granting consistency
        if self.grants_pass:
            if not self.is_causally_verified:
                raise RepairLoopReceiptTamperingError(
                    "Receipt cannot grant PASS if is_causally_verified is False"
                )
            if self.status != RepairLoopStatus.VERIFIED_AFTER_REPAIR:
                raise RepairLoopReceiptTamperingError(
                    "Receipt cannot grant PASS unless status is VERIFIED_AFTER_REPAIR"
                )
            if self.preliminary_verdict != PreliminaryVerdict.VERIFIED:
                raise RepairLoopReceiptTamperingError(
                    "Receipt cannot grant PASS unless preliminary_verdict is VERIFIED"
                )
        else:
            if (
                self.is_causally_verified
                and self.status == RepairLoopStatus.VERIFIED_AFTER_REPAIR
                and self.preliminary_verdict == PreliminaryVerdict.VERIFIED
            ):
                raise RepairLoopReceiptTamperingError(
                    "Receipt claiming verified state must have grants_pass=True"
                )


def build_canonical_repair_loop_receipt_payload(
    *,
    schema_version: str,
    repair_receipt_id: str,
    initial_candidate_id: str,
    initial_patch_digest: str,
    initial_tree_digest: str,
    final_candidate_id: str | None,
    final_patch_digest: str | None,
    final_tree_digest: str | None,
    status: str,
    preliminary_verdict: str,
    is_causally_verified: bool,
    grants_pass: bool,
    is_authoritative: bool,
    total_rounds: int,
    lineage_digests: Sequence[str],
    feedback_digests: Sequence[str],
    reproduction_receipt_digests: Sequence[str],
    counters: Mapping[str, Any],
    failure_reason: str | None,
    provenance: str,
    created_at: str,
) -> dict[str, Any]:
    """Construct deterministic payload dictionary with sorted keys."""
    sorted_counters = {k: counters[k] for k in sorted(counters.keys())}
    return {
        "counters": sorted_counters,
        "created_at": str(created_at),
        "failure_reason": failure_reason,
        "feedback_digests": [str(d).lower() for d in sorted(feedback_digests)],
        "final_candidate_id": final_candidate_id,
        "final_patch_digest": str(final_patch_digest).lower() if final_patch_digest else None,
        "final_tree_digest": str(final_tree_digest).lower() if final_tree_digest else None,
        "grants_pass": bool(grants_pass),
        "initial_candidate_id": str(initial_candidate_id),
        "initial_patch_digest": str(initial_patch_digest).lower(),
        "initial_tree_digest": str(initial_tree_digest).lower(),
        "is_authoritative": bool(is_authoritative),
        "is_causally_verified": bool(is_causally_verified),
        "lineage_digests": [str(d).lower() for d in sorted(lineage_digests)],
        "preliminary_verdict": str(preliminary_verdict),
        "provenance": str(provenance),
        "repair_receipt_id": str(repair_receipt_id),
        "reproduction_receipt_digests": [
            str(d).lower() for d in sorted(reproduction_receipt_digests)
        ],
        "schema_version": str(schema_version),
        "status": str(status),
        "total_rounds": int(total_rounds),
    }


def compute_repair_loop_receipt_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical JSON bytes."""
    clean = {k: v for k, v in payload.items() if k != "receipt_digest"}
    data = json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def verify_repair_loop_receipt_integrity(receipt: RepairLoopReceipt) -> bool:
    """Verify cryptographic receipt digest against recomputed payload."""
    payload = build_canonical_repair_loop_receipt_payload(
        schema_version=receipt.schema_version,
        repair_receipt_id=receipt.repair_receipt_id,
        initial_candidate_id=receipt.initial_candidate_id,
        initial_patch_digest=receipt.initial_patch_digest,
        initial_tree_digest=receipt.initial_tree_digest,
        final_candidate_id=receipt.final_candidate_id,
        final_patch_digest=receipt.final_patch_digest,
        final_tree_digest=receipt.final_tree_digest,
        status=receipt.status.value,
        preliminary_verdict=receipt.preliminary_verdict.value,
        is_causally_verified=receipt.is_causally_verified,
        grants_pass=receipt.grants_pass,
        is_authoritative=receipt.is_authoritative,
        total_rounds=receipt.total_rounds,
        lineage_digests=receipt.lineage_digests,
        feedback_digests=receipt.feedback_digests,
        reproduction_receipt_digests=receipt.reproduction_receipt_digests,
        counters=receipt.counters,
        failure_reason=receipt.failure_reason,
        provenance=receipt.provenance.value,
        created_at=receipt.created_at,
    )
    expected = compute_repair_loop_receipt_digest(payload)
    if receipt.receipt_digest != expected:
        raise RepairLoopReceiptTamperingError(
            f"Repair loop receipt digest mismatch: declared {receipt.receipt_digest}, "
            f"recomputed {expected}"
        )
    return True


def create_repair_loop_receipt(
    *,
    repair_receipt_id: str,
    initial_candidate_id: str,
    initial_patch_digest: str,
    initial_tree_digest: str,
    final_candidate_id: str | None,
    final_patch_digest: str | None,
    final_tree_digest: str | None,
    status: RepairLoopStatus,
    preliminary_verdict: PreliminaryVerdict,
    is_causally_verified: bool,
    grants_pass: bool,
    total_rounds: int,
    lineage_digests: Sequence[str],
    feedback_digests: Sequence[str],
    reproduction_receipt_digests: Sequence[str],
    counters: Mapping[str, Any],
    failure_reason: str | None,
    provenance: EvidenceProvenance,
    created_at: str | None = None,
) -> RepairLoopReceipt:
    """Create a tamper-evident RepairLoopReceipt with cryptographic digest."""
    ts = created_at or datetime.now(timezone.utc).isoformat()
    payload = build_canonical_repair_loop_receipt_payload(
        schema_version=REPAIR_LOOP_RECEIPT_SCHEMA_VERSION,
        repair_receipt_id=repair_receipt_id,
        initial_candidate_id=initial_candidate_id,
        initial_patch_digest=initial_patch_digest,
        initial_tree_digest=initial_tree_digest,
        final_candidate_id=final_candidate_id,
        final_patch_digest=final_patch_digest,
        final_tree_digest=final_tree_digest,
        status=status.value,
        preliminary_verdict=preliminary_verdict.value,
        is_causally_verified=is_causally_verified,
        grants_pass=grants_pass,
        is_authoritative=False,
        total_rounds=total_rounds,
        lineage_digests=lineage_digests,
        feedback_digests=feedback_digests,
        reproduction_receipt_digests=reproduction_receipt_digests,
        counters=counters,
        failure_reason=failure_reason,
        provenance=provenance.value,
        created_at=ts,
    )
    digest = compute_repair_loop_receipt_digest(payload)
    return RepairLoopReceipt(
        schema_version=REPAIR_LOOP_RECEIPT_SCHEMA_VERSION,
        repair_receipt_id=repair_receipt_id,
        initial_candidate_id=initial_candidate_id,
        initial_patch_digest=initial_patch_digest,
        initial_tree_digest=initial_tree_digest,
        final_candidate_id=final_candidate_id,
        final_patch_digest=final_patch_digest,
        final_tree_digest=final_tree_digest,
        status=status,
        preliminary_verdict=preliminary_verdict,
        is_causally_verified=is_causally_verified,
        grants_pass=grants_pass,
        is_authoritative=False,
        total_rounds=total_rounds,
        lineage_digests=tuple(lineage_digests),
        feedback_digests=tuple(feedback_digests),
        reproduction_receipt_digests=tuple(reproduction_receipt_digests),
        counters=dict(counters),
        failure_reason=failure_reason,
        provenance=provenance,
        created_at=ts,
        receipt_digest=digest,
    )


def run_sealed_repair_loop(
    *,
    initial_candidate: CandidateSnapshot,
    frozen_contract: FrozenContract,
    source_identity: SourceIdentity,
    sealed_record: SealedWitnessRecord,
    witness_lock: ImmutableWitnessLock,
    builder_repair_fn: Callable[[BuilderRepairContextEnvelope], CandidateSnapshot],
    sandbox_manager: VerifierSandboxManager,
    sandbox_adapter: Any,
    materializer: Any,
    execution_command: Sequence[str] | str,
    budget: RepairLoopBudget | None = None,
    sanitizer: DisclosureSanitizer | None = None,
    prior_sandbox_ids: Sequence[str] | set[str] | None = None,
    originating_receipt_digest: str | None = None,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
    counterfactual_check: bool = False,
    counterfactual_outcome: WitnessOutcome | None = None,
) -> RepairLoopReceipt:
    """Orchestrate a sealed repair loop within explicit budget ceilings.

    Returns an authentic, tamper-evident RepairLoopReceipt under all outcomes.
    Never pretends repair succeeded. Never hides verifier failures.
    """
    cfg = budget or RepairLoopBudget()
    san = sanitizer or DisclosureSanitizer(
        known_witness_ids=(sealed_record.witness_id,),
    )
    counters = RepairLoopCounters()

    seen_patch_digests: set[str] = {initial_candidate.patch_digest}
    all_sandbox_ids: set[str] = set(prior_sandbox_ids or ())
    lineage_digests: list[str] = []
    feedback_digests: list[str] = []
    reproduction_receipt_digests: list[str] = []

    current_candidate = initial_candidate
    current_receipt_digest = originating_receipt_digest or "0" * 64

    final_candidate_id: str | None = None
    final_patch_digest: str | None = None
    final_tree_digest: str | None = None

    for round_idx in range(1, cfg.max_repair_rounds + 1):
        counters.repair_rounds_completed = round_idx

        # 1. Check clock budget
        if counters.elapsed_seconds >= cfg.max_clock_seconds:
            return create_repair_loop_receipt(
                repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                initial_candidate_id=initial_candidate.candidate_id,
                initial_patch_digest=initial_candidate.patch_digest,
                initial_tree_digest=initial_candidate.candidate_tree_digest,
                final_candidate_id=final_candidate_id,
                final_patch_digest=final_patch_digest,
                final_tree_digest=final_tree_digest,
                status=RepairLoopStatus.REPAIR_BUDGET_EXHAUSTED,
                preliminary_verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                grants_pass=False,
                total_rounds=round_idx - 1,
                lineage_digests=lineage_digests,
                feedback_digests=feedback_digests,
                reproduction_receipt_digests=reproduction_receipt_digests,
                counters=counters.to_dict(),
                failure_reason=(
                    f"Clock timeout exceeded "
                    f"({counters.elapsed_seconds:.2f}s >= {cfg.max_clock_seconds}s)"
                ),
                provenance=provenance,
            )

        # 2. Extract sanitized safe failure feedback
        raw_observed = "Behavioral verification check failed"
        raw_expected = "Pass sealed verification witness"
        try:
            san_observed = san.sanitize_text(raw_observed)
            san_expected = san.sanitize_text(raw_expected)
        except UnsafeDisclosureError as exc:
            return create_repair_loop_receipt(
                repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                initial_candidate_id=initial_candidate.candidate_id,
                initial_patch_digest=initial_candidate.patch_digest,
                initial_tree_digest=initial_candidate.candidate_tree_digest,
                final_candidate_id=final_candidate_id,
                final_patch_digest=final_patch_digest,
                final_tree_digest=final_tree_digest,
                status=RepairLoopStatus.REPAIR_FEEDBACK_UNSAFE,
                preliminary_verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                grants_pass=False,
                total_rounds=round_idx - 1,
                lineage_digests=lineage_digests,
                feedback_digests=feedback_digests,
                reproduction_receipt_digests=reproduction_receipt_digests,
                counters=counters.to_dict(),
                failure_reason=f"Unsafe disclosure detected in feedback extraction: {exc}",
                provenance=provenance,
            )

        feedback_id = f"FB-R{round_idx}-{uuid.uuid4().hex[:8]}"
        feedback = create_safe_repair_feedback(
            feedback_id=feedback_id,
            candidate_id=current_candidate.candidate_id,
            requirement_id=sealed_record.requirement_id,
            change_class=frozen_contract.change_class,
            failed_condition=FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED,
            observed_behavior=san_observed,
            expected_behavior=san_expected,
            originating_receipt_digest=current_receipt_digest,
            feedback_round=round_idx,
            provenance=provenance,
            permitted_patch_region=list(current_candidate.files_modified),
        )
        verify_repair_feedback_integrity(feedback)
        feedback_digests.append(feedback.feedback_digest)

        # 3. Create fresh Builder repair context envelope
        context_id = f"CTX-R{round_idx}-{uuid.uuid4().hex[:8]}"
        repair_context = create_builder_repair_context(
            repair_context_id=context_id,
            parent_candidate_id=current_candidate.candidate_id,
            parent_candidate_tree_digest=current_candidate.candidate_tree_digest,
            parent_patch_digest=current_candidate.patch_digest,
            parent_patch_text=current_candidate.patch_text,
            source_identity=source_identity,
            frozen_contract_digest=frozen_contract.contract_digest,
            requirement_id=sealed_record.requirement_id,
            change_class=frozen_contract.change_class,
            repair_feedback=feedback,
            permitted_paths=list(current_candidate.files_modified),
            repair_round=round_idx,
            max_repair_rounds=cfg.max_repair_rounds,
        )
        verify_builder_repair_context_integrity(repair_context)

        # 4. Invoke Builder in fresh context
        if counters.builder_attempts_used >= cfg.max_builder_attempts:
            return create_repair_loop_receipt(
                repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                initial_candidate_id=initial_candidate.candidate_id,
                initial_patch_digest=initial_candidate.patch_digest,
                initial_tree_digest=initial_candidate.candidate_tree_digest,
                final_candidate_id=final_candidate_id,
                final_patch_digest=final_patch_digest,
                final_tree_digest=final_tree_digest,
                status=RepairLoopStatus.REPAIR_BUDGET_EXHAUSTED,
                preliminary_verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                grants_pass=False,
                total_rounds=round_idx - 1,
                lineage_digests=lineage_digests,
                feedback_digests=feedback_digests,
                reproduction_receipt_digests=reproduction_receipt_digests,
                counters=counters.to_dict(),
                failure_reason="Builder attempts budget exhausted",
                provenance=provenance,
            )

        counters.builder_attempts_used += 1
        repaired_cand_snapshot: CandidateSnapshot
        try:
            repaired_cand_snapshot = builder_repair_fn(repair_context)
        except CandidateCaptureError as exc:
            return create_repair_loop_receipt(
                repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                initial_candidate_id=initial_candidate.candidate_id,
                initial_patch_digest=initial_candidate.patch_digest,
                initial_tree_digest=initial_candidate.candidate_tree_digest,
                final_candidate_id=final_candidate_id,
                final_patch_digest=final_patch_digest,
                final_tree_digest=final_tree_digest,
                status=RepairLoopStatus.REPAIR_INVALID_CANDIDATE,
                preliminary_verdict=PreliminaryVerdict.CONTRADICTED,
                is_causally_verified=False,
                grants_pass=False,
                total_rounds=round_idx,
                lineage_digests=lineage_digests,
                feedback_digests=feedback_digests,
                reproduction_receipt_digests=reproduction_receipt_digests,
                counters=counters.to_dict(),
                failure_reason=f"Builder candidate capture failed: {exc}",
                provenance=provenance,
            )
        except Exception as exc:
            return create_repair_loop_receipt(
                repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                initial_candidate_id=initial_candidate.candidate_id,
                initial_patch_digest=initial_candidate.patch_digest,
                initial_tree_digest=initial_candidate.candidate_tree_digest,
                final_candidate_id=final_candidate_id,
                final_patch_digest=final_patch_digest,
                final_tree_digest=final_tree_digest,
                status=RepairLoopStatus.REPAIR_INFRA_FAILURE,
                preliminary_verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                grants_pass=False,
                total_rounds=round_idx - 1,
                lineage_digests=lineage_digests,
                feedback_digests=feedback_digests,
                reproduction_receipt_digests=reproduction_receipt_digests,
                counters=counters.to_dict(),
                failure_reason=f"Builder execution raised error: {exc}",
                provenance=provenance,
            )

        final_candidate_id = repaired_cand_snapshot.candidate_id
        final_patch_digest = repaired_cand_snapshot.patch_digest
        final_tree_digest = repaired_cand_snapshot.candidate_tree_digest

        # Check: Builder self-certification rejected
        if repaired_cand_snapshot.is_authoritative:
            return create_repair_loop_receipt(
                repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                initial_candidate_id=initial_candidate.candidate_id,
                initial_patch_digest=initial_candidate.patch_digest,
                initial_tree_digest=initial_candidate.candidate_tree_digest,
                final_candidate_id=final_candidate_id,
                final_patch_digest=final_patch_digest,
                final_tree_digest=final_tree_digest,
                status=RepairLoopStatus.REPAIR_INVALID_CANDIDATE,
                preliminary_verdict=PreliminaryVerdict.CONTRADICTED,
                is_causally_verified=False,
                grants_pass=False,
                total_rounds=round_idx,
                lineage_digests=lineage_digests,
                feedback_digests=feedback_digests,
                reproduction_receipt_digests=reproduction_receipt_digests,
                counters=counters.to_dict(),
                failure_reason="Builder attempted self-certification (is_authoritative=True)",
                provenance=provenance,
            )

        # Check: Protected surfaces edit
        manifest = get_canonical_basebreak_protected_manifest()
        for p in repaired_cand_snapshot.files_modified + repaired_cand_snapshot.files_added:
            if is_path_protected(p, manifest):
                return create_repair_loop_receipt(
                    repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                    initial_candidate_id=initial_candidate.candidate_id,
                    initial_patch_digest=initial_candidate.patch_digest,
                    initial_tree_digest=initial_candidate.candidate_tree_digest,
                    final_candidate_id=final_candidate_id,
                    final_patch_digest=final_patch_digest,
                    final_tree_digest=final_tree_digest,
                    status=RepairLoopStatus.REPAIR_INVALID_CANDIDATE,
                    preliminary_verdict=PreliminaryVerdict.CONTRADICTED,
                    is_causally_verified=False,
                    grants_pass=False,
                    total_rounds=round_idx,
                    lineage_digests=lineage_digests,
                    feedback_digests=feedback_digests,
                    reproduction_receipt_digests=reproduction_receipt_digests,
                    counters=counters.to_dict(),
                    failure_reason=f"Candidate edited protected surface {p!r}",
                    provenance=provenance,
                )

        # 5. Build and validate CandidateLineageRecord
        lineage_id = f"LIN-R{round_idx}-{uuid.uuid4().hex[:8]}"
        lineage_record: CandidateLineageRecord
        try:
            lineage_record = create_candidate_lineage_record(
                lineage_id=lineage_id,
                context=repair_context,
                repaired_candidate_id=repaired_cand_snapshot.candidate_id,
                repaired_tree_digest=repaired_cand_snapshot.candidate_tree_digest,
                repaired_patch_digest=repaired_cand_snapshot.patch_digest,
            )
        except CandidateIdentityReuseError as exc:
            return create_repair_loop_receipt(
                repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                initial_candidate_id=initial_candidate.candidate_id,
                initial_patch_digest=initial_candidate.patch_digest,
                initial_tree_digest=initial_candidate.candidate_tree_digest,
                final_candidate_id=final_candidate_id,
                final_patch_digest=final_patch_digest,
                final_tree_digest=final_tree_digest,
                status=RepairLoopStatus.REPAIR_INVALID_CANDIDATE,
                preliminary_verdict=PreliminaryVerdict.CONTRADICTED,
                is_causally_verified=False,
                grants_pass=False,
                total_rounds=round_idx,
                lineage_digests=lineage_digests,
                feedback_digests=feedback_digests,
                reproduction_receipt_digests=reproduction_receipt_digests,
                counters=counters.to_dict(),
                failure_reason=f"Candidate ID reuse rejected: {exc}",
                provenance=provenance,
            )
        except UnchangedCandidateError as exc:
            return create_repair_loop_receipt(
                repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                initial_candidate_id=initial_candidate.candidate_id,
                initial_patch_digest=initial_candidate.patch_digest,
                initial_tree_digest=initial_candidate.candidate_tree_digest,
                final_candidate_id=final_candidate_id,
                final_patch_digest=final_patch_digest,
                final_tree_digest=final_tree_digest,
                status=RepairLoopStatus.REPAIR_NO_PROGRESS,
                preliminary_verdict=PreliminaryVerdict.CONTRADICTED,
                is_causally_verified=False,
                grants_pass=False,
                total_rounds=round_idx,
                lineage_digests=lineage_digests,
                feedback_digests=feedback_digests,
                reproduction_receipt_digests=reproduction_receipt_digests,
                counters=counters.to_dict(),
                failure_reason=f"Candidate stagnation detected: {exc}",
                provenance=provenance,
            )
        except CandidateLineageError as exc:
            return create_repair_loop_receipt(
                repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                initial_candidate_id=initial_candidate.candidate_id,
                initial_patch_digest=initial_candidate.patch_digest,
                initial_tree_digest=initial_candidate.candidate_tree_digest,
                final_candidate_id=final_candidate_id,
                final_patch_digest=final_patch_digest,
                final_tree_digest=final_tree_digest,
                status=RepairLoopStatus.REPAIR_INVALID_CANDIDATE,
                preliminary_verdict=PreliminaryVerdict.CONTRADICTED,
                is_causally_verified=False,
                grants_pass=False,
                total_rounds=round_idx,
                lineage_digests=lineage_digests,
                feedback_digests=feedback_digests,
                reproduction_receipt_digests=reproduction_receipt_digests,
                counters=counters.to_dict(),
                failure_reason=f"Lineage integrity validation failed: {exc}",
                provenance=provenance,
            )

        lineage_digests.append(lineage_record.lineage_digest)

        # Check cycle/stagnation across non-immediate rounds
        if repaired_cand_snapshot.patch_digest in seen_patch_digests:
            return create_repair_loop_receipt(
                repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                initial_candidate_id=initial_candidate.candidate_id,
                initial_patch_digest=initial_candidate.patch_digest,
                initial_tree_digest=initial_candidate.candidate_tree_digest,
                final_candidate_id=final_candidate_id,
                final_patch_digest=final_patch_digest,
                final_tree_digest=final_tree_digest,
                status=RepairLoopStatus.REPAIR_NO_PROGRESS,
                preliminary_verdict=PreliminaryVerdict.CONTRADICTED,
                is_causally_verified=False,
                grants_pass=False,
                total_rounds=round_idx,
                lineage_digests=lineage_digests,
                feedback_digests=feedback_digests,
                reproduction_receipt_digests=reproduction_receipt_digests,
                counters=counters.to_dict(),
                failure_reason="Candidate patch repeated earlier failed state",
                provenance=provenance,
            )
        seen_patch_digests.add(repaired_cand_snapshot.patch_digest)

        # Wrap in RepairedCandidateSnapshot
        repaired_snapshot = RepairedCandidateSnapshot(
            candidate=repaired_cand_snapshot,
            lineage=lineage_record,
            is_authoritative=False,
        )

        # 6. Execute fresh independent verifier reproduction
        if counters.verifier_executions_used >= cfg.max_verifier_executions:
            return create_repair_loop_receipt(
                repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                initial_candidate_id=initial_candidate.candidate_id,
                initial_patch_digest=initial_candidate.patch_digest,
                initial_tree_digest=initial_candidate.candidate_tree_digest,
                final_candidate_id=final_candidate_id,
                final_patch_digest=final_patch_digest,
                final_tree_digest=final_tree_digest,
                status=RepairLoopStatus.REPAIR_BUDGET_EXHAUSTED,
                preliminary_verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                grants_pass=False,
                total_rounds=round_idx,
                lineage_digests=lineage_digests,
                feedback_digests=feedback_digests,
                reproduction_receipt_digests=reproduction_receipt_digests,
                counters=counters.to_dict(),
                failure_reason="Verifier executions budget exhausted",
                provenance=provenance,
            )

        counters.verifier_executions_used += 1
        counters.sandbox_executions_used += 1

        reproduction_receipt: RepairedVerificationReceipt
        try:
            reproduction_receipt = execute_repaired_verifier_reproduction(
                repaired_candidate=repaired_snapshot,
                lineage_record=lineage_record,
                sealed_record=sealed_record,
                witness_lock=witness_lock,
                sandbox_manager=sandbox_manager,
                sandbox_adapter=sandbox_adapter,
                materializer=materializer,
                execution_command=execution_command,
                frozen_contract=frozen_contract,
                source_identity=source_identity,
                prior_sandbox_ids=all_sandbox_ids,
                base_outcome=WitnessOutcome.FAIL,
                counterfactual_outcome=counterfactual_outcome if counterfactual_check else None,
                provenance=provenance,
            )
        except VerifierSandboxReuseError as exc:
            return create_repair_loop_receipt(
                repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                initial_candidate_id=initial_candidate.candidate_id,
                initial_patch_digest=initial_candidate.patch_digest,
                initial_tree_digest=initial_candidate.candidate_tree_digest,
                final_candidate_id=final_candidate_id,
                final_patch_digest=final_patch_digest,
                final_tree_digest=final_tree_digest,
                status=RepairLoopStatus.REPAIR_INFRA_FAILURE,
                preliminary_verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                grants_pass=False,
                total_rounds=round_idx,
                lineage_digests=lineage_digests,
                feedback_digests=feedback_digests,
                reproduction_receipt_digests=reproduction_receipt_digests,
                counters=counters.to_dict(),
                failure_reason=f"Verifier sandbox collision: {exc}",
                provenance=provenance,
            )
        except Exception as exc:
            return create_repair_loop_receipt(
                repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                initial_candidate_id=initial_candidate.candidate_id,
                initial_patch_digest=initial_candidate.patch_digest,
                initial_tree_digest=initial_candidate.candidate_tree_digest,
                final_candidate_id=final_candidate_id,
                final_patch_digest=final_patch_digest,
                final_tree_digest=final_tree_digest,
                status=RepairLoopStatus.REPAIR_INFRA_FAILURE,
                preliminary_verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                grants_pass=False,
                total_rounds=round_idx,
                lineage_digests=lineage_digests,
                feedback_digests=feedback_digests,
                reproduction_receipt_digests=reproduction_receipt_digests,
                counters=counters.to_dict(),
                failure_reason=f"Verifier reproduction execution failed: {exc}",
                provenance=provenance,
            )

        all_sandbox_ids.add(reproduction_receipt.sandbox_id)
        reproduction_receipt_digests.append(reproduction_receipt.receipt_digest)

        # 7. Check reproduction verdict
        if reproduction_receipt.grants_pass:
            return create_repair_loop_receipt(
                repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
                initial_candidate_id=initial_candidate.candidate_id,
                initial_patch_digest=initial_candidate.patch_digest,
                initial_tree_digest=initial_candidate.candidate_tree_digest,
                final_candidate_id=repaired_cand_snapshot.candidate_id,
                final_patch_digest=repaired_cand_snapshot.patch_digest,
                final_tree_digest=repaired_cand_snapshot.candidate_tree_digest,
                status=RepairLoopStatus.VERIFIED_AFTER_REPAIR,
                preliminary_verdict=PreliminaryVerdict.VERIFIED,
                is_causally_verified=True,
                grants_pass=True,
                total_rounds=round_idx,
                lineage_digests=lineage_digests,
                feedback_digests=feedback_digests,
                reproduction_receipt_digests=reproduction_receipt_digests,
                counters=counters.to_dict(),
                failure_reason=None,
                provenance=provenance,
            )

        # Candidate did not pass; prepare for next round
        current_candidate = repaired_cand_snapshot
        current_receipt_digest = reproduction_receipt.receipt_digest

    # All rounds exhausted without pass
    return create_repair_loop_receipt(
        repair_receipt_id=f"RLR-{uuid.uuid4().hex[:12]}",
        initial_candidate_id=initial_candidate.candidate_id,
        initial_patch_digest=initial_candidate.patch_digest,
        initial_tree_digest=initial_candidate.candidate_tree_digest,
        final_candidate_id=final_candidate_id,
        final_patch_digest=final_patch_digest,
        final_tree_digest=final_tree_digest,
        status=RepairLoopStatus.REPAIR_BUDGET_EXHAUSTED,
        preliminary_verdict=PreliminaryVerdict.CONTRADICTED,
        is_causally_verified=False,
        grants_pass=False,
        total_rounds=cfg.max_repair_rounds,
        lineage_digests=lineage_digests,
        feedback_digests=feedback_digests,
        reproduction_receipt_digests=reproduction_receipt_digests,
        counters=counters.to_dict(),
        failure_reason=(
            f"Repairs failed to satisfy verification within {cfg.max_repair_rounds} rounds"
        ),
        provenance=provenance,
    )
