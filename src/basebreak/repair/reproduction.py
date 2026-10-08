"""Fresh verifier reproduction for repaired candidates.

P-14.05: Require fresh verifier reproduction for repaired candidate.

Core Invariants:
1. Fresh disposable verifier sandbox: Repaired candidate verification must execute
   in a freshly allocated verifier sandbox with a unique sandbox ID.
   Reusing the Builder sandbox, the original candidate sandbox, or any prior
   verifier sandbox is strictly prohibited.
2. Clean base checkout + repaired patch: Verifier materializes clean base source
   and applies only the repaired patch. Zero inheritance of prior mutable workspace state.
3. Independent sealed witness: Verifier executes the sealed witness locked before
   candidate execution, completely hidden from the Builder.
4. Non-inheritance / Anti-replay: A repaired candidate cannot inherit or reuse
   PASS receipts from original or earlier iterations.
5. Binding to repaired candidate hash: Emits a fresh verification receipt
   cryptographically bound to the repaired candidate ID, patch digest, tree digest,
   and lineage digest.
6. Counterfactual property holds: For BUG_FIX, causal transition requires
   BASE=FAIL and REPAIRED_CANDIDATE=PASS (and counterfactual=FAIL when evaluated).
7. Verifier crash / timeout never passes: If verifier crashes, times out, or
   fails execution, the repaired candidate does NOT pass.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import posixpath
import re
import shlex
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from basebreak.causal.reconciliation import (
    CausalTransition,
    reconcile_causal_transition,
)
from basebreak.compiler.freeze import FrozenContract
from basebreak.domain.causal import CandidateIdentity, ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.source import SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.repair.lineage import (
    CandidateLineageRecord,
    RepairedCandidateSnapshot,
    verify_candidate_lineage_integrity,
)
from basebreak.verifier.context import VerifierContextEnvelope, VerifierExecutionPolicy
from basebreak.verifier.sandbox import (
    BuilderSandboxReuseError,
    VerifierSandboxManager,
    VerifierSandboxSession,
)
from basebreak.verifier.witness_lock import (
    ImmutableWitnessLock,
    verify_witness_lock_chain,
)
from basebreak.verifier.witness_result import (
    WitnessOutcome,
    normalize_witness_execution,
)
from basebreak.verifier.witness_store import SealedWitnessRecord

REPAIRED_RECEIPT_SCHEMA_VERSION: str = "1.0.0"

_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class VerifierReproductionError(Exception):
    """Base exception for verifier reproduction errors."""


class VerifierSandboxReuseError(VerifierReproductionError):
    """Raised when verifier reproduction attempts to reuse a prior sandbox ID."""


class RepairedReceiptReplayError(VerifierReproductionError):
    """Raised when an old or foreign receipt is presented for a repaired candidate."""


class RepairedCandidateVerificationMismatchError(VerifierReproductionError):
    """Raised when candidate facts do not match expected lineage or reproduction facts."""


class RepairedReceiptTamperingError(VerifierReproductionError):
    """Raised when cryptographic digest verification fails on a repaired receipt."""


@dataclass(frozen=True, slots=True)
class RepairedVerificationReceipt:
    """Deterministic verification receipt for a repaired candidate.

    Binds the new candidate identity, patch digest, tree digest, lineage record,
    frozen contract, sealed witness, fresh verifier sandbox, execution outcome,
    and preliminary verdict.

    Possesses zero unverified authority (is_authoritative=False).
    """

    schema_version: str
    receipt_id: str
    repaired_candidate_id: str
    repaired_patch_digest: str
    repaired_tree_digest: str
    parent_candidate_id: str
    lineage_digest: str
    feedback_round: int
    requirement_id: str
    change_class: ChangeClass
    frozen_contract_digest: str
    witness_digest: str
    lock_digest: str
    sandbox_id: str
    witness_outcome: WitnessOutcome
    exit_code: int | None
    duration_seconds: float
    preliminary_verdict: PreliminaryVerdict
    is_causally_verified: bool
    grants_pass: bool
    is_authoritative: bool
    provenance: EvidenceProvenance
    created_at: str
    receipt_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != REPAIRED_RECEIPT_SCHEMA_VERSION:
            raise RepairedReceiptTamperingError(
                f"Unsupported schema_version: {self.schema_version!r}"
            )
        if not self.receipt_id.strip():
            raise RepairedReceiptTamperingError("receipt_id must be non-empty")
        if not self.repaired_candidate_id.strip():
            raise RepairedReceiptTamperingError("repaired_candidate_id must be non-empty")
        if not _HEX_64_PATTERN.match(self.repaired_patch_digest):
            raise RepairedReceiptTamperingError(
                "repaired_patch_digest must be a 64-char hex string"
            )
        if not _HEX_40_OR_64_PATTERN.match(self.repaired_tree_digest):
            raise RepairedReceiptTamperingError(
                "repaired_tree_digest must be a 40 or 64-char hex string"
            )
        if not self.parent_candidate_id.strip():
            raise RepairedReceiptTamperingError("parent_candidate_id must be non-empty")
        if not _HEX_64_PATTERN.match(self.lineage_digest):
            raise RepairedReceiptTamperingError("lineage_digest must be a 64-char hex string")
        if self.feedback_round < 1:
            raise RepairedReceiptTamperingError("feedback_round must be >= 1")
        if not self.requirement_id.strip():
            raise RepairedReceiptTamperingError("requirement_id must be non-empty")
        if not isinstance(self.change_class, ChangeClass):
            raise TypeError("change_class must be a ChangeClass instance")
        if not _HEX_64_PATTERN.match(self.frozen_contract_digest):
            raise RepairedReceiptTamperingError(
                "frozen_contract_digest must be a 64-char hex string"
            )
        if not _HEX_64_PATTERN.match(self.witness_digest):
            raise RepairedReceiptTamperingError("witness_digest must be a 64-char hex string")
        if not _HEX_64_PATTERN.match(self.lock_digest):
            raise RepairedReceiptTamperingError("lock_digest must be a 64-char hex string")
        if not self.sandbox_id.strip():
            raise RepairedReceiptTamperingError("sandbox_id must be non-empty")
        if not isinstance(self.witness_outcome, WitnessOutcome):
            raise TypeError("witness_outcome must be a WitnessOutcome instance")
        if not isinstance(self.preliminary_verdict, PreliminaryVerdict):
            raise TypeError("preliminary_verdict must be a PreliminaryVerdict instance")
        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError("provenance must be an EvidenceProvenance instance")

        # Zero unverified authority invariant
        if self.is_authoritative is not False:
            raise RepairedReceiptTamperingError("is_authoritative must be strictly False")

        # Pass granting consistency
        if self.grants_pass:
            if not self.is_causally_verified:
                raise RepairedReceiptTamperingError(
                    "Receipt cannot grant PASS if is_causally_verified is False"
                )
            if self.preliminary_verdict != PreliminaryVerdict.VERIFIED:
                raise RepairedReceiptTamperingError(
                    "Receipt cannot grant PASS unless preliminary_verdict is VERIFIED"
                )
        else:
            if (
                self.is_causally_verified
                and self.preliminary_verdict == PreliminaryVerdict.VERIFIED
            ):
                raise RepairedReceiptTamperingError(
                    "Receipt claiming VERIFIED causal state must have grants_pass=True"
                )

        # Candidate identity vs parent check
        if self.repaired_candidate_id == self.parent_candidate_id:
            raise RepairedReceiptTamperingError(
                "repaired_candidate_id must not equal parent_candidate_id"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize receipt to canonical dictionary representation."""
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "repaired_candidate_id": self.repaired_candidate_id,
            "repaired_patch_digest": self.repaired_patch_digest,
            "repaired_tree_digest": self.repaired_tree_digest,
            "parent_candidate_id": self.parent_candidate_id,
            "lineage_digest": self.lineage_digest,
            "feedback_round": self.feedback_round,
            "requirement_id": self.requirement_id,
            "change_class": self.change_class.value,
            "frozen_contract_digest": self.frozen_contract_digest,
            "witness_digest": self.witness_digest,
            "lock_digest": self.lock_digest,
            "sandbox_id": self.sandbox_id,
            "witness_outcome": self.witness_outcome.value,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "preliminary_verdict": self.preliminary_verdict.value,
            "is_causally_verified": self.is_causally_verified,
            "grants_pass": self.grants_pass,
            "is_authoritative": self.is_authoritative,
            "provenance": self.provenance.value,
            "created_at": self.created_at,
            "receipt_digest": self.receipt_digest,
        }


def build_canonical_repaired_receipt_payload(
    *,
    schema_version: str,
    receipt_id: str,
    repaired_candidate_id: str,
    repaired_patch_digest: str,
    repaired_tree_digest: str,
    parent_candidate_id: str,
    lineage_digest: str,
    feedback_round: int,
    requirement_id: str,
    change_class: str,
    frozen_contract_digest: str,
    witness_digest: str,
    lock_digest: str,
    sandbox_id: str,
    witness_outcome: str,
    exit_code: int | None,
    duration_seconds: float,
    preliminary_verdict: str,
    is_causally_verified: bool,
    grants_pass: bool,
    is_authoritative: bool,
    provenance: str,
    created_at: str,
) -> dict[str, Any]:
    """Construct deterministic payload dictionary with sorted keys."""
    return {
        "change_class": str(change_class),
        "created_at": str(created_at),
        "duration_seconds": round(float(duration_seconds), 4),
        "exit_code": exit_code,
        "feedback_round": int(feedback_round),
        "frozen_contract_digest": str(frozen_contract_digest).lower(),
        "grants_pass": bool(grants_pass),
        "is_authoritative": bool(is_authoritative),
        "is_causally_verified": bool(is_causally_verified),
        "lineage_digest": str(lineage_digest).lower(),
        "lock_digest": str(lock_digest).lower(),
        "parent_candidate_id": str(parent_candidate_id),
        "preliminary_verdict": str(preliminary_verdict),
        "provenance": str(provenance),
        "receipt_id": str(receipt_id),
        "repaired_candidate_id": str(repaired_candidate_id),
        "repaired_patch_digest": str(repaired_patch_digest).lower(),
        "repaired_tree_digest": str(repaired_tree_digest).lower(),
        "requirement_id": str(requirement_id),
        "sandbox_id": str(sandbox_id),
        "schema_version": str(schema_version),
        "witness_digest": str(witness_digest).lower(),
        "witness_outcome": str(witness_outcome),
    }


def compute_repaired_receipt_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical JSON bytes."""
    clean = {k: v for k, v in payload.items() if k != "receipt_digest"}
    data = json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def verify_repaired_receipt_integrity(receipt: RepairedVerificationReceipt) -> bool:
    """Verify cryptographic receipt digest against recomputed payload."""
    payload = build_canonical_repaired_receipt_payload(
        schema_version=receipt.schema_version,
        receipt_id=receipt.receipt_id,
        repaired_candidate_id=receipt.repaired_candidate_id,
        repaired_patch_digest=receipt.repaired_patch_digest,
        repaired_tree_digest=receipt.repaired_tree_digest,
        parent_candidate_id=receipt.parent_candidate_id,
        lineage_digest=receipt.lineage_digest,
        feedback_round=receipt.feedback_round,
        requirement_id=receipt.requirement_id,
        change_class=receipt.change_class.value,
        frozen_contract_digest=receipt.frozen_contract_digest,
        witness_digest=receipt.witness_digest,
        lock_digest=receipt.lock_digest,
        sandbox_id=receipt.sandbox_id,
        witness_outcome=receipt.witness_outcome.value,
        exit_code=receipt.exit_code,
        duration_seconds=receipt.duration_seconds,
        preliminary_verdict=receipt.preliminary_verdict.value,
        is_causally_verified=receipt.is_causally_verified,
        grants_pass=receipt.grants_pass,
        is_authoritative=receipt.is_authoritative,
        provenance=receipt.provenance.value,
        created_at=receipt.created_at,
    )
    expected = compute_repaired_receipt_digest(payload)
    if receipt.receipt_digest != expected:
        raise RepairedReceiptTamperingError(
            f"Repaired receipt digest mismatch: declared {receipt.receipt_digest}, "
            f"recomputed {expected}"
        )
    return True


def create_repaired_verification_receipt(
    *,
    receipt_id: str,
    repaired_candidate_id: str,
    repaired_patch_digest: str,
    repaired_tree_digest: str,
    parent_candidate_id: str,
    lineage_digest: str,
    feedback_round: int,
    requirement_id: str,
    change_class: ChangeClass,
    frozen_contract_digest: str,
    witness_digest: str,
    lock_digest: str,
    sandbox_id: str,
    witness_outcome: WitnessOutcome,
    exit_code: int | None,
    duration_seconds: float,
    preliminary_verdict: PreliminaryVerdict,
    is_causally_verified: bool,
    grants_pass: bool,
    provenance: EvidenceProvenance,
    created_at: str | None = None,
) -> RepairedVerificationReceipt:
    """Create a tamper-evident RepairedVerificationReceipt with computed cryptographic digest."""
    ts = created_at or datetime.now(timezone.utc).isoformat()
    payload = build_canonical_repaired_receipt_payload(
        schema_version=REPAIRED_RECEIPT_SCHEMA_VERSION,
        receipt_id=receipt_id,
        repaired_candidate_id=repaired_candidate_id,
        repaired_patch_digest=repaired_patch_digest,
        repaired_tree_digest=repaired_tree_digest,
        parent_candidate_id=parent_candidate_id,
        lineage_digest=lineage_digest,
        feedback_round=feedback_round,
        requirement_id=requirement_id,
        change_class=change_class.value,
        frozen_contract_digest=frozen_contract_digest,
        witness_digest=witness_digest,
        lock_digest=lock_digest,
        sandbox_id=sandbox_id,
        witness_outcome=witness_outcome.value,
        exit_code=exit_code,
        duration_seconds=duration_seconds,
        preliminary_verdict=preliminary_verdict.value,
        is_causally_verified=is_causally_verified,
        grants_pass=grants_pass,
        is_authoritative=False,
        provenance=provenance.value,
        created_at=ts,
    )
    digest = compute_repaired_receipt_digest(payload)
    return RepairedVerificationReceipt(
        schema_version=REPAIRED_RECEIPT_SCHEMA_VERSION,
        receipt_id=receipt_id,
        repaired_candidate_id=repaired_candidate_id,
        repaired_patch_digest=repaired_patch_digest,
        repaired_tree_digest=repaired_tree_digest,
        parent_candidate_id=parent_candidate_id,
        lineage_digest=lineage_digest,
        feedback_round=feedback_round,
        requirement_id=requirement_id,
        change_class=change_class,
        frozen_contract_digest=frozen_contract_digest,
        witness_digest=witness_digest,
        lock_digest=lock_digest,
        sandbox_id=sandbox_id,
        witness_outcome=witness_outcome,
        exit_code=exit_code,
        duration_seconds=duration_seconds,
        preliminary_verdict=preliminary_verdict,
        is_causally_verified=is_causally_verified,
        grants_pass=grants_pass,
        is_authoritative=False,
        provenance=provenance,
        created_at=ts,
        receipt_digest=digest,
    )


def verify_repaired_receipt_non_inheritance(
    receipt: RepairedVerificationReceipt,
    *,
    repaired_candidate: RepairedCandidateSnapshot,
    lineage_record: CandidateLineageRecord,
    prior_candidate_ids: Sequence[str] | set[str] | None = None,
) -> None:
    """Verify that a verification receipt does NOT inherit or replay prior candidate data.

    Enforces that:
    1. Receipt strictly matches the repaired candidate's ID and digests.
    2. Receipt does NOT claim parent candidate ID, patch digest, or tree digest.
    3. Receipt candidate ID is not in prior_candidate_ids.
    4. Receipt lineage digest matches the provided lineage record.
    """
    verify_repaired_receipt_integrity(receipt)

    if receipt.repaired_candidate_id != repaired_candidate.repaired_candidate_id:
        raise RepairedReceiptReplayError(
            f"Receipt repaired_candidate_id ({receipt.repaired_candidate_id}) does not match "
            f"candidate ({repaired_candidate.repaired_candidate_id})"
        )
    if receipt.repaired_patch_digest != repaired_candidate.repaired_patch_digest:
        raise RepairedReceiptReplayError(
            f"Receipt repaired_patch_digest ({receipt.repaired_patch_digest}) does not match "
            f"candidate ({repaired_candidate.repaired_patch_digest})"
        )
    if receipt.repaired_tree_digest != repaired_candidate.repaired_tree_digest:
        raise RepairedReceiptReplayError(
            f"Receipt repaired_tree_digest ({receipt.repaired_tree_digest}) does not match "
            f"candidate ({repaired_candidate.repaired_tree_digest})"
        )
    if receipt.lineage_digest != lineage_record.lineage_digest:
        raise RepairedReceiptReplayError(
            f"Receipt lineage_digest ({receipt.lineage_digest}) does not match "
            f"lineage record ({lineage_record.lineage_digest})"
        )
    if receipt.repaired_candidate_id == lineage_record.parent_candidate_id:
        raise RepairedReceiptReplayError(
            "Repaired receipt attempts to claim parent candidate ID; inheritance forbidden"
        )
    if receipt.repaired_patch_digest == lineage_record.parent_patch_digest:
        raise RepairedReceiptReplayError(
            "Repaired receipt attempts to claim parent patch digest; inheritance forbidden"
        )
    if receipt.repaired_tree_digest == lineage_record.parent_tree_digest:
        raise RepairedReceiptReplayError(
            "Repaired receipt attempts to claim parent tree digest; inheritance forbidden"
        )

    if receipt.feedback_round != lineage_record.repair_round:
        raise RepairedReceiptReplayError(
            f"Receipt feedback_round ({receipt.feedback_round}) does not match "
            f"lineage record repair_round ({lineage_record.repair_round})"
        )
    if prior_candidate_ids is not None:
        p_set = {str(c).strip() for c in prior_candidate_ids}
        if receipt.repaired_candidate_id in p_set:
            raise RepairedReceiptReplayError(
                f"Repaired receipt reuses prior candidate ID {receipt.repaired_candidate_id!r}"
            )


def _deploy_sealed_witness_artifacts(
    *,
    session: VerifierSandboxSession,
    sealed_record: SealedWitnessRecord,
    sandbox_adapter: Any,
) -> None:
    """Deploy sealed witness test files into the isolated verifier sandbox workspace."""
    lines: list[str] = ["set -e"]
    clean_ws = session.workspace_path.rstrip("/")
    lines.append(f"cd {shlex.quote(clean_ws)}")

    for art in sealed_record.artifacts:
        art_posix = art.path.replace("\\", "/").lstrip("/")
        full_path = f"{clean_ws}/{art_posix}"
        parent_dir = posixpath.dirname(full_path)
        b64_content = base64.b64encode(art.content.encode("utf-8")).decode("ascii")

        lines.append(f"mkdir -p {shlex.quote(parent_dir)}")
        lines.append(
            f'printf "%s" {shlex.quote(b64_content)} | base64 -d > {shlex.quote(full_path)}'
        )

    deploy_kwargs: dict[str, Any] = {
        "working_dir": session.workspace_path,
        "timeout_seconds": 60,
    }
    try:
        sig = inspect.signature(sandbox_adapter.execute_command)
        if "disposable" in sig.parameters:
            deploy_kwargs["disposable"] = False
    except Exception:
        pass

    deploy_script = "\n".join(lines) + "\n"
    res = sandbox_adapter.execute_command(
        session.sandbox_identity,
        deploy_script,
        **deploy_kwargs,
    )
    exit_code = getattr(res, "exit_code", None)
    if exit_code is None and hasattr(res, "result"):
        exit_code = getattr(res.result, "exit_code", None)
    if exit_code != 0:
        stderr = getattr(res, "stderr", "") or ""
        raise VerifierReproductionError(
            f"Failed to deploy sealed witness artifacts into verifier sandbox: {stderr}"
        )


def _execute_command_in_sandbox(
    *,
    session: VerifierSandboxSession,
    sandbox_adapter: Any,
    command: Sequence[str] | str,
    timeout_seconds: int,
) -> tuple[int | None, TerminationStatus, str, str, float]:
    """Execute a test command inside the sandbox workspace."""
    cmd_input: Any
    if isinstance(command, (list, tuple)):
        cmd_input = " ".join(shlex.quote(arg) for arg in command)
    else:
        cmd_input = str(command)

    exec_kwargs: dict[str, Any] = {
        "working_dir": session.workspace_path,
        "timeout_seconds": timeout_seconds,
    }
    try:
        sig = inspect.signature(sandbox_adapter.execute_command)
        if "disposable" in sig.parameters:
            exec_kwargs["disposable"] = True
    except Exception:
        pass

    start_time = time.perf_counter()
    try:
        res = sandbox_adapter.execute_command(
            session.sandbox_identity,
            cmd_input,
            **exec_kwargs,
        )
        elapsed = time.perf_counter() - start_time
    except Exception as exc:
        elapsed = time.perf_counter() - start_time
        exc_str = str(exc).lower()
        if "timeout" in exc_str:
            return None, TerminationStatus.TIMED_OUT, "", str(exc), elapsed
        return None, TerminationStatus.COMPLETED, "", str(exc), elapsed

    exit_code = getattr(res, "exit_code", None)
    if exit_code is None and hasattr(res, "result"):
        exit_code = getattr(res.result, "exit_code", None)

    stdout = getattr(res, "stdout", "") or ""
    stderr = getattr(res, "stderr", "") or ""

    term_status = TerminationStatus.COMPLETED
    if getattr(res, "is_timed_out", False):
        term_status = TerminationStatus.TIMED_OUT
    elif getattr(res, "is_cancelled", False):
        term_status = TerminationStatus.CANCELLED
    elif getattr(res, "is_failed_to_start", False):
        term_status = TerminationStatus.FAILED_TO_START

    duration = getattr(res, "duration_seconds", None)
    if duration is None or not isinstance(duration, (int, float)):
        duration = elapsed

    return exit_code, term_status, stdout, stderr, float(duration)


def execute_repaired_verifier_reproduction(
    *,
    repaired_candidate: RepairedCandidateSnapshot,
    lineage_record: CandidateLineageRecord,
    sealed_record: SealedWitnessRecord,
    witness_lock: ImmutableWitnessLock,
    sandbox_manager: VerifierSandboxManager,
    sandbox_adapter: Any,
    materializer: Any,
    execution_command: Sequence[str] | str,
    context_envelope: VerifierContextEnvelope | None = None,
    source_identity: SourceIdentity | None = None,
    frozen_contract: FrozenContract | None = None,
    execution_policy: VerifierExecutionPolicy | None = None,
    prior_sandbox_ids: Sequence[str] | set[str] | None = None,
    base_outcome: WitnessOutcome = WitnessOutcome.FAIL,
    counterfactual_outcome: WitnessOutcome | None = None,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
) -> RepairedVerificationReceipt:
    """Execute fresh independent verifier reproduction for a repaired candidate.

    Enforces all P-14.05 invariants:
    1. Lineage record integrity validation.
    2. Witness lock chain validation.
    3. Sandbox reuse prevention (rejects prior verifier, builder, or parent sandbox IDs).
    4. Clean base checkout + repaired patch materialization in disposable sandbox.
    5. Sealed witness execution hidden from Builder.
    6. Causal and counterfactual property evaluation.
    7. Verifier crash/timeout results in non-pass state.
    8. Returns fresh tamper-evident RepairedVerificationReceipt.
    """
    # 1. Lineage record integrity
    verify_candidate_lineage_integrity(lineage_record)
    if lineage_record.repaired_candidate_id != repaired_candidate.repaired_candidate_id:
        raise RepairedCandidateVerificationMismatchError(
            f"Lineage repaired_candidate_id ({lineage_record.repaired_candidate_id}) "
            f"does not match repaired candidate ID ({repaired_candidate.repaired_candidate_id})"
        )
    if lineage_record.repaired_patch_digest != repaired_candidate.repaired_patch_digest:
        raise RepairedCandidateVerificationMismatchError(
            f"Lineage repaired_patch_digest ({lineage_record.repaired_patch_digest}) "
            f"does not match repaired patch digest ({repaired_candidate.repaired_patch_digest})"
        )
    if lineage_record.repaired_tree_digest != repaired_candidate.repaired_tree_digest:
        raise RepairedCandidateVerificationMismatchError(
            f"Lineage repaired_tree_digest ({lineage_record.repaired_tree_digest}) does not match "
            f"repaired candidate tree digest ({repaired_candidate.repaired_tree_digest})"
        )

    # 2. Context envelope resolution and consistency
    if context_envelope is None:
        if frozen_contract is None or source_identity is None:
            raise RepairedCandidateVerificationMismatchError(
                "Either context_envelope or (frozen_contract, source_identity) must be provided"
            )
        candidate_ident = CandidateIdentity(
            candidate_id=repaired_candidate.repaired_candidate_id,
            source=source_identity,
            patch_digest=repaired_candidate.repaired_patch_digest,
        )
        context_envelope = VerifierContextEnvelope.create(
            frozen_contract=frozen_contract,
            source_identity=source_identity,
            execution_policy=execution_policy or VerifierExecutionPolicy(),
            candidate_identity=candidate_ident,
            candidate_patch_text=repaired_candidate.repaired_patch,
            candidate_tree_digest=repaired_candidate.repaired_tree_digest,
            sealed_witness_references=[sealed_record.witness_id],
        )
    else:
        # Validate that context envelope belongs to the repaired candidate
        if (
            context_envelope.candidate_identity is None
            or context_envelope.candidate_identity.candidate_id
            != repaired_candidate.repaired_candidate_id
        ):
            cand_id = (
                context_envelope.candidate_identity.candidate_id
                if context_envelope.candidate_identity
                else None
            )
            raise RepairedCandidateVerificationMismatchError(
                f"Context envelope candidate ID ({cand_id}) does not match "
                f"repaired candidate ID ({repaired_candidate.repaired_candidate_id})"
            )
        if context_envelope.candidate_identity.candidate_id == lineage_record.parent_candidate_id:
            raise RepairedCandidateVerificationMismatchError(
                "Context envelope targets parent candidate; repair inheritance forbidden"
            )
        if context_envelope.candidate_tree_digest != repaired_candidate.repaired_tree_digest:
            raise RepairedCandidateVerificationMismatchError(
                "Context envelope candidate_tree_digest does not match repaired candidate tree"
            )
        if context_envelope.frozen_contract.contract_digest != witness_lock.frozen_contract_digest:
            raise RepairedCandidateVerificationMismatchError(
                "Context envelope frozen contract digest does not match witness lock"
            )

    # 3. Witness lock chain validation
    verify_witness_lock_chain(
        lock=witness_lock,
        frozen_contract=context_envelope.frozen_contract,
        base_record=sealed_record,
        candidate_record=sealed_record,
    )
    if witness_lock.frozen_contract_digest != context_envelope.frozen_contract.contract_digest:
        raise RepairedCandidateVerificationMismatchError(
            "witness_lock frozen_contract_digest does not match context envelope"
        )
    if sealed_record.frozen_contract_digest != context_envelope.frozen_contract.contract_digest:
        raise RepairedCandidateVerificationMismatchError(
            f"sealed_record frozen_contract_digest ({sealed_record.frozen_contract_digest}) "
            f"does not match context envelope ({context_envelope.frozen_contract.contract_digest})"
        )

    # 4. Anti-sandbox reuse checks
    prior_set = set(prior_sandbox_ids or ())

    # 5. Create fresh isolated verifier sandbox
    session: VerifierSandboxSession
    try:
        session = sandbox_manager.create_isolated_verifier_sandbox(
            context_envelope=context_envelope,
            world=ExecutionWorld.CANDIDATE,
            sandbox_adapter=sandbox_adapter,
            materializer=materializer,
            candidate_tree_digest=repaired_candidate.repaired_tree_digest,
            provenance=provenance,
        )
    except BuilderSandboxReuseError as exc:
        raise VerifierSandboxReuseError(
            f"Verifier sandbox collided with prior sandbox: {exc}"
        ) from exc

    # Explicit check against prior sandbox IDs
    if session.sandbox_identity.sandbox_id in prior_set:
        sandbox_manager._teardown_sandbox(sandbox_adapter, session.sandbox_identity)
        raise VerifierSandboxReuseError(
            f"Verifier sandbox ID {session.sandbox_identity.sandbox_id!r} reuses a prior sandbox ID"
        )

    # 6. Execute sealed witness inside sandbox with guaranteed teardown
    try:
        # Check materialized tree digest
        if session.materialized_tree_digest != repaired_candidate.repaired_tree_digest:
            raise RepairedCandidateVerificationMismatchError(
                f"Materialized tree digest ({session.materialized_tree_digest}) does not match "
                f"repaired candidate tree digest ({repaired_candidate.repaired_tree_digest})"
            )

        # Deploy sealed witness artifacts
        _deploy_sealed_witness_artifacts(
            session=session,
            sealed_record=sealed_record,
            sandbox_adapter=sandbox_adapter,
        )

        # Execute test command
        timeout = context_envelope.execution_policy.timeout_seconds
        exit_code, term_status, stdout, stderr, duration = _execute_command_in_sandbox(
            session=session,
            sandbox_adapter=sandbox_adapter,
            command=execution_command,
            timeout_seconds=timeout,
        )

        # Normalize witness execution
        normalized_result = normalize_witness_execution(
            witness_id=sealed_record.witness_id,
            witness_digest=sealed_record.seal_digest,
            frozen_contract_digest=sealed_record.frozen_contract_digest,
            requirement_id=sealed_record.requirement_id,
            sandbox_identity=session.sandbox_identity,
            source_commit_id=session.materialized_commit_id,
            world=ExecutionWorld.CANDIDATE,
            status=term_status,
            exit_code=exit_code,
            stdout_raw=stdout,
            stderr_raw=stderr,
            duration_seconds=duration,
            provenance=provenance,
            max_output_bytes=context_envelope.execution_policy.max_output_bytes,
        )
    finally:
        # Mandatory fail-closed teardown of verifier sandbox
        sandbox_manager._teardown_sandbox(sandbox_adapter, session.sandbox_identity)

    # 7. Evaluate verdict & causal transitions deterministically
    witness_outcome = normalized_result.outcome
    preliminary_verdict: PreliminaryVerdict
    is_causally_verified: bool
    grants_pass: bool

    change_class = context_envelope.frozen_contract.change_class
    if witness_outcome == WitnessOutcome.PASS:
        if change_class == ChangeClass.BUG_FIX:
            # Reconcile causal transition: BASE=FAIL -> CANDIDATE=PASS
            transition_fact = reconcile_causal_transition(
                base_outcome=base_outcome,
                candidate_outcome=witness_outcome,
            )
            if transition_fact.transition == CausalTransition.CAUSAL_BUG_FIX_VERIFIED:
                # If counterfactual was executed, verify that COUNTERFACTUAL=FAIL
                if (
                    counterfactual_outcome is not None
                    and counterfactual_outcome != WitnessOutcome.FAIL
                ):
                    preliminary_verdict = PreliminaryVerdict.CONTRADICTED
                    is_causally_verified = False
                    grants_pass = False
                else:
                    preliminary_verdict = PreliminaryVerdict.VERIFIED
                    is_causally_verified = True
                    grants_pass = True
            else:
                preliminary_verdict = transition_fact.verdict
                is_causally_verified = False
                grants_pass = False
        else:
            # Non-BUG_FIX: PASS on candidate yields VERIFIED
            preliminary_verdict = PreliminaryVerdict.VERIFIED
            is_causally_verified = True
            grants_pass = True
    elif witness_outcome == WitnessOutcome.FAIL:
        preliminary_verdict = PreliminaryVerdict.CONTRADICTED
        is_causally_verified = False
        grants_pass = False
    else:
        # TIMEOUT, ERROR, or infrastructure failure
        preliminary_verdict = PreliminaryVerdict.INCONCLUSIVE
        is_causally_verified = False
        grants_pass = False

    receipt_id = f"RVR-{uuid.uuid4().hex[:12]}"
    receipt = create_repaired_verification_receipt(
        receipt_id=receipt_id,
        repaired_candidate_id=repaired_candidate.repaired_candidate_id,
        repaired_patch_digest=repaired_candidate.repaired_patch_digest,
        repaired_tree_digest=repaired_candidate.repaired_tree_digest,
        parent_candidate_id=lineage_record.parent_candidate_id,
        lineage_digest=lineage_record.lineage_digest,
        feedback_round=lineage_record.repair_round,
        requirement_id=sealed_record.requirement_id,
        change_class=change_class,
        frozen_contract_digest=context_envelope.frozen_contract.contract_digest,
        witness_digest=sealed_record.seal_digest,
        lock_digest=witness_lock.lock_digest,
        sandbox_id=session.sandbox_identity.sandbox_id,
        witness_outcome=witness_outcome,
        exit_code=exit_code,
        duration_seconds=duration,
        preliminary_verdict=preliminary_verdict,
        is_causally_verified=is_causally_verified,
        grants_pass=grants_pass,
        provenance=provenance,
    )

    # Validate non-inheritance invariant
    verify_repaired_receipt_non_inheritance(
        receipt,
        repaired_candidate=repaired_candidate,
        lineage_record=lineage_record,
        prior_candidate_ids=prior_set,
    )

    return receipt
