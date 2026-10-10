"""Public verification receipt schema, cryptographic binding, and presentation.

P-18: Verification Receipt
- P-18.01: Define public receipt schema.
- P-18.02: Bind base/candidate/counterfactual hashes, witnesses and outcomes.
- P-18.03: Include provenance, runtime identities, timing/cost and NOT_RUN.
- P-18.04: Add integrity digest/signature strategy appropriate to hackathon scope.
- P-18.05: Render human-readable receipt without losing machine truth.

Core Invariants:
1. Public Envelope: A cohesive, self-contained, tamper-evident proof object
   binding all underlying verification evidence.
2. Cryptographic Chain: Binds exact frozen contract digest, source commit SHA,
   candidate tree/patch digests, counterfactual deltas, witness IDs and digests,
   two-world/three-world execution facts, Causal Coverage metrics, and overall verdict.
3. Tamper Rejection: Recomputed SHA-256 receipt digest over canonical JSON bytes.
   Any field alteration immediately fails validation with PublicReceiptTamperingError.
4. Authority Boundary: is_authoritative is strictly False unless independent authority exists.
   A checksum is not an independent verification certificate.
5. Strict Provenance: Explicitly declares evidence provenance (FIXTURE, LOCAL_EXECUTION,
   LIVE_NEBIUS, RECORDED_LIVE).
6. Non-Fabrication: Missing counterrun, missing witness, or unknown cost/timing
   must be represented as None/Unknown or explicit absent reason, never fabricated.
7. Secret Safety: Validates that no credentials, API keys, or hidden sealed witness
   source code leak into public receipt serialization.
8. Presentation Parity: Human-readable Markdown and terminal rendering must strictly
   reflect machine truth without contradiction.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from basebreak.causal.coverage import CausalCoverageSummary, verify_coverage_integrity
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.security.secret_policy import contains_secret
from basebreak.verifier.witness_result import WitnessOutcome

PUBLIC_RECEIPT_SCHEMA_VERSION: str = "1.0.0"

_HEX_40_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")

CANONICAL_RECEIPT_THESIS: str = "If the patch matters, the base must break."
CANONICAL_DISCLAIMER_TEXT: str = (
    "Basebreak provides empirical causal verification under specified test witnesses; "
    "it does not constitute mathematical formal proof or universal equivalence."
)


class PublicReceiptError(Exception):
    """Base exception for public verification receipt errors."""


class PublicReceiptTamperingError(PublicReceiptError):
    """Raised when receipt facts do not match the cryptographic receipt digest."""


class PublicReceiptIntegrityError(PublicReceiptError):
    """Raised when receipt fields violate domain or format constraints."""


class PublicReceiptSecretLeakError(PublicReceiptError):
    """Raised when secret patterns are detected inside receipt serialization."""


@dataclass(frozen=True, slots=True)
class PublicWitnessFact:
    """Public summary of a sealed witness bound to the verification receipt."""

    witness_id: str
    witness_digest: str
    lock_digest: str | None = None
    requirement_id: str | None = None
    execution_command: tuple[str, ...] = ()
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not isinstance(self.witness_id, str) or not self.witness_id.strip():
            raise PublicReceiptIntegrityError("witness_id must be a non-empty string")
        if not isinstance(self.witness_digest, str) or not _HEX_64_PATTERN.match(
            self.witness_digest
        ):
            raise PublicReceiptIntegrityError("witness_digest must be a 64-char hex string")
        if self.lock_digest is not None:
            if not isinstance(self.lock_digest, str) or not _HEX_64_PATTERN.match(self.lock_digest):
                raise PublicReceiptIntegrityError("lock_digest must be a 64-char hex string")

    def to_dict(self) -> dict[str, Any]:
        """Convert to canonical dictionary."""
        return {
            "execution_command": list(self.execution_command),
            "lock_digest": self.lock_digest,
            "requirement_id": self.requirement_id,
            "timeout_seconds": self.timeout_seconds,
            "witness_digest": self.witness_digest,
            "witness_id": self.witness_id,
        }


@dataclass(frozen=True, slots=True)
class PublicExecutionFact:
    """Public summary of a single world execution."""

    world: ExecutionWorld
    sandbox_id: str
    source_commit_id: str
    tree_digest: str
    outcome: WitnessOutcome
    exit_code: int | None
    termination_status: TerminationStatus
    stdout_digest: str
    stderr_digest: str
    duration_seconds: float
    stdout_excerpt: str | None = None
    stderr_excerpt: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.world, ExecutionWorld):
            raise TypeError(f"world must be ExecutionWorld, got {type(self.world).__name__}")
        if not isinstance(self.sandbox_id, str) or not self.sandbox_id.strip():
            raise PublicReceiptIntegrityError("sandbox_id must be a non-empty string")
        if not isinstance(self.source_commit_id, str) or not _HEX_40_PATTERN.match(
            self.source_commit_id
        ):
            raise PublicReceiptIntegrityError("source_commit_id must be a 40-char commit SHA")
        if not isinstance(self.tree_digest, str) or not _HEX_40_OR_64_PATTERN.match(
            self.tree_digest
        ):
            raise PublicReceiptIntegrityError("tree_digest must be 40 or 64 hex characters")
        if not isinstance(self.outcome, WitnessOutcome):
            raise TypeError("outcome must be WitnessOutcome")
        if not isinstance(self.termination_status, TerminationStatus):
            raise TypeError("termination_status must be TerminationStatus")
        if not isinstance(self.stdout_digest, str) or not _HEX_64_PATTERN.match(self.stdout_digest):
            raise PublicReceiptIntegrityError("stdout_digest must be a 64-char hex string")
        if not isinstance(self.stderr_digest, str) or not _HEX_64_PATTERN.match(self.stderr_digest):
            raise PublicReceiptIntegrityError("stderr_digest must be a 64-char hex string")
        if (
            isinstance(self.duration_seconds, bool)
            or not isinstance(self.duration_seconds, (int, float))
            or self.duration_seconds < 0.0
        ):
            raise PublicReceiptIntegrityError("duration_seconds must be a non-negative number")

    def to_dict(self) -> dict[str, Any]:
        """Convert to canonical dictionary."""
        return {
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "outcome": self.outcome.value,
            "sandbox_id": self.sandbox_id,
            "source_commit_id": self.source_commit_id,
            "stderr_digest": self.stderr_digest,
            "stderr_excerpt": self.stderr_excerpt,
            "stdout_digest": self.stdout_digest,
            "stdout_excerpt": self.stdout_excerpt,
            "termination_status": self.termination_status.value,
            "tree_digest": self.tree_digest,
            "world": self.world.value,
        }


@dataclass(frozen=True, slots=True)
class PublicCounterfactualFact:
    """Public facts regarding counterfactual third-world execution (P-11)."""

    is_required: bool
    candidate_tree_digest: str | None = None
    delta_digest: str | None = None
    outcome: WitnessOutcome | None = None
    execution_fact: PublicExecutionFact | None = None
    absence_rationale: str | None = None

    def __post_init__(self) -> None:
        if self.is_required:
            if not self.candidate_tree_digest or not _HEX_40_OR_64_PATTERN.match(
                self.candidate_tree_digest
            ):
                raise PublicReceiptIntegrityError(
                    "candidate_tree_digest required when counterfactual is required"
                )
            if not self.delta_digest or not _HEX_64_PATTERN.match(self.delta_digest):
                raise PublicReceiptIntegrityError(
                    "delta_digest required when counterfactual is required"
                )
            if self.execution_fact is None:
                raise PublicReceiptIntegrityError(
                    "execution_fact required when counterfactual is required"
                )
        else:
            if not self.absence_rationale or not self.absence_rationale.strip():
                raise PublicReceiptIntegrityError(
                    "absence_rationale required when counterfactual is not required"
                )

    def to_dict(self) -> dict[str, Any]:
        """Convert to canonical dictionary."""
        return {
            "absence_rationale": self.absence_rationale,
            "candidate_tree_digest": self.candidate_tree_digest,
            "delta_digest": self.delta_digest,
            "execution_fact": (
                self.execution_fact.to_dict() if self.execution_fact is not None else None
            ),
            "is_required": self.is_required,
            "outcome": self.outcome.value if self.outcome is not None else None,
        }


@dataclass(frozen=True, slots=True)
class PublicCostAccountingFact:
    """Public accounting of model tokens, runtime duration, and measured cost."""

    model_call_count: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    sandbox_runtime_seconds: float = 0.0
    estimated_cost_usd: float | None = None
    currency: str = "USD"
    is_metered: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to canonical dictionary."""
        return {
            "completion_tokens": self.completion_tokens,
            "currency": self.currency,
            "estimated_cost_usd": self.estimated_cost_usd,
            "is_metered": self.is_metered,
            "model_call_count": self.model_call_count,
            "prompt_tokens": self.prompt_tokens,
            "sandbox_runtime_seconds": self.sandbox_runtime_seconds,
        }


@dataclass(frozen=True, slots=True)
class PublicVerificationReceipt:
    """Authoritative public verification receipt proof object."""

    schema_version: str
    receipt_digest: str
    frozen_contract_digest: str
    task_id: str
    repo_locator: str
    source_commit_id: str
    candidate_tree_digest: str
    candidate_patch_digest: str | None
    counterfactual: PublicCounterfactualFact | None
    coverage_summary: CausalCoverageSummary
    witnesses: tuple[PublicWitnessFact, ...]
    executions: tuple[PublicExecutionFact, ...]
    overall_verdict: PreliminaryVerdict
    provenance: EvidenceProvenance
    runtime_identities: tuple[str, ...]
    timing: dict[str, Any]
    accounting: PublicCostAccountingFact | None
    not_run_obligations: tuple[str, ...]
    signature_strategy: str
    signature: str | None
    is_authoritative: bool
    disclaimers: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != PUBLIC_RECEIPT_SCHEMA_VERSION:
            raise PublicReceiptIntegrityError(
                f"Unsupported schema version: {self.schema_version!r}"
            )
        if not isinstance(self.receipt_digest, str) or not _HEX_64_PATTERN.match(
            self.receipt_digest
        ):
            raise PublicReceiptIntegrityError("receipt_digest must be a 64-char hex string")
        if not isinstance(self.frozen_contract_digest, str) or not _HEX_64_PATTERN.match(
            self.frozen_contract_digest
        ):
            raise PublicReceiptIntegrityError("frozen_contract_digest must be a 64-char hex string")
        if not isinstance(self.source_commit_id, str) or not _HEX_40_PATTERN.match(
            self.source_commit_id
        ):
            raise PublicReceiptIntegrityError("source_commit_id must be a 40-char commit SHA")
        if not isinstance(self.candidate_tree_digest, str) or not _HEX_40_OR_64_PATTERN.match(
            self.candidate_tree_digest
        ):
            raise PublicReceiptIntegrityError("candidate_tree_digest must be 40 or 64 hex chars")
        if not isinstance(self.overall_verdict, PreliminaryVerdict):
            raise TypeError("overall_verdict must be PreliminaryVerdict")
        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError("provenance must be EvidenceProvenance")

    def to_dict(self) -> dict[str, Any]:
        """Convert to canonical dictionary."""
        return {
            "accounting": self.accounting.to_dict() if self.accounting is not None else None,
            "candidate_patch_digest": self.candidate_patch_digest,
            "candidate_tree_digest": self.candidate_tree_digest,
            "counterfactual": (
                self.counterfactual.to_dict() if self.counterfactual is not None else None
            ),
            "coverage_summary": self.coverage_summary.to_dict(),
            "disclaimers": list(self.disclaimers),
            "executions": [e.to_dict() for e in self.executions],
            "frozen_contract_digest": self.frozen_contract_digest,
            "is_authoritative": self.is_authoritative,
            "not_run_obligations": list(self.not_run_obligations),
            "overall_verdict": self.overall_verdict.value,
            "provenance": self.provenance.value,
            "receipt_digest": self.receipt_digest,
            "repo_locator": self.repo_locator,
            "runtime_identities": list(self.runtime_identities),
            "schema_version": self.schema_version,
            "signature": self.signature,
            "signature_strategy": self.signature_strategy,
            "source_commit_id": self.source_commit_id,
            "task_id": self.task_id,
            "timing": self.timing,
            "witnesses": [w.to_dict() for w in self.witnesses],
        }

    def to_json(self, indent: int | None = None) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PublicVerificationReceipt:
        """Reconstruct PublicVerificationReceipt from a canonical dictionary."""
        from basebreak.causal.coverage import (
            RequirementCausalState,
            RequirementEligibility,
            RequirementVerificationFact,
        )
        from basebreak.causal.reconciliation import CausalTransition
        from basebreak.domain.semantics import ChangeClass

        witnesses = []
        for w in data.get("witnesses", []):
            witnesses.append(
                PublicWitnessFact(
                    witness_id=w["witness_id"],
                    witness_digest=w["witness_digest"],
                    lock_digest=w.get("lock_digest"),
                    requirement_id=w.get("requirement_id"),
                    execution_command=tuple(w.get("execution_command", ())),
                    timeout_seconds=float(w.get("timeout_seconds", 30.0)),
                )
            )

        executions = []
        for e in data.get("executions", []):
            executions.append(
                PublicExecutionFact(
                    world=ExecutionWorld(e["world"]),
                    sandbox_id=e["sandbox_id"],
                    source_commit_id=e["source_commit_id"],
                    tree_digest=e["tree_digest"],
                    outcome=WitnessOutcome(e["outcome"]),
                    exit_code=e.get("exit_code"),
                    termination_status=TerminationStatus(e["termination_status"]),
                    duration_seconds=float(e["duration_seconds"]),
                    stdout_digest=e["stdout_digest"],
                    stderr_digest=e["stderr_digest"],
                    stdout_excerpt=e.get("stdout_excerpt", ""),
                    stderr_excerpt=e.get("stderr_excerpt", ""),
                )
            )

        cf_fact: PublicCounterfactualFact | None = None
        cf_raw = data.get("counterfactual")
        if cf_raw is not None:
            cf_exec: PublicExecutionFact | None = None
            if cf_raw.get("execution_fact"):
                cfe = cf_raw["execution_fact"]
                cf_exec = PublicExecutionFact(
                    world=ExecutionWorld(cfe["world"]),
                    sandbox_id=cfe["sandbox_id"],
                    source_commit_id=cfe["source_commit_id"],
                    tree_digest=cfe["tree_digest"],
                    outcome=WitnessOutcome(cfe["outcome"]),
                    exit_code=cfe.get("exit_code"),
                    termination_status=TerminationStatus(cfe["termination_status"]),
                    duration_seconds=float(cfe["duration_seconds"]),
                    stdout_digest=cfe["stdout_digest"],
                    stderr_digest=cfe["stderr_digest"],
                    stdout_excerpt=cfe.get("stdout_excerpt", ""),
                    stderr_excerpt=cfe.get("stderr_excerpt", ""),
                )
            cf_fact = PublicCounterfactualFact(
                is_required=bool(cf_raw["is_required"]),
                candidate_tree_digest=cf_raw.get("candidate_tree_digest"),
                delta_digest=cf_raw.get("delta_digest"),
                outcome=WitnessOutcome(cf_raw["outcome"]) if cf_raw.get("outcome") else None,
                execution_fact=cf_exec,
                absence_rationale=cf_raw.get("absence_rationale"),
            )

        ac_fact: PublicCostAccountingFact | None = None
        ac_raw = data.get("accounting")
        if ac_raw is not None:
            ac_fact = PublicCostAccountingFact(
                model_call_count=int(ac_raw.get("model_call_count", 0)),
                prompt_tokens=int(ac_raw.get("prompt_tokens", 0)),
                completion_tokens=int(ac_raw.get("completion_tokens", 0)),
                sandbox_runtime_seconds=float(ac_raw.get("sandbox_runtime_seconds", 0.0)),
                estimated_cost_usd=(
                    float(ac_raw["estimated_cost_usd"])
                    if ac_raw.get("estimated_cost_usd") is not None
                    else None
                ),
                currency=str(ac_raw.get("currency", "USD")),
                is_metered=bool(ac_raw.get("is_metered", False)),
            )

        cov_raw = data["coverage_summary"]
        req_facts = []
        for rf in cov_raw.get("per_requirement_facts", []):
            trans = CausalTransition(rf["transition"]) if rf.get("transition") else None
            req_facts.append(
                RequirementVerificationFact(
                    requirement_id=rf["requirement_id"],
                    change_class=ChangeClass(rf["change_class"]),
                    eligibility=RequirementEligibility(rf["eligibility"]),
                    causal_state=RequirementCausalState(rf["causal_state"]),
                    preliminary_verdict=PreliminaryVerdict(rf["preliminary_verdict"]),
                    transition=trans,
                    witness_id=rf.get("witness_id"),
                    witness_digest=rf.get("witness_digest"),
                    execution_obligation=rf["execution_obligation"],
                    rationale=rf["rationale"],
                    fact_digest=rf["fact_digest"],
                )
            )

        cov_summary = CausalCoverageSummary(
            contract_digest=cov_raw["contract_digest"],
            total_requirements=int(cov_raw["total_requirements"]),
            eligible_count=int(cov_raw["eligible_count"]),
            excluded_count=int(cov_raw["excluded_count"]),
            verified_count=int(cov_raw["verified_count"]),
            not_run_count=int(cov_raw["not_run_count"]),
            inconclusive_count=int(cov_raw["inconclusive_count"]),
            contradicted_count=int(cov_raw["contradicted_count"]),
            blocked_count=int(cov_raw["blocked_count"]),
            coverage_ratio=(
                float(cov_raw["coverage_ratio"])
                if cov_raw.get("coverage_ratio") is not None
                else None
            ),
            coverage_percentage=(
                float(cov_raw["coverage_percentage"])
                if cov_raw.get("coverage_percentage") is not None
                else None
            ),
            is_fully_verified=bool(cov_raw["is_fully_verified"]),
            overall_verdict=PreliminaryVerdict(cov_raw["overall_verdict"]),
            per_requirement_facts=tuple(req_facts),
            coverage_digest=cov_raw["coverage_digest"],
        )

        return cls(
            schema_version=data["schema_version"],
            receipt_digest=data["receipt_digest"],
            frozen_contract_digest=data["frozen_contract_digest"],
            task_id=data["task_id"],
            repo_locator=data["repo_locator"],
            source_commit_id=data["source_commit_id"],
            candidate_tree_digest=data["candidate_tree_digest"],
            candidate_patch_digest=data.get("candidate_patch_digest"),
            counterfactual=cf_fact,
            coverage_summary=cov_summary,
            witnesses=tuple(witnesses),
            executions=tuple(executions),
            overall_verdict=PreliminaryVerdict(data["overall_verdict"]),
            provenance=EvidenceProvenance(data["provenance"]),
            runtime_identities=tuple(data.get("runtime_identities", ())),
            timing=dict(data.get("timing", {})),
            accounting=ac_fact,
            not_run_obligations=tuple(data.get("not_run_obligations", ())),
            signature_strategy=data.get("signature_strategy", "SHA256_DIGEST_ONLY"),
            signature=data.get("signature"),
            is_authoritative=bool(data.get("is_authoritative", False)),
            disclaimers=tuple(data.get("disclaimers", ())),
        )


def build_canonical_public_receipt_payload(
    *,
    schema_version: str,
    frozen_contract_digest: str,
    task_id: str,
    repo_locator: str,
    source_commit_id: str,
    candidate_tree_digest: str,
    candidate_patch_digest: str | None,
    counterfactual: PublicCounterfactualFact | None,
    coverage_summary: CausalCoverageSummary,
    witnesses: Sequence[PublicWitnessFact],
    executions: Sequence[PublicExecutionFact],
    overall_verdict: PreliminaryVerdict,
    provenance: EvidenceProvenance,
    runtime_identities: Sequence[str],
    timing: Mapping[str, Any],
    accounting: PublicCostAccountingFact | None,
    not_run_obligations: Sequence[str],
    signature_strategy: str,
    signature: str | None,
    is_authoritative: bool,
    disclaimers: Sequence[str],
) -> dict[str, Any]:
    """Construct canonical identity dictionary for receipt digest computation."""
    return {
        "accounting": accounting.to_dict() if accounting is not None else None,
        "candidate_patch_digest": (
            candidate_patch_digest.strip().lower() if candidate_patch_digest else None
        ),
        "candidate_tree_digest": candidate_tree_digest.strip().lower(),
        "counterfactual": counterfactual.to_dict() if counterfactual is not None else None,
        "coverage_summary": coverage_summary.to_dict(),
        "disclaimers": sorted(str(d).strip() for d in disclaimers),
        "executions": [e.to_dict() for e in executions],
        "frozen_contract_digest": frozen_contract_digest.strip().lower(),
        "is_authoritative": is_authoritative,
        "not_run_obligations": sorted(str(o).strip() for o in not_run_obligations),
        "overall_verdict": overall_verdict.value,
        "provenance": provenance.value,
        "repo_locator": repo_locator.strip(),
        "runtime_identities": sorted(str(r).strip() for r in runtime_identities),
        "schema_version": schema_version.strip(),
        "signature": signature,
        "signature_strategy": signature_strategy.strip(),
        "source_commit_id": source_commit_id.strip().lower(),
        "task_id": task_id.strip(),
        "timing": dict(timing),
        "witnesses": [w.to_dict() for w in witnesses],
    }


def compute_public_receipt_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical JSON bytes."""
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def create_public_verification_receipt(
    *,
    frozen_contract_digest: str,
    task_id: str,
    repo_locator: str,
    source_commit_id: str,
    candidate_tree_digest: str,
    coverage_summary: CausalCoverageSummary,
    executions: Sequence[PublicExecutionFact],
    witnesses: Sequence[PublicWitnessFact],
    overall_verdict: PreliminaryVerdict,
    provenance: EvidenceProvenance,
    candidate_patch_digest: str | None = None,
    counterfactual: PublicCounterfactualFact | None = None,
    runtime_identities: Sequence[str] = (),
    timing: Mapping[str, Any] | None = None,
    accounting: PublicCostAccountingFact | None = None,
    not_run_obligations: Sequence[str] = (),
    signature_strategy: str = "SHA256_DIGEST_ONLY",
    signature: str | None = None,
    is_authoritative: bool = False,
    disclaimers: Sequence[str] = (CANONICAL_RECEIPT_THESIS, CANONICAL_DISCLAIMER_TEXT),
) -> PublicVerificationReceipt:
    """Factory creating an authoritative, tamper-evident PublicVerificationReceipt."""
    # Ensure coverage summary binds to the contract digest
    if coverage_summary.contract_digest.lower() != frozen_contract_digest.strip().lower():
        raise PublicReceiptIntegrityError(
            f"Coverage summary contract_digest {coverage_summary.contract_digest} "
            f"does not match receipt frozen_contract_digest {frozen_contract_digest}"
        )

    # Validate timing dictionary
    active_timing = dict(timing) if timing is not None else {}
    if "created_at_utc" not in active_timing:
        active_timing["created_at_utc"] = datetime.now(timezone.utc).isoformat()
    if "total_duration_seconds" not in active_timing:
        total_dur = sum(e.duration_seconds for e in executions)
        active_timing["total_duration_seconds"] = round(total_dur, 4)

    payload = build_canonical_public_receipt_payload(
        schema_version=PUBLIC_RECEIPT_SCHEMA_VERSION,
        frozen_contract_digest=frozen_contract_digest,
        task_id=task_id,
        repo_locator=repo_locator,
        source_commit_id=source_commit_id,
        candidate_tree_digest=candidate_tree_digest,
        candidate_patch_digest=candidate_patch_digest,
        counterfactual=counterfactual,
        coverage_summary=coverage_summary,
        witnesses=witnesses,
        executions=executions,
        overall_verdict=overall_verdict,
        provenance=provenance,
        runtime_identities=runtime_identities,
        timing=active_timing,
        accounting=accounting,
        not_run_obligations=not_run_obligations,
        signature_strategy=signature_strategy,
        signature=signature,
        is_authoritative=is_authoritative,
        disclaimers=disclaimers,
    )

    # Check for secret patterns in public payload
    raw_json = json.dumps(payload)
    if contains_secret(raw_json):
        raise PublicReceiptSecretLeakError("Public receipt payload contains unredacted secrets!")

    receipt_digest = compute_public_receipt_digest(payload)

    return PublicVerificationReceipt(
        schema_version=PUBLIC_RECEIPT_SCHEMA_VERSION,
        receipt_digest=receipt_digest,
        frozen_contract_digest=frozen_contract_digest.strip().lower(),
        task_id=task_id.strip(),
        repo_locator=repo_locator.strip(),
        source_commit_id=source_commit_id.strip().lower(),
        candidate_tree_digest=candidate_tree_digest.strip().lower(),
        candidate_patch_digest=(
            candidate_patch_digest.strip().lower() if candidate_patch_digest else None
        ),
        counterfactual=counterfactual,
        coverage_summary=coverage_summary,
        witnesses=tuple(witnesses),
        executions=tuple(executions),
        overall_verdict=overall_verdict,
        provenance=provenance,
        runtime_identities=tuple(runtime_identities),
        timing=active_timing,
        accounting=accounting,
        not_run_obligations=tuple(not_run_obligations),
        signature_strategy=signature_strategy,
        signature=signature,
        is_authoritative=is_authoritative,
        disclaimers=tuple(disclaimers),
    )


def verify_public_receipt_integrity(receipt: PublicVerificationReceipt) -> None:
    """Verify cryptographic integrity, hash consistency, and secret safety of receipt."""
    payload = build_canonical_public_receipt_payload(
        schema_version=receipt.schema_version,
        frozen_contract_digest=receipt.frozen_contract_digest,
        task_id=receipt.task_id,
        repo_locator=receipt.repo_locator,
        source_commit_id=receipt.source_commit_id,
        candidate_tree_digest=receipt.candidate_tree_digest,
        candidate_patch_digest=receipt.candidate_patch_digest,
        counterfactual=receipt.counterfactual,
        coverage_summary=receipt.coverage_summary,
        witnesses=receipt.witnesses,
        executions=receipt.executions,
        overall_verdict=receipt.overall_verdict,
        provenance=receipt.provenance,
        runtime_identities=receipt.runtime_identities,
        timing=receipt.timing,
        accounting=receipt.accounting,
        not_run_obligations=receipt.not_run_obligations,
        signature_strategy=receipt.signature_strategy,
        signature=receipt.signature,
        is_authoritative=receipt.is_authoritative,
        disclaimers=receipt.disclaimers,
    )

    expected_digest = compute_public_receipt_digest(payload)
    if receipt.receipt_digest != expected_digest:
        raise PublicReceiptTamperingError(
            f"Public receipt digest tampering detected: declared {receipt.receipt_digest}, "
            f"recomputed {expected_digest}"
        )

    # Check secret leak
    raw_json = json.dumps(payload)
    if contains_secret(raw_json):
        raise PublicReceiptSecretLeakError("Public receipt contains unredacted secrets!")

    # Verify coverage summary integrity
    verify_coverage_integrity(receipt.coverage_summary)


def render_receipt_markdown(receipt: PublicVerificationReceipt) -> str:
    """Render comprehensive, human-readable GitHub Flavored Markdown from receipt."""
    cov = receipt.coverage_summary
    ratio_str = f"{cov.coverage_percentage:.1f}%" if cov.coverage_percentage is not None else "N/A"
    verdict_badge = f"**{receipt.overall_verdict.value}**"

    lines = [
        "# Basebreak Causal Verification Receipt",
        "",
        f"> **Thesis:** *{CANONICAL_RECEIPT_THESIS}*",
        "",
        "## Summary",
        f"- **Task ID:** `{receipt.task_id}`",
        f"- **Repository:** `{receipt.repo_locator}`",
        f"- **Verdict:** {verdict_badge}",
        f"- **Causal Coverage:** `{ratio_str}` "
        f"({cov.verified_count}/{cov.eligible_count} verified)",
        f"- **Provenance:** `{receipt.provenance.value}`",
        f"- **Receipt Digest:** `{receipt.receipt_digest}`",
        f"- **Frozen Contract:** `{receipt.frozen_contract_digest}`",
        f"- **Base Commit:** `{receipt.source_commit_id}`",
        f"- **Candidate Tree:** `{receipt.candidate_tree_digest}`",
        "",
        "## Requirement Causal Status",
        "| Requirement ID | Change Class | Causal State | Verdict | Obligation |",
        "|---|---|---|---|---|",
    ]

    for fact in cov.per_requirement_facts:
        lines.append(
            f"| `{fact.requirement_id}` | `{fact.change_class.value}` | "
            f"`{fact.causal_state.value}` | `{fact.preliminary_verdict.value}` | "
            f"`{fact.execution_obligation}` |"
        )

    lines.extend([
        "",
        "## Execution Evidence",
        "| World | Sandbox | Outcome | Exit Code | Stdout Digest | Duration |",
        "|---|---|---|---|---|---|",
    ])

    for ex in receipt.executions:
        exit_code_str = str(ex.exit_code) if ex.exit_code is not None else "N/A"
        lines.append(
            f"| `{ex.world.value}` | `{ex.sandbox_id}` | `{ex.outcome.value}` | "
            f"`{exit_code_str}` | `{ex.stdout_digest[:16]}...` | {ex.duration_seconds:.2f}s |"
        )

    if receipt.counterfactual is not None:
        lines.extend([
            "",
            "## Counterfactual Third-Run (P-11)",
        ])
        if receipt.counterfactual.is_required:
            cf_out = (
                receipt.counterfactual.outcome.value
                if receipt.counterfactual.outcome
                else "N/A"
            )
            lines.append("- **Required:** Yes")
            lines.append(f"- **Delta Digest:** `{receipt.counterfactual.delta_digest}`")
            lines.append(f"- **Outcome:** `{cf_out}`")
        else:
            lines.append("- **Required:** No")
            lines.append(f"- **Rationale:** {receipt.counterfactual.absence_rationale}")

    if receipt.not_run_obligations:
        lines.extend([
            "",
            "## NOT_RUN / Limitations",
        ])
        for ob in receipt.not_run_obligations:
            lines.append(f"- {ob}")

    auth_str = "Yes" if receipt.is_authoritative else "No (Deterministic Fact Envelope)"
    lines.extend([
        "",
        "## Integrity & Disclaimers",
        f"- **Signature Strategy:** `{receipt.signature_strategy}`",
        f"- **Authoritative Certificate:** `{auth_str}`",
    ])
    for d in receipt.disclaimers:
        lines.append(f"> {d}")

    return "\n".join(lines)


def render_receipt_terminal(receipt: PublicVerificationReceipt) -> str:
    """Render terminal-friendly representation of receipt."""
    cov = receipt.coverage_summary
    ratio_str = f"{cov.coverage_percentage:.1f}%" if cov.coverage_percentage is not None else "N/A"
    sep = "=" * 70

    lines = [
        sep,
        "BASEBREAK CAUSAL VERIFICATION RECEIPT",
        f"Thesis: {CANONICAL_RECEIPT_THESIS}",
        sep,
        f"Task:            {receipt.task_id}",
        f"Verdict:         {receipt.overall_verdict.value}",
        f"Causal Coverage: {ratio_str} ({cov.verified_count}/{cov.eligible_count} eligible)",
        f"Provenance:      {receipt.provenance.value}",
        f"Base Commit:     {receipt.source_commit_id}",
        f"Candidate Tree:  {receipt.candidate_tree_digest}",
        f"Receipt Digest:  {receipt.receipt_digest}",
        sep,
        "REQUIREMENTS:",
    ]

    for f in cov.per_requirement_facts:
        lines.append(
            f"  [{f.causal_state.value:12s}] {f.requirement_id}: "
            f"{f.change_class.value} ({f.execution_obligation})"
        )

    lines.append("-" * 70)
    lines.append("EXECUTIONS:")
    for ex in receipt.executions:
        lines.append(
            f"  {ex.world.value:12s} -> {ex.outcome.value:10s} "
            f"(exit: {ex.exit_code}, {ex.duration_seconds:.2f}s)"
        )

    lines.append(sep)
    return "\n".join(lines)
