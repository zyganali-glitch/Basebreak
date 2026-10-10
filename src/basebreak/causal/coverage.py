"""Deterministic causal coverage and multi-requirement reconciliation.

P-17: Causal Coverage & Multi-Requirement Reconciliation
- P-17.01: Define eligibility denominator for behavioral requirements.
- P-17.02: Aggregate per-requirement causal states.
- P-17.03: Compute deterministic Causal Coverage.
- P-17.04: Handle mixed semantic classes and NOT_RUN requirements.
- P-17.05: Prevent model confidence from entering coverage math.

Core Invariants:
1. Denominator Authority: Coverage denominator is strictly derived from
   eligible behavioral requirements frozen in the authoritative contract.
   Omitted or unexecuted requirements cannot shrink the denominator.
2. Anti-Inflation: Duplicate requirement IDs or duplicate witness outcomes
   never inflate coverage or the denominator.
3. Zero-Denominator Safety: An empty eligible denominator yields an explicitly
   undefined/None coverage ratio, NEVER an automatic 100% (1.0).
4. Zero Model Authority: Model confidence scores, LLM probability estimates,
   and model prose have ZERO mathematical authority over coverage metrics.
   Caller-supplied confidence values are strictly rejected or forbidden.
5. Multi-Class Parity: All 6 canonical change classes (BUG_FIX, FEATURE,
   SECURITY_FIX, REFACTOR, PERFORMANCE, DEP_API_CHANGE) are evaluated under
   their exact semantic-specific verification obligations.
6. Non-Collapsing Reconciliation: BLOCKED, INCONCLUSIVE, CONTRADICTED, NOT_RUN,
   and VERIFIED states are preserved without loss of fidelity.
7. Cryptographic Chain: The coverage summary binds directly to the frozen contract digest.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.causal.receipt import LocalCausalReceipt
from basebreak.causal.reconciliation import CausalTransition, ReconciliationFact
from basebreak.causal.semantic_receipt import SemanticVerificationReceipt
from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.domain.semantics import ChangeClass, get_verification_requirements
from basebreak.domain.verdict import PreliminaryVerdict

_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_REQUIREMENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]+$")


class CoverageError(Exception):
    """Base exception for causal coverage errors."""


class ContractDigestMismatchError(CoverageError):
    """Raised when frozen contract digest does not match expected digest."""


class DuplicateRequirementError(CoverageError):
    """Raised when duplicate requirement IDs are encountered."""


class UnknownRequirementError(CoverageError):
    """Raised when a result references a requirement not present in the contract."""


class CoverageIntegrityError(CoverageError):
    """Raised when a coverage summary fails cryptographic or arithmetic verification."""


class ModelAuthorityViolationError(CoverageError):
    """Raised when caller attempts to inject model confidence into coverage math."""


class RequirementEligibility(str, Enum):
    """Eligibility classification for contract requirements in coverage calculations."""

    ELIGIBLE = "ELIGIBLE"
    EXCLUDED_NON_BEHAVIORAL = "EXCLUDED_NON_BEHAVIORAL"
    EXCLUDED_OUT_OF_SCOPE = "EXCLUDED_OUT_OF_SCOPE"
    EXCLUDED_UNVERIFIABLE = "EXCLUDED_UNVERIFIABLE"


class RequirementCausalState(str, Enum):
    """Per-requirement causal verification state."""

    VERIFIED = "VERIFIED"
    CONTRADICTED = "CONTRADICTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"
    NOT_RUN = "NOT_RUN"


@dataclass(frozen=True, slots=True)
class EligibilityDecision:
    """Deterministic eligibility decision for a contract requirement."""

    requirement_id: str
    change_class: ChangeClass
    eligibility: RequirementEligibility
    exclusion_rationale: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.requirement_id, str) or not _REQUIREMENT_ID_PATTERN.match(
            self.requirement_id
        ):
            raise ValueError(f"Invalid requirement_id: {self.requirement_id!r}")
        if not isinstance(self.change_class, ChangeClass):
            cls_name = type(self.change_class).__name__
            raise TypeError(f"change_class must be ChangeClass, got {cls_name}")
        if not isinstance(self.eligibility, RequirementEligibility):
            el_name = type(self.eligibility).__name__
            raise TypeError(f"eligibility must be RequirementEligibility, got {el_name}")
        if self.eligibility != RequirementEligibility.ELIGIBLE:
            if not self.exclusion_rationale or not self.exclusion_rationale.strip():
                raise ValueError("exclusion_rationale is required for non-eligible requirements")

    @property
    def is_eligible(self) -> bool:
        """Return True if requirement is eligible for behavioral verification."""
        return self.eligibility == RequirementEligibility.ELIGIBLE


@dataclass(frozen=True, slots=True)
class RequirementVerificationFact:
    """Immutable verification fact for an individual requirement."""

    requirement_id: str
    change_class: ChangeClass
    eligibility: RequirementEligibility
    causal_state: RequirementCausalState
    preliminary_verdict: PreliminaryVerdict
    transition: CausalTransition | None
    witness_id: str | None
    witness_digest: str | None
    execution_obligation: str
    rationale: str
    fact_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.requirement_id, str) or not _REQUIREMENT_ID_PATTERN.match(
            self.requirement_id
        ):
            raise ValueError(f"Invalid requirement_id: {self.requirement_id!r}")
        if not isinstance(self.change_class, ChangeClass):
            raise TypeError("change_class must be ChangeClass")
        if not isinstance(self.eligibility, RequirementEligibility):
            raise TypeError("eligibility must be RequirementEligibility")
        if not isinstance(self.causal_state, RequirementCausalState):
            raise TypeError("causal_state must be RequirementCausalState")
        if not isinstance(self.preliminary_verdict, PreliminaryVerdict):
            raise TypeError("preliminary_verdict must be PreliminaryVerdict")
        if self.transition is not None and not isinstance(self.transition, CausalTransition):
            raise TypeError("transition must be CausalTransition or None")
        if not isinstance(self.execution_obligation, str) or not self.execution_obligation.strip():
            raise ValueError("execution_obligation must be a non-empty string")
        if not isinstance(self.rationale, str) or not self.rationale.strip():
            raise ValueError("rationale must be a non-empty string")
        if not isinstance(self.fact_digest, str) or not _HEX_64_PATTERN.match(self.fact_digest):
            raise ValueError("fact_digest must be a 64-char hex string")

    def to_dict(self) -> dict[str, Any]:
        """Convert to canonical dictionary representation."""
        return {
            "causal_state": self.causal_state.value,
            "change_class": self.change_class.value,
            "eligibility": self.eligibility.value,
            "execution_obligation": self.execution_obligation,
            "fact_digest": self.fact_digest,
            "preliminary_verdict": self.preliminary_verdict.value,
            "rationale": self.rationale,
            "requirement_id": self.requirement_id,
            "transition": self.transition.value if self.transition is not None else None,
            "witness_digest": self.witness_digest,
            "witness_id": self.witness_id,
        }


def compute_fact_digest(
    *,
    requirement_id: str,
    change_class: ChangeClass,
    eligibility: RequirementEligibility,
    causal_state: RequirementCausalState,
    preliminary_verdict: PreliminaryVerdict,
    transition: CausalTransition | None,
    witness_id: str | None,
    witness_digest: str | None,
    execution_obligation: str,
    rationale: str,
) -> str:
    """Compute canonical SHA-256 digest for an individual requirement verification fact."""
    payload = {
        "causal_state": causal_state.value,
        "change_class": change_class.value,
        "eligibility": eligibility.value,
        "execution_obligation": execution_obligation.strip(),
        "preliminary_verdict": preliminary_verdict.value,
        "rationale": rationale.strip(),
        "requirement_id": requirement_id.strip(),
        "transition": transition.value if transition is not None else None,
        "witness_digest": witness_digest.strip().lower() if witness_digest else None,
        "witness_id": witness_id.strip() if witness_id else None,
    }
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class CausalCoverageSummary:
    """Deterministic, tamper-evident Causal Coverage summary across all requirements."""

    contract_digest: str
    total_requirements: int
    eligible_count: int
    excluded_count: int
    verified_count: int
    not_run_count: int
    inconclusive_count: int
    contradicted_count: int
    blocked_count: int
    coverage_ratio: float | None
    coverage_percentage: float | None
    is_fully_verified: bool
    overall_verdict: PreliminaryVerdict
    per_requirement_facts: tuple[RequirementVerificationFact, ...]
    coverage_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.contract_digest, str) or not _HEX_64_PATTERN.match(
            self.contract_digest
        ):
            raise ValueError("contract_digest must be a 64-char hex string")
        if not isinstance(self.coverage_digest, str) or not _HEX_64_PATTERN.match(
            self.coverage_digest
        ):
            raise ValueError("coverage_digest must be a 64-char hex string")
        if self.eligible_count < 0 or self.total_requirements < 0:
            raise ValueError("counts cannot be negative")
        if self.eligible_count + self.excluded_count != self.total_requirements:
            raise ValueError("eligible_count + excluded_count must equal total_requirements")
        if (
            self.verified_count
            + self.not_run_count
            + self.inconclusive_count
            + self.contradicted_count
            + self.blocked_count
            != self.eligible_count
        ):
            raise ValueError("Sum of causal states must equal eligible_count")

    def to_dict(self) -> dict[str, Any]:
        """Convert to canonical dictionary representation."""
        return {
            "blocked_count": self.blocked_count,
            "contract_digest": self.contract_digest,
            "contradicted_count": self.contradicted_count,
            "coverage_digest": self.coverage_digest,
            "coverage_percentage": self.coverage_percentage,
            "coverage_ratio": self.coverage_ratio,
            "eligible_count": self.eligible_count,
            "excluded_count": self.excluded_count,
            "inconclusive_count": self.inconclusive_count,
            "is_fully_verified": self.is_fully_verified,
            "not_run_count": self.not_run_count,
            "overall_verdict": self.overall_verdict.value,
            "per_requirement_facts": [f.to_dict() for f in self.per_requirement_facts],
            "total_requirements": self.total_requirements,
            "verified_count": self.verified_count,
        }


def compute_coverage_digest(
    *,
    contract_digest: str,
    total_requirements: int,
    eligible_count: int,
    excluded_count: int,
    verified_count: int,
    not_run_count: int,
    inconclusive_count: int,
    contradicted_count: int,
    blocked_count: int,
    coverage_ratio: float | None,
    coverage_percentage: float | None,
    is_fully_verified: bool,
    overall_verdict: PreliminaryVerdict,
    per_requirement_facts: Sequence[RequirementVerificationFact],
) -> str:
    """Compute canonical SHA-256 digest for a Causal Coverage summary."""
    payload = {
        "blocked_count": blocked_count,
        "contract_digest": contract_digest.strip().lower(),
        "contradicted_count": contradicted_count,
        "coverage_percentage": coverage_percentage,
        "coverage_ratio": coverage_ratio,
        "eligible_count": eligible_count,
        "excluded_count": excluded_count,
        "inconclusive_count": inconclusive_count,
        "is_fully_verified": is_fully_verified,
        "not_run_count": not_run_count,
        "overall_verdict": overall_verdict.value,
        "per_requirement_facts": [f.to_dict() for f in per_requirement_facts],
        "total_requirements": total_requirements,
        "verified_count": verified_count,
    }
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def determine_requirement_eligibility(
    requirement: FrozenRequirement,
    change_class: ChangeClass,
    *,
    eligibility_overrides: Mapping[str, RequirementEligibility] | None = None,
    exclusion_rationales: Mapping[str, str] | None = None,
) -> EligibilityDecision:
    """Determine deterministic eligibility for a contract requirement.

    By default, requirements with canonical change classes are ELIGIBLE for behavioral
    verification unless explicit non-behavioral or out-of-scope overrides are specified.
    Caller-controlled exclusions cannot silently remove behavioral obligations from the denominator.
    """
    req_id = requirement.requirement_id
    if eligibility_overrides and req_id in eligibility_overrides:
        eligibility = eligibility_overrides[req_id]
        rationale = exclusion_rationales.get(req_id) if exclusion_rationales else None
        if eligibility != RequirementEligibility.ELIGIBLE:
            # Prevent arbitrary exclusions from artificially removing behavioral obligations
            is_behavioral_class = change_class in (
                ChangeClass.BUG_FIX,
                ChangeClass.FEATURE,
                ChangeClass.SECURITY_FIX,
            )
            stmt_lower = requirement.statement.lower()
            is_obviously_non_behavioral = any(
                term in stmt_lower
                for term in ("doc", "readme", "comment", "typo", "license", "metadata", "changelog")
            )
            if is_behavioral_class and not is_obviously_non_behavioral:
                raise CoverageIntegrityError(
                    f"Cannot exclude behavioral requirement {req_id} ({change_class.value}): "
                    f"behavioral obligations cannot be removed from coverage denominator."
                )
            if not rationale or not rationale.strip():
                if is_behavioral_class:
                    raise CoverageIntegrityError(
                        f"Exclusion of requirement {req_id} requires explicit, "
                        "non-empty exclusion rationale."
                    )
                rationale = f"Non-behavioral exclusion: {eligibility.value}"
        return EligibilityDecision(
            requirement_id=req_id,
            change_class=change_class,
            eligibility=eligibility,
            exclusion_rationale=rationale,
        )

    return EligibilityDecision(
        requirement_id=req_id,
        change_class=change_class,
        eligibility=RequirementEligibility.ELIGIBLE,
        exclusion_rationale=None,
    )


def compute_causal_coverage(
    *,
    frozen_contract: FrozenContract,
    results: Mapping[str, Any] | None = None,
    eligibility_overrides: Mapping[str, RequirementEligibility] | None = None,
    exclusion_rationales: Mapping[str, str] | None = None,
    requirement_classes: Mapping[str, ChangeClass] | None = None,
    expected_contract_digest: str | None = None,
    **kwargs: Any,
) -> CausalCoverageSummary:
    """Deterministically compute project-level Causal Coverage from frozen contract and results.

    Args:
        frozen_contract: Authoritative FrozenContract root.
        results: Mapping of requirement_id to execution/reconciliation results.
            Accepted result types: ReconciliationFact, SemanticVerificationReceipt,
            LocalCausalReceipt, or a dict containing verification fields.
        eligibility_overrides: Optional overrides for non-behavioral requirements.
        exclusion_rationales: Rationales for excluded requirements.
        requirement_classes: Optional mapping of requirement_id to ChangeClass for mixed contracts.
        expected_contract_digest: Optional expected contract digest to verify binding.
        **kwargs: Rejects model confidence or unauthorized arguments fail-closed.

    Returns:
        Deterministic, tamper-evident CausalCoverageSummary.
    """
    # P-17.05: Prevent model confidence from entering coverage math
    forbidden_keys = {
        "model_confidence",
        "confidence",
        "confidence_score",
        "llm_confidence",
        "probability",
        "likelihood",
        "model_weight",
    }
    present_forbidden = forbidden_keys.intersection(kwargs.keys())
    if present_forbidden:
        keys_str = ", ".join(sorted(present_forbidden))
        raise ModelAuthorityViolationError(
            f"Model confidence parameter(s) {keys_str} strictly forbidden in Causal Coverage math."
        )

    # Validate contract binding
    if expected_contract_digest is not None:
        if expected_contract_digest.strip().lower() != frozen_contract.contract_digest.lower():
            raise ContractDigestMismatchError(
                f"Contract digest mismatch: expected {expected_contract_digest}, "
                f"got {frozen_contract.contract_digest}"
            )

    # Detect duplicate requirements in the contract
    seen_contract_reqs: set[str] = set()
    for req in frozen_contract.requirements:
        if req.requirement_id in seen_contract_reqs:
            raise DuplicateRequirementError(
                f"Duplicate requirement ID in contract: {req.requirement_id}"
            )
        seen_contract_reqs.add(req.requirement_id)

    # Parse and validate results mapping
    active_results: dict[str, Any] = dict(results) if results is not None else {}

    # Reject unknown requirement IDs in results
    unknown_ids = set(active_results.keys()) - seen_contract_reqs
    if unknown_ids:
        raise UnknownRequirementError(
            f"Results contain requirement IDs not found in frozen contract: {sorted(unknown_ids)}"
        )

    facts: list[RequirementVerificationFact] = []
    eligible_count = 0
    excluded_count = 0
    verified_count = 0
    not_run_count = 0
    inconclusive_count = 0
    contradicted_count = 0
    blocked_count = 0

    for req in frozen_contract.requirements:
        cand_class = (
            requirement_classes.get(req.requirement_id)
            if requirement_classes and req.requirement_id in requirement_classes
            else getattr(req, "change_class", frozen_contract.change_class)
        )
        req_class: ChangeClass = (
            cand_class if isinstance(cand_class, ChangeClass) else frozen_contract.change_class
        )

        eligibility_decision = determine_requirement_eligibility(
            req,
            change_class=req_class,
            eligibility_overrides=eligibility_overrides,
            exclusion_rationales=exclusion_rationales,
        )

        class_req = get_verification_requirements(req_class)
        obligation = f"{class_req.base_expectation}->{class_req.candidate_expectation}"

        if not eligibility_decision.is_eligible:
            excluded_count += 1
            ex_rationale = (
                eligibility_decision.exclusion_rationale
                or "Requirement excluded from coverage denominator"
            )
            fact_digest = compute_fact_digest(
                requirement_id=req.requirement_id,
                change_class=req_class,
                eligibility=eligibility_decision.eligibility,
                causal_state=RequirementCausalState.NOT_RUN,
                preliminary_verdict=PreliminaryVerdict.NOT_RUN,
                transition=None,
                witness_id=None,
                witness_digest=None,
                execution_obligation=obligation,
                rationale=ex_rationale,
            )
            facts.append(
                RequirementVerificationFact(
                    requirement_id=req.requirement_id,
                    change_class=req_class,
                    eligibility=eligibility_decision.eligibility,
                    causal_state=RequirementCausalState.NOT_RUN,
                    preliminary_verdict=PreliminaryVerdict.NOT_RUN,
                    transition=None,
                    witness_id=None,
                    witness_digest=None,
                    execution_obligation=obligation,
                    rationale=ex_rationale,
                    fact_digest=fact_digest,
                )
            )
            continue

        # Requirement is ELIGIBLE -> Must be in denominator!
        eligible_count += 1
        res = active_results.get(req.requirement_id)

        if res is None:
            # Eligible requirement NOT RUN -> Stays in denominator, 0 numerator!
            not_run_count += 1
            rationale = "Requirement was eligible but not executed."
            fact_digest = compute_fact_digest(
                requirement_id=req.requirement_id,
                change_class=req_class,
                eligibility=RequirementEligibility.ELIGIBLE,
                causal_state=RequirementCausalState.NOT_RUN,
                preliminary_verdict=PreliminaryVerdict.NOT_RUN,
                transition=None,
                witness_id=None,
                witness_digest=None,
                execution_obligation=obligation,
                rationale=rationale,
            )
            facts.append(
                RequirementVerificationFact(
                    requirement_id=req.requirement_id,
                    change_class=req_class,
                    eligibility=RequirementEligibility.ELIGIBLE,
                    causal_state=RequirementCausalState.NOT_RUN,
                    preliminary_verdict=PreliminaryVerdict.NOT_RUN,
                    transition=None,
                    witness_id=None,
                    witness_digest=None,
                    execution_obligation=obligation,
                    rationale=rationale,
                    fact_digest=fact_digest,
                )
            )
            continue

        # Extract outcome facts from result
        transition: CausalTransition | None = None
        verdict: PreliminaryVerdict = PreliminaryVerdict.INCONCLUSIVE
        is_verified = False
        witness_id: str | None = None
        witness_digest: str | None = None
        rationale = ""

        if isinstance(res, ReconciliationFact):
            transition = res.transition
            verdict = res.verdict
            is_verified = res.is_causally_verified
            rationale = res.rationale
        elif isinstance(res, SemanticVerificationReceipt):
            transition = res.transition
            verdict = res.verdict
            is_verified = res.is_causally_verified
            witness_id = res.witness_id
            witness_digest = res.witness_digest
            rationale = res.narrative
        elif isinstance(res, LocalCausalReceipt):
            if res.frozen_contract_digest.lower() != frozen_contract.contract_digest.lower():
                raise ContractDigestMismatchError(
                    f"Receipt contract digest {res.frozen_contract_digest} does not match "
                    f"frozen contract {frozen_contract.contract_digest}"
                )
            if res.requirement_id != req.requirement_id:
                raise UnknownRequirementError(
                    f"Receipt requirement_id {res.requirement_id} does not match "
                    f"{req.requirement_id}"
                )
            transition = res.transition
            verdict = res.verdict
            is_verified = res.is_causally_verified and res.verdict == PreliminaryVerdict.VERIFIED
            witness_id = res.witness_id
            witness_digest = res.witness_digest
            rationale = res.narrative
        elif isinstance(res, dict):
            # Check for model confidence injection in dict
            for k in res:
                if k in forbidden_keys:
                    raise ModelAuthorityViolationError(
                        f"Model confidence key {k!r} forbidden in requirement result"
                    )

            # Validate contract binding if present
            dict_cd = res.get("frozen_contract_digest") or res.get("contract_digest")
            if dict_cd and dict_cd.strip().lower() != frozen_contract.contract_digest.lower():
                raise ContractDigestMismatchError(
                    f"Result contract digest {dict_cd} does not match "
                    f"frozen contract {frozen_contract.contract_digest}"
                )

            # Validate requirement ID binding if present
            dict_rid = res.get("requirement_id")
            if dict_rid and dict_rid.strip() != req.requirement_id:
                raise UnknownRequirementError(
                    f"Result requirement_id {dict_rid} does not match {req.requirement_id}"
                )

            transition_val = res.get("transition")
            if transition_val is not None:
                transition = (
                    transition_val
                    if isinstance(transition_val, CausalTransition)
                    else CausalTransition(str(transition_val))
                )
            verdict_val = res.get("verdict", PreliminaryVerdict.INCONCLUSIVE)
            verdict = (
                verdict_val
                if isinstance(verdict_val, PreliminaryVerdict)
                else PreliminaryVerdict(str(verdict_val))
            )
            raw_is_verified = bool(res.get("is_causally_verified", False))
            witness_id = res.get("witness_id")
            witness_digest = res.get("witness_digest")
            rationale = str(res.get("rationale", res.get("narrative", "Result processed")))

            # Independent causal evidence validation:
            # 1. Witness presence and format validation
            has_valid_witness = (
                isinstance(witness_id, str)
                and bool(witness_id.strip())
                and isinstance(witness_digest, str)
                and bool(_HEX_64_PATTERN.match(witness_digest))
            )

            # 2. Class-specific transition compatibility
            is_valid_transition = False
            if transition is not None:
                if req_class == ChangeClass.BUG_FIX:
                    is_valid_transition = transition in (
                        CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                        CausalTransition.CAUSAL_TRIPLET_VERIFIED,
                    )
                elif req_class == ChangeClass.FEATURE:
                    is_valid_transition = transition in (
                        CausalTransition.FEATURE_VERIFIED,
                        CausalTransition.CAUSAL_TRIPLET_VERIFIED,
                    )
                elif req_class == ChangeClass.SECURITY_FIX:
                    is_valid_transition = transition in (
                        CausalTransition.SECURITY_FIX_VERIFIED,
                        CausalTransition.CAUSAL_TRIPLET_VERIFIED,
                    )
                elif req_class == ChangeClass.REFACTOR:
                    is_valid_transition = transition in (
                        CausalTransition.REFACTOR_VERIFIED,
                        CausalTransition.CAUSAL_TRIPLET_VERIFIED,
                    )
                elif req_class == ChangeClass.PERFORMANCE:
                    is_valid_transition = transition in (
                        CausalTransition.PERFORMANCE_VERIFIED,
                        CausalTransition.CAUSAL_TRIPLET_VERIFIED,
                    )
                elif req_class == ChangeClass.DEP_API_CHANGE:
                    is_valid_transition = transition in (
                        CausalTransition.DEP_API_CHANGE_VERIFIED,
                        CausalTransition.CAUSAL_TRIPLET_VERIFIED,
                    )

            if raw_is_verified and verdict == PreliminaryVerdict.VERIFIED:
                if not has_valid_witness or not is_valid_transition:
                    # Reject unproven assertion: cannot promote arbitrary dict to VERIFIED!
                    is_verified = False
                    verdict = PreliminaryVerdict.INCONCLUSIVE
                    rationale = (
                        f"Unproven assertion rejected: missing witness evidence or incompatible "
                        f"transition {transition} for {req_class.value}."
                    )
                else:
                    is_verified = True
            else:
                is_verified = False
        else:
            res_type = type(res).__name__
            raise TypeError(
                f"Unsupported result type for requirement {req.requirement_id}: {res_type}"
            )

        # Map to deterministic RequirementCausalState
        if is_verified and verdict == PreliminaryVerdict.VERIFIED:
            causal_state = RequirementCausalState.VERIFIED
            verified_count += 1
        elif verdict == PreliminaryVerdict.CONTRADICTED:
            causal_state = RequirementCausalState.CONTRADICTED
            contradicted_count += 1
        elif verdict == PreliminaryVerdict.BLOCKED:
            causal_state = RequirementCausalState.BLOCKED
            blocked_count += 1
        elif verdict == PreliminaryVerdict.NOT_RUN:
            causal_state = RequirementCausalState.NOT_RUN
            not_run_count += 1
        else:
            causal_state = RequirementCausalState.INCONCLUSIVE
            inconclusive_count += 1

        fact_digest = compute_fact_digest(
            requirement_id=req.requirement_id,
            change_class=req_class,
            eligibility=RequirementEligibility.ELIGIBLE,
            causal_state=causal_state,
            preliminary_verdict=verdict,
            transition=transition,
            witness_id=witness_id,
            witness_digest=witness_digest,
            execution_obligation=obligation,
            rationale=rationale,
        )
        facts.append(
            RequirementVerificationFact(
                requirement_id=req.requirement_id,
                change_class=req_class,
                eligibility=RequirementEligibility.ELIGIBLE,
                causal_state=causal_state,
                preliminary_verdict=verdict,
                transition=transition,
                witness_id=witness_id,
                witness_digest=witness_digest,
                execution_obligation=obligation,
                rationale=rationale,
                fact_digest=fact_digest,
            )
        )

    # Compute coverage math
    total_reqs = len(frozen_contract.requirements)

    if eligible_count == 0:
        # Zero-denominator: explicitly undefined / None. NEVER 100%!
        coverage_ratio = None
        coverage_percentage = None
        is_fully_verified = False
        overall_verdict = PreliminaryVerdict.NOT_RUN
    else:
        coverage_ratio = round(verified_count / eligible_count, 6)
        coverage_percentage = round((verified_count / eligible_count) * 100.0, 2)
        is_fully_verified = (
            verified_count == eligible_count
            and contradicted_count == 0
            and blocked_count == 0
            and inconclusive_count == 0
            and not_run_count == 0
        )

        if contradicted_count > 0:
            overall_verdict = PreliminaryVerdict.CONTRADICTED
        elif blocked_count > 0:
            overall_verdict = PreliminaryVerdict.BLOCKED
        elif is_fully_verified:
            overall_verdict = PreliminaryVerdict.VERIFIED
        elif verified_count > 0:
            overall_verdict = PreliminaryVerdict.PARTIALLY_VERIFIED
        elif inconclusive_count > 0:
            overall_verdict = PreliminaryVerdict.INCONCLUSIVE
        else:
            overall_verdict = PreliminaryVerdict.NOT_RUN

    cov_digest = compute_coverage_digest(
        contract_digest=frozen_contract.contract_digest,
        total_requirements=total_reqs,
        eligible_count=eligible_count,
        excluded_count=excluded_count,
        verified_count=verified_count,
        not_run_count=not_run_count,
        inconclusive_count=inconclusive_count,
        contradicted_count=contradicted_count,
        blocked_count=blocked_count,
        coverage_ratio=coverage_ratio,
        coverage_percentage=coverage_percentage,
        is_fully_verified=is_fully_verified,
        overall_verdict=overall_verdict,
        per_requirement_facts=facts,
    )

    return CausalCoverageSummary(
        contract_digest=frozen_contract.contract_digest,
        total_requirements=total_reqs,
        eligible_count=eligible_count,
        excluded_count=excluded_count,
        verified_count=verified_count,
        not_run_count=not_run_count,
        inconclusive_count=inconclusive_count,
        contradicted_count=contradicted_count,
        blocked_count=blocked_count,
        coverage_ratio=coverage_ratio,
        coverage_percentage=coverage_percentage,
        is_fully_verified=is_fully_verified,
        overall_verdict=overall_verdict,
        per_requirement_facts=tuple(facts),
        coverage_digest=cov_digest,
    )


def verify_coverage_integrity(summary: CausalCoverageSummary) -> None:
    """Verify cryptographic digest and arithmetic consistency of a CausalCoverageSummary."""
    expected_digest = compute_coverage_digest(
        contract_digest=summary.contract_digest,
        total_requirements=summary.total_requirements,
        eligible_count=summary.eligible_count,
        excluded_count=summary.excluded_count,
        verified_count=summary.verified_count,
        not_run_count=summary.not_run_count,
        inconclusive_count=summary.inconclusive_count,
        contradicted_count=summary.contradicted_count,
        blocked_count=summary.blocked_count,
        coverage_ratio=summary.coverage_ratio,
        coverage_percentage=summary.coverage_percentage,
        is_fully_verified=summary.is_fully_verified,
        overall_verdict=summary.overall_verdict,
        per_requirement_facts=summary.per_requirement_facts,
    )

    if summary.coverage_digest != expected_digest:
        raise CoverageIntegrityError(
            f"Coverage digest tampering detected: declared {summary.coverage_digest}, "
            f"recomputed {expected_digest}"
        )

    # Verify each fact digest
    for fact in summary.per_requirement_facts:
        exp_fact_digest = compute_fact_digest(
            requirement_id=fact.requirement_id,
            change_class=fact.change_class,
            eligibility=fact.eligibility,
            causal_state=fact.causal_state,
            preliminary_verdict=fact.preliminary_verdict,
            transition=fact.transition,
            witness_id=fact.witness_id,
            witness_digest=fact.witness_digest,
            execution_obligation=fact.execution_obligation,
            rationale=fact.rationale,
        )
        if fact.fact_digest != exp_fact_digest:
            raise CoverageIntegrityError(
                f"Fact digest tampering detected for {fact.requirement_id}: "
                f"declared {fact.fact_digest}, recomputed {exp_fact_digest}"
            )
