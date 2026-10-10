"""Adversarial and functional test suite for deterministic Causal Coverage (P-17).

Tests:
- P-17.01: Define eligibility denominator for behavioral requirements.
- P-17.02: Aggregate per-requirement causal states.
- P-17.03: Compute deterministic Causal Coverage.
- P-17.04: Handle mixed semantic classes and NOT_RUN requirements.
- P-17.05: Prevent model confidence from entering coverage math.
"""

from __future__ import annotations

import pytest

from basebreak.causal.coverage import (
    CausalCoverageSummary,
    ContractDigestMismatchError,
    CoverageIntegrityError,
    DuplicateRequirementError,
    ModelAuthorityViolationError,
    RequirementCausalState,
    RequirementEligibility,
    UnknownRequirementError,
    compute_causal_coverage,
    verify_coverage_integrity,
)
from basebreak.causal.reconciliation import CausalTransition, ReconciliationFact
from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.compiler.semantics import CertaintyLevel
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import PreliminaryVerdict


def _make_frozen_contract(
    req_tuples: list[tuple[str, ChangeClass, str]],
    task_id: str = "TASK-TEST-001",
    contract_digest: str = "a" * 64,
) -> FrozenContract:
    frozen_reqs = []
    for rid, _cclass, stmt in req_tuples:
        citation_len = min(len(stmt), 20)
        req = FrozenRequirement(
            requirement_id=rid,
            statement=stmt,
            citation=stmt[:citation_len] if citation_len > 0 else "sample citation",
            citation_start=0,
            citation_end=citation_len if citation_len > 0 else 15,
            rationale="Test rationale",
        )
        frozen_reqs.append(req)

    main_class = req_tuples[0][1] if req_tuples else ChangeClass.BUG_FIX
    contract = object.__new__(FrozenContract)
    object.__setattr__(contract, "schema_version", "1.0.0")
    object.__setattr__(contract, "task_digest", "t" * 64)
    object.__setattr__(contract, "change_class", main_class)
    object.__setattr__(contract, "certainty", CertaintyLevel.CONFIDENT)
    object.__setattr__(contract, "requirements", tuple(frozen_reqs))
    object.__setattr__(contract, "contract_digest", contract_digest)
    return contract


class TestCausalCoverageP17:
    """Test suite covering P-17.01 through P-17.05."""

    def test_p17_01_denominator_derived_from_eligible_requirements(self) -> None:
        """P-17.01: Eligibility denominator excludes non-behavioral requirements."""
        contract = _make_frozen_contract(
            [
                ("REQ-1", ChangeClass.BUG_FIX, "Fix null dereference"),
                ("REQ-2", ChangeClass.FEATURE, "Add export endpoint"),
                ("REQ-DOC", ChangeClass.BUG_FIX, "Update README notes"),
            ]
        )
        overrides = {"REQ-DOC": RequirementEligibility.EXCLUDED_NON_BEHAVIORAL}
        rationales = {"REQ-DOC": "Documentation-only requirement"}

        # Provide verification for REQ-1 only
        results = {
            "REQ-1": ReconciliationFact(
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                is_causally_verified=True,
                rationale="BASE=FAIL, CANDIDATE=PASS",
            )
        }

        summary = compute_causal_coverage(
            frozen_contract=contract,
            results=results,
            eligibility_overrides=overrides,
            exclusion_rationales=rationales,
        )

        assert summary.total_requirements == 3
        assert summary.eligible_count == 2
        assert summary.excluded_count == 1
        assert summary.verified_count == 1
        assert summary.not_run_count == 1  # REQ-2 was eligible but not run
        assert summary.coverage_ratio == 0.5
        assert summary.coverage_percentage == 50.0
        assert summary.is_fully_verified is False
        assert summary.overall_verdict == PreliminaryVerdict.PARTIALLY_VERIFIED
        verify_coverage_integrity(summary)

    def test_p17_01_empty_denominator_yields_none_ratio(self) -> None:
        """P-17.01: An empty denominator must be undefined/None, never 100%."""
        contract = _make_frozen_contract([("REQ-DOC", ChangeClass.REFACTOR, "Doc refactor only")])
        overrides = {"REQ-DOC": RequirementEligibility.EXCLUDED_NON_BEHAVIORAL}

        summary = compute_causal_coverage(
            frozen_contract=contract,
            results={},
            eligibility_overrides=overrides,
        )

        assert summary.total_requirements == 1
        assert summary.eligible_count == 0
        assert summary.excluded_count == 1
        assert summary.verified_count == 0
        assert summary.coverage_ratio is None
        assert summary.coverage_percentage is None
        assert summary.is_fully_verified is False
        assert summary.overall_verdict == PreliminaryVerdict.NOT_RUN
        verify_coverage_integrity(summary)

    def test_p17_02_aggregate_per_requirement_causal_states(self) -> None:
        """P-17.02: Aggregate facts preserving transitions, verdicts, and digests."""
        contract = _make_frozen_contract(
            [
                ("REQ-1", ChangeClass.BUG_FIX, "Fix memory leak"),
                ("REQ-2", ChangeClass.BUG_FIX, "Fix off-by-one"),
            ]
        )
        results = {
            "REQ-1": ReconciliationFact(
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                is_causally_verified=True,
                rationale="Base broke, candidate passed",
            ),
            "REQ-2": ReconciliationFact(
                transition=CausalTransition.UNVERIFIED_DEFECT_PERSISTS,
                verdict=PreliminaryVerdict.CONTRADICTED,
                is_causally_verified=False,
                rationale="Candidate still failed",
            ),
        }

        summary = compute_causal_coverage(frozen_contract=contract, results=results)

        assert len(summary.per_requirement_facts) == 2
        f1, f2 = summary.per_requirement_facts
        assert f1.requirement_id == "REQ-1"
        assert f1.causal_state == RequirementCausalState.VERIFIED
        assert f1.preliminary_verdict == PreliminaryVerdict.VERIFIED

        assert f2.requirement_id == "REQ-2"
        assert f2.causal_state == RequirementCausalState.CONTRADICTED
        assert f2.preliminary_verdict == PreliminaryVerdict.CONTRADICTED

        # Because REQ-2 is CONTRADICTED, overall verdict must be CONTRADICTED
        assert summary.overall_verdict == PreliminaryVerdict.CONTRADICTED
        assert summary.coverage_ratio == 0.5
        verify_coverage_integrity(summary)

    def test_p17_03_compute_deterministic_causal_coverage_fully_verified(self) -> None:
        """P-17.03: 100% verified coverage when all eligible pass without flaw."""
        contract = _make_frozen_contract(
            [
                ("REQ-1", ChangeClass.BUG_FIX, "Fix bug 1"),
                ("REQ-2", ChangeClass.BUG_FIX, "Fix bug 2"),
            ]
        )
        results = {
            "REQ-1": ReconciliationFact(
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                is_causally_verified=True,
                rationale="Passed",
            ),
            "REQ-2": ReconciliationFact(
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                is_causally_verified=True,
                rationale="Passed",
            ),
        }

        summary = compute_causal_coverage(frozen_contract=contract, results=results)

        assert summary.eligible_count == 2
        assert summary.verified_count == 2
        assert summary.coverage_ratio == 1.0
        assert summary.coverage_percentage == 100.0
        assert summary.is_fully_verified is True
        assert summary.overall_verdict == PreliminaryVerdict.VERIFIED
        verify_coverage_integrity(summary)

    def test_p17_04_mixed_semantic_classes(self) -> None:
        """P-17.04: Supports all 6 canonical classes in a single contract."""
        contract = _make_frozen_contract(
            [
                ("REQ-BUG", ChangeClass.BUG_FIX, "Fix crash"),
                ("REQ-FEAT", ChangeClass.FEATURE, "Add endpoint"),
                ("REQ-SEC", ChangeClass.SECURITY_FIX, "Block injection"),
                ("REQ-REF", ChangeClass.REFACTOR, "Clean up internals"),
                ("REQ-PERF", ChangeClass.PERFORMANCE, "Speed up query"),
                ("REQ-DEP", ChangeClass.DEP_API_CHANGE, "Migrate library"),
            ]
        )

        results = {
            "REQ-BUG": {
                "transition": CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                "verdict": PreliminaryVerdict.VERIFIED,
                "is_causally_verified": True,
                "witness_id": "wit-bug",
                "witness_digest": "b" * 64,
                "rationale": "Base failed, candidate passed",
            },
            "REQ-FEAT": {
                "transition": CausalTransition.FEATURE_VERIFIED,
                "verdict": PreliminaryVerdict.VERIFIED,
                "is_causally_verified": True,
                "witness_id": "wit-feat",
                "witness_digest": "c" * 64,
                "rationale": "Absent -> Present",
            },
            "REQ-SEC": {
                "transition": CausalTransition.SECURITY_FIX_VERIFIED,
                "verdict": PreliminaryVerdict.VERIFIED,
                "is_causally_verified": True,
                "witness_id": "wit-sec",
                "witness_digest": "d" * 64,
                "rationale": "Exploitable -> Blocked",
            },
            "REQ-REF": {
                "transition": CausalTransition.REFACTOR_VERIFIED,
                "verdict": PreliminaryVerdict.VERIFIED,
                "is_causally_verified": True,
                "witness_id": "wit-ref",
                "witness_digest": "e" * 64,
                "rationale": "Behavioral equivalence verified",
            },
            "REQ-PERF": {
                "transition": CausalTransition.PERFORMANCE_VERIFIED,
                "verdict": PreliminaryVerdict.VERIFIED,
                "is_causally_verified": True,
                "witness_id": "wit-perf",
                "witness_digest": "f" * 64,
                "rationale": "Parity verified and positive speedup measured",
            },
            "REQ-DEP": {
                "transition": CausalTransition.DEP_API_CHANGE_VERIFIED,
                "verdict": PreliminaryVerdict.VERIFIED,
                "is_causally_verified": True,
                "witness_id": "wit-dep",
                "witness_digest": "a" * 64,
                "rationale": "New API satisfied without regression",
            },
        }

        req_classes = {
            "REQ-BUG": ChangeClass.BUG_FIX,
            "REQ-FEAT": ChangeClass.FEATURE,
            "REQ-SEC": ChangeClass.SECURITY_FIX,
            "REQ-REF": ChangeClass.REFACTOR,
            "REQ-PERF": ChangeClass.PERFORMANCE,
            "REQ-DEP": ChangeClass.DEP_API_CHANGE,
        }
        summary = compute_causal_coverage(
            frozen_contract=contract,
            results=results,
            requirement_classes=req_classes,
        )

        assert summary.eligible_count == 6
        assert summary.verified_count == 6
        assert summary.coverage_ratio == 1.0
        assert summary.is_fully_verified is True
        assert summary.overall_verdict == PreliminaryVerdict.VERIFIED
        verify_coverage_integrity(summary)

    def test_p17_04_omitted_eligible_requirement_cannot_increase_coverage(self) -> None:
        """P-17.04: Removing an unexecuted or failing requirement cannot shrink denominator."""
        contract = _make_frozen_contract(
            [
                ("REQ-1", ChangeClass.BUG_FIX, "Bug 1"),
                ("REQ-2", ChangeClass.BUG_FIX, "Bug 2"),
                ("REQ-3", ChangeClass.BUG_FIX, "Bug 3"),
            ]
        )

        # Adversary only submits results for REQ-1 (passing) and tries to omit REQ-2 and REQ-3
        results = {
            "REQ-1": {
                "transition": CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                "verdict": PreliminaryVerdict.VERIFIED,
                "is_causally_verified": True,
                "witness_id": "wit-1",
                "witness_digest": "b" * 64,
                "rationale": "Passed",
            }
        }

        summary = compute_causal_coverage(frozen_contract=contract, results=results)

        # Denominator must remain 3!
        assert summary.eligible_count == 3
        assert summary.verified_count == 1
        assert summary.not_run_count == 2
        assert summary.coverage_ratio == round(1 / 3, 6)
        assert summary.overall_verdict == PreliminaryVerdict.PARTIALLY_VERIFIED
        verify_coverage_integrity(summary)

    def test_adversarial_forged_dict_without_witness_rejected(self) -> None:
        """Adversarial: Forged dict with is_causally_verified=True cannot increase coverage."""
        contract = _make_frozen_contract([("REQ-1", ChangeClass.BUG_FIX, "Bug 1")])
        forged_results = {
            "REQ-1": {
                "transition": CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                "verdict": PreliminaryVerdict.VERIFIED,
                "is_causally_verified": True,
                # Missing witness_id and witness_digest!
                "rationale": "Attacker claims verified without proof",
            }
        }
        summary = compute_causal_coverage(frozen_contract=contract, results=forged_results)
        assert summary.eligible_count == 1
        assert summary.verified_count == 0
        assert summary.inconclusive_count == 1
        assert summary.coverage_ratio == 0.0
        assert summary.overall_verdict == PreliminaryVerdict.INCONCLUSIVE

    def test_adversarial_caller_controlled_exclusion_of_behavioral_obligation_rejected(
        self,
    ) -> None:
        """Adversarial: Caller cannot exclude behavioral requirement from denominator."""
        contract = _make_frozen_contract(
            [("REQ-BUG", ChangeClass.BUG_FIX, "Fix memory safety vulnerability")]
        )
        with pytest.raises(
            CoverageIntegrityError, match="behavioral obligations cannot be removed"
        ):
            compute_causal_coverage(
                frozen_contract=contract,
                results={},
                eligibility_overrides={"REQ-BUG": RequirementEligibility.EXCLUDED_NON_BEHAVIORAL},
                exclusion_rationales={"REQ-BUG": "Caller wants to drop this requirement"},
            )

    def test_p17_05_model_confidence_kwargs_rejected(self) -> None:
        """P-17.05: Reject caller-supplied confidence arguments fail-closed."""
        contract = _make_frozen_contract([("REQ-1", ChangeClass.BUG_FIX, "Bug 1")])

        with pytest.raises(ModelAuthorityViolationError, match="strictly forbidden"):
            compute_causal_coverage(
                frozen_contract=contract,
                results={},
                model_confidence=0.99,
            )

    def test_p17_05_model_confidence_in_dict_rejected(self) -> None:
        """P-17.05: Reject model confidence keys embedded in result dictionaries."""
        contract = _make_frozen_contract([("REQ-1", ChangeClass.BUG_FIX, "Bug 1")])

        with pytest.raises(ModelAuthorityViolationError, match="forbidden"):
            compute_causal_coverage(
                frozen_contract=contract,
                results={
                    "REQ-1": {
                        "transition": CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                        "verdict": PreliminaryVerdict.VERIFIED,
                        "is_causally_verified": True,
                        "confidence": 0.95,
                    }
                },
            )

    def test_adversarial_duplicate_requirement_in_contract_rejected(self) -> None:
        """Adversarial: Contract containing duplicate requirement IDs fails closed."""
        req = FrozenRequirement(
            requirement_id="REQ-DUP",
            statement="Duplicate statement",
            citation="Duplicate citation",
            citation_start=0,
            citation_end=15,
            rationale="Test",
        )
        contract = object.__new__(FrozenContract)
        object.__setattr__(contract, "schema_version", "1.0.0")
        object.__setattr__(contract, "task_digest", "t" * 64)
        object.__setattr__(contract, "change_class", ChangeClass.BUG_FIX)
        object.__setattr__(contract, "certainty", CertaintyLevel.CONFIDENT)
        object.__setattr__(contract, "requirements", (req, req))
        object.__setattr__(contract, "contract_digest", "c" * 64)

        with pytest.raises(DuplicateRequirementError, match="Duplicate requirement ID"):
            compute_causal_coverage(frozen_contract=contract, results={})

    def test_adversarial_unknown_requirement_id_rejected(self) -> None:
        """Adversarial: Submitting results for nonexistent requirement fails."""
        contract = _make_frozen_contract([("REQ-1", ChangeClass.BUG_FIX, "Bug 1")])

        with pytest.raises(UnknownRequirementError, match="not found in frozen contract"):
            compute_causal_coverage(
                frozen_contract=contract,
                results={
                    "REQ-1": {
                        "verdict": PreliminaryVerdict.VERIFIED,
                        "is_causally_verified": True,
                    },
                    "REQ-FAKE": {
                        "verdict": PreliminaryVerdict.VERIFIED,
                        "is_causally_verified": True,
                    },
                },
            )

    def test_adversarial_contract_digest_mismatch_rejected(self) -> None:
        """Adversarial: Expected contract digest mismatch fails closed."""
        contract = _make_frozen_contract(
            [("REQ-1", ChangeClass.BUG_FIX, "Bug 1")],
            contract_digest="a" * 64,
        )

        with pytest.raises(ContractDigestMismatchError, match="Contract digest mismatch"):
            compute_causal_coverage(
                frozen_contract=contract,
                results={},
                expected_contract_digest="b" * 64,
            )

    def test_adversarial_tampered_coverage_digest_detected(self) -> None:
        """Adversarial: Modifying summary fields invalidates digest recomputation."""
        contract = _make_frozen_contract([("REQ-1", ChangeClass.BUG_FIX, "Bug 1")])
        summary = compute_causal_coverage(frozen_contract=contract, results={})

        # Tamper with verified_count
        tampered_summary = CausalCoverageSummary(
            contract_digest=summary.contract_digest,
            total_requirements=summary.total_requirements,
            eligible_count=summary.eligible_count,
            excluded_count=summary.excluded_count,
            verified_count=1,  # Fabricated!
            not_run_count=0,
            inconclusive_count=0,
            contradicted_count=0,
            blocked_count=0,
            coverage_ratio=1.0,
            coverage_percentage=100.0,
            is_fully_verified=True,
            overall_verdict=PreliminaryVerdict.VERIFIED,
            per_requirement_facts=summary.per_requirement_facts,
            coverage_digest=summary.coverage_digest,  # Old digest!
        )

        with pytest.raises(CoverageIntegrityError, match="Coverage digest tampering detected"):
            verify_coverage_integrity(tampered_summary)
