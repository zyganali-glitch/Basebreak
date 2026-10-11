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
from basebreak.causal.receipt import (
    LocalCausalReceipt,
    WorldExecutionFact,
    create_causal_receipt,
)
from basebreak.causal.reconciliation import CausalTransition
from basebreak.causal.semantic_receipt import (
    SemanticVerificationReceipt,
    create_semantic_receipt,
)
from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.compiler.semantics import CertaintyLevel
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.witness_result import WitnessOutcome
from basebreak.verifier.witness_store import (
    TrustedWitnessVault,
    WitnessArtifact,
)


def _make_causal_receipt(
    requirement_id: str,
    contract_digest: str = "a" * 64,
    transition: CausalTransition = CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
    verdict: PreliminaryVerdict = PreliminaryVerdict.VERIFIED,
    witness_id: str | None = None,
    witness_digest: str = "b" * 64,
    narrative: str = "Base failed, candidate passed",
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
    vault: TrustedWitnessVault | None = None,
) -> LocalCausalReceipt:
    effective_wid = witness_id or f"wit-{requirement_id}"
    effective_prov = provenance
    if vault is not None and vault.authorized_provenances:
        if (
            provenance not in vault.authorized_provenances
            and EvidenceProvenance.FIXTURE in vault.authorized_provenances
        ):
            effective_prov = EvidenceProvenance.FIXTURE

    base_exec = WorldExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="sbx-base-1",
        source_commit_id="1" * 40,
        tree_digest="2" * 40,
        outcome=WitnessOutcome.FAIL,
        exit_code=1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="3" * 64,
        stderr_digest="4" * 64,
        result_digest="5" * 64,
        duration_seconds=1.0,
    )
    is_ver = verdict == PreliminaryVerdict.VERIFIED
    cand_exec = WorldExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="sbx-cand-1",
        source_commit_id="1" * 40,
        tree_digest="6" * 40,
        outcome=WitnessOutcome.PASS if is_ver else WitnessOutcome.FAIL,
        exit_code=0 if is_ver else 1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="7" * 64,
        stderr_digest="8" * 64,
        result_digest="9" * 64,
        duration_seconds=1.0,
    )
    attestation = None
    if vault is not None:
        if effective_wid not in vault.list_sealed_witness_ids():
            artifact = WitnessArtifact.from_text(
                path=f"tests/witness_{effective_wid}.py",
                content=f"def test_{effective_wid}(): assert True\n",
            )
            rec = vault.seal_witness(
                witness_id=effective_wid,
                requirement_id=requirement_id,
                frozen_contract_digest=contract_digest,
                source_commit_id=base_exec.source_commit_id,
                artifacts=[artifact],
            )
            witness_digest = rec.seal_digest
        else:
            witness_digest = vault.get_witness(effective_wid).seal_digest
        vault.record_observed_execution(
            witness_id=effective_wid,
            witness_digest=witness_digest,
            requirement_id=requirement_id,
            frozen_contract_digest=contract_digest,
            source_commit_id=base_exec.source_commit_id,
            candidate_tree_digest=cand_exec.tree_digest,
            sandbox_id=base_exec.sandbox_id,
            world=ExecutionWorld.BASE,
            command=("pytest", f"tests/witness_{effective_wid}.py"),
            exit_code=base_exec.exit_code,
            termination_status=base_exec.termination_status,
            stdout_digest=base_exec.stdout_digest,
            stderr_digest=base_exec.stderr_digest,
            result_digest=base_exec.result_digest,
            outcome=base_exec.outcome,
            provenance=effective_prov,
        )
        vault.record_observed_execution(
            witness_id=effective_wid,
            witness_digest=witness_digest,
            requirement_id=requirement_id,
            frozen_contract_digest=contract_digest,
            source_commit_id=base_exec.source_commit_id,
            candidate_tree_digest=cand_exec.tree_digest,
            sandbox_id=cand_exec.sandbox_id,
            world=ExecutionWorld.CANDIDATE,
            command=("pytest", f"tests/witness_{effective_wid}.py"),
            exit_code=cand_exec.exit_code,
            termination_status=cand_exec.termination_status,
            stdout_digest=cand_exec.stdout_digest,
            stderr_digest=cand_exec.stderr_digest,
            result_digest=cand_exec.result_digest,
            outcome=cand_exec.outcome,
            provenance=effective_prov,
        )
        attestation = vault.attest_execution(
            witness_id=effective_wid,
            requirement_id=requirement_id,
            frozen_contract_digest=contract_digest,
            source_commit_id=base_exec.source_commit_id,
            candidate_tree_digest=cand_exec.tree_digest,
            base_execution=base_exec,
            candidate_execution=cand_exec,
            counterfactual_execution=None,
            transition=transition,
            verdict=verdict,
            provenance=effective_prov,
        )
    return create_causal_receipt(
        requirement_id=requirement_id,
        frozen_contract_digest=contract_digest,
        witness_id=effective_wid,
        witness_digest=witness_digest,
        lock_digest="d" * 64,
        base_execution=base_exec,
        candidate_execution=cand_exec,
        transition=transition,
        verdict=verdict,
        provenance=effective_prov,
        narrative=narrative,
        attestation=attestation,
    )


def _make_semantic_receipt(
    requirement_id: str,
    change_class: ChangeClass,
    contract_digest: str = "a" * 64,
    transition: CausalTransition = CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
    verdict: PreliminaryVerdict = PreliminaryVerdict.VERIFIED,
    witness_id: str | None = None,
    witness_digest: str = "b" * 64,
    narrative: str = "Verified",
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
    vault: TrustedWitnessVault | None = None,
) -> SemanticVerificationReceipt:
    effective_wid = witness_id or f"wit-{requirement_id}"
    effective_prov = provenance
    if vault is not None and vault.authorized_provenances:
        if (
            provenance not in vault.authorized_provenances
            and EvidenceProvenance.FIXTURE in vault.authorized_provenances
        ):
            effective_prov = EvidenceProvenance.FIXTURE

    breaking = change_class in (
        ChangeClass.BUG_FIX,
        ChangeClass.FEATURE,
        ChangeClass.SECURITY_FIX,
    )
    base_exec = WorldExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="sbx-base-1",
        source_commit_id="1" * 40,
        tree_digest="2" * 40,
        outcome=WitnessOutcome.FAIL if breaking else WitnessOutcome.PASS,
        exit_code=1 if breaking else 0,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="3" * 64,
        stderr_digest="4" * 64,
        result_digest="5" * 64,
        duration_seconds=1.0,
    )
    is_ver = verdict == PreliminaryVerdict.VERIFIED
    cand_exec = WorldExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="sbx-cand-1",
        source_commit_id="1" * 40,
        tree_digest="6" * 40,
        outcome=WitnessOutcome.PASS if is_ver else WitnessOutcome.FAIL,
        exit_code=0 if is_ver else 1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="7" * 64,
        stderr_digest="8" * 64,
        result_digest="9" * 64,
        duration_seconds=1.0,
    )
    attestation = None
    if vault is not None:
        if effective_wid not in vault.list_sealed_witness_ids():
            artifact = WitnessArtifact.from_text(
                path=f"tests/witness_{effective_wid}.py",
                content=f"def test_{effective_wid}(): assert True\n",
            )
            rec = vault.seal_witness(
                witness_id=effective_wid,
                requirement_id=requirement_id,
                frozen_contract_digest=contract_digest,
                source_commit_id=base_exec.source_commit_id,
                artifacts=[artifact],
            )
            witness_digest = rec.seal_digest
        else:
            witness_digest = vault.get_witness(effective_wid).seal_digest
        vault.record_observed_execution(
            witness_id=effective_wid,
            witness_digest=witness_digest,
            requirement_id=requirement_id,
            frozen_contract_digest=contract_digest,
            source_commit_id=base_exec.source_commit_id,
            candidate_tree_digest=cand_exec.tree_digest,
            sandbox_id=base_exec.sandbox_id,
            world=ExecutionWorld.BASE,
            command=("pytest", f"tests/witness_{effective_wid}.py"),
            exit_code=base_exec.exit_code,
            termination_status=base_exec.termination_status,
            stdout_digest=base_exec.stdout_digest,
            stderr_digest=base_exec.stderr_digest,
            result_digest=base_exec.result_digest,
            outcome=base_exec.outcome,
            provenance=effective_prov,
        )
        vault.record_observed_execution(
            witness_id=effective_wid,
            witness_digest=witness_digest,
            requirement_id=requirement_id,
            frozen_contract_digest=contract_digest,
            source_commit_id=base_exec.source_commit_id,
            candidate_tree_digest=cand_exec.tree_digest,
            sandbox_id=cand_exec.sandbox_id,
            world=ExecutionWorld.CANDIDATE,
            command=("pytest", f"tests/witness_{effective_wid}.py"),
            exit_code=cand_exec.exit_code,
            termination_status=cand_exec.termination_status,
            stdout_digest=cand_exec.stdout_digest,
            stderr_digest=cand_exec.stderr_digest,
            result_digest=cand_exec.result_digest,
            outcome=cand_exec.outcome,
            provenance=effective_prov,
        )
        attestation = vault.attest_execution(
            witness_id=effective_wid,
            requirement_id=requirement_id,
            frozen_contract_digest=contract_digest,
            source_commit_id=base_exec.source_commit_id,
            candidate_tree_digest=cand_exec.tree_digest,
            base_execution=base_exec,
            candidate_execution=cand_exec,
            counterfactual_execution=None,
            transition=transition,
            verdict=verdict,
            provenance=effective_prov,
        )
    return create_semantic_receipt(
        change_class=change_class,
        requirement_id=requirement_id,
        frozen_contract_digest=contract_digest,
        witness_id=effective_wid,
        witness_digest=witness_digest,
        lock_digest="d" * 64,
        source_commit_id="1" * 40,
        candidate_tree_digest="6" * 40,
        base_execution=base_exec,
        candidate_execution=cand_exec,
        class_specific_payload={},
        transition=transition,
        verdict=verdict,
        is_causally_verified=(verdict == PreliminaryVerdict.VERIFIED),
        provenance=effective_prov,
        narrative=narrative,
        attestation=attestation,
    )


class MockNonBehavioralRequirement(FrozenRequirement):
    is_behavioral: bool = False


def _make_frozen_contract(
    req_tuples: list[tuple[str, ChangeClass, str]],
    task_id: str = "TASK-TEST-001",
    contract_digest: str = "a" * 64,
    non_behavioral_ids: set[str] | None = None,
) -> FrozenContract:
    non_beh = non_behavioral_ids or set()
    frozen_reqs = []
    for rid, _cclass, stmt in req_tuples:
        citation_len = min(len(stmt), 20)
        req_cls = MockNonBehavioralRequirement if rid in non_beh else FrozenRequirement
        req = req_cls(
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

    def setup_method(self) -> None:
        self.vault = TrustedWitnessVault.create_authorized_vault()

    def test_p17_01_denominator_derived_from_eligible_requirements(self) -> None:
        """P-17.01: Eligibility denominator excludes non-behavioral requirements."""
        contract = _make_frozen_contract(
            [
                ("REQ-1", ChangeClass.BUG_FIX, "Fix null dereference"),
                ("REQ-2", ChangeClass.FEATURE, "Add export endpoint"),
                ("REQ-DOC", ChangeClass.BUG_FIX, "Update README notes"),
            ],
            non_behavioral_ids={"REQ-DOC"},
        )
        overrides = {"REQ-DOC": RequirementEligibility.EXCLUDED_NON_BEHAVIORAL}
        rationales = {"REQ-DOC": "Documentation-only requirement"}

        # Provide verification for REQ-1 only
        results = {
            "REQ-1": _make_causal_receipt(
                requirement_id="REQ-1",
                contract_digest=contract.contract_digest,
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                vault=self.vault,
            )
        }

        summary = compute_causal_coverage(
            frozen_contract=contract,
            results=results,
            eligibility_overrides=overrides,
            exclusion_rationales=rationales,
            verifier_authority=self.vault,
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
        contract = _make_frozen_contract(
            [("REQ-DOC", ChangeClass.REFACTOR, "Doc refactor only")],
            non_behavioral_ids={"REQ-DOC"},
        )
        overrides = {"REQ-DOC": RequirementEligibility.EXCLUDED_NON_BEHAVIORAL}
        rationales = {"REQ-DOC": "Non-behavioral doc change"}

        summary = compute_causal_coverage(
            frozen_contract=contract,
            results={},
            eligibility_overrides=overrides,
            exclusion_rationales=rationales,
            verifier_authority=self.vault,
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
            "REQ-1": _make_causal_receipt(
                requirement_id="REQ-1",
                contract_digest=contract.contract_digest,
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                vault=self.vault,
            ),
            "REQ-2": _make_causal_receipt(
                requirement_id="REQ-2",
                contract_digest=contract.contract_digest,
                transition=CausalTransition.UNVERIFIED_DEFECT_PERSISTS,
                verdict=PreliminaryVerdict.CONTRADICTED,
                vault=self.vault,
            ),
        }

        summary = compute_causal_coverage(
            frozen_contract=contract,
            results=results,
            verifier_authority=self.vault,
        )

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
            "REQ-1": _make_causal_receipt(
                requirement_id="REQ-1",
                contract_digest=contract.contract_digest,
                vault=self.vault,
            ),
            "REQ-2": _make_causal_receipt(
                requirement_id="REQ-2",
                contract_digest=contract.contract_digest,
                vault=self.vault,
            ),
        }

        summary = compute_causal_coverage(
            frozen_contract=contract,
            results=results,
            verifier_authority=self.vault,
        )

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

        transitions = {
            "REQ-BUG": CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            "REQ-FEAT": CausalTransition.FEATURE_VERIFIED,
            "REQ-SEC": CausalTransition.SECURITY_FIX_VERIFIED,
            "REQ-REF": CausalTransition.REFACTOR_VERIFIED,
            "REQ-PERF": CausalTransition.PERFORMANCE_VERIFIED,
            "REQ-DEP": CausalTransition.DEP_API_CHANGE_VERIFIED,
        }
        req_classes = {
            "REQ-BUG": ChangeClass.BUG_FIX,
            "REQ-FEAT": ChangeClass.FEATURE,
            "REQ-SEC": ChangeClass.SECURITY_FIX,
            "REQ-REF": ChangeClass.REFACTOR,
            "REQ-PERF": ChangeClass.PERFORMANCE,
            "REQ-DEP": ChangeClass.DEP_API_CHANGE,
        }
        results = {
            rid: _make_semantic_receipt(
                requirement_id=rid,
                change_class=req_classes[rid],
                contract_digest=contract.contract_digest,
                transition=transitions[rid],
                verdict=PreliminaryVerdict.VERIFIED,
                vault=self.vault,
            )
            for rid in req_classes
        }

        summary = compute_causal_coverage(
            frozen_contract=contract,
            results=results,
            requirement_classes=req_classes,
            verifier_authority=self.vault,
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
            "REQ-1": _make_causal_receipt(
                requirement_id="REQ-1",
                contract_digest=contract.contract_digest,
                vault=self.vault,
            )
        }

        summary = compute_causal_coverage(
            frozen_contract=contract,
            results=results,
            verifier_authority=self.vault,
        )

        # Denominator must remain 3!
        assert summary.eligible_count == 3
        assert summary.verified_count == 1
        assert summary.not_run_count == 2
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

    def test_adversarial_fabricated_local_causal_receipt_rejected(self) -> None:
        """Adversarial (Defect B): A self-consistent LocalCausalReceipt with correct digest and
        claimed LOCAL_EXECUTION cannot produce VERIFIED coverage without trusted verifier authority.
        """
        contract = _make_frozen_contract([("REQ-1", ChangeClass.BUG_FIX, "Fix bug")])
        fabricated_rc = _make_causal_receipt(
            requirement_id="REQ-1",
            contract_digest=contract.contract_digest,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        # Attempt compute_causal_coverage without verifier authority
        summary_no_auth = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-1": fabricated_rc},
        )
        assert summary_no_auth.verified_count == 0
        assert summary_no_auth.inconclusive_count == 1
        assert summary_no_auth.overall_verdict == PreliminaryVerdict.INCONCLUSIVE
        assert (
            summary_no_auth.per_requirement_facts[0].causal_state
            == RequirementCausalState.INCONCLUSIVE
        )

        # Attempt compute_causal_coverage with an independent vault where receipt has NO attestation
        foreign_vault = TrustedWitnessVault()
        summary_foreign = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-1": fabricated_rc},
            verifier_authority=foreign_vault,
        )
        assert summary_foreign.verified_count == 0
        assert summary_foreign.inconclusive_count == 1
        assert summary_foreign.overall_verdict == PreliminaryVerdict.INCONCLUSIVE

    def test_adversarial_fabricated_semantic_receipt_rejected(self) -> None:
        """Adversarial (Defect B): A self-consistent SemanticVerificationReceipt with
        correct digest and claimed LOCAL_EXECUTION cannot produce VERIFIED coverage
        without trusted verifier authority.
        """
        contract = _make_frozen_contract([("REQ-1", ChangeClass.BUG_FIX, "Fix bug")])
        fabricated_sem = _make_semantic_receipt(
            requirement_id="REQ-1",
            change_class=ChangeClass.BUG_FIX,
            contract_digest=contract.contract_digest,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        summary = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-1": fabricated_sem},
        )
        assert summary.verified_count == 0
        assert summary.inconclusive_count == 1
        assert summary.overall_verdict == PreliminaryVerdict.INCONCLUSIVE

    def test_adversarial_forged_vault_signature_rejected(self) -> None:
        """Adversarial (Defect B): An attestation signed with an untrusted key/vault is rejected."""
        contract = _make_frozen_contract([("REQ-1", ChangeClass.BUG_FIX, "Fix bug")])
        attacker_vault = TrustedWitnessVault.create_authorized_vault(
            vault_secret=b"attacker_secret_key_1234567890123"
        )
        honest_vault = TrustedWitnessVault.create_authorized_vault(
            vault_secret=b"honest_verifier_key_12345678901234"
        )

        signed_by_attacker = _make_causal_receipt(
            requirement_id="REQ-1",
            contract_digest=contract.contract_digest,
            vault=attacker_vault,
        )
        # Honest verifier evaluating coverage must reject the attacker's signature
        summary = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-1": signed_by_attacker},
            verifier_authority=honest_vault,
        )
        assert summary.verified_count == 0
        assert summary.inconclusive_count == 1
        assert summary.overall_verdict == PreliminaryVerdict.INCONCLUSIVE
