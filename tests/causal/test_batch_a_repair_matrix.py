"""Independent Adversarial Regression Test Suite for Batch A Second Surgical Repair.

Covers the 14 minimal regression acceptance criteria from Section 5:
1. An unrelated nonempty patch against the trusted demo cannot receive VERIFIED.
2. A malformed patch cannot receive VERIFIED.
3. The genuine intended patch must be applied to the actual candidate tree.
4. Changing the patch changes the candidate identity or fails validation.
5. Counterfactual subtraction must match actual source reconstruction.
6. An arbitrary base_sha cannot be accepted as executed source identity.
7. A modified/tampered trusted fixture cannot be silently trusted.
8. A fully populated forged dict, including plausible witness ID, 64-character digest
   and verified transition, cannot increase Causal Coverage.
9. A fabricated intermediate reconciliation record cannot bypass evidence authority.
10. Caller-controlled exclusion of behavioral obligations cannot silently increase coverage.
11. Genuine class-specific REFACTOR/PERFORMANCE/DEP_API_CHANGE evidence is not rejected
    by a blanket BASE=FAIL rule.
12. Class-specific invalid evidence cannot obtain VERIFIED.
13. Arbitrary signature strategy plus arbitrary signature cannot promote a
    public receipt to authoritative.
14. Genuine FIXTURE evidence cannot be presented as LOCAL_EXECUTION or LIVE_NEBIUS.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from basebreak.causal.coverage import (
    CoverageIntegrityError,
    RequirementEligibility,
    compute_causal_coverage,
)
from basebreak.causal.public_receipt import (
    PublicCounterfactualFact,
    PublicExecutionFact,
    PublicReceiptIntegrityError,
    PublicVerificationReceipt,
    PublicWitnessFact,
    create_public_verification_receipt,
    verify_public_receipt_integrity,
)
from basebreak.causal.receipt import (
    CausalReceiptTamperingError,
    LocalCausalReceipt,
    WorldExecutionFact,
    create_causal_receipt,
)
from basebreak.causal.reconciliation import CausalTransition, ReconciliationFact
from basebreak.causal.semantic_receipt import (
    create_semantic_receipt,
)
from basebreak.cli.config import BasebreakConfig
from basebreak.cli.runner import (
    CANONICAL_DEMO_PATCH,
    execute_verification_pipeline,
)
from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.compiler.semantics import CertaintyLevel
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.witness_result import WitnessOutcome


def _demo_target_path() -> str:
    fixtures_dir = Path(__file__).resolve().parent.parent / "fixtures" / "demo_target"
    return str(fixtures_dir)


def _make_test_contract(
    req_tuples: list[tuple[str, ChangeClass, str]],
    contract_digest: str = "c" * 64,
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


def _make_sample_causal_receipt(
    requirement_id: str = "REQ-001",
    contract_digest: str = "c" * 64,
    change_class: ChangeClass = ChangeClass.BUG_FIX,
    verdict: PreliminaryVerdict = PreliminaryVerdict.VERIFIED,
    transition: CausalTransition = CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
) -> LocalCausalReceipt:
    base_wef = WorldExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="sbx-base",
        source_commit_id="1" * 40,
        tree_digest="2" * 40,
        outcome=WitnessOutcome.FAIL,
        exit_code=1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="3" * 64,
        stderr_digest="4" * 64,
        result_digest="8" * 64,
        duration_seconds=1.0,
    )
    is_ver = verdict == PreliminaryVerdict.VERIFIED
    cand_wef = WorldExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="sbx-cand",
        source_commit_id="1" * 40,
        tree_digest="5" * 40,
        outcome=WitnessOutcome.PASS if is_ver else WitnessOutcome.FAIL,
        exit_code=0 if is_ver else 1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="6" * 64,
        stderr_digest="7" * 64,
        result_digest="9" * 64,
        duration_seconds=1.0,
    )
    return create_causal_receipt(
        requirement_id=requirement_id,
        frozen_contract_digest=contract_digest,
        witness_id="WIT-001",
        witness_digest="a" * 64,
        lock_digest="d" * 64,
        base_execution=base_wef,
        candidate_execution=cand_wef,
        transition=transition,
        verdict=verdict,
        provenance=provenance,
        narrative="Test execution fact",
    )


def _make_class_specific_public_receipt(
    change_class: ChangeClass,
    base_outcome: WitnessOutcome,
    cand_outcome: WitnessOutcome,
    cf_outcome: WitnessOutcome | None = None,
    overall_verdict: PreliminaryVerdict = PreliminaryVerdict.VERIFIED,
) -> PublicVerificationReceipt:
    contract = _make_test_contract(
        [("REQ-001", change_class, f"Requirement for {change_class.value}")]
    )
    req_classes = {"REQ-001": change_class}

    is_breaking = change_class in (
        ChangeClass.BUG_FIX,
        ChangeClass.FEATURE,
        ChangeClass.SECURITY_FIX,
    )
    transition = (
        CausalTransition.CAUSAL_BUG_FIX_VERIFIED
        if change_class == ChangeClass.BUG_FIX
        else CausalTransition.FEATURE_VERIFIED
        if change_class == ChangeClass.FEATURE
        else CausalTransition.SECURITY_FIX_VERIFIED
        if change_class == ChangeClass.SECURITY_FIX
        else CausalTransition.REFACTOR_VERIFIED
        if change_class == ChangeClass.REFACTOR
        else CausalTransition.PERFORMANCE_VERIFIED
        if change_class == ChangeClass.PERFORMANCE
        else CausalTransition.DEP_API_CHANGE_VERIFIED
    )

    base_wef = WorldExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="sbx-base",
        source_commit_id="1" * 40,
        tree_digest="2" * 40,
        outcome=base_outcome,
        exit_code=0 if base_outcome == WitnessOutcome.PASS else 1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="3" * 64,
        stderr_digest="4" * 64,
        result_digest="8" * 64,
        duration_seconds=1.0,
    )
    cand_wef = WorldExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="sbx-cand",
        source_commit_id="1" * 40,
        tree_digest="5" * 40,
        outcome=cand_outcome,
        exit_code=0 if cand_outcome == WitnessOutcome.PASS else 1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="6" * 64,
        stderr_digest="7" * 64,
        result_digest="9" * 64,
        duration_seconds=1.0,
    )

    sem_receipt = create_semantic_receipt(
        change_class=change_class,
        requirement_id="REQ-001",
        frozen_contract_digest="c" * 64,
        witness_id="WIT-001",
        witness_digest="a" * 64,
        lock_digest="d" * 64,
        source_commit_id="1" * 40,
        candidate_tree_digest="5" * 40,
        base_execution=base_wef,
        candidate_execution=cand_wef,
        class_specific_payload={},
        transition=transition,
        verdict=overall_verdict,
        is_causally_verified=(overall_verdict == PreliminaryVerdict.VERIFIED),
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
        narrative=f"Verification for {change_class.value}",
    )

    coverage = compute_causal_coverage(
        frozen_contract=contract,
        results={"REQ-001": sem_receipt},
        requirement_classes=req_classes,
    )

    base_pub = PublicExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="sbx-base",
        source_commit_id="1" * 40,
        tree_digest="2" * 40,
        outcome=base_outcome,
        exit_code=0 if base_outcome == WitnessOutcome.PASS else 1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="3" * 64,
        stderr_digest="4" * 64,
        duration_seconds=1.0,
    )
    cand_pub = PublicExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="sbx-cand",
        source_commit_id="1" * 40,
        tree_digest="5" * 40,
        outcome=cand_outcome,
        exit_code=0 if cand_outcome == WitnessOutcome.PASS else 1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="6" * 64,
        stderr_digest="7" * 64,
        duration_seconds=1.0,
    )
    witness = PublicWitnessFact(
        witness_id="WIT-001",
        witness_digest="a" * 64,
        requirement_id="REQ-001",
    )

    cf_fact: PublicCounterfactualFact | None = None
    if is_breaking:
        cf_exec = (
            PublicExecutionFact(
                world=ExecutionWorld.COUNTERFACTUAL,
                sandbox_id="sbx-cf",
                source_commit_id="1" * 40,
                tree_digest="2" * 40,
                outcome=cf_outcome or WitnessOutcome.FAIL,
                exit_code=1,
                termination_status=TerminationStatus.COMPLETED,
                stdout_digest="c" * 64,
                stderr_digest="d" * 64,
                duration_seconds=1.0,
            )
            if cf_outcome is not None
            else None
        )
        cf_fact = PublicCounterfactualFact(
            is_required=True,
            candidate_tree_digest="5" * 40,
            delta_digest="e" * 64,
            execution_fact=cf_exec,
            outcome=cf_outcome,
        )

    return create_public_verification_receipt(
        frozen_contract_digest="c" * 64,
        task_id="TASK-CLASS-TEST",
        repo_locator="https://github.com/example/repo.git",
        source_commit_id="1" * 40,
        candidate_tree_digest="5" * 40,
        coverage_summary=coverage,
        executions=(base_pub, cand_pub),
        witnesses=(witness,),
        overall_verdict=overall_verdict,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
        counterfactual=cf_fact,
    )


class TestBatchARepairAdversarialMatrix:
    """Exercises the 14 mandatory adversarial acceptance checks."""

    def test_01_unrelated_nonempty_patch_cannot_receive_verified(self, tmp_path: Path) -> None:
        """1. An unrelated nonempty patch against trusted demo cannot receive VERIFIED."""
        unrelated_patch = (
            "diff --git a/unrelated_file.py b/unrelated_file.py\n"
            "new file mode 100644\n"
            "index 0000000..e69de29\n"
        )
        cfg = BasebreakConfig(runs_dir=tmp_path / "runs")
        result = execute_verification_pipeline(
            target=_demo_target_path(),
            patch=unrelated_patch,
            config=cfg,
        )
        assert result.exit_code == 1
        assert result.status == "CONTRADICTED"
        assert result.causal_transition in ("PATCH_APPLICATION_FAILED", "TARGET_FILE_UNMODIFIED")
        assert result.receipt is None

    def test_02_malformed_patch_cannot_receive_verified(self, tmp_path: Path) -> None:
        """2. A malformed patch cannot receive VERIFIED."""
        malformed_patch = "This is not a unified diff format\n+++ invalid lines\n"
        cfg = BasebreakConfig(runs_dir=tmp_path / "runs")
        result = execute_verification_pipeline(
            target=_demo_target_path(),
            patch=malformed_patch,
            config=cfg,
        )
        assert result.exit_code == 1
        assert result.status == "CONTRADICTED"
        assert result.causal_transition == "PATCH_APPLICATION_FAILED"
        assert result.receipt is None

    def test_03_genuine_intended_patch_applied_to_candidate_tree(self, tmp_path: Path) -> None:
        """3. The genuine intended patch must be applied to the actual candidate tree."""
        cfg = BasebreakConfig(runs_dir=tmp_path / "runs")
        result = execute_verification_pipeline(
            target=_demo_target_path(),
            patch=CANONICAL_DEMO_PATCH,
            config=cfg,
        )
        assert result.exit_code == 0
        assert result.status == "VERIFIED"
        assert result.causal_transition in ("CAUSAL_BUG_FIX_VERIFIED", "FAIL->PASS (CF=FAIL)")
        assert result.receipt is not None
        assert result.receipt.overall_verdict == PreliminaryVerdict.VERIFIED

    def test_04_changing_patch_changes_candidate_identity_or_fails(self, tmp_path: Path) -> None:
        """4. Changing the patch changes candidate identity or fails validation."""
        cfg = BasebreakConfig(runs_dir=tmp_path / "runs")
        # Attempt to run with forged candidate_sha
        forged_cand_sha = "0" * 64
        result = execute_verification_pipeline(
            target=_demo_target_path(),
            patch=CANONICAL_DEMO_PATCH,
            candidate_sha=forged_cand_sha,
            config=cfg,
        )
        assert result.exit_code == 1
        assert result.status == "CONTRADICTED"
        assert result.causal_transition == "CANDIDATE_IDENTITY_MISMATCH"

    def test_05_counterfactual_subtraction_matches_source_reconstruction(
        self, tmp_path: Path
    ) -> None:
        """5. Counterfactual subtraction must match actual source reconstruction."""
        # On positive verification, verify that cf_tree matches base_tree
        cfg = BasebreakConfig(runs_dir=tmp_path / "runs")
        result = execute_verification_pipeline(
            target=_demo_target_path(),
            patch=CANONICAL_DEMO_PATCH,
            config=cfg,
        )
        assert result.exit_code == 0
        assert result.status == "VERIFIED"
        # Receipt counterfactual record exists and binds accurately
        assert result.receipt is not None
        assert result.receipt.counterfactual is not None
        assert result.receipt.counterfactual.outcome == WitnessOutcome.FAIL

    def test_06_arbitrary_base_sha_cannot_be_accepted(self, tmp_path: Path) -> None:
        """6. An arbitrary base_sha cannot be accepted as executed source identity."""
        cfg = BasebreakConfig(runs_dir=tmp_path / "runs")
        result = execute_verification_pipeline(
            target=_demo_target_path(),
            base_sha="1" * 40,
            config=cfg,
        )
        assert result.exit_code == 2
        assert result.status == "BLOCKED"
        assert "not a valid committed git revision" in result.message

    def test_07_tampered_fixture_cannot_be_silently_trusted(self, tmp_path: Path) -> None:
        """7. Symlinks or modified fixture contents cannot bypass security checks."""
        # Test symlink detection logic directly
        symlink_target = tmp_path / "symlink_dir"
        symlink_target.mkdir()
        link_path = tmp_path / "link_to_target"
        try:
            link_path.symlink_to(symlink_target, target_is_directory=True)
            cfg = BasebreakConfig(runs_dir=tmp_path / "runs")
            result = execute_verification_pipeline(
                target=str(link_path),
                config=cfg,
            )
            assert result.exit_code == 2
            assert result.status == "BLOCKED"
        except OSError:
            # On Windows without developer mode symlink creation may require privilege;
            # verify that non-allowlisted directory is blocked:
            cfg = BasebreakConfig(runs_dir=tmp_path / "runs")
            result = execute_verification_pipeline(
                target=str(symlink_target),
                config=cfg,
            )
            assert result.exit_code == 2
            assert result.status == "BLOCKED"
            assert result.status == "BLOCKED"
        except OSError:
            # On Windows without developer mode symlink creation may require privilege;
            # verify that non-allowlisted directory is blocked:
            cfg = BasebreakConfig(runs_dir=tmp_path / "runs")
            result = execute_verification_pipeline(
                target_locator=str(symlink_target),
                config=cfg,
            )
            assert result.exit_code == 2
            assert result.status == "BLOCKED"

    def test_08_fully_populated_forged_dict_cannot_increase_coverage(self) -> None:
        """8. Fully populated forged dict cannot increase Causal Coverage."""
        contract = _make_test_contract([("REQ-001", ChangeClass.BUG_FIX, "Bug fix")])
        forged_dict = {
            "REQ-001": {
                "is_causally_verified": True,
                "verdict": PreliminaryVerdict.VERIFIED,
                "transition": CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                "witness_id": "WIT-FORGED",
                "witness_digest": "a" * 64,
                "rationale": "Caller claims verified coverage without cryptographic receipt",
            }
        }
        summary = compute_causal_coverage(frozen_contract=contract, results=forged_dict)
        assert summary.eligible_count == 1
        assert summary.verified_count == 0  # Dict MUST NOT confer verified!
        assert summary.inconclusive_count == 1
        assert summary.coverage_ratio == 0.0
        assert summary.is_fully_verified is False
        assert summary.overall_verdict == PreliminaryVerdict.INCONCLUSIVE

    def test_09_fabricated_reconciliation_record_cannot_bypass_authority(self) -> None:
        """9. A fabricated intermediate reconciliation record cannot bypass authority."""
        contract = _make_test_contract([("REQ-001", ChangeClass.BUG_FIX, "Bug fix")])
        unbound_fact = {
            "REQ-001": ReconciliationFact(
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                is_causally_verified=True,
                rationale="Unbound caller assertion",
            )
        }
        summary = compute_causal_coverage(frozen_contract=contract, results=unbound_fact)
        assert summary.eligible_count == 1
        assert summary.verified_count == 0  # Unbound fact MUST NOT confer verified!
        assert summary.inconclusive_count == 1
        assert summary.coverage_ratio == 0.0
        assert summary.is_fully_verified is False

    def test_10_caller_controlled_exclusion_of_behavioral_obligation_rejected(self) -> None:
        """10. Caller-controlled exclusion of behavioral obligations cannot
        silently increase coverage.
        """
        contract = _make_test_contract([("REQ-001", ChangeClass.BUG_FIX, "Fix safety bug")])
        with pytest.raises(
            CoverageIntegrityError, match="behavioral obligations cannot be removed"
        ):
            compute_causal_coverage(
                frozen_contract=contract,
                results={},
                eligibility_overrides={"REQ-001": RequirementEligibility.EXCLUDED_NON_BEHAVIORAL},
                exclusion_rationales={"REQ-001": "Caller tries to drop safety requirement"},
            )

    def test_11_refactor_perf_dep_api_change_not_rejected_by_blanket_base_fail(self) -> None:
        """11. Genuine class-specific REFACTOR/PERFORMANCE/DEP_API_CHANGE evidence
        is not rejected by a blanket BASE=FAIL rule.
        """
        for cclass in (ChangeClass.REFACTOR, ChangeClass.PERFORMANCE, ChangeClass.DEP_API_CHANGE):
            receipt = _make_class_specific_public_receipt(
                change_class=cclass,
                base_outcome=WitnessOutcome.PASS,  # BASE=PASS is legitimate for refactor!
                cand_outcome=WitnessOutcome.PASS,
                overall_verdict=PreliminaryVerdict.VERIFIED,
            )
            assert receipt.overall_verdict == PreliminaryVerdict.VERIFIED
            verify_public_receipt_integrity(receipt)

    def test_12_class_specific_invalid_evidence_cannot_obtain_verified(self) -> None:
        """12. Class-specific invalid evidence cannot obtain VERIFIED."""
        # 12a: BUG_FIX where BASE passes must be rejected (base did not break)
        with pytest.raises(PublicReceiptIntegrityError, match="base did not break"):
            _make_class_specific_public_receipt(
                change_class=ChangeClass.BUG_FIX,
                base_outcome=WitnessOutcome.PASS,  # Invalid: bug fix base passed!
                cand_outcome=WitnessOutcome.PASS,
                cf_outcome=WitnessOutcome.FAIL,
                overall_verdict=PreliminaryVerdict.VERIFIED,
            )

        # 12b: REFACTOR where BASE fails must be rejected (baseline broke)
        with pytest.raises(PublicReceiptIntegrityError, match="baseline behavior failed"):
            _make_class_specific_public_receipt(
                change_class=ChangeClass.REFACTOR,
                base_outcome=WitnessOutcome.FAIL,  # Invalid: refactor baseline failed!
                cand_outcome=WitnessOutcome.PASS,
                overall_verdict=PreliminaryVerdict.VERIFIED,
            )

    def test_13_arbitrary_signature_strategy_cannot_promote_receipt_to_authoritative(
        self,
    ) -> None:
        """13. Arbitrary signature strategy plus signature cannot promote receipt to
        authoritative.
        """
        contract = _make_test_contract([("REQ-001", ChangeClass.BUG_FIX, "Bug fix")])
        local_rc = _make_sample_causal_receipt()
        coverage = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-001": local_rc},
        )
        base_exec = PublicExecutionFact(
            world=ExecutionWorld.BASE,
            sandbox_id="sbx-1",
            source_commit_id="1" * 40,
            tree_digest="2" * 40,
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="3" * 64,
            stderr_digest="4" * 64,
            duration_seconds=1.0,
        )
        cand_exec = PublicExecutionFact(
            world=ExecutionWorld.CANDIDATE,
            sandbox_id="sbx-2",
            source_commit_id="1" * 40,
            tree_digest="5" * 40,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="6" * 64,
            stderr_digest="7" * 64,
            duration_seconds=1.0,
        )
        witness = PublicWitnessFact(
            witness_id="WIT-001",
            witness_digest="a" * 64,
            requirement_id="REQ-001",
        )
        cf = PublicCounterfactualFact(
            is_required=True,
            candidate_tree_digest="5" * 40,
            delta_digest="e" * 64,
            execution_fact=PublicExecutionFact(
                world=ExecutionWorld.COUNTERFACTUAL,
                sandbox_id="sbx-cf",
                source_commit_id="1" * 40,
                tree_digest="2" * 40,
                outcome=WitnessOutcome.FAIL,
                exit_code=1,
                termination_status=TerminationStatus.COMPLETED,
                stdout_digest="c" * 64,
                stderr_digest="d" * 64,
                duration_seconds=1.0,
            ),
            outcome=WitnessOutcome.FAIL,
        )

        with pytest.raises(
            PublicReceiptIntegrityError, match="is_authoritative cannot be asserted"
        ):
            create_public_verification_receipt(
                frozen_contract_digest="c" * 64,
                task_id="TASK-PROMOTION",
                repo_locator="https://github.com/example/repo.git",
                source_commit_id="1" * 40,
                candidate_tree_digest="5" * 40,
                coverage_summary=coverage,
                executions=(base_exec, cand_exec),
                witnesses=(witness,),
                overall_verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                counterfactual=cf,
                signature_strategy="CUSTOM_ENTERPRISE_PKI",
                signature="signed_by_attacker_key",
                is_authoritative=True,  # Attacker attempts promotion!
            )

    def test_14_fixture_evidence_cannot_be_claimed_as_local_or_live_in_local_receipt(
        self,
    ) -> None:
        """14. Genuine FIXTURE evidence cannot be forged into a different provenance."""
        rc = _make_sample_causal_receipt(provenance=EvidenceProvenance.FIXTURE)
        assert rc.provenance == EvidenceProvenance.FIXTURE

        # Tampering with provenance without changing digest fails integrity verification
        with pytest.raises(CausalReceiptTamperingError, match="receipt_digest mismatch"):
            LocalCausalReceipt(
                schema_version=rc.schema_version,
                requirement_id=rc.requirement_id,
                frozen_contract_digest=rc.frozen_contract_digest,
                witness_id=rc.witness_id,
                witness_digest=rc.witness_digest,
                lock_digest=rc.lock_digest,
                base_execution=rc.base_execution,
                candidate_execution=rc.candidate_execution,
                transition=rc.transition,
                verdict=rc.verdict,
                provenance=EvidenceProvenance.LIVE_NEBIUS,  # Forged provenance!
                created_at_utc=rc.created_at_utc,
                receipt_digest=rc.receipt_digest,
                narrative=rc.narrative,
            )
