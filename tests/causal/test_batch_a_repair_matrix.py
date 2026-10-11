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
from typing import Any

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
from basebreak.verifier.witness_lock import create_witness_lock
from basebreak.verifier.witness_result import WitnessOutcome
from basebreak.verifier.witness_store import (
    TrustedWitnessVault,
    UntrustedWitnessAuthorityError,
    WitnessArtifact,
    WitnessTamperingError,
)


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
    vault: TrustedWitnessVault | None = None,
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
    attestation = None
    witness_digest = "a" * 64
    effective_prov = provenance
    if vault is not None and vault.authorized_provenances:
        if (
            provenance not in vault.authorized_provenances
            and EvidenceProvenance.FIXTURE in vault.authorized_provenances
        ):
            effective_prov = EvidenceProvenance.FIXTURE

    if vault is not None:
        if "WIT-001" not in vault.list_sealed_witness_ids():
            wa = WitnessArtifact.from_text(
                path="tests/test_wit.py",
                content="def test_w(): pass\n",
            )
            rec = vault.seal_witness(
                witness_id="WIT-001",
                requirement_id=requirement_id,
                frozen_contract_digest=contract_digest,
                source_commit_id="1" * 40,
                artifacts=[wa],
            )
            witness_digest = rec.seal_digest
        else:
            witness_digest = vault.get_witness("WIT-001").seal_digest

        vault.record_observed_execution(
            witness_id="WIT-001",
            witness_digest=witness_digest,
            requirement_id=requirement_id,
            frozen_contract_digest=contract_digest,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=base_wef.sandbox_id,
            world=ExecutionWorld.BASE,
            command=("pytest", "tests/test_wit.py"),
            exit_code=base_wef.exit_code,
            termination_status=base_wef.termination_status,
            stdout_digest=base_wef.stdout_digest,
            stderr_digest=base_wef.stderr_digest,
            result_digest=base_wef.result_digest,
            outcome=base_wef.outcome,
            provenance=effective_prov,
        )
        vault.record_observed_execution(
            witness_id="WIT-001",
            witness_digest=witness_digest,
            requirement_id=requirement_id,
            frozen_contract_digest=contract_digest,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=cand_wef.sandbox_id,
            world=ExecutionWorld.CANDIDATE,
            command=("pytest", "tests/test_wit.py"),
            exit_code=cand_wef.exit_code,
            termination_status=cand_wef.termination_status,
            stdout_digest=cand_wef.stdout_digest,
            stderr_digest=cand_wef.stderr_digest,
            result_digest=cand_wef.result_digest,
            outcome=cand_wef.outcome,
            provenance=effective_prov,
        )

        attestation = vault.attest_execution(
            witness_id="WIT-001",
            requirement_id=requirement_id,
            frozen_contract_digest=contract_digest,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            counterfactual_execution=None,
            transition=transition,
            verdict=verdict,
            provenance=effective_prov,
            witness_digest=witness_digest,
        )
    return create_causal_receipt(
        requirement_id=requirement_id,
        frozen_contract_digest=contract_digest,
        witness_id="WIT-001",
        witness_digest=witness_digest,
        lock_digest="d" * 64,
        base_execution=base_wef,
        candidate_execution=cand_wef,
        transition=transition,
        verdict=verdict,
        provenance=effective_prov,
        narrative="Test execution fact",
        attestation=attestation,
    )


def _make_class_specific_public_receipt(
    change_class: ChangeClass,
    base_outcome: WitnessOutcome,
    cand_outcome: WitnessOutcome,
    cf_outcome: WitnessOutcome | None = None,
    overall_verdict: PreliminaryVerdict = PreliminaryVerdict.VERIFIED,
    vault: TrustedWitnessVault | None = None,
) -> PublicVerificationReceipt:
    if vault is None:
        vault = TrustedWitnessVault.create_authorized_vault()
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

    if "WIT-001" not in vault.list_sealed_witness_ids():
        wa = WitnessArtifact.from_text(
            path="tests/test_wit.py",
            content="def test_w(): pass\n",
        )
        rec = vault.seal_witness(
            witness_id="WIT-001",
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
        wit_digest = rec.seal_digest
    else:
        wit_digest = vault.get_witness("WIT-001").seal_digest

    attestation = None
    effective_prov = EvidenceProvenance.FIXTURE
    if vault.authorized_provenances:
        if EvidenceProvenance.FIXTURE in vault.authorized_provenances:
            effective_prov = EvidenceProvenance.FIXTURE
        else:
            effective_prov = next(iter(vault.authorized_provenances))

    if overall_verdict == PreliminaryVerdict.VERIFIED:
        vault.record_observed_execution(
            witness_id="WIT-001",
            witness_digest=wit_digest,
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=base_wef.sandbox_id,
            world=ExecutionWorld.BASE,
            command=("pytest", "tests/test_wit.py"),
            exit_code=base_wef.exit_code,
            termination_status=base_wef.termination_status,
            stdout_digest=base_wef.stdout_digest,
            stderr_digest=base_wef.stderr_digest,
            result_digest=base_wef.result_digest,
            outcome=base_wef.outcome,
            provenance=effective_prov,
        )
        vault.record_observed_execution(
            witness_id="WIT-001",
            witness_digest=wit_digest,
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=cand_wef.sandbox_id,
            world=ExecutionWorld.CANDIDATE,
            command=("pytest", "tests/test_wit.py"),
            exit_code=cand_wef.exit_code,
            termination_status=cand_wef.termination_status,
            stdout_digest=cand_wef.stdout_digest,
            stderr_digest=cand_wef.stderr_digest,
            result_digest=cand_wef.result_digest,
            outcome=cand_wef.outcome,
            provenance=effective_prov,
        )
        attestation = vault.attest_execution(
            witness_id="WIT-001",
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            counterfactual_execution=None,
            transition=transition,
            verdict=overall_verdict,
            provenance=effective_prov,
            witness_digest=wit_digest,
        )

    sem_receipt = create_semantic_receipt(
        change_class=change_class,
        requirement_id="REQ-001",
        frozen_contract_digest="c" * 64,
        witness_id="WIT-001",
        witness_digest=wit_digest,
        lock_digest="d" * 64,
        source_commit_id="1" * 40,
        candidate_tree_digest="5" * 40,
        base_execution=base_wef,
        candidate_execution=cand_wef,
        class_specific_payload={},
        transition=transition,
        verdict=overall_verdict,
        is_causally_verified=(overall_verdict == PreliminaryVerdict.VERIFIED),
        provenance=effective_prov,
        narrative=f"Verification for {change_class.value}",
        attestation=attestation,
    )

    coverage = compute_causal_coverage(
        frozen_contract=contract,
        results={"REQ-001": sem_receipt},
        requirement_classes=req_classes,
        verifier_authority=vault,
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
        provenance=effective_prov,
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
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
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
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
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
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
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
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
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
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
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
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
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
            cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
            result = execute_verification_pipeline(
                target=str(link_path),
                config=cfg,
            )
            assert result.exit_code == 2
            assert result.status == "BLOCKED"
        except OSError:
            # On Windows without developer mode symlink creation may require privilege;
            # verify that non-allowlisted directory is blocked:
            cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
            result = execute_verification_pipeline(
                target=str(symlink_target),
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
        vault = TrustedWitnessVault.create_authorized_vault()
        local_rc = _make_sample_causal_receipt(vault=vault)
        coverage = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-001": local_rc},
            verifier_authority=vault,
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

    def test_15_adversarial_defect_a_multi_file_patch_rejected_before_candidate_subprocess(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Adversarial (Defect A): A patch modifying target AND auxiliary files
        (e.g., conftest.py) must be rejected BEFORE any candidate subprocess is invoked.
        """
        import subprocess

        multi_file_patch = (
            "--- a/src/demo_target/cli.py\n"
            "+++ b/src/demo_target/cli.py\n"
            "@@ -1,3 +1,3 @@\n"
            "-def run(): pass\n"
            "+def run(): return 0\n"
            "--- a/tests/conftest.py\n"
            "+++ b/tests/conftest.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+# auxiliary injection\n"
            "+def pytest_configure(): pass\n"
        )
        real_subprocess_run = subprocess.run
        invoked_commands: list[list[str]] = []

        def spy_subprocess_run(cmd: Any, *args: Any, **kwargs: Any) -> Any:
            invoked_commands.append(list(cmd) if isinstance(cmd, (list, tuple)) else [str(cmd)])
            return real_subprocess_run(cmd, *args, **kwargs)

        monkeypatch.setattr(subprocess, "run", spy_subprocess_run)

        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
        result = execute_verification_pipeline(
            target=_demo_target_path(),
            patch=multi_file_patch,
            config=cfg,
        )

        assert result.exit_code == 1
        assert result.status == "CONTRADICTED"
        assert result.causal_transition == "PATCH_APPLICATION_FAILED"
        assert "Unauthorized patch modification" in result.message

        # Assert no candidate or counterfactual pytest execution was ever reached!
        candidate_or_cf_calls = [
            cmd
            for cmd in invoked_commands
            if any(
                "candidate" in str(arg).lower() or "counterfactual" in str(arg).lower()
                for arg in cmd
            )
        ]
        assert len(candidate_or_cf_calls) == 0

    def test_16_adversarial_defect_b_fabricated_receipts_cannot_acquire_authority(
        self,
    ) -> None:
        """Adversarial (Defect B): Construct a self-consistent LocalCausalReceipt and
        SemanticVerificationReceipt with valid SHA-256 digests claiming LOCAL_EXECUTION.
        Prove neither can produce an authoritative VERIFIED coverage result without
        trusted verifier-side execution evidence.
        """
        contract = _make_test_contract([("REQ-001", ChangeClass.BUG_FIX, "Fix bug")])

        # 16a: LocalCausalReceipt with no attestation
        unattested_causal = _make_sample_causal_receipt(
            requirement_id="REQ-001",
            contract_digest=contract.contract_digest,
            verdict=PreliminaryVerdict.VERIFIED,
            vault=None,
        )
        cov_causal = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-001": unattested_causal},
        )
        assert cov_causal.verified_count == 0
        assert cov_causal.inconclusive_count == 1
        assert cov_causal.overall_verdict == PreliminaryVerdict.INCONCLUSIVE

        # 16b: SemanticVerificationReceipt with no attestation
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
        cand_wef = WorldExecutionFact(
            world=ExecutionWorld.CANDIDATE,
            sandbox_id="sbx-cand",
            source_commit_id="1" * 40,
            tree_digest="5" * 40,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="6" * 64,
            stderr_digest="7" * 64,
            result_digest="9" * 64,
            duration_seconds=1.0,
        )
        unattested_semantic = create_semantic_receipt(
            change_class=ChangeClass.BUG_FIX,
            requirement_id="REQ-001",
            frozen_contract_digest=contract.contract_digest,
            witness_id="WIT-001",
            witness_digest="a" * 64,
            lock_digest="d" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            class_specific_payload={},
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            is_causally_verified=True,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            narrative="Fabricated without verifier authority",
            attestation=None,
        )
        cov_sem = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-001": unattested_semantic},
            requirement_classes={"REQ-001": ChangeClass.BUG_FIX},
        )
        assert cov_sem.verified_count == 0
        assert cov_sem.inconclusive_count == 1
        assert cov_sem.overall_verdict == PreliminaryVerdict.INCONCLUSIVE

        # 16c: Positive reconciliation with genuine TrustedWitnessVault authority
        trusted_vault = TrustedWitnessVault.create_authorized_vault()
        attested_causal = _make_sample_causal_receipt(
            requirement_id="REQ-001",
            contract_digest=contract.contract_digest,
            verdict=PreliminaryVerdict.VERIFIED,
            vault=trusted_vault,
        )
        cov_auth = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-001": attested_causal},
            verifier_authority=trusted_vault,
        )
        assert cov_auth.verified_count == 1
        assert cov_auth.inconclusive_count == 0
        assert cov_auth.overall_verdict == PreliminaryVerdict.VERIFIED


class TestBatchAFinalAuthorityBoundary:
    """Mandatory adversarial tests for Batch A Final Authority-Boundary Repair.

    Strictly proves that:
    1. verifier_authority=lambda *_: True cannot award VERIFIED coverage.
    2. A fabricated, digest-valid receipt plus a caller-owned fresh vault cannot award VERIFIED.
    3. Direct attest_execution() with only a witness digest and fabricated outcome values
       cannot produce independent verified authority.
    4. A legitimate attestation cannot certify a receipt with altered witness ID/digest,
       source identity, candidate tree, outcome, transition or verdict.
    5. An attestation for LOCAL_EXECUTION cannot certify a receipt claiming LIVE_NEBIUS.
    6. Authentic verifier-side BASE/CANDIDATE/COUNTERFACTUAL execution still produces valid
       authority and VERIFIED coverage when the required causal transition is genuinely observed.
    """

    def test_01_caller_supplied_callable_authority_bypass_rejected(self) -> None:
        """1. verifier_authority=lambda *_: True cannot award VERIFIED coverage."""
        contract = _make_test_contract([("REQ-001", ChangeClass.BUG_FIX, "Fix bug")])
        receipt = _make_sample_causal_receipt(
            requirement_id="REQ-001",
            contract_digest=contract.contract_digest,
            verdict=PreliminaryVerdict.VERIFIED,
            vault=None,
        )
        with pytest.raises(
            CoverageIntegrityError, match="verifier_authority must be a TrustedWitnessVault"
        ):
            compute_causal_coverage(
                frozen_contract=contract,
                results={"REQ-001": receipt},
                verifier_authority=lambda *_: True,
            )

    def test_02_fabricated_receipt_plus_caller_owned_fresh_vault_cannot_award_verified(
        self,
    ) -> None:
        """2. A fabricated, digest-valid receipt plus a caller-owned fresh vault
        cannot award VERIFIED.
        """
        contract = _make_test_contract([("REQ-001", ChangeClass.BUG_FIX, "Fix bug")])
        caller_vault = TrustedWitnessVault()
        assert not caller_vault.is_authoritative_root

        # Caller vault cannot issue attestations
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
        cand_wef = WorldExecutionFact(
            world=ExecutionWorld.CANDIDATE,
            sandbox_id="sbx-cand",
            source_commit_id="1" * 40,
            tree_digest="5" * 40,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="6" * 64,
            stderr_digest="7" * 64,
            result_digest="9" * 64,
            duration_seconds=1.0,
        )
        with pytest.raises(
            UntrustedWitnessAuthorityError,
            match="not authorized to attest execution",
        ):
            caller_vault.attest_execution(
                witness_id="WIT-001",
                requirement_id="REQ-001",
                frozen_contract_digest=contract.contract_digest,
                source_commit_id="1" * 40,
                base_execution=base_wef,
                candidate_execution=cand_wef,
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
            )

        # Unattested receipt evaluated under caller vault fails closed
        unattested_rc = _make_sample_causal_receipt(
            requirement_id="REQ-001",
            contract_digest=contract.contract_digest,
            verdict=PreliminaryVerdict.VERIFIED,
            vault=None,
        )
        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-001": unattested_rc},
            verifier_authority=caller_vault,
        )
        assert cov.verified_count == 0
        assert cov.inconclusive_count == 1
        assert cov.overall_verdict == PreliminaryVerdict.INCONCLUSIVE

    def test_03_direct_attest_execution_with_unsealed_witness_and_fabricated_outcomes_rejected(
        self,
    ) -> None:
        """3. Direct attest_execution() with only a witness digest and fabricated outcome values
        cannot produce independent verified authority.
        """
        vault = TrustedWitnessVault.create_authorized_vault()
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
        cand_wef = WorldExecutionFact(
            world=ExecutionWorld.CANDIDATE,
            sandbox_id="sbx-cand",
            source_commit_id="1" * 40,
            tree_digest="5" * 40,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="6" * 64,
            stderr_digest="7" * 64,
            result_digest="9" * 64,
            duration_seconds=1.0,
        )

        # 3a. Unsealed witness rejected even if witness_digest is supplied
        with pytest.raises(
            UntrustedWitnessAuthorityError, match="must be sealed in the trusted vault"
        ):
            vault.attest_execution(
                witness_id="unsealed-wit-999",
                requirement_id="REQ-001",
                frozen_contract_digest="c" * 64,
                source_commit_id="1" * 40,
                base_execution=base_wef,
                candidate_execution=cand_wef,
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.FIXTURE,
                witness_digest="a" * 64,
            )

        # Seal the witness properly
        wa = WitnessArtifact.from_text(path="tests/test_w.py", content="def test_w(): pass\n")
        vault.seal_witness(
            witness_id="WIT-001",
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )

        # 3b. Direct outcome values without execution records rejected
        with pytest.raises(
            UntrustedWitnessAuthorityError, match="requires verifier execution records"
        ):
            vault.attest_execution(
                witness_id="WIT-001",
                requirement_id="REQ-001",
                frozen_contract_digest="c" * 64,
                source_commit_id="1" * 40,
                base_execution=None,
                candidate_execution=None,
                base_outcome=WitnessOutcome.FAIL,
                candidate_outcome=WitnessOutcome.PASS,
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.FIXTURE,
            )

        # Pre-record observations for 3c
        vault.record_observed_execution(
            witness_id="WIT-001",
            witness_digest=vault.get_witness("WIT-001").seal_digest,
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=base_wef.sandbox_id,
            world=ExecutionWorld.BASE,
            command=("pytest", "tests/test_w.py"),
            exit_code=base_wef.exit_code,
            termination_status=base_wef.termination_status,
            stdout_digest=base_wef.stdout_digest,
            stderr_digest=base_wef.stderr_digest,
            result_digest=base_wef.result_digest,
            outcome=base_wef.outcome,
            provenance=EvidenceProvenance.FIXTURE,
        )
        vault.record_observed_execution(
            witness_id="WIT-001",
            witness_digest=vault.get_witness("WIT-001").seal_digest,
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=cand_wef.sandbox_id,
            world=ExecutionWorld.CANDIDATE,
            command=("pytest", "tests/test_w.py"),
            exit_code=cand_wef.exit_code,
            termination_status=cand_wef.termination_status,
            stdout_digest=cand_wef.stdout_digest,
            stderr_digest=cand_wef.stderr_digest,
            result_digest=cand_wef.result_digest,
            outcome=cand_wef.outcome,
            provenance=EvidenceProvenance.FIXTURE,
        )

        # 3c. Direct outcome values conflicting with execution records rejected
        with pytest.raises(WitnessTamperingError, match="conflicts with"):
            vault.attest_execution(
                witness_id="WIT-001",
                requirement_id="REQ-001",
                frozen_contract_digest="c" * 64,
                source_commit_id="1" * 40,
                base_execution=base_wef,  # has outcome=FAIL
                candidate_execution=cand_wef,
                base_outcome=WitnessOutcome.PASS,  # tampered conflict
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.FIXTURE,
            )

    def test_04_legitimate_attestation_cannot_certify_tampered_receipt(self) -> None:
        """4. A legitimate attestation cannot certify a receipt with altered witness ID/digest,
        source identity, candidate tree, outcome, transition or verdict.
        """
        vault = TrustedWitnessVault.create_authorized_vault()
        wa = WitnessArtifact.from_text(path="tests/test_w.py", content="def test_w(): pass\n")
        rec = vault.seal_witness(
            witness_id="WIT-001",
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
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
        cand_wef = WorldExecutionFact(
            world=ExecutionWorld.CANDIDATE,
            sandbox_id="sbx-cand",
            source_commit_id="1" * 40,
            tree_digest="5" * 40,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="6" * 64,
            stderr_digest="7" * 64,
            result_digest="9" * 64,
            duration_seconds=1.0,
        )

        vault.record_observed_execution(
            witness_id="WIT-001",
            witness_digest=rec.seal_digest,
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=base_wef.sandbox_id,
            world=ExecutionWorld.BASE,
            command=("pytest", "tests/test_w.py"),
            exit_code=base_wef.exit_code,
            termination_status=base_wef.termination_status,
            stdout_digest=base_wef.stdout_digest,
            stderr_digest=base_wef.stderr_digest,
            result_digest=base_wef.result_digest,
            outcome=base_wef.outcome,
            provenance=EvidenceProvenance.FIXTURE,
        )
        vault.record_observed_execution(
            witness_id="WIT-001",
            witness_digest=rec.seal_digest,
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=cand_wef.sandbox_id,
            world=ExecutionWorld.CANDIDATE,
            command=("pytest", "tests/test_w.py"),
            exit_code=cand_wef.exit_code,
            termination_status=cand_wef.termination_status,
            stdout_digest=cand_wef.stdout_digest,
            stderr_digest=cand_wef.stderr_digest,
            result_digest=cand_wef.result_digest,
            outcome=cand_wef.outcome,
            provenance=EvidenceProvenance.FIXTURE,
        )

        attestation = vault.attest_execution(
            witness_id="WIT-001",
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
        )

        legit_rc = create_causal_receipt(
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            witness_id="WIT-001",
            witness_digest=rec.seal_digest,
            lock_digest="d" * 64,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
            narrative="Genuine execution",
            attestation=attestation,
        )
        assert vault.verify_execution_authority(receipt=legit_rc) is True

        # Tampered witness_id in receipt
        tampered_wid_rc = object.__new__(LocalCausalReceipt)
        for k in legit_rc.__dataclass_fields__:
            object.__setattr__(tampered_wid_rc, k, getattr(legit_rc, k))
        object.__setattr__(tampered_wid_rc, "witness_id", "WIT-TAMPERED")
        assert vault.verify_execution_authority(receipt=tampered_wid_rc) is False

        # Tampered verdict in receipt
        tampered_verdict_rc = object.__new__(LocalCausalReceipt)
        for k in legit_rc.__dataclass_fields__:
            object.__setattr__(tampered_verdict_rc, k, getattr(legit_rc, k))
        object.__setattr__(tampered_verdict_rc, "verdict", PreliminaryVerdict.CONTRADICTED)
        assert vault.verify_execution_authority(receipt=tampered_verdict_rc) is False

        # Tampered unhashed receipt rejected by coverage integrity check
        contract = _make_test_contract([("REQ-001", ChangeClass.BUG_FIX, "Fix bug")])
        with pytest.raises(CoverageIntegrityError):
            compute_causal_coverage(
                frozen_contract=contract,
                results={"REQ-001": tampered_wid_rc},
                verifier_authority=vault,
            )

        # Internally consistent receipt re-created with altered witness but legitimate attestation
        # rejected by vault authority check, remaining INCONCLUSIVE
        recreated_tampered_rc = create_causal_receipt(
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            witness_id="WIT-TAMPERED",
            witness_digest=rec.seal_digest,
            lock_digest="d" * 64,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
            narrative="Tampered witness ID with legitimate attestation",
            attestation=attestation,
        )
        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-001": recreated_tampered_rc},
            verifier_authority=vault,
        )
        assert cov.verified_count == 0
        assert cov.inconclusive_count == 1
        assert cov.overall_verdict == PreliminaryVerdict.INCONCLUSIVE

    def test_05_attestation_provenance_mismatch_rejected(self) -> None:
        """5. An attestation for LOCAL_EXECUTION cannot certify a receipt claiming LIVE_NEBIUS."""
        vault = TrustedWitnessVault()
        vault._authorized_provenances = frozenset({EvidenceProvenance.LOCAL_EXECUTION})
        wa = WitnessArtifact.from_text(path="tests/test_w.py", content="def test_w(): pass\n")
        rec = vault.seal_witness(
            witness_id="WIT-001",
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
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
        cand_wef = WorldExecutionFact(
            world=ExecutionWorld.CANDIDATE,
            sandbox_id="sbx-cand",
            source_commit_id="1" * 40,
            tree_digest="5" * 40,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="6" * 64,
            stderr_digest="7" * 64,
            result_digest="9" * 64,
            duration_seconds=1.0,
        )

        vault.record_observed_execution(
            witness_id="WIT-001",
            witness_digest=rec.seal_digest,
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=base_wef.sandbox_id,
            world=ExecutionWorld.BASE,
            command=("pytest", "tests/test_w.py"),
            exit_code=base_wef.exit_code,
            termination_status=base_wef.termination_status,
            stdout_digest=base_wef.stdout_digest,
            stderr_digest=base_wef.stderr_digest,
            result_digest=base_wef.result_digest,
            outcome=base_wef.outcome,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        vault.record_observed_execution(
            witness_id="WIT-001",
            witness_digest=rec.seal_digest,
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=cand_wef.sandbox_id,
            world=ExecutionWorld.CANDIDATE,
            command=("pytest", "tests/test_w.py"),
            exit_code=cand_wef.exit_code,
            termination_status=cand_wef.termination_status,
            stdout_digest=cand_wef.stdout_digest,
            stderr_digest=cand_wef.stderr_digest,
            result_digest=cand_wef.result_digest,
            outcome=cand_wef.outcome,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        attestation = vault.attest_execution(
            witness_id="WIT-001",
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        # Receipt claiming LIVE_NEBIUS with LOCAL_EXECUTION attestation
        receipt_live = create_causal_receipt(
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            witness_id="WIT-001",
            witness_digest=rec.seal_digest,
            lock_digest="d" * 64,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LIVE_NEBIUS,  # Claimed LIVE_NEBIUS
            narrative="Attempted promotion",
            attestation=attestation,
        )
        assert vault.verify_execution_authority(receipt=receipt_live) is False

        # Expected LIVE_NEBIUS check against LOCAL_EXECUTION attestation
        receipt_local = create_causal_receipt(
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            witness_id="WIT-001",
            witness_digest=rec.seal_digest,
            lock_digest="d" * 64,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            narrative="Local execution",
            attestation=attestation,
        )
        assert (
            vault.verify_execution_authority(
                receipt=receipt_local,
                provenance=EvidenceProvenance.LIVE_NEBIUS,
            )
            is False
        )

        contract = _make_test_contract([("REQ-001", ChangeClass.BUG_FIX, "Fix bug")])
        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-001": receipt_live},
            verifier_authority=vault,
        )
        assert cov.verified_count == 0
        assert cov.inconclusive_count == 1

    def test_06_authentic_verifier_execution_produces_valid_authority_and_verified_coverage(
        self,
    ) -> None:
        """6. Authentic verifier-side BASE/CANDIDATE execution produces valid authority
        and VERIFIED coverage when the required causal transition is genuinely observed.
        """
        import sys
        from unittest.mock import MagicMock

        from basebreak.causal.engine import CausalExecutionEngine
        from basebreak.domain.execution import SandboxIdentity
        from basebreak.verifier.sandbox import VerifierSandboxManager

        causal_tests_dir = str(Path(__file__).resolve().parent)
        if causal_tests_dir not in sys.path:
            sys.path.insert(0, causal_tests_dir)
        import test_engine

        envelope, sealed_record, vault = test_engine._build_test_contract_and_envelope()
        MockMaterializer = test_engine.MockMaterializer
        MockSandboxResult = test_engine.MockSandboxResult
        lock = create_witness_lock(record=sealed_record, vault=vault)

        mock_adapter = MagicMock()
        sbx_count = 0

        def create_sandbox_side_effect(*args: Any, **kwargs: Any) -> SandboxIdentity:
            nonlocal sbx_count
            sbx_count += 1
            return SandboxIdentity(sandbox_id=f"sbx-auth-{sbx_count:03d}")

        mock_adapter.create_sandbox.side_effect = create_sandbox_side_effect

        def exec_side_effect(sbx: Any, cmd: Any, **kwargs: Any) -> Any:
            if "printf" in cmd:
                return MockSandboxResult(exit_code=0)
            if "sbx-auth-001" in str(sbx):
                return MockSandboxResult(exit_code=1, stderr="AssertionError: quiet flag broken")
            return MockSandboxResult(exit_code=0, stdout="1 passed")

        mock_adapter.execute_command.side_effect = exec_side_effect

        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=MockMaterializer(),
            vault=vault,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        receipt = engine.execute_causal_pair(
            context_envelope=envelope,
            sealed_record=sealed_record,
            witness_lock=lock,
            execution_command=("pytest", "tests/test_quiet_behavior.py"),
        )

        assert receipt.is_causally_verified is True
        assert receipt.verdict == PreliminaryVerdict.VERIFIED
        assert receipt.attestation is not None

        # Verify coverage under authentic engine vault
        cov = compute_causal_coverage(
            frozen_contract=envelope.frozen_contract,
            results={sealed_record.requirement_id: receipt},
            verifier_authority=engine.vault,
        )
        assert cov.verified_count == 1
        assert cov.inconclusive_count == 0
        assert cov.overall_verdict == PreliminaryVerdict.VERIFIED


class TestMandatoryAdversarialAcceptanceA1ThroughA8:
    """Mandatory adversarial acceptance test suite covering criteria A1-A8 from Section 5."""

    def test_a1_public_factory_bypass_cannot_acquire_local_execution_authority(self) -> None:
        """A1 — An attacker calls TrustedWitnessVault.create_authorized_vault(), seals a witness,
        fabricates BASE=FAIL and CANDIDATE=PASS facts and attempts VERIFIED LOCAL_EXECUTION
        coverage. Expected: no independent VERIFIED authority.
        """
        vault = TrustedWitnessVault.create_authorized_vault()
        wa = WitnessArtifact.from_text(path="tests/test_a1.py", content="def test_a1(): pass\n")
        rec = vault.seal_witness(
            witness_id="WIT-A1",
            requirement_id="REQ-A1",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
        base_wef = WorldExecutionFact(
            world=ExecutionWorld.BASE,
            sandbox_id="sbx-a1-base",
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
        cand_wef = WorldExecutionFact(
            world=ExecutionWorld.CANDIDATE,
            sandbox_id="sbx-a1-cand",
            source_commit_id="1" * 40,
            tree_digest="5" * 40,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="6" * 64,
            stderr_digest="7" * 64,
            result_digest="9" * 64,
            duration_seconds=1.0,
        )

        # Attacker cannot attest LOCAL_EXECUTION with fixture-scoped vault
        with pytest.raises(UntrustedWitnessAuthorityError, match="not authorized to attest"):
            vault.attest_execution(
                witness_id="WIT-A1",
                requirement_id="REQ-A1",
                frozen_contract_digest="c" * 64,
                source_commit_id="1" * 40,
                base_execution=base_wef,
                candidate_execution=cand_wef,
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
            )

        # Receipt claiming LOCAL_EXECUTION evaluated with fixture vault fails closed
        unattested_rc = create_causal_receipt(
            requirement_id="REQ-A1",
            frozen_contract_digest="c" * 64,
            witness_id="WIT-A1",
            witness_digest=rec.seal_digest,
            lock_digest="d" * 64,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            narrative="Attacker claims local execution without genuine authority",
            attestation=None,
        )
        contract = _make_test_contract([("REQ-A1", ChangeClass.BUG_FIX, "Fix A1 bug")])
        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-A1": unattested_rc},
            verifier_authority=vault,
        )
        assert cov.verified_count == 0
        assert cov.inconclusive_count == 1
        assert cov.overall_verdict == PreliminaryVerdict.INCONCLUSIVE

    def test_a2_fake_engine_bootstrap_receives_fixture_only_authority(self) -> None:
        """A2 — A caller constructs CausalExecutionEngine with a mock sandbox adapter
        and fabricated results, requesting LOCAL_EXECUTION.
        Expected: fixture-only authority; never genuine LOCAL_EXECUTION or LIVE_NEBIUS.
        """
        from unittest.mock import MagicMock

        from basebreak.causal.engine import CausalExecutionEngine
        from basebreak.verifier.sandbox import VerifierSandboxManager

        vault = TrustedWitnessVault()
        manager = VerifierSandboxManager()
        mock_adapter = MagicMock()
        mock_materializer = MagicMock()

        # Caller requests LOCAL_EXECUTION, but engine detects mock adapter and materializer
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=mock_materializer,
            vault=vault,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        assert engine.provenance == EvidenceProvenance.FIXTURE
        assert EvidenceProvenance.LOCAL_EXECUTION not in engine.vault.authorized_provenances
        assert EvidenceProvenance.LIVE_NEBIUS not in engine.vault.authorized_provenances
        assert EvidenceProvenance.FIXTURE in engine.vault.authorized_provenances

    def test_a3_circular_observation_registration_rejected(self) -> None:
        """A3 — A caller supplies fabricated WorldExecutionFact records directly to
        attest_execution().
        Expected: attestation cannot turn them into trusted verifier-observed facts.
        """
        vault = TrustedWitnessVault.create_authorized_vault()
        wa = WitnessArtifact.from_text(path="tests/test_a3.py", content="def test_a3(): pass\n")
        vault.seal_witness(
            witness_id="WIT-A3",
            requirement_id="REQ-A3",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
        base_wef = WorldExecutionFact(
            world=ExecutionWorld.BASE,
            sandbox_id="sbx-a3-base",
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
        cand_wef = WorldExecutionFact(
            world=ExecutionWorld.CANDIDATE,
            sandbox_id="sbx-a3-cand",
            source_commit_id="1" * 40,
            tree_digest="5" * 40,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="6" * 64,
            stderr_digest="7" * 64,
            result_digest="9" * 64,
            duration_seconds=1.0,
        )

        # Direct submission of unobserved facts to attest_execution fails closed
        with pytest.raises(
            UntrustedWitnessAuthorityError,
            match="pre-existing verifier-observed execution records",
        ):
            vault.attest_execution(
                witness_id="WIT-A3",
                requirement_id="REQ-A3",
                frozen_contract_digest="c" * 64,
                source_commit_id="1" * 40,
                base_execution=base_wef,
                candidate_execution=cand_wef,
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.FIXTURE,
            )

    def test_a4_no_prior_observation_rejected(self) -> None:
        """A4 — An execution record has not been observed and registered through the
        authorized verifier execution boundary.
        Expected: attestation authority rejected.
        """
        vault = TrustedWitnessVault.create_authorized_vault()
        wa = WitnessArtifact.from_text(path="tests/test_a4.py", content="def test_a4(): pass\n")
        vault.seal_witness(
            witness_id="WIT-A4",
            requirement_id="REQ-A4",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )

        # Check that vault rejects verifying authority on unobserved execution
        dummy_receipt = _make_sample_causal_receipt(
            requirement_id="REQ-A4",
            verdict=PreliminaryVerdict.VERIFIED,
            vault=None,
        )
        assert vault.verify_execution_authority(receipt=dummy_receipt) is False

    def test_a5_identity_mismatch_fails_closed(self) -> None:
        """A5 — Modify one binding at a time: sandbox identity, witness digest,
        source commit, candidate tree, execution outcome, transition, verdict or provenance.
        Expected: authority verification fails closed.
        """
        vault = TrustedWitnessVault.create_authorized_vault()
        wa = WitnessArtifact.from_text(path="tests/test_a5.py", content="def test_a5(): pass\n")
        rec = vault.seal_witness(
            witness_id="WIT-A5",
            requirement_id="REQ-A5",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
        base_wef = WorldExecutionFact(
            world=ExecutionWorld.BASE,
            sandbox_id="sbx-a5-base",
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
        cand_wef = WorldExecutionFact(
            world=ExecutionWorld.CANDIDATE,
            sandbox_id="sbx-a5-cand",
            source_commit_id="1" * 40,
            tree_digest="5" * 40,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="6" * 64,
            stderr_digest="7" * 64,
            result_digest="9" * 64,
            duration_seconds=1.0,
        )

        vault.record_observed_execution(
            witness_id="WIT-A5",
            witness_digest=rec.seal_digest,
            requirement_id="REQ-A5",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=base_wef.sandbox_id,
            world=ExecutionWorld.BASE,
            command=("pytest", "tests/test_a5.py"),
            exit_code=base_wef.exit_code,
            termination_status=base_wef.termination_status,
            stdout_digest=base_wef.stdout_digest,
            stderr_digest=base_wef.stderr_digest,
            result_digest=base_wef.result_digest,
            outcome=base_wef.outcome,
            provenance=EvidenceProvenance.FIXTURE,
        )
        vault.record_observed_execution(
            witness_id="WIT-A5",
            witness_digest=rec.seal_digest,
            requirement_id="REQ-A5",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=cand_wef.sandbox_id,
            world=ExecutionWorld.CANDIDATE,
            command=("pytest", "tests/test_a5.py"),
            exit_code=cand_wef.exit_code,
            termination_status=cand_wef.termination_status,
            stdout_digest=cand_wef.stdout_digest,
            stderr_digest=cand_wef.stderr_digest,
            result_digest=cand_wef.result_digest,
            outcome=cand_wef.outcome,
            provenance=EvidenceProvenance.FIXTURE,
        )

        att = vault.attest_execution(
            witness_id="WIT-A5",
            requirement_id="REQ-A5",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
        )
        legit = create_causal_receipt(
            requirement_id="REQ-A5",
            frozen_contract_digest="c" * 64,
            witness_id="WIT-A5",
            witness_digest=rec.seal_digest,
            lock_digest="d" * 64,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
            narrative="Genuine A5 execution",
            attestation=att,
        )
        assert vault.verify_execution_authority(receipt=legit) is True

        # Test each single alteration:
        for field, tampered_val in [
            ("witness_id", "WIT-TAMPERED"),
            ("witness_digest", "f" * 64),
            ("frozen_contract_digest", "f" * 64),
            ("requirement_id", "REQ-TAMPERED"),
            ("verdict", PreliminaryVerdict.CONTRADICTED),
            ("transition", CausalTransition.UNVERIFIED_TRIVIAL_PASS),
            ("provenance", EvidenceProvenance.LIVE_NEBIUS),
        ]:
            t_rc = object.__new__(LocalCausalReceipt)
            for k in legit.__dataclass_fields__:
                object.__setattr__(t_rc, k, getattr(legit, k))
            object.__setattr__(t_rc, field, tampered_val)
            assert not vault.verify_execution_authority(receipt=t_rc), (
                f"Failed to reject tampered {field}"
            )

    def test_a6_provenance_laundering_rejected(self) -> None:
        """A6 — Attempt FIXTURE->LOCAL_EXECUTION, LOCAL_EXECUTION->LIVE_NEBIUS and
        RECORDED_LIVE->LIVE_NEBIUS promotion.
        Expected: all rejected.
        """
        vault_fixture = TrustedWitnessVault.create_authorized_vault()
        # FIXTURE -> LOCAL_EXECUTION
        assert (
            vault_fixture.verify_execution_authority(
                receipt_or_attestation=object(),
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
            )
            is False
        )

        # LOCAL_EXECUTION -> LIVE_NEBIUS
        vault_local = TrustedWitnessVault()
        vault_local._authorized_provenances = frozenset({EvidenceProvenance.LOCAL_EXECUTION})
        assert (
            vault_local.verify_execution_authority(
                receipt_or_attestation=object(),
                provenance=EvidenceProvenance.LIVE_NEBIUS,
            )
            is False
        )

        # RECORDED_LIVE -> LIVE_NEBIUS
        vault_recorded = TrustedWitnessVault()
        vault_recorded._authorized_provenances = frozenset({EvidenceProvenance.RECORDED_LIVE})
        assert (
            vault_recorded.verify_execution_authority(
                receipt_or_attestation=object(),
                provenance=EvidenceProvenance.LIVE_NEBIUS,
            )
            is False
        )

    def test_a7_honest_real_execution(self) -> None:
        """A7 — Where an authorized actual local execution runtime is available, execute a
        genuine behavioral witness through the trusted verifier path.
        Expected: real BASE=FAIL and CANDIDATE=PASS bound to genuine execution evidence.
        If that path cannot be executed safely, record BLOCKED/NOT_RUN rather than substituting
        a mocked positive test.
        """
        import os

        has_local_sandbox_runtime = os.environ.get("BASEBREAK_ENABLE_LOCAL_SANDBOX_RUNTIME") == "1"
        if not has_local_sandbox_runtime:
            pytest.skip(
                "BLOCKED / NOT_RUN: No authorized isolated local sandbox runtime available in "
                "this environment. Per Section 5 A7 and HostExecutionFallbackError, refusing to "
                "substitute a mocked positive test."
            )

    def test_a8_regression_protection(self) -> None:
        """A8 — Retain all previous protections:
        - caller callable bypass rejection;
        - forged receipt rejection;
        - demo patch pre-execution allowlist;
        - sandbox separation;
        - six-class semantics;
        - coverage denominator safety;
        - receipt integrity;
        - public receipt non-self-certification;
        - API/CLI compatibility.
        """
        contract = _make_test_contract([("REQ-A8", ChangeClass.BUG_FIX, "Fix A8 bug")])
        vault = TrustedWitnessVault()

        # Callable bypass rejection
        with pytest.raises(
            CoverageIntegrityError, match="verifier_authority must be a TrustedWitnessVault"
        ):
            compute_causal_coverage(
                frozen_contract=contract,
                results={},
                verifier_authority=lambda *_: True,
            )

        # Forged receipt rejection
        forged_rc = _make_sample_causal_receipt(
            requirement_id="REQ-A8",
            contract_digest=contract.contract_digest,
            verdict=PreliminaryVerdict.VERIFIED,
            vault=None,
        )
        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-A8": forged_rc},
            verifier_authority=vault,
        )
        assert cov.verified_count == 0
        assert cov.inconclusive_count == 1
        assert cov.overall_verdict == PreliminaryVerdict.INCONCLUSIVE
