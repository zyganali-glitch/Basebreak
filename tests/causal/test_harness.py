"""Unit tests for developer integration harness and proof summary formatter (P-10.07)."""

from __future__ import annotations

import hashlib
from typing import Any
from unittest.mock import MagicMock

from basebreak.causal.harness import (
    BASEBREAK_JUDGE_CLAIM,
    BASEBREAK_THESIS,
    format_judge_proof_summary,
    render_judge_proof_markdown,
    run_causal_verification_slice,
)
from basebreak.causal.receipt import LocalCausalReceipt, WorldExecutionFact, create_causal_receipt
from basebreak.causal.reconciliation import CausalTransition
from basebreak.compiler.freeze import freeze_review_result
from basebreak.compiler.ingestion import ingest_task
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.review import ReviewBundle, ReviewSession
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeClass,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
)
from basebreak.domain.causal import CandidateIdentity, ExecutionWorld
from basebreak.domain.execution import SandboxIdentity, TerminationStatus
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.context import VerifierContextEnvelope
from basebreak.verifier.sandbox import VerifierSandboxManager
from basebreak.verifier.witness_plan import ValidatedWitnessArtifact, ValidatedWitnessPlan
from basebreak.verifier.witness_result import WitnessOutcome
from basebreak.verifier.witness_store import TrustedWitnessVault


def _build_test_receipt() -> LocalCausalReceipt:
    base_fact = WorldExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="sbx-base-101",
        source_commit_id="c" * 40,
        tree_digest="1" * 40,
        outcome=WitnessOutcome.FAIL,
        exit_code=1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="b" * 64,
        stderr_digest="c" * 64,
        result_digest="d" * 64,
        duration_seconds=1.5,
    )
    cand_fact = WorldExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="sbx-cand-102",
        source_commit_id="c" * 40,
        tree_digest="2" * 40,
        outcome=WitnessOutcome.PASS,
        exit_code=0,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="e" * 64,
        stderr_digest="f" * 64,
        result_digest="0" * 64,
        duration_seconds=1.2,
    )
    return create_causal_receipt(
        requirement_id="REQ-QUIET-001",
        frozen_contract_digest="f" * 64,
        witness_id="wit-quiet-001",
        witness_digest="a" * 64,
        lock_digest="b" * 64,
        base_execution=base_fact,
        candidate_execution=cand_fact,
        transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
        verdict=PreliminaryVerdict.VERIFIED,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
        narrative="Base broke, candidate passed. Causal BUG_FIX verified.",
    )


class TestCausalHarness:
    """Validates proof summary formatting, markdown rendering, and slice execution."""

    def test_format_judge_proof_summary_structure(self) -> None:
        """Machine-readable summary contains thesis, verdict, and full cryptographic chain."""
        receipt = _build_test_receipt()
        summary = format_judge_proof_summary(receipt)

        assert summary["causal_thesis"] == BASEBREAK_THESIS
        assert summary["judge_claim"] == BASEBREAK_JUDGE_CLAIM
        assert summary["preliminary_verdict"] == "VERIFIED"
        assert summary["is_causally_verified"] is True
        assert summary["causal_transition"] == "CAUSAL_BUG_FIX_VERIFIED"
        assert summary["evidence_provenance"] == "LOCAL_EXECUTION"

        chain = summary["cryptographic_digest_chain"]
        assert chain["requirement_id"] == "REQ-QUIET-001"
        assert chain["frozen_contract_digest"] == "f" * 64
        assert chain["witness_digest"] == "a" * 64
        assert chain["lock_digest"] == "b" * 64
        assert chain["base_execution_digest"] == "d" * 64
        assert chain["candidate_execution_digest"] == "0" * 64
        assert chain["receipt_digest"] == receipt.receipt_digest

        facts = summary["two_world_execution_facts"]
        assert facts["base"]["outcome"] == "FAIL"
        assert facts["base"]["exit_code"] == 1
        assert facts["candidate"]["outcome"] == "PASS"
        assert facts["candidate"]["exit_code"] == 0

    def test_render_judge_proof_markdown_content(self) -> None:
        """Human-readable markdown contains thesis, ascii transition diagram, and digest table."""
        receipt = _build_test_receipt()
        summary = format_judge_proof_summary(receipt)
        md = render_judge_proof_markdown(summary)

        assert "# Basebreak Causal Verification Proof Summary" in md
        assert BASEBREAK_THESIS in md
        assert "BASE WORLD      [Outcome: FAIL]" in md
        assert "CANDIDATE WORLD [Outcome: PASS]" in md
        assert "CAUSAL TRANSITION: CAUSAL_BUG_FIX_VERIFIED" in md
        assert "REQ-QUIET-001" in md
        assert receipt.receipt_digest in md
        assert "## Verification Identity" not in md

    def test_render_judge_proof_markdown_with_implementation_sha(self) -> None:
        """Markdown prominently records full verbatim Basebreak implementation SHA when supplied."""
        receipt = _build_test_receipt()
        summary = format_judge_proof_summary(receipt)
        full_sha = "1e7c1c564ade556f834e9145846f78133a9ec508"
        summary["basebreak_implementation_sha"] = full_sha

        md = render_judge_proof_markdown(summary)
        assert "## Verification Identity" in md
        assert f"- **Basebreak Implementation SHA:** `{full_sha}`" in md
        assert full_sha in md

    def test_render_judge_proof_markdown_omits_implementation_sha_safely(self) -> None:
        """Markdown rendering succeeds without error when implementation SHA is omitted."""
        receipt = _build_test_receipt()
        summary = format_judge_proof_summary(receipt)
        assert "basebreak_implementation_sha" not in summary

        md = render_judge_proof_markdown(summary)
        assert "## Verification Identity" not in md
        assert "Basebreak Implementation SHA" not in md

    def test_run_causal_verification_slice_end_to_end(self) -> None:
        """Integration harness executes full slice from validated plan to proof summary."""
        raw_text = "When user specifies --quiet flag, stdout must be empty."
        task = ingest_task(raw_text)
        fact = DeterministicClassificationFact(
            inferred_class=ChangeClass.BUG_FIX,
            certainty=CertaintyLevel.CONFIDENT,
            confidence=1.0,
            alternative_classes=(),
            rationale="Fixes verbose leak when quiet flag is set",
            evidence_citations=("quiet flag",),
            matched_signals=("quiet", "bug"),
        )
        semantics = ChangeSemanticsClassification(
            task_digest=task.task_digest,
            change_class=ChangeClass.BUG_FIX,
            certainty=CertaintyLevel.CONFIDENT,
            confidence=1.0,
            alternative_classes=(),
            rationale="Fixes verbose leak when quiet flag is set",
            evidence_citations=("quiet flag",),
            deterministic_facts=fact,
        )
        cit = "When user specifies --quiet flag, stdout must be empty."
        start = task.normalized_text.index(cit)
        end = start + len(cit)
        req = ProposedRequirement(
            statement="Stdout must be empty when --quiet flag is active",
            citation=cit,
            citation_start=start,
            citation_end=end,
            rationale="Mandated quiet flag behavior",
        )
        bundle = ReviewBundle(
            task=task,
            semantics=semantics,
            requirements=(req,),
        )
        session = ReviewSession(bundle)
        contract = freeze_review_result(session.approve())
        req_id = contract.requirements[0].requirement_id

        source_id = SourceIdentity(
            locator="https://github.com/zyganali-glitch/Basebreak.git",
            revision=CommitRevision("c" * 40),
        )
        patch_text = "--- a/src/cli.py\n+++ b/src/cli.py\n@@ -1 +1 @@\n-print('hello')\n+pass\n"
        patch_digest = hashlib.sha256(patch_text.encode("utf-8")).hexdigest()
        cand_id = CandidateIdentity(
            candidate_id="cand-001",
            source=source_id,
            patch_digest=patch_digest,
        )
        envelope = VerifierContextEnvelope.create(
            frozen_contract=contract,
            source_identity=source_id,
            candidate_identity=cand_id,
            candidate_patch_text=patch_text,
            candidate_tree_digest="2" * 40,
        )

        test_code = "def test_quiet():\n    val = 1\n    assert val == 1\n"
        test_digest = hashlib.sha256(test_code.encode("utf-8")).hexdigest()
        art = ValidatedWitnessArtifact(
            path="tests/test_quiet_behavior.py",
            content=test_code,
            content_digest=test_digest,
            byte_size=len(test_code.encode("utf-8")),
            rationale="Test quiet flag",
        )
        plan = ValidatedWitnessPlan(
            witness_id="wit-quiet-001",
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            source_commit_id="c" * 40,
            change_class=ChangeClass.BUG_FIX,
            plan_summary="Test quiet flag",
            target_files=("src/cli.py",),
            artifacts=(art,),
            execution_command=("pytest", "tests/test_quiet_behavior.py"),
            expected_failure_at_base="Fails on base",
            expected_success_at_candidate="Passes on candidate",
            plan_digest="d" * 64,
        )

        vault = TrustedWitnessVault(vault_secret=b"test-secret-key-vault")
        manager = VerifierSandboxManager()

        mock_adapter = MagicMock()
        sbx_count = 0

        def create_sbx(*args: Any, **kwargs: Any) -> SandboxIdentity:
            nonlocal sbx_count
            sbx_count += 1
            return SandboxIdentity(sandbox_id=f"sbx-slice-{sbx_count:03d}")

        mock_adapter.create_sandbox.side_effect = create_sbx

        class MockRes:
            def __init__(self, exit_code: int, stdout: str = "", stderr: str = "") -> None:
                self.exit_code = exit_code
                self.stdout = stdout
                self.stderr = stderr
                self.duration_seconds = 0.5
                self.is_timed_out = False
                self.is_cancelled = False
                self.is_failed_to_start = False

        def exec_cmd(sbx: Any, cmd: Any, **kwargs: Any) -> MockRes:
            if "printf" in cmd:
                return MockRes(exit_code=0)
            if "sbx-slice-001" in str(sbx):
                return MockRes(exit_code=1, stderr="AssertionError: stdout not empty")
            return MockRes(exit_code=0, stdout="1 passed")

        mock_adapter.execute_command.side_effect = exec_cmd

        class MockMaterializer:
            def materialize_repository(self, *args: Any, **kwargs: Any) -> dict[str, object]:
                world = kwargs.get("world", ExecutionWorld.BASE)
                tree = "1" * 40 if world == ExecutionWorld.BASE else "2" * 40
                return {
                    "resolved_commit_sha": "c" * 40,
                    "resolved_tree_sha": tree,
                    "workspace_path": "/verifier_workspace",
                    "is_verified": True,
                }

        receipt, summary_dict, md = run_causal_verification_slice(
            context_envelope=envelope,
            validated_plan=plan,
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=MockMaterializer(),
            vault=vault,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        assert receipt.is_causally_verified is True
        assert summary_dict["preliminary_verdict"] == "VERIFIED"
        assert "[PASS] VERIFIED" in md
