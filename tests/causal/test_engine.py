"""Unit tests for CausalExecutionEngine (P-10.01 through P-10.05)."""

from __future__ import annotations

import hashlib
from typing import Any
from unittest.mock import MagicMock

import pytest

from basebreak.causal.engine import (
    CausalBindingError,
    CausalExecutionEngine,
)
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
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.context import VerifierContextEnvelope
from basebreak.verifier.sandbox import VerifierSandboxManager
from basebreak.verifier.witness_lock import create_witness_lock
from basebreak.verifier.witness_result import WitnessOutcome
from basebreak.verifier.witness_store import (
    SealedWitnessRecord,
    TrustedWitnessVault,
    WitnessArtifact,
)


def _build_test_contract_and_envelope() -> tuple[
    VerifierContextEnvelope, SealedWitnessRecord, TrustedWitnessVault
]:
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
    approval = session.approve()
    contract = freeze_review_result(approval)
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

    vault = TrustedWitnessVault(vault_secret=b"test-secret-key-for-vault-auth")
    wa = WitnessArtifact.from_text(
        path="tests/test_quiet_behavior.py",
        content="def test_quiet():\n    val = 1\n    assert val == 1\n",
    )
    sealed_record = vault.seal_witness(
        witness_id="wit-quiet-001",
        requirement_id=req_id,
        frozen_contract_digest=contract.contract_digest,
        source_commit_id="c" * 40,
        artifacts=[wa],
    )
    return envelope, sealed_record, vault


class MockSandboxResult:
    def __init__(
        self, exit_code: int, stdout: str = "", stderr: str = "", duration: float = 0.5
    ) -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_seconds = duration
        self.is_timed_out = False
        self.is_cancelled = False
        self.is_failed_to_start = False


class MockMaterializer:
    def __init__(self, candidate_tree: str = "2" * 40) -> None:
        self.candidate_tree = candidate_tree

    def materialize_repository(self, *args: Any, **kwargs: Any) -> dict[str, object]:
        world = kwargs.get("world", ExecutionWorld.BASE)
        tree = "1" * 40 if world == ExecutionWorld.BASE else self.candidate_tree
        return {
            "resolved_commit_sha": "c" * 40,
            "resolved_tree_sha": tree,
            "workspace_path": "/verifier_workspace",
            "is_verified": True,
        }


class TestCausalExecutionEngine:
    """Validates two-world execution, cryptographic binding, and outcome reconciliation."""

    def test_p10_01_through_p10_04_successful_bug_fix_verification(self) -> None:
        """P-10.01-04: BASE=FAIL (exit 1), CANDIDATE=PASS (exit 0) produces verified receipt."""
        envelope, sealed_record, vault = _build_test_contract_and_envelope()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        # Mock adapter
        mock_adapter = MagicMock()
        # Returns distinct sandbox IDs for base and candidate
        sbx_count = 0

        def create_sandbox_side_effect(*args: Any, **kwargs: Any) -> SandboxIdentity:
            nonlocal sbx_count
            sbx_count += 1
            return SandboxIdentity(sandbox_id=f"sbx-fresh-{sbx_count:03d}")

        mock_adapter.create_sandbox.side_effect = create_sandbox_side_effect

        # deploy exit 0; test command: exit 1 on base, exit 0 on candidate
        cmd_count = 0

        def exec_side_effect(sbx: Any, cmd: Any, **kwargs: Any) -> MockSandboxResult:
            nonlocal cmd_count
            cmd_count += 1
            # Deploy script
            if "printf" in cmd:
                return MockSandboxResult(exit_code=0)
            # Test command
            if "sbx-fresh-001" in str(sbx):
                return MockSandboxResult(exit_code=1, stderr="AssertionError: stdout not empty")
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
        assert receipt.transition == CausalTransition.CAUSAL_BUG_FIX_VERIFIED
        assert receipt.base_execution.sandbox_id == "sbx-fresh-001"
        assert receipt.candidate_execution.sandbox_id == "sbx-fresh-002"
        assert receipt.base_execution.outcome == WitnessOutcome.FAIL
        assert receipt.candidate_execution.outcome == WitnessOutcome.PASS
        # Verify teardown was called for both sandboxes
        assert mock_adapter.teardown_sandbox.call_count == 2

    def test_p10_05_trivial_pass_reconciled(self) -> None:
        """P-10.05: BASE=PASS and CANDIDATE=PASS yields UNVERIFIED_TRIVIAL_PASS."""
        envelope, sealed_record, vault = _build_test_contract_and_envelope()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        mock_adapter = MagicMock()
        sbx_count = 0

        def create_sandbox_side_effect(*args: Any, **kwargs: Any) -> SandboxIdentity:
            nonlocal sbx_count
            sbx_count += 1
            return SandboxIdentity(sandbox_id=f"sbx-pass-{sbx_count:03d}")

        mock_adapter.create_sandbox.side_effect = create_sandbox_side_effect
        mock_adapter.execute_command.return_value = MockSandboxResult(
            exit_code=0, stdout="1 passed"
        )

        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=MockMaterializer(),
            vault=vault,
        )

        receipt = engine.execute_causal_pair(
            context_envelope=envelope,
            sealed_record=sealed_record,
            witness_lock=lock,
            execution_command=("pytest", "tests/test_quiet_behavior.py"),
        )

        assert receipt.is_causally_verified is False
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.transition == CausalTransition.UNVERIFIED_TRIVIAL_PASS

    def test_adversarial_lock_binding_mismatch_fails_closed(self) -> None:
        """Witness lock bound to different contract fails closed before execution."""
        envelope, sealed_record, vault = _build_test_contract_and_envelope()

        # Create lock with wrong contract digest
        forged_lock = MagicMock()
        forged_lock.witness_digest = sealed_record.seal_digest
        forged_lock.frozen_contract_digest = "f" * 64  # Wrong digest
        forged_lock.source_commit_id = "c" * 40
        forged_lock.requirement_id = sealed_record.requirement_id

        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=MagicMock(),
            materializer=MagicMock(),
            vault=vault,
        )

        with pytest.raises((CausalBindingError, Exception)):
            engine.execute_causal_pair(
                context_envelope=envelope,
                sealed_record=sealed_record,
                witness_lock=forged_lock,
                execution_command=("pytest", "tests/test_quiet_behavior.py"),
            )

    def test_adversarial_sandbox_id_collision_detected(self) -> None:
        """If adapter reuses the same sandbox ID for both worlds, integrity failure is triggered."""
        envelope, sealed_record, vault = _build_test_contract_and_envelope()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        mock_adapter = MagicMock()
        # Same sandbox ID reused for both worlds!
        mock_adapter.create_sandbox.return_value = SandboxIdentity(
            sandbox_id="sbx-reused-collision"
        )
        mock_adapter.execute_command.return_value = MockSandboxResult(exit_code=0)

        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=MockMaterializer(),
            vault=vault,
        )

        receipt = engine.execute_causal_pair(
            context_envelope=envelope,
            sealed_record=sealed_record,
            witness_lock=lock,
            execution_command=("pytest", "tests/test_quiet_behavior.py"),
        )

        assert receipt.is_causally_verified is False
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.transition == CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE
        assert "reused the same sandbox identity" in receipt.narrative

    def test_adversarial_empty_candidate_patch_detected(self) -> None:
        """If candidate tree equals base tree, integrity failure is triggered."""
        envelope, sealed_record, vault = _build_test_contract_and_envelope()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        # Empty candidate envelope where candidate_tree_digest matches base tree
        empty_envelope = VerifierContextEnvelope.create(
            frozen_contract=envelope.frozen_contract,
            source_identity=envelope.source_identity,
            candidate_identity=CandidateIdentity(
                candidate_id="cand-empty",
                source=envelope.source_identity,
                patch_digest=hashlib.sha256(b"").hexdigest(),
            ),
            candidate_patch_text="",
            candidate_tree_digest="1" * 40,
        )

        mock_adapter = MagicMock()
        sbx_count = 0

        def create_sandbox_side_effect(*args: Any, **kwargs: Any) -> SandboxIdentity:
            nonlocal sbx_count
            sbx_count += 1
            return SandboxIdentity(sandbox_id=f"sbx-fresh-{sbx_count:03d}")

        mock_adapter.create_sandbox.side_effect = create_sandbox_side_effect
        mock_adapter.execute_command.return_value = MockSandboxResult(exit_code=0)

        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=MockMaterializer(candidate_tree="1" * 40),
            vault=vault,
        )

        receipt = engine.execute_causal_pair(
            context_envelope=empty_envelope,
            sealed_record=sealed_record,
            witness_lock=lock,
            execution_command=("pytest", "tests/test_quiet_behavior.py"),
        )

        assert receipt.is_causally_verified is False
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.transition == CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE
        assert "empty patch" in receipt.narrative
