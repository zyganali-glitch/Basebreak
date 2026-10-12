"""Tests for Phase P-22: Judge & Operator UI.

P-22.01: Single-screen causal story before implementation
P-22.02: Task/contract and live execution timeline
P-22.03: BASE/CANDIDATE/COUNTERFACTUAL comparison
P-22.04: Requirement -> witness -> causal-slice map
P-22.05: Receipt/provenance/NOT_RUN inspection
P-22.06: Responsive judge mode with no fake animations/data
"""

from __future__ import annotations

import urllib.request
from collections.abc import Generator
from pathlib import Path

import pytest

from basebreak.api.auth import ApiAuthManager
from basebreak.api.server import BasebreakApiServer
from basebreak.api.store import ApiRunStore
from basebreak.causal.coverage import compute_causal_coverage
from basebreak.causal.public_receipt import (
    PublicExecutionFact,
    PublicVerificationReceipt,
    PublicWitnessFact,
    create_public_verification_receipt,
)
from basebreak.causal.receipt import WorldExecutionFact, create_causal_receipt
from basebreak.causal.reconciliation import CausalTransition
from basebreak.cli.main import main
from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.compiler.semantics import CertaintyLevel
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.ui.renderer import render_judge_ui_html
from basebreak.verifier.witness_result import WitnessOutcome
from basebreak.verifier.witness_store import TrustedWitnessVault, WitnessArtifact


def _build_sample_receipt() -> PublicVerificationReceipt:
    req = FrozenRequirement(
        requirement_id="REQ-AUTH-01",
        statement="Enforce token validation",
        citation="token validation",
        citation_start=0,
        citation_end=16,
        rationale="Fix auth bug",
    )
    contract = object.__new__(FrozenContract)
    object.__setattr__(contract, "schema_version", "1.0.0")
    object.__setattr__(contract, "task_digest", "f" * 64)
    object.__setattr__(contract, "change_class", ChangeClass.BUG_FIX)
    object.__setattr__(contract, "certainty", CertaintyLevel.CONFIDENT)
    object.__setattr__(contract, "requirements", (req,))
    object.__setattr__(contract, "contract_digest", "c" * 64)

    base_wef = WorldExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="sbx-base-123",
        source_commit_id="1" * 40,
        tree_digest="2" * 40,
        outcome=WitnessOutcome.FAIL,
        exit_code=1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="3" * 64,
        stderr_digest="4" * 64,
        result_digest="8" * 64,
        duration_seconds=2.5,
    )
    cand_wef = WorldExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="sbx-cand-456",
        source_commit_id="1" * 40,
        tree_digest="5" * 40,
        outcome=WitnessOutcome.PASS,
        exit_code=0,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="6" * 64,
        stderr_digest="7" * 64,
        result_digest="9" * 64,
        duration_seconds=1.8,
    )
    vault = TrustedWitnessVault.create_authorized_vault()
    wa = WitnessArtifact.from_text(
        path="tests/test_auth_witness.py",
        content="def test_auth(): assert True\n",
    )
    rec = vault.seal_witness(
        witness_id="WIT-001",
        requirement_id="REQ-AUTH-01",
        frozen_contract_digest="c" * 64,
        source_commit_id="1" * 40,
        artifacts=[wa],
    )
    vault.record_observed_execution(
        witness_id="WIT-001",
        witness_digest=rec.seal_digest,
        requirement_id="REQ-AUTH-01",
        frozen_contract_digest="c" * 64,
        source_commit_id="1" * 40,
        candidate_tree_digest="5" * 40,
        sandbox_id=base_wef.sandbox_id,
        world=ExecutionWorld.BASE,
        command=("pytest", "tests/test_auth_witness.py"),
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
        requirement_id="REQ-AUTH-01",
        frozen_contract_digest="c" * 64,
        source_commit_id="1" * 40,
        candidate_tree_digest="5" * 40,
        sandbox_id=cand_wef.sandbox_id,
        world=ExecutionWorld.CANDIDATE,
        command=("pytest", "tests/test_auth_witness.py"),
        exit_code=cand_wef.exit_code,
        termination_status=cand_wef.termination_status,
        stdout_digest=cand_wef.stdout_digest,
        stderr_digest=cand_wef.stderr_digest,
        result_digest=cand_wef.result_digest,
        outcome=cand_wef.outcome,
        provenance=EvidenceProvenance.FIXTURE,
    )
    attestation = vault.attest_execution(
        requirement_id="REQ-AUTH-01",
        frozen_contract_digest="c" * 64,
        witness_id="WIT-001",
        source_commit_id="1" * 40,
        candidate_tree_digest="5" * 40,
        base_execution=base_wef,
        candidate_execution=cand_wef,
        counterfactual_execution=None,
        transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
        verdict=PreliminaryVerdict.VERIFIED,
        provenance=EvidenceProvenance.FIXTURE,
    )
    local_receipt = create_causal_receipt(
        requirement_id="REQ-AUTH-01",
        frozen_contract_digest="c" * 64,
        witness_id="WIT-001",
        witness_digest=rec.seal_digest,
        lock_digest="d" * 64,
        base_execution=base_wef,
        candidate_execution=cand_wef,
        transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
        verdict=PreliminaryVerdict.VERIFIED,
        provenance=EvidenceProvenance.FIXTURE,
        narrative="Base failed, candidate passed",
        attestation=attestation,
    )
    coverage = compute_causal_coverage(
        frozen_contract=contract,
        results={"REQ-AUTH-01": local_receipt},
        verifier_authority=vault,
    )
    witness = PublicWitnessFact(
        witness_id="WIT-001",
        witness_digest=rec.seal_digest,
        requirement_id="REQ-AUTH-01",
        execution_command=("pytest", "tests/witness.py"),
        timeout_seconds=20.0,
    )
    base_exec = PublicExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="sbx-base-123",
        source_commit_id="1" * 40,
        tree_digest="2" * 40,
        outcome=WitnessOutcome.FAIL,
        exit_code=1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="3" * 64,
        stderr_digest="4" * 64,
        duration_seconds=2.5,
    )
    cand_exec = PublicExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="sbx-cand-456",
        source_commit_id="1" * 40,
        tree_digest="5" * 40,
        outcome=WitnessOutcome.PASS,
        exit_code=0,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="6" * 64,
        stderr_digest="7" * 64,
        duration_seconds=1.8,
    )
    return create_public_verification_receipt(
        frozen_contract_digest="c" * 64,
        task_id="TASK-AUTH-FIX",
        repo_locator="https://github.com/example/auth-service.git",
        source_commit_id="1" * 40,
        candidate_tree_digest="5" * 40,
        candidate_patch_digest="b" * 64,
        coverage_summary=coverage,
        executions=(base_exec, cand_exec),
        witnesses=(witness,),
        overall_verdict=PreliminaryVerdict.VERIFIED,
        provenance=EvidenceProvenance.FIXTURE,
        runtime_identities=("sbx-base-123", "sbx-cand-456"),
    )


@pytest.fixture
def sample_receipt() -> PublicVerificationReceipt:
    """Authentic sample public verification receipt from P-18 test suite."""
    return _build_sample_receipt()


class TestJudgeUiRenderer:
    """P-22.01 through P-22.05 unit tests for UI model and HTML rendering."""

    def test_p22_01_single_screen_causal_story_prominent(
        self, sample_receipt: PublicVerificationReceipt
    ) -> None:
        """P-22.01: Header prominently features the thesis and verdict badge."""
        html_doc = render_judge_ui_html(sample_receipt)

        # Central claim must be prominent
        assert "“If the patch matters, the base must break.”" in html_doc
        assert "BASEBREAK VERIFICATION RUNTIME" in html_doc
        assert "VERIFIED" in html_doc
        assert "badge-verified" in html_doc

    def test_p22_02_execution_timeline_has_factual_stages(
        self, sample_receipt: PublicVerificationReceipt
    ) -> None:
        """P-22.02: Execution stage timeline contains factual stages with no fake progress."""
        html_doc = render_judge_ui_html(sample_receipt)

        assert "Execution Stage Timeline" in html_doc
        assert "1. Task Ingestion &amp; Invariant Lock" in html_doc
        assert "2. Contract Compilation" in html_doc
        assert "3. Builder Execution Boundary" in html_doc
        assert "4. Sealed Witness Generation" in html_doc
        assert "5. Causal Two-World Engine" in html_doc
        assert "6. Counterfactual Third Run" in html_doc
        assert "7. Minimal Causal Slice" in html_doc
        assert "8. Public Receipt Issuance &amp; Integrity" in html_doc
        # No simulated progress spinners or fake animations
        assert "progress-bar" not in html_doc
        assert "fake-spinner" not in html_doc

    def test_p22_03_three_world_behavioral_comparison(
        self, sample_receipt: PublicVerificationReceipt
    ) -> None:
        """P-22.03: BASE, CANDIDATE, and COUNTERFACTUAL worlds are compared."""
        html_doc = render_judge_ui_html(sample_receipt)

        assert "Three-World Causal Verification" in html_doc
        assert "1. Base (Clean Source)" in html_doc
        assert "2. Candidate (With Patch)" in html_doc
        assert "3. Counterfactual (Delta Subtracted)" in html_doc
        assert "BASE=FAIL -&gt; CANDIDATE=PASS" in html_doc

    def test_p22_04_requirement_witness_slice_map(
        self, sample_receipt: PublicVerificationReceipt
    ) -> None:
        """P-22.04: Requirement -> witness -> causal slice map is displayed."""
        html_doc = render_judge_ui_html(sample_receipt)

        assert "Requirement &rarr; Sealed Witness &rarr; Causal-Slice Map" in html_doc
        assert "REQ-AUTH-01" in html_doc
        assert "WIT-001" in html_doc

    def test_p22_05_receipt_provenance_and_not_run_inspection(
        self, sample_receipt: PublicVerificationReceipt
    ) -> None:
        """P-22.05: Public receipt facts, provenance, and honest NOT_RUN inspection."""
        html_doc = render_judge_ui_html(sample_receipt)

        assert "Receipt Digest:" in html_doc
        assert "AUTHENTIC (SHA-256 Verified)" in html_doc
        assert "FIXTURE" in html_doc
        assert "badge-fixture" in html_doc

    def test_p22_05_tampered_receipt_detection_in_ui(
        self, sample_receipt: PublicVerificationReceipt
    ) -> None:
        """Adversarial: Tampered receipt displays TAMPERED / INVALID in UI."""
        tampered_dict = sample_receipt.to_dict()
        tampered_dict["candidate_tree_digest"] = "f" * 40  # Mutate fact
        html_doc = render_judge_ui_html(tampered_dict)

        assert "TAMPERED / INVALID" in html_doc
        assert "badge-invalid" in html_doc


class TestJudgeUiIntegration:
    """P-22.06: Responsive judge mode via API server and CLI."""

    @pytest.fixture
    def server_with_receipt(
        self, tmp_path: Path, sample_receipt: PublicVerificationReceipt
    ) -> Generator[tuple[BasebreakApiServer, str, str], None, None]:
        runs_dir = tmp_path / "runs"
        store = ApiRunStore(runs_dir=runs_dir)
        run_id = "test-run-p22"

        # Persist run metadata and receipt
        store.persistence.save_run(
            run_id=run_id,
            metadata={
                "run_id": run_id,
                "status": "VERIFIED",
                "exit_code": 0,
                "target": "https://github.com/example/auth-service.git",
            },
            receipt=sample_receipt.to_dict(),
        )
        store.recover_from_disk()

        auth = ApiAuthManager()  # Read-only inspection allowed
        server = BasebreakApiServer(store=store, auth=auth, host="127.0.0.1", port=0)
        server.start()
        try:
            yield server, server.base_url, run_id
        finally:
            server.stop()

    def test_p22_06_server_serves_judge_ui(
        self, server_with_receipt: tuple[BasebreakApiServer, str, str]
    ) -> None:
        """P-22.06: API server serves judge dashboard at /judge and /judge/{run_id}."""
        _, base_url, run_id = server_with_receipt

        # 1. GET /judge
        with urllib.request.urlopen(f"{base_url}/judge") as resp:
            assert resp.status == 200
            assert "text/html" in resp.headers.get("Content-Type", "")
            body = resp.read().decode("utf-8")
            assert "BASEBREAK VERIFICATION RUNTIME" in body
            assert run_id in body

        # 2. GET /judge/{run_id}
        with urllib.request.urlopen(f"{base_url}/judge/{run_id}") as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "AUTHENTIC (SHA-256 Verified)" in body

    def test_p22_06_cli_ui_export(
        self, tmp_path: Path, sample_receipt: PublicVerificationReceipt
    ) -> None:
        """P-22.06: CLI command `basebreak ui <run_id> --output <file>` generates valid HTML."""
        runs_dir = tmp_path / "runs"
        store = ApiRunStore(runs_dir=runs_dir)
        run_id = "test-cli-run-ui"

        store.persistence.save_run(
            run_id=run_id,
            metadata={
                "run_id": run_id,
                "status": "VERIFIED",
                "exit_code": 0,
            },
            receipt=sample_receipt.to_dict(),
        )

        out_html = tmp_path / "judge_view.html"
        exit_code = main(["--runs-dir", str(runs_dir), "ui", run_id, "--output", str(out_html)])

        assert exit_code == 0
        assert out_html.is_file()
        content = out_html.read_text(encoding="utf-8")
        assert "“If the patch matters, the base must break.”" in content
        assert "FIXTURE" in content
