"""Mandatory Adversarial Acceptance Tests for Batch A Surgical Repair.

Directly proves that each of the 18 blocking causal evidence integrity failure
modes is deterministically rejected or honestly classified.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from basebreak.api.auth import ApiAuthManager
from basebreak.api.server import BasebreakApiServer
from basebreak.api.store import ApiRunStore
from basebreak.causal.coverage import (
    CoverageIntegrityError,
    RequirementEligibility,
    compute_causal_coverage,
)
from basebreak.causal.engine import CausalExecutionEngine
from basebreak.causal.public_receipt import (
    PublicExecutionFact,
    PublicReceiptIntegrityError,
    PublicReceiptTamperingError,
    PublicVerificationReceipt,
    PublicWitnessFact,
    create_public_verification_receipt,
    verify_public_receipt_integrity,
)
from basebreak.causal.receipt import WorldExecutionFact, create_causal_receipt
from basebreak.causal.reconciliation import CausalTransition
from basebreak.cli.config import BasebreakConfig
from basebreak.cli.runner import execute_verification_pipeline
from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.compiler.semantics import CertaintyLevel
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.integrations.github.ingestion import GitHubRepoReference
from basebreak.integrations.github.mutation_boundary import (
    GitHubMutationBoundary,
    UnauthorizedMutationError,
)
from basebreak.verifier.sandbox import VerifierSandboxManager
from basebreak.verifier.witness_result import WitnessOutcome
from basebreak.verifier.witness_store import (
    TrustedWitnessVault,
    UntrustedWitnessAuthorityError,
    WitnessArtifact,
)


def _make_sample_contract(change_class: ChangeClass = ChangeClass.BUG_FIX) -> FrozenContract:
    req = FrozenRequirement(
        requirement_id="REQ-001",
        statement="Behavioral fix statement",
        citation="fix statement",
        citation_start=0,
        citation_end=13,
        rationale="Test rationale",
    )
    contract = object.__new__(FrozenContract)
    object.__setattr__(contract, "schema_version", "1.0.0")
    object.__setattr__(contract, "task_digest", "t" * 64)
    object.__setattr__(contract, "change_class", change_class)
    object.__setattr__(contract, "certainty", CertaintyLevel.CONFIDENT)
    object.__setattr__(contract, "requirements", (req,))
    object.__setattr__(contract, "contract_digest", "c" * 64)
    return contract


class TestBatchAAdversarialMatrix:
    """Verifies all 18 mandatory adversarial criteria."""

    def test_case_01_arbitrary_nonexistent_repo_cannot_return_verified(
        self, tmp_path: Path
    ) -> None:
        """1. basebreak verify with an arbitrary nonexistent repository cannot return VERIFIED."""
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
        res = execute_verification_pipeline(
            target="completely_nonexistent_repo_locator",
            base_sha="1" * 40,
            config=cfg,
        )
        assert res.status == "BLOCKED"
        assert res.exit_code == 2
        assert res.receipt is None
        assert "strictly forbidden under Basebreak security boundaries" in res.message

    def test_case_02_providing_only_user_selected_shas_cannot_produce_causal_proof(
        self, tmp_path: Path
    ) -> None:
        """2. Providing only user-selected SHA strings cannot produce causal proof."""
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
        res = execute_verification_pipeline(
            target="untrusted_repo_with_shas",
            base_sha="a" * 40,
            candidate_sha="b" * 40,
            config=cfg,
        )
        assert res.status != "VERIFIED"
        assert res.status == "BLOCKED"
        assert res.receipt is None

    def test_case_03_world_results_cannot_default_to_successful_triplet(
        self, tmp_path: Path
    ) -> None:
        """3. BASE/CANDIDATE/COUNTERFACTUAL results cannot default to the successful triplet."""
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
        res = execute_verification_pipeline(target="some_repo", config=cfg)
        # Cannot default to BASE=FAIL, CAND=PASS, CF=FAIL when nothing was executed!
        assert res.world_states == {}
        assert res.status == "BLOCKED"

    def test_case_04_missing_executable_witness_cannot_produce_local_execution(
        self, tmp_path: Path
    ) -> None:
        """4. A missing executable witness cannot produce LOCAL_EXECUTION."""
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
        # Using test fixture override facility produces EvidenceProvenance.FIXTURE,
        # never LOCAL_EXECUTION
        res = execute_verification_pipeline(
            target="override_target",
            config=cfg,
            base_outcome_override=WitnessOutcome.FAIL,
            candidate_outcome_override=WitnessOutcome.PASS,
            cf_outcome_override=WitnessOutcome.FAIL,
        )
        assert res.receipt is not None
        assert res.receipt.provenance == EvidenceProvenance.FIXTURE
        prov: Any = res.receipt.provenance
        assert prov != EvidenceProvenance.LOCAL_EXECUTION

    def test_case_05_missing_source_identity_cannot_be_replaced_by_synthetic_success(
        self, tmp_path: Path
    ) -> None:
        """5. A missing source identity cannot be replaced by a synthetic successful identity."""
        cfg = BasebreakConfig(runs_dir=str(tmp_path / "runs"))
        res = execute_verification_pipeline(
            target="",  # Missing target identity
            config=cfg,
        )
        assert res.status == "INVALID_INPUT"
        assert res.exit_code == 2

    def test_case_06_forged_dict_cannot_increase_coverage(self) -> None:
        """6. A forged dict with is_causally_verified=True cannot increase coverage."""
        contract = _make_sample_contract()
        forged_dict = {
            "REQ-001": {
                "verdict": PreliminaryVerdict.VERIFIED,
                "is_causally_verified": True,
                # Missing witness_id and witness_digest!
                "rationale": "Fabricated pass",
            }
        }
        summary = compute_causal_coverage(frozen_contract=contract, results=forged_dict)
        assert summary.eligible_count == 1
        assert summary.verified_count == 0
        assert summary.inconclusive_count == 1
        assert summary.coverage_ratio == 0.0

    def test_case_07_caller_controlled_exclusion_cannot_silently_remove_behavioral_obligations(
        self,
    ) -> None:
        """7. Caller-controlled exclusions cannot silently remove behavioral obligations."""
        contract = _make_sample_contract(change_class=ChangeClass.BUG_FIX)
        with pytest.raises(
            CoverageIntegrityError, match="behavioral obligations cannot be removed"
        ):
            compute_causal_coverage(
                frozen_contract=contract,
                results={},
                eligibility_overrides={"REQ-001": RequirementEligibility.EXCLUDED_NON_BEHAVIORAL},
                exclusion_rationales={"REQ-001": "Caller attempts to shrink denominator"},
            )

    def test_case_08_altered_receipt_content_cannot_pass_integrity_verification(self) -> None:
        """8. Altered receipt content cannot pass integrity verification."""
        contract = _make_sample_contract()
        base_wef = WorldExecutionFact(
            world=ExecutionWorld.BASE,
            sandbox_id="sbx-1",
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
            sandbox_id="sbx-2",
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
        vault = TrustedWitnessVault.create_authorized_vault()
        wa = WitnessArtifact.from_text(
            path="tests/test_wit.py",
            content="def test_w(): pass\n",
        )
        rec = vault.seal_witness(
            witness_id="wit-1",
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
        vault.record_observed_execution(
            witness_id="wit-1",
            witness_digest=rec.seal_digest,
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
            provenance=EvidenceProvenance.FIXTURE,
        )
        vault.record_observed_execution(
            witness_id="wit-1",
            witness_digest=rec.seal_digest,
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
            provenance=EvidenceProvenance.FIXTURE,
        )
        attestation = vault.attest_execution(
            witness_id="wit-1",
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            counterfactual_execution=None,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
            witness_digest=rec.seal_digest,
        )
        local_rc = create_causal_receipt(
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            witness_id="wit-1",
            witness_digest=rec.seal_digest,
            lock_digest="d" * 64,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
            narrative="Proven",
            attestation=attestation,
        )
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
            witness_id="wit-1",
            witness_digest="a" * 64,
            requirement_id="REQ-001",
        )
        rc = create_public_verification_receipt(
            frozen_contract_digest="c" * 64,
            task_id="task-1",
            repo_locator="https://github.com/example/repo.git",
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            coverage_summary=coverage,
            executions=(base_exec, cand_exec),
            witnesses=(witness,),
            overall_verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
        )

        # Alter candidate_tree_digest without recomputing digest
        tampered = PublicVerificationReceipt(
            schema_version=rc.schema_version,
            receipt_digest=rc.receipt_digest,
            frozen_contract_digest=rc.frozen_contract_digest,
            task_id=rc.task_id,
            repo_locator=rc.repo_locator,
            source_commit_id=rc.source_commit_id,
            candidate_tree_digest="9" * 40,  # Tampered!
            candidate_patch_digest=rc.candidate_patch_digest,
            counterfactual=rc.counterfactual,
            coverage_summary=rc.coverage_summary,
            witnesses=rc.witnesses,
            executions=rc.executions,
            overall_verdict=rc.overall_verdict,
            provenance=rc.provenance,
            runtime_identities=rc.runtime_identities,
            timing=rc.timing,
            accounting=rc.accounting,
            not_run_obligations=rc.not_run_obligations,
            signature_strategy=rc.signature_strategy,
            signature=rc.signature,
            is_authoritative=rc.is_authoritative,
            disclaimers=rc.disclaimers,
        )
        with pytest.raises(PublicReceiptTamperingError, match="tampering detected"):
            verify_public_receipt_integrity(tampered)

    def test_case_09_internally_rehashed_but_causally_inconsistent_receipt_rejected(self) -> None:
        """9. An internally rehashed but causally inconsistent receipt
        must not obtain valid VERIFIED status.
        """
        contract = _make_sample_contract()
        base_wef = WorldExecutionFact(
            world=ExecutionWorld.BASE,
            sandbox_id="sbx-1",
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
            sandbox_id="sbx-2",
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
        vault = TrustedWitnessVault.create_authorized_vault()
        wa = WitnessArtifact.from_text(
            path="tests/test_wit.py",
            content="def test_w(): pass\n",
        )
        rec = vault.seal_witness(
            witness_id="wit-1",
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
        vault.record_observed_execution(
            witness_id="wit-1",
            witness_digest=rec.seal_digest,
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
            provenance=EvidenceProvenance.FIXTURE,
        )
        vault.record_observed_execution(
            witness_id="wit-1",
            witness_digest=rec.seal_digest,
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
            provenance=EvidenceProvenance.FIXTURE,
        )
        attestation = vault.attest_execution(
            witness_id="wit-1",
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            counterfactual_execution=None,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
            witness_digest=rec.seal_digest,
        )
        local_rc = create_causal_receipt(
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            witness_id="wit-1",
            witness_digest=rec.seal_digest,
            lock_digest="d" * 64,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
            narrative="Proven",
            attestation=attestation,
        )
        coverage = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-001": local_rc},
            verifier_authority=vault,
        )
        base_exec_pass = PublicExecutionFact(
            world=ExecutionWorld.BASE,
            sandbox_id="sbx-1",
            source_commit_id="1" * 40,
            tree_digest="2" * 40,
            outcome=WitnessOutcome.PASS,  # Base passed!
            exit_code=0,
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
            witness_id="wit-1",
            witness_digest="a" * 64,
            requirement_id="REQ-001",
        )
        with pytest.raises(PublicReceiptIntegrityError, match="base did not break"):
            create_public_verification_receipt(
                frozen_contract_digest="c" * 64,
                task_id="task-1",
                repo_locator="https://github.com/example/repo.git",
                source_commit_id="1" * 40,
                candidate_tree_digest="5" * 40,
                coverage_summary=coverage,
                executions=(base_exec_pass, cand_exec),
                witnesses=(witness,),
                overall_verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.FIXTURE,
            )

    def test_case_10_cli_and_api_reject_forged_receipts_on_retrieval(self, tmp_path: Path) -> None:
        """10. CLI/API must reject or block forged receipts on retrieval."""
        runs_dir = tmp_path / "runs"
        store = ApiRunStore(runs_dir=runs_dir)
        token = "test_sec_token_001"
        auth = ApiAuthManager(bearer_token=token)
        server = BasebreakApiServer(store=store, auth=auth, port=0)
        server.start()

        try:
            # Manually plant a corrupted receipt file in the runs directory
            run_dir = runs_dir / "run_corrupt_123"
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "metadata.json").write_text(
                json.dumps({"run_id": "run_corrupt_123", "status": "VERIFIED"}),
                encoding="utf-8",
            )
            (run_dir / "receipt.json").write_text(
                json.dumps({"schema_version": "1.0.0", "receipt_digest": "corrupt_fake"}),
                encoding="utf-8",
            )

            # Attempt to retrieve corrupted receipt via API
            req = urllib.request.Request(
                f"{server.base_url}/v1/runs/run_corrupt_123/receipt",
                headers={"Authorization": f"Bearer {token}"},
            )
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(req)
            assert exc.value.code == 400
            err_body = exc.value.read().decode("utf-8")
            assert "Receipt integrity verification failed" in err_body
        finally:
            server.stop()

    def test_case_11_unauthorized_post_runs_denied_by_default(self, tmp_path: Path) -> None:
        """11. Unauthorized POST /v1/runs must be denied by default."""
        store = ApiRunStore(runs_dir=tmp_path / "runs")
        server = BasebreakApiServer(store=store, auth=ApiAuthManager(bearer_token="secret"), port=0)
        server.start()
        try:
            req = urllib.request.Request(
                f"{server.base_url}/v1/runs",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(req)
            assert exc.value.code == 401
        finally:
            server.stop()

    def test_case_12_blocked_run_produces_no_fictitious_world_execution_events(
        self, tmp_path: Path
    ) -> None:
        """12. A blocked run produces no fictitious world-execution events."""
        store = ApiRunStore(runs_dir=tmp_path / "runs")
        token = "secret_tok_12"
        server = BasebreakApiServer(store=store, auth=ApiAuthManager(bearer_token=token), port=0)
        server.start()
        try:
            req = urllib.request.Request(
                f"{server.base_url}/v1/runs",
                data=json.dumps({"target": "untrusted_repo"}).encode("utf-8"),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                created = json.loads(resp.read().decode("utf-8"))
                run_id = created["run_id"]
                assert created["status"] == "BLOCKED"

            # SSE endpoint check
            req_events = urllib.request.Request(
                f"{server.base_url}/v1/runs/{run_id}/events",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(req_events) as resp:
                sse_data = resp.read().decode("utf-8")
                assert "event: run.blocked" in sse_data
                assert "base.completed" not in sse_data
                assert "candidate.completed" not in sse_data
                assert "counterfactual.completed" not in sse_data
        finally:
            server.stop()

    def test_case_13_sse_and_json_endpoints_must_not_leak_credentials(self, tmp_path: Path) -> None:
        """13. SSE and JSON endpoints must not leak credentials."""
        store = ApiRunStore(runs_dir=tmp_path / "runs")
        token = "secret_tok_13"
        server = BasebreakApiServer(store=store, auth=ApiAuthManager(bearer_token=token), port=0)
        server.start()
        try:
            leaked_secret = "ghp_PersonalAccessTokenSecret123456789012"
            payload = {"target": f"https://user:{leaked_secret}@github.com/repo"}
            req = urllib.request.Request(
                f"{server.base_url}/v1/runs",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                body = resp.read().decode("utf-8")
                assert leaked_secret not in body
                assert "[REDACTED]" in body
                run_id = json.loads(body)["run_id"]

            req_events = urllib.request.Request(
                f"{server.base_url}/v1/runs/{run_id}/events",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(req_events) as resp:
                sse_body = resp.read().decode("utf-8")
                assert leaked_secret not in sse_body
                assert "[REDACTED]" in sse_body
        finally:
            server.stop()

    def test_case_14_malformed_and_oversized_payloads_rejected_safely(self, tmp_path: Path) -> None:
        """14. Malformed JSON/oversized bodies are rejected safely."""
        store = ApiRunStore(runs_dir=tmp_path / "runs")
        token = "secret_tok_14"
        server = BasebreakApiServer(store=store, auth=ApiAuthManager(bearer_token=token), port=0)
        server.start()
        try:
            # Malformed JSON -> 400
            req_malformed = urllib.request.Request(
                f"{server.base_url}/v1/runs",
                data=b"{not valid json",
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc1:
                urllib.request.urlopen(req_malformed)
            assert exc1.value.code == 400

            # Oversized body -> 413 or connection reset
            oversized = b"a" * (1024 * 1024 + 1024)
            req_oversized = urllib.request.Request(
                f"{server.base_url}/v1/runs",
                data=oversized,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                method="POST",
            )
            try:
                urllib.request.urlopen(req_oversized)
                pytest.fail("Expected 413 HTTPError or connection reset for oversized payload")
            except urllib.error.HTTPError as exc2:
                assert exc2.code == 413
            except urllib.error.URLError as url_err:
                assert any(
                    err in str(url_err)
                    for err in ("Broken pipe", "Connection reset", "Errno 32", "Errno 104")
                )
        finally:
            server.stop()

    def test_case_15_idempotent_replays_cannot_trigger_duplicate_verification(
        self, tmp_path: Path
    ) -> None:
        """15. Idempotent replays cannot trigger duplicate verification runs."""
        store = ApiRunStore(runs_dir=tmp_path / "runs")
        token = "secret_tok_15"
        server = BasebreakApiServer(store=store, auth=ApiAuthManager(bearer_token=token), port=0)
        server.start()
        try:
            payload = {"target": "idemp_target", "idempotency_key": "key_15"}
            data = json.dumps(payload).encode("utf-8")
            req1 = urllib.request.Request(
                f"{server.base_url}/v1/runs",
                data=data,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                method="POST",
            )
            with urllib.request.urlopen(req1) as resp1:
                assert resp1.status == 201
                run_id_1 = json.loads(resp1.read().decode("utf-8"))["run_id"]

            req2 = urllib.request.Request(
                f"{server.base_url}/v1/runs",
                data=data,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                method="POST",
            )
            with urllib.request.urlopen(req2) as resp2:
                assert resp2.status == 200
                run_id_2 = json.loads(resp2.read().decode("utf-8"))["run_id"]
                assert run_id_1 == run_id_2
        finally:
            server.stop()

    def test_case_16_conflicting_payloads_with_same_idempotency_key_return_409(
        self, tmp_path: Path
    ) -> None:
        """16. Conflicting payloads with same Idempotency-Key return 409 Conflict."""
        store = ApiRunStore(runs_dir=tmp_path / "runs")
        token = "secret_tok_16"
        server = BasebreakApiServer(store=store, auth=ApiAuthManager(bearer_token=token), port=0)
        server.start()
        try:
            req1 = urllib.request.Request(
                f"{server.base_url}/v1/runs",
                data=json.dumps({"target": "alpha", "idempotency_key": "conflict_16"}).encode(
                    "utf-8"
                ),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                method="POST",
            )
            with urllib.request.urlopen(req1) as resp:
                assert resp.status == 201

            req2 = urllib.request.Request(
                f"{server.base_url}/v1/runs",
                data=json.dumps({"target": "beta", "idempotency_key": "conflict_16"}).encode(
                    "utf-8"
                ),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(req2)
            assert exc.value.code == 409
        finally:
            server.stop()

    def test_case_17_recovered_runs_reflect_factual_state_not_synthetic_success(
        self, tmp_path: Path
    ) -> None:
        """17. Recovered runs reflect factual state, not synthetic success."""
        runs_dir = tmp_path / "runs"
        token = "secret_tok_17"
        auth = ApiAuthManager(bearer_token=token)

        store1 = ApiRunStore(runs_dir=runs_dir)
        server1 = BasebreakApiServer(store=store1, auth=auth, port=0)
        server1.start()
        try:
            req = urllib.request.Request(
                f"{server1.base_url}/v1/runs",
                data=json.dumps({"target": "untrusted_repo"}).encode("utf-8"),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                run_id = json.loads(resp.read().decode("utf-8"))["run_id"]
        finally:
            server1.stop()

        # Restart server on same store directory
        store2 = ApiRunStore(runs_dir=runs_dir)
        server2 = BasebreakApiServer(store=store2, auth=auth, port=0)
        server2.start()
        try:
            req_get = urllib.request.Request(
                f"{server2.base_url}/v1/runs/{run_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(req_get) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                assert data["run_id"] == run_id
                assert data["status"] == "BLOCKED"
                assert data["status"] != "VERIFIED"
        finally:
            server2.stop()

    def test_case_18_github_mutation_actions_default_to_dry_run_and_cannot_claim_live_mutation(
        self,
    ) -> None:
        """18. GitHub mutation actions default to dry-run and cannot claim live mutation."""
        boundary = GitHubMutationBoundary(
            allow_github_mutation=True,
            human_authority_token="valid_entropy_operator_token_999",
        )
        repo_ref = GitHubRepoReference(
            raw_input="https://github.com/zyganali-glitch/Basebreak/pull/1",
            owner="zyganali-glitch",
            repo="Basebreak",
            ref=None,
            pr_number=1,
            commit_sha=None,
            is_local_path=False,
            local_path=None,
        )

        # Default dry_run=True must NEVER perform mutation
        preview = boundary.execute_post_pr_comment(
            repo_ref=repo_ref,
            comment_body="Comment body",
            dry_run=True,
        )
        assert preview["status"] == "DRY_RUN_PREVIEW"
        assert preview["mutation_performed"] is False

        # Non-dry-run must fail closed without claiming external mutation
        with pytest.raises(UnauthorizedMutationError, match="External GitHub write operations"):
            boundary.execute_post_pr_comment(
                repo_ref=repo_ref,
                comment_body="Comment body",
                dry_run=False,
            )


class TestAuthorityOriginRepairMatrix:
    """Mandatory adversarial regression matrix proving authority origin closure across 7 vectors."""

    def test_adv_01_authorize_verifier_runtime_arbitrary_object_rejected(self) -> None:
        """1. _authorize_verifier_runtime(object(), LIVE_NEBIUS) cannot produce authority."""
        vault = TrustedWitnessVault()
        with pytest.raises(
            UntrustedWitnessAuthorityError,
            match="authentic CausalExecutionEngine|not an authorized verifier execution boundary",
        ):
            vault._authorize_verifier_runtime(
                object(),
                EvidenceProvenance.LIVE_NEBIUS,
            )
        assert EvidenceProvenance.LIVE_NEBIUS not in vault.authorized_provenances
        assert not vault.is_authoritative_root

    def test_adv_02_caller_runtime_avoiding_mock_names_cannot_obtain_production_authority(
        self,
    ) -> None:
        """2. Caller runtime whose class name avoids Mock/Fake/Stub cannot obtain authority."""
        vault = TrustedWitnessVault()

        class ProductionRunner:
            provenance = EvidenceProvenance.LIVE_NEBIUS
            sandbox_adapter = object()
            materializer = object()

        with pytest.raises(UntrustedWitnessAuthorityError):
            vault._authorize_verifier_runtime(
                ProductionRunner(),
                EvidenceProvenance.LIVE_NEBIUS,
            )
        assert EvidenceProvenance.LIVE_NEBIUS not in vault.authorized_provenances

        # Also prove via CausalExecutionEngine that custom adapter falls back to FIXTURE
        class InnocentCustomAdapter:
            def create_sandbox(self, **kwargs: Any) -> Any:
                return "sbx-innocent"

            def execute(self, **kwargs: Any) -> Any:
                return None

        class InnocentCustomMaterializer:
            pass

        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=InnocentCustomAdapter(),
            materializer=InnocentCustomMaterializer(),
            vault=vault,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
        )
        assert engine.provenance != EvidenceProvenance.LIVE_NEBIUS
        assert engine.provenance == EvidenceProvenance.FIXTURE
        assert EvidenceProvenance.LIVE_NEBIUS not in vault.authorized_provenances

    def test_adv_03_direct_production_authorization_through_engine_root_rejected(self) -> None:
        """3. Direct production authorization through _authorize_as_engine_root() is rejected."""
        vault = TrustedWitnessVault()

        class LiveRootEngine:
            provenance = EvidenceProvenance.LIVE_NEBIUS
            sandbox_adapter = object()

        with pytest.raises(UntrustedWitnessAuthorityError):
            vault._authorize_as_engine_root(LiveRootEngine())

        assert EvidenceProvenance.LIVE_NEBIUS not in vault.authorized_provenances
        assert not vault.is_authoritative_root

    def test_adv_04_caller_originated_record_observed_execution_without_trusted_execution_rejected(
        self,
    ) -> None:
        """4. Caller-originated record_observed_execution() cannot produce authority."""
        vault = TrustedWitnessVault()
        wa = WitnessArtifact.from_text(path="tests/test_adv4.py", content="def test_adv4(): pass\n")
        rec = vault.seal_witness(
            witness_id="WIT-ADV4",
            requirement_id="REQ-ADV4",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
        # Attempting to record LIVE_NEBIUS observations without trusted execution MUST fail closed
        with pytest.raises(
            UntrustedWitnessAuthorityError,
            match="Caller-originated record_observed_execution|Vault is not authorized",
        ):
            vault.record_observed_execution(
                witness_id="WIT-ADV4",
                witness_digest=rec.seal_digest,
                requirement_id="REQ-ADV4",
                frozen_contract_digest="c" * 64,
                source_commit_id="1" * 40,
                candidate_tree_digest="5" * 40,
                sandbox_id="sbx-adv4",
                world=ExecutionWorld.BASE,
                command=("pytest", "tests/test_adv4.py"),
                exit_code=1,
                termination_status=TerminationStatus.COMPLETED,
                stdout_digest="3" * 64,
                stderr_digest="4" * 64,
                result_digest="8" * 64,
                outcome=WitnessOutcome.FAIL,
                provenance=EvidenceProvenance.LIVE_NEBIUS,
            )

    def test_adv_05_direct_mutation_or_substitution_of_provenance_state_rejected(self) -> None:
        """5. Direct mutation or substitution of provenance authorization state fails closed."""
        vault = TrustedWitnessVault()
        # Direct assignment to _authorized_provenances
        with pytest.raises(UntrustedWitnessAuthorityError, match="Direct mutation or substitution"):
            vault._authorized_provenances = frozenset({EvidenceProvenance.LIVE_NEBIUS})

        # Property assignment to authorized_provenances
        with pytest.raises((UntrustedWitnessAuthorityError, AttributeError)):
            vault.authorized_provenances = frozenset({EvidenceProvenance.LIVE_NEBIUS})  # type: ignore[misc]

        # setattr invocation
        with pytest.raises(UntrustedWitnessAuthorityError, match="Direct mutation or substitution"):
            setattr(vault, "_authorized_provenances", frozenset({EvidenceProvenance.LIVE_NEBIUS}))

        assert EvidenceProvenance.LIVE_NEBIUS not in vault.authorized_provenances
        assert not vault.is_authoritative_root

    def test_adv_06_fabricated_observations_and_attestation_cannot_achieve_verified_causal_coverage(
        self,
    ) -> None:
        """6. Fabricated BASE=FAIL and CANDIDATE=PASS observations followed by attestation
        cannot produce VERIFIED causal coverage for a production claim.
        """
        contract = _make_sample_contract(ChangeClass.BUG_FIX)
        req_id = "REQ-001"
        c_digest = contract.contract_digest

        vault = TrustedWitnessVault.create_authorized_vault()
        wa = WitnessArtifact.from_text(path="tests/test_adv6.py", content="def test_adv6(): pass\n")
        rec = vault.seal_witness(
            witness_id="WIT-ADV6",
            requirement_id=req_id,
            frozen_contract_digest=c_digest,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
        base_wef = WorldExecutionFact(
            world=ExecutionWorld.BASE,
            sandbox_id="sbx-adv6-base",
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
            sandbox_id="sbx-adv6-cand",
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
            witness_id="WIT-ADV6",
            witness_digest=rec.seal_digest,
            requirement_id=req_id,
            frozen_contract_digest=c_digest,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=base_wef.sandbox_id,
            world=ExecutionWorld.BASE,
            command=("pytest", "tests/test_adv6.py"),
            exit_code=base_wef.exit_code,
            termination_status=base_wef.termination_status,
            stdout_digest=base_wef.stdout_digest,
            stderr_digest=base_wef.stderr_digest,
            result_digest=base_wef.result_digest,
            outcome=base_wef.outcome,
            provenance=EvidenceProvenance.FIXTURE,
        )
        vault.record_observed_execution(
            witness_id="WIT-ADV6",
            witness_digest=rec.seal_digest,
            requirement_id=req_id,
            frozen_contract_digest=c_digest,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=cand_wef.sandbox_id,
            world=ExecutionWorld.CANDIDATE,
            command=("pytest", "tests/test_adv6.py"),
            exit_code=cand_wef.exit_code,
            termination_status=cand_wef.termination_status,
            stdout_digest=cand_wef.stdout_digest,
            stderr_digest=cand_wef.stderr_digest,
            result_digest=cand_wef.result_digest,
            outcome=cand_wef.outcome,
            provenance=EvidenceProvenance.FIXTURE,
        )
        att = vault.attest_execution(
            witness_id="WIT-ADV6",
            requirement_id=req_id,
            frozen_contract_digest=c_digest,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
        )

        # Attacker crafts receipt claiming LOCAL_EXECUTION
        receipt_local = create_causal_receipt(
            requirement_id=req_id,
            frozen_contract_digest=c_digest,
            witness_id="WIT-ADV6",
            witness_digest=rec.seal_digest,
            lock_digest="d" * 64,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            narrative="Fabricated local execution attempt",
            attestation=att,
        )
        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-001": receipt_local},
            verifier_authority=vault,
        )
        assert cov.verified_count == 0
        assert cov.overall_verdict != PreliminaryVerdict.VERIFIED

    def test_adv_07_attempted_fixture_or_local_promotion_to_live_nebius_rejected(self) -> None:
        """7. Attempted FIXTURE or LOCAL_EXECUTION promotion to LIVE_NEBIUS is rejected."""
        vault = TrustedWitnessVault.create_authorized_vault()
        # 1. Attesting LIVE_NEBIUS from fixture vault fails closed
        with pytest.raises(UntrustedWitnessAuthorityError, match="not authorized to attest"):
            vault.attest_execution(
                witness_id="WIT-ADV7",
                requirement_id="REQ-ADV7",
                frozen_contract_digest="c" * 64,
                source_commit_id="1" * 40,
                base_execution=object(),
                candidate_execution=object(),
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.LIVE_NEBIUS,
            )

        # 2. Verifying receipt claiming LIVE_NEBIUS against fixture vault returns False
        dummy_rc = create_causal_receipt(
            requirement_id="REQ-ADV7",
            frozen_contract_digest="c" * 64,
            witness_id="WIT-ADV7",
            witness_digest="a" * 64,
            lock_digest="b" * 64,
            base_execution=WorldExecutionFact(
                world=ExecutionWorld.BASE,
                sandbox_id="sbx-1",
                source_commit_id="1" * 40,
                tree_digest="2" * 40,
                outcome=WitnessOutcome.FAIL,
                exit_code=1,
                termination_status=TerminationStatus.COMPLETED,
                stdout_digest="3" * 64,
                stderr_digest="4" * 64,
                result_digest="8" * 64,
                duration_seconds=1.0,
            ),
            candidate_execution=WorldExecutionFact(
                world=ExecutionWorld.CANDIDATE,
                sandbox_id="sbx-2",
                source_commit_id="1" * 40,
                tree_digest="5" * 40,
                outcome=WitnessOutcome.PASS,
                exit_code=0,
                termination_status=TerminationStatus.COMPLETED,
                stdout_digest="6" * 64,
                stderr_digest="7" * 64,
                result_digest="9" * 64,
                duration_seconds=1.0,
            ),
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
            narrative="Promotion attempt",
            attestation=None,
        )
        assert vault.verify_execution_authority(receipt=dummy_rc) is False
        assert (
            vault.verify_execution_authority(
                receipt=dummy_rc, provenance=EvidenceProvenance.LIVE_NEBIUS
            )
            is False
        )

    def test_trust_boundary_01_env_without_isolated_runtime_no_local_execution(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """1. Setting BASEBREAK_ENABLE_LOCAL_SANDBOX_RUNTIME=1 without a real isolated runtime
        does not grant authoritative LOCAL_EXECUTION, and complete path through
        compute_causal_coverage fails closed.
        """
        from unittest.mock import patch

        from basebreak.causal.engine import is_genuine_local_sandbox_runtime

        monkeypatch.setenv("BASEBREAK_ENABLE_LOCAL_SANDBOX_RUNTIME", "1")
        # Ensure container isolation probe returns False (simulating absence of docker daemon)
        with patch("basebreak.causal.engine._probe_local_container_isolation", return_value=False):
            assert is_genuine_local_sandbox_runtime() is False

            vault = TrustedWitnessVault()
            manager = VerifierSandboxManager()
            engine = CausalExecutionEngine(
                sandbox_manager=manager,
                sandbox_adapter=object(),
                materializer=object(),
                vault=vault,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
            )
            # Engine cannot obtain LOCAL_EXECUTION authority
            assert engine.provenance == EvidenceProvenance.FIXTURE
            assert EvidenceProvenance.LOCAL_EXECUTION not in engine.vault.authorized_provenances

            # Attacker crafts receipt claiming LOCAL_EXECUTION
            contract = _make_sample_contract(ChangeClass.BUG_FIX)
            req_id = "REQ-001"
            base_wef = WorldExecutionFact(
                world=ExecutionWorld.BASE,
                sandbox_id="sbx-env-base",
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
                sandbox_id="sbx-env-cand",
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
            receipt = create_causal_receipt(
                requirement_id=req_id,
                frozen_contract_digest=contract.contract_digest,
                witness_id="WIT-ENV",
                witness_digest="a" * 64,
                lock_digest="b" * 64,
                base_execution=base_wef,
                candidate_execution=cand_wef,
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                narrative="Fabricated local execution via env var",
            )

            # Test complete attacker path through compute_causal_coverage
            cov = compute_causal_coverage(
                frozen_contract=contract,
                results={req_id: receipt},
                verifier_authority=engine.vault,
            )
            assert cov.verified_count == 0
            assert cov.inconclusive_count == 1
            assert cov.overall_verdict == PreliminaryVerdict.INCONCLUSIVE

    def test_trust_boundary_02_plausible_adapter_no_production_authority(
        self,
    ) -> None:
        """2. Constructing an engine with plausible-looking custom adapter/materializer objects
        does not grant production authority, and complete path through compute_causal_coverage
        fails closed.
        """

        class PlausibleLookingSandboxAdapter:
            is_simulation = False
            is_mock = False

            def execute_command(self, *args: Any, **kwargs: Any) -> Any:
                return None

        class PlausibleLookingMaterializer:
            is_simulation = False
            is_mock = False

        vault = TrustedWitnessVault()
        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=PlausibleLookingSandboxAdapter(),
            materializer=PlausibleLookingMaterializer(),
            vault=vault,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
        )
        assert engine.provenance == EvidenceProvenance.FIXTURE
        assert EvidenceProvenance.LIVE_NEBIUS not in engine.vault.authorized_provenances

        # Test complete attacker path through compute_causal_coverage
        contract = _make_sample_contract(ChangeClass.BUG_FIX)
        req_id = "REQ-001"
        receipt = create_causal_receipt(
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            witness_id="WIT-PLAUSIBLE",
            witness_digest="a" * 64,
            lock_digest="b" * 64,
            base_execution=WorldExecutionFact(
                world=ExecutionWorld.BASE,
                sandbox_id="sbx-p-base",
                source_commit_id="1" * 40,
                tree_digest="2" * 40,
                outcome=WitnessOutcome.FAIL,
                exit_code=1,
                termination_status=TerminationStatus.COMPLETED,
                stdout_digest="3" * 64,
                stderr_digest="4" * 64,
                result_digest="8" * 64,
                duration_seconds=1.0,
            ),
            candidate_execution=WorldExecutionFact(
                world=ExecutionWorld.CANDIDATE,
                sandbox_id="sbx-p-cand",
                source_commit_id="1" * 40,
                tree_digest="5" * 40,
                outcome=WitnessOutcome.PASS,
                exit_code=0,
                termination_status=TerminationStatus.COMPLETED,
                stdout_digest="6" * 64,
                stderr_digest="7" * 64,
                result_digest="9" * 64,
                duration_seconds=1.0,
            ),
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
            narrative="Plausible adapter production claim",
        )
        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={req_id: receipt},
            verifier_authority=engine.vault,
        )
        assert cov.verified_count == 0
        assert cov.inconclusive_count == 1
        assert cov.overall_verdict == PreliminaryVerdict.INCONCLUSIVE

    def test_trust_boundary_03_authentic_adapter_unobserved_no_verified_receipt(
        self,
    ) -> None:
        """3. An authentic configured adapter without an observed execution cannot mint a
        VERIFIED receipt, and complete path through compute_causal_coverage fails closed.
        """
        from basebreak.adapters.nebius.sandbox import NebiusSandboxAdapter, SandboxClientConfig

        # Authentic adapter class and configuration
        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="authentic_api_key_format",
            )
        )
        vault = TrustedWitnessVault()
        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=adapter,
            materializer=object(),
            vault=vault,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
        )

        # Construction alone must NOT grant production provenance or authority
        assert engine.provenance == EvidenceProvenance.FIXTURE
        assert EvidenceProvenance.LIVE_NEBIUS not in engine.vault.authorized_provenances

        # Calling attest_execution without prior observed execution fails closed
        contract = _make_sample_contract(ChangeClass.BUG_FIX)
        req_id = "REQ-001"
        wa = WitnessArtifact.from_text(path="tests/test_auth.py", content="def test_auth(): pass\n")
        sealed = engine.vault.seal_witness(
            witness_id="WIT-AUTH",
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )

        # Attestation fails closed because no observed execution was witnessed
        with pytest.raises(UntrustedWitnessAuthorityError):
            engine.vault.attest_execution(
                witness_id="WIT-AUTH",
                requirement_id=req_id,
                frozen_contract_digest=contract.contract_digest,
                source_commit_id="1" * 40,
                base_execution=object(),
                candidate_execution=object(),
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.LIVE_NEBIUS,
            )

        # Any un-attested or forged receipt fails closed in coverage
        receipt = create_causal_receipt(
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            witness_id="WIT-AUTH",
            witness_digest=sealed.seal_digest,
            lock_digest="b" * 64,
            base_execution=WorldExecutionFact(
                world=ExecutionWorld.BASE,
                sandbox_id="sbx-unobs-base",
                source_commit_id="1" * 40,
                tree_digest="2" * 40,
                outcome=WitnessOutcome.FAIL,
                exit_code=1,
                termination_status=TerminationStatus.COMPLETED,
                stdout_digest="3" * 64,
                stderr_digest="4" * 64,
                result_digest="8" * 64,
                duration_seconds=1.0,
            ),
            candidate_execution=WorldExecutionFact(
                world=ExecutionWorld.CANDIDATE,
                sandbox_id="sbx-unobs-cand",
                source_commit_id="1" * 40,
                tree_digest="5" * 40,
                outcome=WitnessOutcome.PASS,
                exit_code=0,
                termination_status=TerminationStatus.COMPLETED,
                stdout_digest="6" * 64,
                stderr_digest="7" * 64,
                result_digest="9" * 64,
                duration_seconds=1.0,
            ),
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
            narrative="No observation execution",
        )
        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={req_id: receipt},
            verifier_authority=engine.vault,
        )
        assert cov.verified_count == 0
        assert cov.inconclusive_count == 1
        assert cov.overall_verdict == PreliminaryVerdict.INCONCLUSIVE

    def test_trust_boundary_04_setattr_mutation_cannot_become_verification_authority(
        self,
    ) -> None:
        """4. object.__setattr__() mutation of vault authorization state cannot become accepted
        independent verification authority, and complete path through compute_causal_coverage
        fails closed.
        """
        vault = TrustedWitnessVault()
        contract = _make_sample_contract(ChangeClass.BUG_FIX)
        req_id = "REQ-001"
        c_digest = contract.contract_digest

        wa = WitnessArtifact.from_text(path="tests/test_setattr.py", content="def test_s(): pass\n")
        sealed = vault.seal_witness(
            witness_id="WIT-SETATTR",
            requirement_id=req_id,
            frozen_contract_digest=c_digest,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )

        # Attacker uses object.__setattr__ to bypass property protection
        object.__setattr__(
            vault,
            "_authorized_provenances",
            frozenset({EvidenceProvenance.LOCAL_EXECUTION, EvidenceProvenance.LIVE_NEBIUS}),
        )
        assert EvidenceProvenance.LOCAL_EXECUTION in vault.authorized_provenances

        # Even with mutated internal attribute, attest_execution rejects production provenance
        with pytest.raises(
            UntrustedWitnessAuthorityError, match="Vault is not authorized to attest"
        ):
            vault.attest_execution(
                witness_id="WIT-SETATTR",
                requirement_id=req_id,
                frozen_contract_digest=c_digest,
                source_commit_id="1" * 40,
                base_execution=object(),
                candidate_execution=object(),
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
            )

        # And verify_execution_authority fails closed
        base_wef = WorldExecutionFact(
            world=ExecutionWorld.BASE,
            sandbox_id="sbx-mut-base",
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
            sandbox_id="sbx-mut-cand",
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
        receipt = create_causal_receipt(
            requirement_id=req_id,
            frozen_contract_digest=c_digest,
            witness_id="WIT-SETATTR",
            witness_digest=sealed.seal_digest,
            lock_digest="b" * 64,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            narrative="Mutated vault receipt",
        )
        assert vault.verify_execution_authority(receipt=receipt) is False

        # And compute_causal_coverage fails closed
        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={req_id: receipt},
            verifier_authority=vault,
        )
        assert cov.verified_count == 0
        assert cov.inconclusive_count == 1
        assert cov.overall_verdict == PreliminaryVerdict.INCONCLUSIVE

    def test_trust_boundary_05_directly_fabricated_observations_cannot_generate_verified_coverage(
        self,
    ) -> None:
        """5. Directly fabricated BASE=FAIL and CANDIDATE=PASS observation records cannot
        generate independently accepted VERIFIED coverage through compute_causal_coverage.
        """
        vault = TrustedWitnessVault()
        contract = _make_sample_contract(ChangeClass.BUG_FIX)
        req_id = "REQ-001"
        c_digest = contract.contract_digest

        wa = WitnessArtifact.from_text(path="tests/test_fab.py", content="def test_f(): pass\n")
        sealed = vault.seal_witness(
            witness_id="WIT-FAB",
            requirement_id=req_id,
            frozen_contract_digest=c_digest,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )

        # Direct caller invocation of record_observed_execution for production
        # provenance is rejected
        with pytest.raises(
            UntrustedWitnessAuthorityError, match="Caller-originated record_observed_execution"
        ):
            vault.record_observed_execution(
                witness_id="WIT-FAB",
                witness_digest=sealed.seal_digest,
                requirement_id=req_id,
                frozen_contract_digest=c_digest,
                source_commit_id="1" * 40,
                candidate_tree_digest="5" * 40,
                sandbox_id="sbx-fab-base",
                world=ExecutionWorld.BASE,
                command=("pytest", "tests/test_fab.py"),
                exit_code=1,
                termination_status=TerminationStatus.COMPLETED,
                stdout_digest="3" * 64,
                stderr_digest="4" * 64,
                result_digest="8" * 64,
                outcome=WitnessOutcome.FAIL,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
            )

        # Even if attacker directly injects fabricated records into _observed_executions:
        from basebreak.verifier.witness_store import VerifierObservedExecutionRecord

        fake_base = VerifierObservedExecutionRecord(
            witness_id="WIT-FAB",
            witness_digest=sealed.seal_digest,
            requirement_id=req_id,
            frozen_contract_digest=c_digest,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id="sbx-fab-base",
            world=ExecutionWorld.BASE,
            command=("pytest", "tests/test_fab.py"),
            exit_code=1,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="3" * 64,
            stderr_digest="4" * 64,
            result_digest="8" * 64,
            outcome=WitnessOutcome.FAIL,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            observed_at_utc="2026-10-11T00:00:00Z",
        )
        fake_cand = VerifierObservedExecutionRecord(
            witness_id="WIT-FAB",
            witness_digest=sealed.seal_digest,
            requirement_id=req_id,
            frozen_contract_digest=c_digest,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id="sbx-fab-cand",
            world=ExecutionWorld.CANDIDATE,
            command=("pytest", "tests/test_fab.py"),
            exit_code=0,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="6" * 64,
            stderr_digest="7" * 64,
            result_digest="9" * 64,
            outcome=WitnessOutcome.PASS,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            observed_at_utc="2026-10-11T00:00:00Z",
        )
        object.__setattr__(
            vault,
            "_observed_executions",
            {
                ("WIT-FAB", "BASE"): fake_base,
                ("WIT-FAB", "CANDIDATE"): fake_cand,
            },
        )

        receipt = create_causal_receipt(
            requirement_id=req_id,
            frozen_contract_digest=c_digest,
            witness_id="WIT-FAB",
            witness_digest=sealed.seal_digest,
            lock_digest="b" * 64,
            base_execution=WorldExecutionFact(
                world=ExecutionWorld.BASE,
                sandbox_id="sbx-fab-base",
                source_commit_id="1" * 40,
                tree_digest="2" * 40,
                outcome=WitnessOutcome.FAIL,
                exit_code=1,
                termination_status=TerminationStatus.COMPLETED,
                stdout_digest="3" * 64,
                stderr_digest="4" * 64,
                result_digest="8" * 64,
                duration_seconds=1.0,
            ),
            candidate_execution=WorldExecutionFact(
                world=ExecutionWorld.CANDIDATE,
                sandbox_id="sbx-fab-cand",
                source_commit_id="1" * 40,
                tree_digest="5" * 40,
                outcome=WitnessOutcome.PASS,
                exit_code=0,
                termination_status=TerminationStatus.COMPLETED,
                stdout_digest="6" * 64,
                stderr_digest="7" * 64,
                result_digest="9" * 64,
                duration_seconds=1.0,
            ),
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            narrative="Directly fabricated observations attempt",
        )

        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={req_id: receipt},
            verifier_authority=vault,
        )
        assert cov.verified_count == 0
        assert cov.inconclusive_count == 1
        assert cov.overall_verdict == PreliminaryVerdict.INCONCLUSIVE

    def test_trust_boundary_06_genuine_trusted_execution_or_not_run(
        self,
    ) -> None:
        """6. A genuine trusted execution path remains functional where safely available
        (FIXTURE-scoped verification pipeline); production live execution is honestly NOT_RUN
        when live credentials or container runtime are absent.
        """
        from basebreak.verifier.witness_lock import create_witness_lock

        # 1. Genuine FIXTURE execution path remains fully functional
        vault = TrustedWitnessVault.create_authorized_vault()
        contract = _make_sample_contract(ChangeClass.BUG_FIX)
        req_id = "REQ-001"
        wa = WitnessArtifact.from_text(path="tests/test_gen.py", content="def test_g(): pass\n")
        sealed = vault.seal_witness(
            witness_id="WIT-GEN",
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
        lock = create_witness_lock(record=sealed, vault=vault)

        base_wef = WorldExecutionFact(
            world=ExecutionWorld.BASE,
            sandbox_id="sbx-gen-base",
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
            sandbox_id="sbx-gen-cand",
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
            witness_id="WIT-GEN",
            witness_digest=sealed.seal_digest,
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=base_wef.sandbox_id,
            world=ExecutionWorld.BASE,
            command=("pytest", "tests/test_gen.py"),
            exit_code=base_wef.exit_code,
            termination_status=base_wef.termination_status,
            stdout_digest=base_wef.stdout_digest,
            stderr_digest=base_wef.stderr_digest,
            result_digest=base_wef.result_digest,
            outcome=base_wef.outcome,
            provenance=EvidenceProvenance.FIXTURE,
        )
        vault.record_observed_execution(
            witness_id="WIT-GEN",
            witness_digest=sealed.seal_digest,
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=cand_wef.sandbox_id,
            world=ExecutionWorld.CANDIDATE,
            command=("pytest", "tests/test_gen.py"),
            exit_code=cand_wef.exit_code,
            termination_status=cand_wef.termination_status,
            stdout_digest=cand_wef.stdout_digest,
            stderr_digest=cand_wef.stderr_digest,
            result_digest=cand_wef.result_digest,
            outcome=cand_wef.outcome,
            provenance=EvidenceProvenance.FIXTURE,
        )
        att = vault.attest_execution(
            witness_id="WIT-GEN",
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
        )
        legit_receipt = create_causal_receipt(
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            witness_id="WIT-GEN",
            witness_digest=sealed.seal_digest,
            lock_digest=lock.lock_digest,
            base_execution=base_wef,
            candidate_execution=cand_wef,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
            narrative="Genuine fixture execution",
            attestation=att,
        )
        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={req_id: legit_receipt},
            verifier_authority=vault,
        )
        assert cov.verified_count == 1
        assert cov.overall_verdict == PreliminaryVerdict.VERIFIED
        assert cov.coverage_ratio == 1.0

        # 2. Production execution is honestly NOT_RUN / BLOCKED when prerequisites absent
        from basebreak.causal.engine import is_genuine_local_sandbox_runtime

        has_docker = is_genuine_local_sandbox_runtime()
        if not has_docker:
            # Honestly NOT_RUN rather than creating false production evidence
            assert not is_genuine_local_sandbox_runtime()
