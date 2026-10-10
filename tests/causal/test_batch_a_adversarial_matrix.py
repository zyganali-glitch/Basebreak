"""Mandatory Adversarial Acceptance Tests for Batch A Surgical Repair.

Directly proves that each of the 18 blocking causal evidence integrity failure
modes is deterministically rejected or honestly classified.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from basebreak.api.auth import ApiAuthManager
from basebreak.api.server import BasebreakApiServer
from basebreak.api.store import ApiRunStore
from basebreak.causal.coverage import (
    CoverageIntegrityError,
    RequirementEligibility,
    compute_causal_coverage,
)
from basebreak.causal.public_receipt import (
    PublicExecutionFact,
    PublicReceiptIntegrityError,
    PublicReceiptTamperingError,
    PublicVerificationReceipt,
    PublicWitnessFact,
    create_public_verification_receipt,
    verify_public_receipt_integrity,
)
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
from basebreak.verifier.witness_result import WitnessOutcome


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
        assert res.receipt.provenance != EvidenceProvenance.LOCAL_EXECUTION

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
        coverage = compute_causal_coverage(
            frozen_contract=contract,
            results={
                "REQ-001": {
                    "transition": CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                    "verdict": PreliminaryVerdict.VERIFIED,
                    "is_causally_verified": True,
                    "witness_id": "wit-1",
                    "witness_digest": "a" * 64,
                    "rationale": "Proven",
                }
            },
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
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
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
        coverage = compute_causal_coverage(
            frozen_contract=contract,
            results={
                "REQ-001": {
                    "transition": CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                    "verdict": PreliminaryVerdict.VERIFIED,
                    "is_causally_verified": True,
                    "witness_id": "wit-1",
                    "witness_digest": "a" * 64,
                    "rationale": "Proven",
                }
            },
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
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
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

            # Oversized body -> 413
            oversized = b"a" * (1024 * 1024 + 1024)
            req_oversized = urllib.request.Request(
                f"{server.base_url}/v1/runs",
                data=oversized,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc2:
                urllib.request.urlopen(req_oversized)
            assert exc2.value.code == 413
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
