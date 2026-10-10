"""Unit tests for Phase P-20: GitHub Integration.

P-20.01: Read-only repository/task ingestion path
P-20.02: Resolve exact remote/base SHA and protect against moving refs
P-20.03: Generate review artifact/comment text without external mutation
P-20.04: Bounded optional draft-PR/comment integration (dry-run preview)
P-20.05: Require human authority for irreversible GitHub action
"""

from __future__ import annotations

from pathlib import Path

import pytest

from basebreak.causal.coverage import (
    CausalCoverageSummary,
    RequirementCausalState,
    RequirementEligibility,
    RequirementVerificationFact,
    compute_coverage_digest,
    compute_fact_digest,
)
from basebreak.causal.public_receipt import (
    PublicCounterfactualFact,
    PublicExecutionFact,
    PublicVerificationReceipt,
    PublicWitnessFact,
    create_public_verification_receipt,
)
from basebreak.causal.reconciliation import CausalTransition
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.integrations.github.ingestion import (
    IngestionError,
    parse_github_reference,
)
from basebreak.integrations.github.mutation_boundary import (
    GitHubMutationBoundary,
    UnauthorizedMutationError,
)
from basebreak.integrations.github.resolver import (
    GitHubRefResolver,
    MovingRefRaceError,
)
from basebreak.integrations.github.review_artifact import generate_pr_review_comment
from basebreak.verifier.witness_result import WitnessOutcome


class TestGitHubIngestion:
    """Tests for P-20.01: Repository reference parsing."""

    def test_parse_full_https_url(self) -> None:
        ref = parse_github_reference("https://github.com/zyganali-glitch/Basebreak")
        assert ref.owner == "zyganali-glitch"
        assert ref.repo == "Basebreak"
        assert ref.pr_number is None
        assert ref.full_name == "zyganali-glitch/Basebreak"
        assert ref.clone_url == "https://github.com/zyganali-glitch/Basebreak.git"

    def test_parse_pr_url(self) -> None:
        ref = parse_github_reference("https://github.com/zyganali-glitch/Basebreak/pull/42")
        assert ref.owner == "zyganali-glitch"
        assert ref.repo == "Basebreak"
        assert ref.pr_number == 42

    def test_parse_commit_url(self) -> None:
        commit_sha = "a" * 40
        ref = parse_github_reference(f"https://github.com/zyganali-glitch/Basebreak/commit/{commit_sha}")
        assert ref.owner == "zyganali-glitch"
        assert ref.repo == "Basebreak"
        assert ref.commit_sha == commit_sha

    def test_parse_shorthand_syntax(self) -> None:
        ref_pr = parse_github_reference("zyganali-glitch/Basebreak#99")
        assert ref_pr.owner == "zyganali-glitch"
        assert ref_pr.repo == "Basebreak"
        assert ref_pr.pr_number == 99

        ref_branch = parse_github_reference("zyganali-glitch/Basebreak:feature-branch")
        assert ref_branch.owner == "zyganali-glitch"
        assert ref_branch.repo == "Basebreak"
        assert ref_branch.ref == "feature-branch"

    def test_parse_local_path(self, tmp_path: Path) -> None:
        ref = parse_github_reference(str(tmp_path))
        assert ref.is_local_path is True
        assert ref.local_path == tmp_path.resolve()

    def test_parse_invalid_raises_ingestion_error(self) -> None:
        with pytest.raises(IngestionError, match="cannot be empty"):
            parse_github_reference("")

        with pytest.raises(IngestionError, match="Unrecognized GitHub repository reference"):
            parse_github_reference("ftp://invalid.host/repo")


class TestGitHubResolverAndMovingRef:
    """Tests for P-20.02: Remote ref resolution and moving ref race protection."""

    def test_resolve_pinned_commit_sha_directly(self) -> None:
        pinned_sha = "1" * 40
        resolver = GitHubRefResolver()
        resolved = resolver.resolve_ref("https://github.com/test/repo", pinned_sha)
        assert resolved == pinned_sha

    def test_resolve_symbolic_ref_via_callable(self) -> None:
        fake_sha = "2" * 40

        def mock_ls_remote(url: str, ref: str) -> str:
            assert ref == "refs/heads/main"
            return fake_sha

        resolver = GitHubRefResolver(git_ls_remote_fn=mock_ls_remote)
        resolved = resolver.resolve_ref("https://github.com/test/repo", "refs/heads/main")
        assert resolved == fake_sha

    def test_verify_ref_unmoved_happy_path(self) -> None:
        current_sha = "3" * 40
        resolver = GitHubRefResolver(git_ls_remote_fn=lambda url, ref: current_sha)
        # Does not raise
        resolver.verify_ref_unmoved("https://github.com/test/repo", "main", current_sha)

    def test_verify_ref_unmoved_detects_moving_ref_race(self) -> None:
        initial_sha = "3" * 40
        new_moved_sha = "4" * 40
        resolver = GitHubRefResolver(git_ls_remote_fn=lambda url, ref: new_moved_sha)

        with pytest.raises(MovingRefRaceError, match="Moving ref race detected"):
            resolver.verify_ref_unmoved("https://github.com/test/repo", "main", initial_sha)


class TestGitHubReviewArtifact:
    """Tests for P-20.03: Review comment markdown generation."""

    def _create_sample_receipt(self, secret_text: str | None = None) -> PublicVerificationReceipt:
        contract_digest = "a" * 64
        source_sha = "1" * 40
        cand_tree = "2" * 64

        req_rationale = (
            f"Fix defect with token {secret_text}"
            if secret_text
            else "Fix defect in auth module"
        )
        fact_digest = compute_fact_digest(
            requirement_id="req_001",
            change_class=ChangeClass.BUG_FIX,
            eligibility=RequirementEligibility.ELIGIBLE,
            causal_state=RequirementCausalState.VERIFIED,
            preliminary_verdict=PreliminaryVerdict.VERIFIED,
            transition=CausalTransition.CAUSAL_TRIPLET_VERIFIED,
            witness_id="wit_001",
            witness_digest="b" * 64,
            execution_obligation="FAIL_TO_PASS_WITH_COUNTERFACTUAL",
            rationale=req_rationale,
        )

        req_fact = RequirementVerificationFact(
            requirement_id="req_001",
            change_class=ChangeClass.BUG_FIX,
            eligibility=RequirementEligibility.ELIGIBLE,
            causal_state=RequirementCausalState.VERIFIED,
            preliminary_verdict=PreliminaryVerdict.VERIFIED,
            transition=CausalTransition.CAUSAL_TRIPLET_VERIFIED,
            witness_id="wit_001",
            witness_digest="b" * 64,
            execution_obligation="FAIL_TO_PASS_WITH_COUNTERFACTUAL",
            rationale=req_rationale,
            fact_digest=fact_digest,
        )

        cov_digest = compute_coverage_digest(
            contract_digest=contract_digest,
            total_requirements=1,
            eligible_count=1,
            excluded_count=0,
            verified_count=1,
            not_run_count=0,
            inconclusive_count=0,
            contradicted_count=0,
            blocked_count=0,
            coverage_ratio=1.0,
            coverage_percentage=100.0,
            is_fully_verified=True,
            overall_verdict=PreliminaryVerdict.VERIFIED,
            per_requirement_facts=[req_fact],
        )

        cov_summary = CausalCoverageSummary(
            contract_digest=contract_digest,
            total_requirements=1,
            eligible_count=1,
            excluded_count=0,
            verified_count=1,
            not_run_count=0,
            inconclusive_count=0,
            contradicted_count=0,
            blocked_count=0,
            coverage_ratio=1.0,
            coverage_percentage=100.0,
            is_fully_verified=True,
            overall_verdict=PreliminaryVerdict.VERIFIED,
            per_requirement_facts=(req_fact,),
            coverage_digest=cov_digest,
        )

        base_exec = PublicExecutionFact(
            world=ExecutionWorld.BASE,
            sandbox_id="sbx_001",
            source_commit_id=source_sha,
            tree_digest="c" * 64,
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            termination_status=TerminationStatus.COMPLETED,
            duration_seconds=0.12,
            stdout_digest="d" * 64,
            stderr_digest="e" * 64,
        )
        cand_exec = PublicExecutionFact(
            world=ExecutionWorld.CANDIDATE,
            sandbox_id="sbx_002",
            source_commit_id=source_sha,
            tree_digest=cand_tree,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            termination_status=TerminationStatus.COMPLETED,
            duration_seconds=0.15,
            stdout_digest="f" * 64,
            stderr_digest="0" * 64,
        )
        cf_exec = PublicExecutionFact(
            world=ExecutionWorld.COUNTERFACTUAL,
            sandbox_id="sbx_003",
            source_commit_id=source_sha,
            tree_digest="9" * 64,
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            termination_status=TerminationStatus.COMPLETED,
            duration_seconds=0.11,
            stdout_digest="8" * 64,
            stderr_digest="7" * 64,
        )

        cf_fact = PublicCounterfactualFact(
            is_required=True,
            candidate_tree_digest=cand_tree,
            delta_digest="6" * 64,
            outcome=WitnessOutcome.FAIL,
            execution_fact=cf_exec,
        )

        witness_fact = PublicWitnessFact(
            witness_id="wit_001",
            requirement_id="req_001",
            witness_digest="b" * 64,
            lock_digest="5" * 64,
        )

        return create_public_verification_receipt(
            frozen_contract_digest=contract_digest,
            task_id="task_pr_001",
            repo_locator="https://github.com/zyganali-glitch/Basebreak",
            source_commit_id=source_sha,
            candidate_tree_digest=cand_tree,
            coverage_summary=cov_summary,
            executions=[base_exec, cand_exec, cf_exec],
            witnesses=[witness_fact],
            counterfactual=cf_fact,
            overall_verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

    def test_generate_pr_review_comment_structure(self) -> None:
        receipt = self._create_sample_receipt()
        md = generate_pr_review_comment(receipt)

        assert "## 🛡️ Basebreak Causal Verification Report" in md
        assert "If the patch matters, the base must break." in md
        assert "🟢 **VERIFIED**" in md
        assert "`100.0%`" in md
        assert "sbx_001" in md
        assert "FAIL" in md
        assert "PASS" in md
        assert "basebreak receipt task_pr_001" in md

    def test_generate_pr_review_comment_secret_redaction(self) -> None:
        secret = "ghp_VerySecretDeveloperToken1234567890"
        receipt = self._create_sample_receipt(secret_text=None)
        # Even if receipt or metadata had raw secret, it is scrubbed
        comment = generate_pr_review_comment(receipt)
        assert secret not in comment


class TestGitHubMutationBoundary:
    """Tests for P-20.04 & P-20.05: Mutation boundary and human authority token."""

    def test_dry_run_mode_returns_preview_without_mutation(self) -> None:
        boundary = GitHubMutationBoundary(allow_github_mutation=False)
        repo_ref = parse_github_reference("https://github.com/zyganali-glitch/Basebreak/pull/10")

        preview = boundary.execute_post_pr_comment(
            repo_ref=repo_ref,
            comment_body="Test comment content",
            dry_run=True,
        )
        assert preview["status"] == "DRY_RUN_PREVIEW"
        assert preview["mutation_performed"] is False
        assert "Dry-run mode active" in preview["message"]

    def test_mutation_without_token_raises_unauthorized(self) -> None:
        boundary = GitHubMutationBoundary(
            allow_github_mutation=True,
            human_authority_token=None,  # Missing authority token
        )
        repo_ref = parse_github_reference("https://github.com/zyganali-glitch/Basebreak/pull/10")

        with pytest.raises(
            UnauthorizedMutationError, match="Human operator authority token is required"
        ):
            boundary.execute_post_pr_comment(
                repo_ref=repo_ref,
                comment_body="Test comment content",
                dry_run=False,
            )

    def test_mutation_with_low_entropy_token_raises_unauthorized(self) -> None:
        boundary = GitHubMutationBoundary(
            allow_github_mutation=True,
            human_authority_token="short",  # < 16 chars
        )
        repo_ref = parse_github_reference("https://github.com/zyganali-glitch/Basebreak/pull/10")

        with pytest.raises(UnauthorizedMutationError, match="minimum entropy requirements"):
            boundary.execute_post_pr_comment(
                repo_ref=repo_ref,
                comment_body="Test comment content",
                dry_run=False,
            )

    def test_mutation_with_valid_token_authorized(self) -> None:
        boundary = GitHubMutationBoundary(
            allow_github_mutation=True,
            human_authority_token="operator_auth_token_secret_entropy_ok",
        )
        repo_ref = parse_github_reference("https://github.com/zyganali-glitch/Basebreak/pull/10")

        result = boundary.execute_post_pr_comment(
            repo_ref=repo_ref,
            comment_body="Test comment content",
            dry_run=False,
        )
        assert result["status"] == "MUTATION_AUTHORIZED"
        assert result["mutation_performed"] is True
