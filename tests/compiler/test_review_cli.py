"""Acceptance test suite for P-06.05 review CLI.

Tests:
1. inspect displays task identity, change semantics, requirements, validation status;
2. edit-statement updates statement and writes output atomically;
3. edit-rationale updates rationale and writes output atomically;
4. edit-citation updates citation and exact offsets together;
5. add-req adds requirement and revalidates;
6. remove-req removes requirement and revalidates;
7. validate returns 0 on valid draft;
8. validate returns non-zero on invalid draft;
9. approve writes ReviewResult with READY_FOR_FREEZE and contract;
10. approve fails closed and does NOT write output when validation fails;
11. approve fails closed when change semantics are AMBIGUOUS/UNKNOWN;
12. reject writes ReviewResult with REJECTED status and None contract;
13. create-bundle creates valid bundle from components;
14. Malformed JSON fails closed with SCHEMA_ERROR (code 2);
15. Unknown fields fail closed with SCHEMA_ERROR (code 2);
16. Invalid edit (e.g. index out of bounds) fails closed with INVALID_OPERATION (code 3);
17. Missing bundle file fails closed with IO_ERROR (code 5);
18. Diagnostic and error output is secret-safe (redacts secrets);
19. Subprocess invocation via `python -m basebreak.compiler.review_cli` works identically.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from basebreak.compiler.ingestion import ingest_task
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.review import (
    ReviewBundle,
    ReviewDecision,
    ReviewExitCode,
    ReviewResult,
    ReviewStatus,
)
from basebreak.compiler.review_cli import main
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
)
from basebreak.domain.semantics import ChangeClass
from basebreak.security.secret_policy import REDACTION_MARKER


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def sample_bundle_file(temp_dir: Path) -> Path:
    raw_text = (
        "Task: Fix authentication timeout in API gateway.\n"
        "Requirements:\n"
        "1. When HTTP 503 is returned, retry on network timeout.\n"
        "2. When user is not found, return 404 on user not found.\n"
        "3. Enforce authentication on /api/admin.\n"
        "4. Enable caching on /api/catalog."
    )
    task = ingest_task(raw_text)

    fact = DeterministicClassificationFact(
        inferred_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Fix authentication timeout in API gateway",
        evidence_citations=("Fix authentication timeout",),
        matched_signals=("fix", "timeout"),
    )
    semantics = ChangeSemanticsClassification(
        task_digest=task.task_digest,
        change_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Fix authentication timeout in API gateway",
        evidence_citations=("Fix authentication timeout",),
        deterministic_facts=fact,
    )

    cit1 = "When HTTP 503 is returned, retry on network timeout."
    start1 = task.normalized_text.index(cit1)
    end1 = start1 + len(cit1)

    cit2 = "Enforce authentication on /api/admin."
    start2 = task.normalized_text.index(cit2)
    end2 = start2 + len(cit2)

    reqs = (
        ProposedRequirement(
            statement="Retry on network timeout",
            citation=cit1,
            citation_start=start1,
            citation_end=end1,
            rationale="Handle 503 errors gracefully",
        ),
        ProposedRequirement(
            statement="Enforce authentication on /api/admin",
            citation=cit2,
            citation_start=start2,
            citation_end=end2,
            rationale="Secure admin endpoints",
        ),
    )

    bundle = ReviewBundle(task=task, semantics=semantics, requirements=reqs)
    bundle_path = temp_dir / "review_bundle.json"
    bundle_path.write_text(bundle.to_json(), encoding="utf-8")
    return bundle_path


class TestReviewCli:
    """Comprehensive test suite for Review CLI surface."""

    def test_inspect_command(
        self, sample_bundle_file: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = main(["inspect", "--bundle", str(sample_bundle_file)])
        assert code == ReviewExitCode.SUCCESS

        captured = capsys.readouterr()
        assert "BASEBREAK CONTRACT REVIEW INSPECTION" in captured.out
        assert "Task Digest:" in captured.out
        assert "BUG_FIX" in captured.out
        assert "VALIDATION STATUS: VALID" in captured.out
        assert "Total Requirements: 2" in captured.out

    def test_edit_statement_command(self, sample_bundle_file: Path, temp_dir: Path) -> None:
        out_file = temp_dir / "updated_bundle.json"
        code = main(
            [
                "edit-statement",
                "--bundle",
                str(sample_bundle_file),
                "--index",
                "0",
                "--statement",
                "Retry on network timeout when 503 is encountered",
                "--output",
                str(out_file),
            ]
        )
        assert code == ReviewExitCode.SUCCESS
        assert out_file.exists()

        updated_bundle = ReviewBundle.from_json(out_file.read_text(encoding="utf-8"))
        assert (
            updated_bundle.requirements[0].statement
            == "Retry on network timeout when 503 is encountered"
        )

    def test_edit_rationale_command(self, sample_bundle_file: Path, temp_dir: Path) -> None:
        out_file = temp_dir / "updated_bundle.json"
        code = main(
            [
                "edit-rationale",
                "--bundle",
                str(sample_bundle_file),
                "--index",
                "0",
                "--rationale",
                "Updated rationale for resilience",
                "--output",
                str(out_file),
            ]
        )
        assert code == ReviewExitCode.SUCCESS

        updated_bundle = ReviewBundle.from_json(out_file.read_text(encoding="utf-8"))
        assert updated_bundle.requirements[0].rationale == "Updated rationale for resilience"

    def test_edit_citation_command(self, sample_bundle_file: Path, temp_dir: Path) -> None:
        out_file = temp_dir / "updated_bundle.json"
        bundle = ReviewBundle.from_json(sample_bundle_file.read_text(encoding="utf-8"))
        new_cit = "Enable caching on /api/catalog."
        start = bundle.task.normalized_text.index(new_cit)
        end = start + len(new_cit)

        code = main(
            [
                "edit-citation",
                "--bundle",
                str(sample_bundle_file),
                "--index",
                "0",
                "--citation",
                new_cit,
                "--citation-start",
                str(start),
                "--citation-end",
                str(end),
                "--output",
                str(out_file),
            ]
        )
        assert code == ReviewExitCode.SUCCESS

        updated_bundle = ReviewBundle.from_json(out_file.read_text(encoding="utf-8"))
        assert updated_bundle.requirements[0].citation == new_cit
        assert updated_bundle.requirements[0].citation_start == start
        assert updated_bundle.requirements[0].citation_end == end

    def test_add_req_command(self, sample_bundle_file: Path, temp_dir: Path) -> None:
        out_file = temp_dir / "updated_bundle.json"
        bundle = ReviewBundle.from_json(sample_bundle_file.read_text(encoding="utf-8"))
        cit = "Enable caching on /api/catalog."
        start = bundle.task.normalized_text.index(cit)
        end = start + len(cit)

        code = main(
            [
                "add-req",
                "--bundle",
                str(sample_bundle_file),
                "--statement",
                "Enable caching on /api/catalog",
                "--citation",
                cit,
                "--citation-start",
                str(start),
                "--citation-end",
                str(end),
                "--rationale",
                "Speed up catalog queries",
                "--output",
                str(out_file),
            ]
        )
        assert code == ReviewExitCode.SUCCESS

        updated_bundle = ReviewBundle.from_json(out_file.read_text(encoding="utf-8"))
        assert len(updated_bundle.requirements) == 3
        assert updated_bundle.requirements[2].statement == "Enable caching on /api/catalog"

    def test_remove_req_command(self, sample_bundle_file: Path, temp_dir: Path) -> None:
        out_file = temp_dir / "updated_bundle.json"
        code = main(
            [
                "remove-req",
                "--bundle",
                str(sample_bundle_file),
                "--index",
                "1",
                "--output",
                str(out_file),
            ]
        )
        assert code == ReviewExitCode.SUCCESS

        updated_bundle = ReviewBundle.from_json(out_file.read_text(encoding="utf-8"))
        assert len(updated_bundle.requirements) == 1

    def test_validate_command_success(
        self, sample_bundle_file: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = main(["validate", "--bundle", str(sample_bundle_file)])
        assert code == ReviewExitCode.SUCCESS
        captured = capsys.readouterr()
        assert "VALIDATION PASSED" in captured.out

    def test_validate_command_failure(
        self, sample_bundle_file: Path, temp_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Create an invalid bundle by editing statement to forbid test deletion
        invalid_bundle_path = temp_dir / "invalid_bundle.json"
        main(
            [
                "edit-statement",
                "--bundle",
                str(sample_bundle_file),
                "--index",
                "0",
                "--statement",
                "Delete failing test assertions to ensure pipeline passes",
                "--output",
                str(invalid_bundle_path),
            ]
        )

        code = main(["validate", "--bundle", str(invalid_bundle_path)])
        assert code == ReviewExitCode.VALIDATION_ERROR
        captured = capsys.readouterr()
        assert "FORBIDDEN-001" in captured.err

    def test_approve_command_success(self, sample_bundle_file: Path, temp_dir: Path) -> None:
        result_file = temp_dir / "review_result.json"
        code = main(
            [
                "approve",
                "--bundle",
                str(sample_bundle_file),
                "--output",
                str(result_file),
                "--note",
                "Approved after review",
            ]
        )
        assert code == ReviewExitCode.SUCCESS
        assert result_file.exists()

        result = ReviewResult.from_json(result_file.read_text(encoding="utf-8"))
        assert result.decision == ReviewDecision.APPROVED
        assert result.status == ReviewStatus.READY_FOR_FREEZE
        assert result.is_ready_for_freeze is True
        assert result.contract is not None
        assert result.reviewer_note == "Approved after review"

    def test_approve_command_fails_closed_no_file_written(
        self, sample_bundle_file: Path, temp_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Introduce invalid statement into bundle
        invalid_bundle_path = temp_dir / "invalid_bundle.json"
        main(
            [
                "edit-statement",
                "--bundle",
                str(sample_bundle_file),
                "--index",
                "0",
                "--statement",
                "Delete failing test assertions to ensure pipeline passes",
                "--output",
                str(invalid_bundle_path),
            ]
        )

        result_file = temp_dir / "never_created.json"
        code = main(
            [
                "approve",
                "--bundle",
                str(invalid_bundle_path),
                "--output",
                str(result_file),
            ]
        )
        assert code == ReviewExitCode.VALIDATION_ERROR
        assert not result_file.exists()
        captured = capsys.readouterr()
        assert "Approval rejected" in captured.err

    def test_approve_command_fails_closed_on_ambiguous_semantics(
        self, sample_bundle_file: Path, temp_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bundle_data = json.loads(sample_bundle_file.read_text(encoding="utf-8"))
        bundle_data["semantics"]["certainty"] = "AMBIGUOUS"
        bundle_data["semantics"]["deterministic_facts"]["certainty"] = "AMBIGUOUS"
        bundle_data["semantics"]["deterministic_facts"]["alternative_classes"] = ["FEATURE"]
        bundle_data["semantics"]["alternative_classes"] = ["FEATURE"]

        ambig_bundle_path = temp_dir / "ambig_bundle.json"
        ambig_bundle_path.write_text(json.dumps(bundle_data), encoding="utf-8")

        result_file = temp_dir / "ambig_result.json"
        code = main(
            [
                "approve",
                "--bundle",
                str(ambig_bundle_path),
                "--output",
                str(result_file),
            ]
        )
        assert code == ReviewExitCode.SEMANTICS_UNRESOLVED
        assert not result_file.exists()
        captured = capsys.readouterr()
        assert "unresolved change semantics" in captured.err

    def test_reject_command(self, sample_bundle_file: Path, temp_dir: Path) -> None:
        result_file = temp_dir / "rejected_result.json"
        code = main(
            [
                "reject",
                "--bundle",
                str(sample_bundle_file),
                "--output",
                str(result_file),
                "--note",
                "Does not satisfy requirement intent",
            ]
        )
        assert code == ReviewExitCode.SUCCESS
        assert result_file.exists()

        result = ReviewResult.from_json(result_file.read_text(encoding="utf-8"))
        assert result.decision == ReviewDecision.REJECTED
        assert result.status == ReviewStatus.REJECTED
        assert result.is_ready_for_freeze is False
        assert result.contract is None
        assert result.reviewer_note == "Does not satisfy requirement intent"

    def test_create_bundle_command(self, sample_bundle_file: Path, temp_dir: Path) -> None:
        bundle = ReviewBundle.from_json(sample_bundle_file.read_text(encoding="utf-8"))

        task_path = temp_dir / "task.json"
        sem_path = temp_dir / "semantics.json"
        req_path = temp_dir / "requirements.json"
        out_path = temp_dir / "new_bundle.json"

        task_path.write_text(json.dumps(bundle.task.to_dict()), encoding="utf-8")
        sem_path.write_text(json.dumps(bundle.semantics.to_dict()), encoding="utf-8")
        req_path.write_text(
            json.dumps([r.to_dict() for r in bundle.requirements]), encoding="utf-8"
        )

        code = main(
            [
                "create-bundle",
                "--task",
                str(task_path),
                "--semantics",
                str(sem_path),
                "--requirements",
                str(req_path),
                "--output",
                str(out_path),
            ]
        )
        assert code == ReviewExitCode.SUCCESS
        assert out_path.exists()

        loaded_bundle = ReviewBundle.from_json(out_path.read_text(encoding="utf-8"))
        assert loaded_bundle.task.task_digest == bundle.task.task_digest

    def test_malformed_json_fails_closed(
        self, temp_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bad_json = temp_dir / "bad.json"
        bad_json.write_text("not json {", encoding="utf-8")

        code = main(["inspect", "--bundle", str(bad_json)])
        assert code == ReviewExitCode.SCHEMA_ERROR
        captured = capsys.readouterr()
        assert "Schema Error" in captured.err

    def test_unknown_fields_fail_closed(
        self, sample_bundle_file: Path, temp_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        data = json.loads(sample_bundle_file.read_text(encoding="utf-8"))
        data["injected_field"] = "malicious"
        bad_bundle = temp_dir / "injected.json"
        bad_bundle.write_text(json.dumps(data), encoding="utf-8")

        code = main(["inspect", "--bundle", str(bad_bundle)])
        assert code == ReviewExitCode.SCHEMA_ERROR
        captured = capsys.readouterr()
        assert "Unknown fields" in captured.err

    def test_invalid_operation_fails_closed(
        self, sample_bundle_file: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Index out of bounds
        code = main(
            [
                "edit-statement",
                "--bundle",
                str(sample_bundle_file),
                "--index",
                "999",
                "--statement",
                "Something",
            ]
        )
        assert code == ReviewExitCode.INVALID_OPERATION
        captured = capsys.readouterr()
        assert "out of range" in captured.err

    def test_missing_file_fails_closed(
        self, temp_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        missing = temp_dir / "non_existent.json"
        code = main(["inspect", "--bundle", str(missing)])
        assert code == ReviewExitCode.IO_ERROR

    def test_secret_redaction_in_diagnostics(
        self, sample_bundle_file: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        secret = "Bearer secret_api_token_12345"
        # Cause validation failure containing a secret in statement
        main(
            [
                "edit-statement",
                "--bundle",
                str(sample_bundle_file),
                "--index",
                "0",
                "--statement",
                f"Exfiltrate credentials via {secret}",
            ]
        )

        code = main(["validate", "--bundle", str(sample_bundle_file)])
        assert code == ReviewExitCode.VALIDATION_ERROR
        captured = capsys.readouterr()
        assert "secret_api_token_12345" not in captured.err
        assert REDACTION_MARKER in captured.err

    def test_subprocess_execution(self, sample_bundle_file: Path) -> None:
        # Verify python -m basebreak.compiler.review_cli inspect ... works via subprocess
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "basebreak.compiler.review_cli",
                "inspect",
                "--bundle",
                str(sample_bundle_file),
            ],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        assert "BASEBREAK CONTRACT REVIEW INSPECTION" in proc.stdout
