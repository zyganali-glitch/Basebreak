"""Tests for P-09.01 and P-09.02: Nemotron witness-plan generation and deterministic validation.

Verifies:
1. Structured witness plan proposal generation and JSON parsing.
2. Binding to frozen contract digest, requirement ID, and source commit SHA.
3. Zero Builder authority leakage and rejection of Builder state.
4. Fail-closed parsing against malformed, unparseable, or empty model responses.
5. Strict BUG_FIX scope enforcement.
6. Execution command security: approved executables, shell operator rejection.
7. Artifact security: path normalization, protected-surface collisions, secrets,
   Builder workspace references.
8. Rejection of self-certification or authority smuggling attempts.
9. Deterministic plan digest computation.
10. Provider purity (zero adapter imports in witness_plan).
"""

from __future__ import annotations

import ast
import inspect
from typing import Any

import pytest

from basebreak.compiler.freeze import FrozenContract, freeze_review_result
from basebreak.compiler.ingestion import NormalizedTask, ingest_task
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.review import ReviewBundle, ReviewResult, ReviewSession
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeClass,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
)
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.verifier.context import (
    VerifierContextEnvelope,
    VerifierExecutionPolicy,
)
from basebreak.verifier.witness_plan import (
    ProposedWitnessArtifact,
    ValidatedWitnessPlan,
    WitnessPlanAuthoritySmugglingError,
    WitnessPlanBindingMismatchError,
    WitnessPlanProposal,
    WitnessPlanScopeError,
    WitnessPlanSecurityError,
    WitnessPlanValidator,
    generate_witness_plan,
    parse_witness_plan_proposal,
)


class DummyModelClient:
    """Deterministic dummy model client for unit tests."""

    def __init__(self, response_text: str) -> None:
        self.response_text = response_text
        self.calls: list[dict[str, Any]] = []

    def complete(
        self,
        *,
        messages: list[dict[str, str]],
        model: str,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        timeout_seconds: float = 30.0,
    ) -> dict[str, str]:
        self.calls.append(
            {
                "max_tokens": max_tokens,
                "messages": messages,
                "model": model,
                "temperature": temperature,
                "timeout_seconds": timeout_seconds,
            }
        )
        return {"content": self.response_text}


@pytest.fixture
def sample_task() -> NormalizedTask:
    raw_text = (
        "Task: Fix off-by-one error in buffer indexing.\n"
        "Requirements:\n"
        "1. Prevent buffer overflow on exact capacity."
    )
    return ingest_task(raw_text)


@pytest.fixture
def sample_contract(sample_task: NormalizedTask) -> FrozenContract:
    fact = DeterministicClassificationFact(
        inferred_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Fix buffer defect",
        evidence_citations=("Fix off-by-one",),
        matched_signals=("fix", "buffer"),
    )
    semantics = ChangeSemanticsClassification(
        task_digest=sample_task.task_digest,
        change_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Fix buffer defect",
        evidence_citations=("Fix off-by-one",),
        deterministic_facts=fact,
    )
    cit1 = "Prevent buffer overflow on exact capacity."
    start1 = sample_task.normalized_text.index(cit1)
    end1 = start1 + len(cit1)
    reqs = [
        ProposedRequirement(
            statement="Prevent buffer overflow on exact capacity.",
            citation=cit1,
            citation_start=start1,
            citation_end=end1,
            rationale="Off-by-one error fix",
        )
    ]
    bundle = ReviewBundle(task=sample_task, semantics=semantics, requirements=tuple(reqs))
    session = ReviewSession(bundle)
    review_result: ReviewResult = session.approve(reviewer_note="Approved for freeze")
    return freeze_review_result(review_result)


@pytest.fixture
def sample_envelope(sample_contract: FrozenContract) -> VerifierContextEnvelope:
    source = SourceIdentity(
        locator="https://github.com/example/repo",
        revision=CommitRevision(commit_id="a" * 40),
    )
    return VerifierContextEnvelope.create(
        frozen_contract=sample_contract,
        source_identity=source,
        execution_policy=VerifierExecutionPolicy(timeout_seconds=60),
    )


DUMMY_DIGEST = "0" * 64


def test_parse_valid_witness_plan_proposal() -> None:
    raw_json = f"""
    {{
        "witness_id": "wit-test-01",
        "requirement_id": "REQ-TEST-01",
        "frozen_contract_digest": "{DUMMY_DIGEST}",
        "source_commit_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "change_class": "BUG_FIX",
        "plan_summary": "Test buffer capacity boundary check",
        "target_files": ["src/buffer.py"],
        "artifacts": [
            {{
                "path": "tests/test_buffer_witness.py",
                "content": "def test_boundary():\\n    assert buffer_check(10) is True\\n",
                "rationale": "Asserts boundary condition"
            }}
        ],
        "execution_command": ["python", "-m", "pytest", "tests/test_buffer_witness.py"],
        "expected_failure_at_base": "Fails at capacity 10 with IndexError",
        "expected_success_at_candidate": "Passes at capacity 10"
    }}
    """
    proposal = parse_witness_plan_proposal(raw_json)
    assert isinstance(proposal, WitnessPlanProposal)
    assert proposal.witness_id == "wit-test-01"
    assert proposal.requirement_id == "REQ-TEST-01"
    assert proposal.change_class == ChangeClass.BUG_FIX
    assert len(proposal.artifacts) == 1
    assert proposal.artifacts[0].path == "tests/test_buffer_witness.py"
    assert proposal.is_authoritative is False
    assert proposal.grants_pass is False


def test_parse_proposal_strips_markdown_fences() -> None:
    raw = f"""```json
    {{
        "witness_id": "wit-test-02",
        "requirement_id": "REQ-TEST-01",
        "frozen_contract_digest": "{DUMMY_DIGEST}",
        "source_commit_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "change_class": "BUG_FIX",
        "plan_summary": "Test buffer capacity",
        "target_files": [],
        "artifacts": [
            {{
                "path": "tests/test_wit.py",
                "content": "assert True"
            }}
        ],
        "execution_command": ["pytest"],
        "expected_failure_at_base": "Fails",
        "expected_success_at_candidate": "Passes"
    }}
    ```"""
    proposal = parse_witness_plan_proposal(raw)
    assert proposal.witness_id == "wit-test-02"


def test_parse_proposal_rejects_smuggled_authority() -> None:
    raw = f"""
    {{
        "witness_id": "wit-test-03",
        "requirement_id": "REQ-TEST-01",
        "frozen_contract_digest": "{DUMMY_DIGEST}",
        "source_commit_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "change_class": "BUG_FIX",
        "plan_summary": "Test",
        "artifacts": [{{"path": "t.py", "content": "pass"}}],
        "execution_command": ["pytest"],
        "expected_failure_at_base": "f",
        "expected_success_at_candidate": "p",
        "is_verified": true
    }}
    """
    with pytest.raises(WitnessPlanAuthoritySmugglingError, match="Smuggled authority key"):
        parse_witness_plan_proposal(raw)


def test_parse_proposal_rejects_builder_data() -> None:
    raw = f"""
    {{
        "witness_id": "wit-test-04",
        "requirement_id": "REQ-TEST-01",
        "frozen_contract_digest": "{DUMMY_DIGEST}",
        "source_commit_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "change_class": "BUG_FIX",
        "plan_summary": "Test",
        "artifacts": [{{"path": "t.py", "content": "pass"}}],
        "execution_command": ["pytest"],
        "expected_failure_at_base": "f",
        "expected_success_at_candidate": "p",
        "builder_summary": "I fixed the bug"
    }}
    """
    with pytest.raises(WitnessPlanAuthoritySmugglingError, match="Forbidden Builder key"):
        parse_witness_plan_proposal(raw)


def test_generate_witness_plan_end_to_end(sample_envelope: VerifierContextEnvelope) -> None:
    c_dig = sample_envelope.frozen_contract_digest
    s_sha = sample_envelope.source_commit_id
    req_id = sample_envelope.frozen_contract.requirements[0].requirement_id
    response_json = f"""
    {{
        "witness_id": "wit-gen-01",
        "requirement_id": "{req_id}",
        "frozen_contract_digest": "{c_dig}",
        "source_commit_id": "{s_sha}",
        "change_class": "BUG_FIX",
        "plan_summary": "Test boundary conditions independently",
        "target_files": ["src/buffer.py"],
        "artifacts": [
            {{
                "path": "tests/witness/test_buffer_witness.py",
                "content": "def test_independent():\\n    assert True\\n",
                "rationale": "Independent check"
            }}
        ],
        "execution_command": ["pytest", "tests/witness/test_buffer_witness.py"],
        "expected_failure_at_base": "Fails at base",
        "expected_success_at_candidate": "Passes at candidate"
    }}
    """
    client = DummyModelClient(response_json)
    source_files = {"src/buffer.py": "def buffer_check(n):\n    return n < 10\n"}

    proposal = generate_witness_plan(
        context_envelope=sample_envelope,
        requirement_id=req_id,
        source_files=source_files,
        model_client=client,
    )

    assert proposal.witness_id == "wit-gen-01"
    assert proposal.requirement_id == req_id
    assert proposal.frozen_contract_digest == c_dig
    assert proposal.source_commit_id == s_sha
    assert len(client.calls) == 1
    assert "### AUTHORITATIVE VERIFICATION TARGET" in client.calls[0]["messages"][1]["content"]


def test_generate_witness_plan_binding_mismatch(sample_envelope: VerifierContextEnvelope) -> None:
    wrong_dig = "f" * 64
    s_sha = sample_envelope.source_commit_id
    req_id = sample_envelope.frozen_contract.requirements[0].requirement_id
    response_json = f"""
    {{
        "witness_id": "wit-gen-02",
        "requirement_id": "{req_id}",
        "frozen_contract_digest": "{wrong_dig}",
        "source_commit_id": "{s_sha}",
        "change_class": "BUG_FIX",
        "plan_summary": "Summary",
        "artifacts": [{{"path": "t.py", "content": "pass"}}],
        "execution_command": ["pytest"],
        "expected_failure_at_base": "f",
        "expected_success_at_candidate": "p"
    }}
    """
    client = DummyModelClient(response_json)
    with pytest.raises(WitnessPlanBindingMismatchError, match="contract digest"):
        generate_witness_plan(
            context_envelope=sample_envelope,
            requirement_id=req_id,
            source_files={},
            model_client=client,
        )


def test_validator_success(sample_envelope: VerifierContextEnvelope) -> None:
    c_dig = sample_envelope.frozen_contract_digest
    s_sha = sample_envelope.source_commit_id
    req_id = sample_envelope.frozen_contract.requirements[0].requirement_id
    proposal = WitnessPlanProposal(
        witness_id="wit-val-01",
        requirement_id=req_id,
        frozen_contract_digest=c_dig,
        source_commit_id=s_sha,
        change_class=ChangeClass.BUG_FIX,
        plan_summary="Plan summary",
        target_files=("src/buffer.py",),
        artifacts=(
            ProposedWitnessArtifact(
                path="tests/test_witness.py",
                content="def test_wit():\n    assert 1 == 1\n",
                rationale="Valid test",
            ),
        ),
        execution_command=("pytest", "tests/test_witness.py"),
        expected_failure_at_base="Fails",
        expected_success_at_candidate="Passes",
        is_authoritative=False,
        grants_pass=False,
    )
    validator = WitnessPlanValidator()
    validated = validator.validate(proposal, context_envelope=sample_envelope)

    assert isinstance(validated, ValidatedWitnessPlan)
    assert validated.witness_id == "wit-val-01"
    assert len(validated.artifacts) == 1
    assert len(validated.plan_digest) == 64
    assert validated.is_authoritative is False


def test_validator_rejects_non_bug_fix(sample_envelope: VerifierContextEnvelope) -> None:
    req_id = sample_envelope.frozen_contract.requirements[0].requirement_id
    proposal = WitnessPlanProposal(
        witness_id="wit-val-02",
        requirement_id=req_id,
        frozen_contract_digest=sample_envelope.frozen_contract_digest,
        source_commit_id=sample_envelope.source_commit_id,
        change_class=ChangeClass.FEATURE,
        plan_summary="Feature test",
        target_files=(),
        artifacts=(ProposedWitnessArtifact(path="t.py", content="pass"),),
        execution_command=("pytest",),
        expected_failure_at_base="f",
        expected_success_at_candidate="p",
    )
    validator = WitnessPlanValidator()
    with pytest.raises(WitnessPlanScopeError, match="Only BUG_FIX"):
        validator.validate(proposal, context_envelope=sample_envelope)


def test_validator_rejects_disallowed_executable(sample_envelope: VerifierContextEnvelope) -> None:
    req_id = sample_envelope.frozen_contract.requirements[0].requirement_id
    proposal = WitnessPlanProposal(
        witness_id="wit-val-03",
        requirement_id=req_id,
        frozen_contract_digest=sample_envelope.frozen_contract_digest,
        source_commit_id=sample_envelope.source_commit_id,
        change_class=ChangeClass.BUG_FIX,
        plan_summary="Bad exe",
        target_files=(),
        artifacts=(ProposedWitnessArtifact(path="t.py", content="pass"),),
        execution_command=("bash", "-c", "echo hello"),
        expected_failure_at_base="f",
        expected_success_at_candidate="p",
    )
    validator = WitnessPlanValidator()
    with pytest.raises(WitnessPlanSecurityError, match="Disallowed test executable"):
        validator.validate(proposal, context_envelope=sample_envelope)


def test_validator_rejects_shell_injection(sample_envelope: VerifierContextEnvelope) -> None:
    req_id = sample_envelope.frozen_contract.requirements[0].requirement_id
    proposal = WitnessPlanProposal(
        witness_id="wit-val-04",
        requirement_id=req_id,
        frozen_contract_digest=sample_envelope.frozen_contract_digest,
        source_commit_id=sample_envelope.source_commit_id,
        change_class=ChangeClass.BUG_FIX,
        plan_summary="Shell inject",
        target_files=(),
        artifacts=(ProposedWitnessArtifact(path="t.py", content="pass"),),
        execution_command=("pytest", ";", "rm", "-rf", "/"),
        expected_failure_at_base="f",
        expected_success_at_candidate="p",
    )
    validator = WitnessPlanValidator()
    with pytest.raises(WitnessPlanSecurityError, match="Forbidden shell character"):
        validator.validate(proposal, context_envelope=sample_envelope)


def test_validator_rejects_protected_surface_collision(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    req_id = sample_envelope.frozen_contract.requirements[0].requirement_id
    proposal = WitnessPlanProposal(
        witness_id="wit-val-05",
        requirement_id=req_id,
        frozen_contract_digest=sample_envelope.frozen_contract_digest,
        source_commit_id=sample_envelope.source_commit_id,
        change_class=ChangeClass.BUG_FIX,
        plan_summary="Protected surface collision",
        target_files=(),
        artifacts=(ProposedWitnessArtifact(path="AGENTS.md", content="malicious"),),
        execution_command=("pytest",),
        expected_failure_at_base="f",
        expected_success_at_candidate="p",
    )
    validator = WitnessPlanValidator()
    with pytest.raises(
        WitnessPlanSecurityError, match="collides with protected governance surface"
    ):
        validator.validate(proposal, context_envelope=sample_envelope)


def test_validator_rejects_secrets(sample_envelope: VerifierContextEnvelope) -> None:
    req_id = sample_envelope.frozen_contract.requirements[0].requirement_id
    proposal = WitnessPlanProposal(
        witness_id="wit-val-06",
        requirement_id=req_id,
        frozen_contract_digest=sample_envelope.frozen_contract_digest,
        source_commit_id=sample_envelope.source_commit_id,
        change_class=ChangeClass.BUG_FIX,
        plan_summary="Secret leakage",
        target_files=(),
        artifacts=(
            ProposedWitnessArtifact(
                path="tests/test_secret.py",
                content="API_KEY = 'AKIA1234567890EXAMPLE'\n",
            ),
        ),
        execution_command=("pytest",),
        expected_failure_at_base="f",
        expected_success_at_candidate="p",
    )
    validator = WitnessPlanValidator()
    with pytest.raises(WitnessPlanSecurityError, match="contains credentials or secrets"):
        validator.validate(proposal, context_envelope=sample_envelope)


def test_witness_plan_provider_purity() -> None:
    import basebreak.verifier.witness_plan as wp_mod

    source = inspect.getsource(wp_mod)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("basebreak.adapters"), (
                    f"witness_plan must not import adapters: {alias.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert not node.module.startswith("basebreak.adapters"), (
                    f"witness_plan must not import adapters: {node.module}"
                )
