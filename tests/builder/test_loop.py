"""Acceptance test suite for P-07.02: Nemotron Builder plan/code loop in disposable sandbox.

Validates the 11 core requirements:
1. Only valid authoritative BuilderContextEnvelope enters the loop.
2. Malformed/tampered context fails closed.
3. Structured Builder response validation (plan, proposed_file_actions, proposed_commands).
4. Model output cannot self-award PASS/VERIFIED authority.
5. Bounded model-call behavior (max_model_calls limit).
6. Timeout and error propagation.
7. Adapter failures do not silently fall back.
8. No provider credentials enter prompt/context or output.
9. Contract/context/source identity remains bound through the Builder result.
10. P-07.02 does not itself apply arbitrary model-proposed file edits or commands.
11. Provider-specific interaction occurs only through canonical adapter boundary.
"""

from __future__ import annotations

import ast
import inspect
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from basebreak.builder.context import (
    BuilderContextAllowlist,
    BuilderContextEnvelope,
    BuilderContextEnvelopeError,
)
from basebreak.builder.loop import (
    BoundedModelCallExceededError,
    BuilderLoopConfig,
    BuilderLoopConfigError,
    BuilderLoopResult,
    BuilderPlanCodeLoop,
    BuilderTimeoutError,
    FileActionType,
    InvalidProposedActionError,
    MalformedBuilderOutputError,
    SandboxExecutionFailedError,
    SecretLeakageError,
    TamperedContextError,
    assemble_builder_plan_code_context,
    parse_and_validate_builder_response,
)
from basebreak.compiler.freeze import FrozenContract, freeze_review_result
from basebreak.compiler.ingestion import NormalizedTask, ingest_task
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.review import ReviewBundle, ReviewResult, ReviewSession
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
)
from basebreak.domain.execution import ExecutionCommand, SandboxIdentity
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance

# --- Mock Adapters for Deterministic Unit Testing ---


@dataclass
class MockUsage:
    prompt_tokens: int = 120
    completion_tokens: int = 85
    total_tokens: int = 205


class MockModelClientResult:
    def __init__(
        self,
        content: str,
        *,
        model: str = "nvidia/Nemotron-3_5-Lightning",
        usage: MockUsage | None = None,
        telemetry_digest: str | None = "a" * 64,
    ) -> None:
        self.content = content
        self.raw_text = content
        self.returned_model = model
        self.configured_model = model
        self.usage = usage or MockUsage()
        self.telemetry_digest = telemetry_digest


class MockModelClient:
    """Mock model client adhering to the P-05 ModelClientProtocol."""

    def __init__(
        self,
        response_content: str | None = None,
        *,
        should_timeout: bool = False,
        should_fail: bool = False,
        error_message: str = "Model API error",
        exception_to_raise: Exception | None = None,
    ) -> None:
        self.response_content = response_content or (
            '{\n  "plan": {\n    "summary": "Implement pool cleanup",\n'
            '    "reasoning": "Closes leaked connections on idle",\n'
            '    "steps": ["Step 1", "Step 2"]\n  },\n'
            '  "proposed_file_actions": [\n    {\n      "path": "src/pool.py",\n'
            '      "action": "MODIFY",\n      "content": "def cleanup(): pass",\n'
            '      "rationale": "Add cleanup function"\n    }\n  ],\n'
            '  "proposed_commands": [\n    {\n      "command": "pytest tests/test_pool.py",\n'
            '      "rationale": "Run pool tests"\n    }\n  ]\n}'
        )
        self.should_timeout = should_timeout
        self.should_fail = should_fail
        self.error_message = error_message
        self.exception_to_raise = exception_to_raise
        self.calls: list[list[dict[str, str]]] = []
        self.kwargs_received: list[dict[str, Any]] = []

    def complete(self, messages: Any, **kwargs: Any) -> MockModelClientResult:
        self.calls.append(messages)
        self.kwargs_received.append(kwargs)
        if self.exception_to_raise is not None:
            raise self.exception_to_raise
        if self.should_timeout:
            raise TimeoutError("Model completion timed out after 45.0s")
        if self.should_fail:
            raise RuntimeError(self.error_message)
        return MockModelClientResult(self.response_content)


@dataclass
class MockSandboxHandle:
    sandbox_identity: SandboxIdentity
    image: str
    disposable: bool


@dataclass
class MockSandboxResult:
    sandbox_identity: SandboxIdentity
    exit_code: int = 0
    stdout: str = "BASEBREAK_BUILDER_SANDBOX_READY\n"
    stderr: str = ""
    duration_seconds: float = 0.5
    stdout_digest: str = "b" * 64
    stderr_digest: str = "c" * 64


class MockSandboxAdapter:
    """Mock sandbox adapter adhering to the P-05 SandboxAdapterProtocol."""

    def __init__(
        self,
        *,
        exit_code: int = 0,
        should_timeout: bool = False,
        should_fail: bool = False,
        error_message: str = "Sandbox error",
    ) -> None:
        self.exit_code = exit_code
        self.should_timeout = should_timeout
        self.should_fail = should_fail
        self.error_message = error_message
        self.created_handles: list[MockSandboxHandle] = []
        self.executed_commands: list[ExecutionCommand] = []
        self.torn_down_handles: list[MockSandboxHandle] = []

    def create_sandbox(self, image: str, disposable: bool) -> MockSandboxHandle:
        handle = MockSandboxHandle(
            sandbox_identity=SandboxIdentity(sandbox_id=f"sbx-test-{len(self.created_handles)}"),
            image=image,
            disposable=disposable,
        )
        self.created_handles.append(handle)
        return handle

    def execute_command(
        self, sandbox: MockSandboxHandle, command: ExecutionCommand, timeout_seconds: int = 300
    ) -> MockSandboxResult:
        self.executed_commands.append(command)
        if self.should_timeout:
            raise TimeoutError("Sandbox execution timed out")
        if self.should_fail:
            raise RuntimeError(self.error_message)
        return MockSandboxResult(
            sandbox_identity=sandbox.sandbox_identity,
            exit_code=self.exit_code,
            stdout="BASEBREAK_BUILDER_SANDBOX_READY\n" if self.exit_code == 0 else "",
            stderr="" if self.exit_code == 0 else "Sandbox execution failed",
        )

    def teardown_sandbox(self, sandbox: MockSandboxHandle) -> None:
        self.torn_down_handles.append(sandbox)


# --- Fixtures ---


@pytest.fixture
def sample_task() -> NormalizedTask:
    raw_text = (
        "Task: Fix memory leak in connection pool.\n"
        "Requirements:\n"
        "1. Close idle connections when pool exceeds threshold.\n"
        "2. Log warning when maximum pool size is reached."
    )
    return ingest_task(raw_text)


@pytest.fixture
def sample_contract(sample_task: NormalizedTask) -> FrozenContract:
    fact = DeterministicClassificationFact(
        inferred_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Fix memory leak in pool",
        evidence_citations=("Fix memory leak",),
        matched_signals=("fix", "leak"),
    )
    semantics = ChangeSemanticsClassification(
        task_digest=sample_task.task_digest,
        change_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Fix memory leak in pool",
        evidence_citations=("Fix memory leak",),
        deterministic_facts=fact,
    )
    cit1 = "Close idle connections when pool exceeds threshold."
    start1 = sample_task.normalized_text.index(cit1)
    end1 = start1 + len(cit1)

    reqs = [
        ProposedRequirement(
            statement="Close idle connections on threshold",
            citation=cit1,
            citation_start=start1,
            citation_end=end1,
            rationale="Prevent connection leakage",
        )
    ]
    bundle = ReviewBundle(task=sample_task, semantics=semantics, requirements=tuple(reqs))
    session = ReviewSession(bundle)
    review_result: ReviewResult = session.approve(reviewer_note="Approved for freeze")
    return freeze_review_result(review_result)


@pytest.fixture
def sample_source_identity() -> SourceIdentity:
    return SourceIdentity(
        locator="github.com/example/pool-lib",
        revision=CommitRevision("0123456789abcdef0123456789abcdef01234567"),
    )


@pytest.fixture
def sample_envelope(
    sample_contract: FrozenContract,
    sample_source_identity: SourceIdentity,
) -> BuilderContextEnvelope:
    repo = {"src/pool.py": "def get_connection(): pass\n"}
    allowlist = BuilderContextAllowlist.from_paths(["src/pool.py"])
    return assemble_builder_plan_code_context(
        frozen_contract=sample_contract,
        source_identity=sample_source_identity,
        allowlist=allowlist,
        repository_files=repo,
    )


# --- 1. Only Valid Authoritative BuilderContextEnvelope Enters the Loop ---


class TestEnvelopeAuthorityGate:
    def test_only_valid_envelope_enters_loop(self) -> None:
        loop = BuilderPlanCodeLoop(model_client=MockModelClient())
        with pytest.raises(TypeError, match="envelope must be BuilderContextEnvelope"):
            loop.run({"not": "an_envelope"})  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="envelope must be BuilderContextEnvelope"):
            loop.run("string_context")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="envelope must be BuilderContextEnvelope"):
            loop.run(None)  # type: ignore[arg-type]

    def test_tampered_context_digest_fails_closed(
        self,
        sample_envelope: BuilderContextEnvelope,
    ) -> None:
        loop = BuilderPlanCodeLoop(model_client=MockModelClient())

        # 1. Constructor-level rejection of tampered digest
        with pytest.raises(BuilderContextEnvelopeError):
            BuilderContextEnvelope(
                schema_version=sample_envelope.schema_version,
                frozen_contract=sample_envelope.frozen_contract,
                source_identity=sample_envelope.source_identity,
                admitted_files=sample_envelope.admitted_files,
                system_instructions=sample_envelope.system_instructions,
                context_digest="f" * 64,  # Replaced digest
                max_admitted_files=sample_envelope.max_admitted_files,
                max_total_bytes=sample_envelope.max_total_bytes,
            )

        # 2. Runtime loop-level rejection of tampered envelope
        tampered = assemble_builder_plan_code_context(
            frozen_contract=sample_envelope.frozen_contract,
            source_identity=sample_envelope.source_identity,
            allowlist=BuilderContextAllowlist.from_paths(["src/pool.py"]),
            repository_files={"src/pool.py": "def get_connection(): pass\n"},
        )
        object.__setattr__(tampered, "context_digest", "e" * 64)
        with pytest.raises(TamperedContextError, match="context_digest mismatch"):
            loop.run(tampered)

    def test_tampered_contract_digest_fails_closed(
        self,
        sample_envelope: BuilderContextEnvelope,
        sample_contract: FrozenContract,
    ) -> None:
        loop = BuilderPlanCodeLoop(model_client=MockModelClient())
        tampered = assemble_builder_plan_code_context(
            frozen_contract=sample_contract,
            source_identity=sample_envelope.source_identity,
            allowlist=BuilderContextAllowlist.from_paths(["src/pool.py"]),
            repository_files={"src/pool.py": "def get_connection(): pass\n"},
        )
        # Directly tamper the bound contract reference
        object.__setattr__(tampered.frozen_contract, "contract_digest", "0" * 64)

        with pytest.raises(TamperedContextError, match="context_digest mismatch"):
            loop.run(tampered)


# --- 2. Structured Builder Response Validation ---


class TestStructuredResponseValidation:
    def test_valid_structured_response_parsing(self) -> None:
        raw_json = (
            '{\n  "plan": {\n    "summary": "Fix connection pool leak",\n'
            '    "reasoning": "Release idle connections on threshold limit",\n'
            '    "steps": ["Inspect active connections", "Evict idle sockets"]\n  },\n'
            '  "proposed_file_actions": [\n    {\n      "path": "src/pool.py",\n'
            '      "action": "MODIFY",\n      "content": "def evict_idle(): pass",\n'
            '      "rationale": "Evict idle connections"\n    }\n  ],\n'
            '  "proposed_commands": [\n    {\n      "command": "pytest tests/test_pool.py",\n'
            '      "rationale": "Verify fix"\n    }\n  ]\n}'
        )
        proposal = parse_and_validate_builder_response(raw_json)
        assert proposal.plan.summary == "Fix connection pool leak"
        assert len(proposal.plan.steps) == 2
        assert len(proposal.proposed_file_actions) == 1
        assert proposal.proposed_file_actions[0].action == FileActionType.MODIFY
        assert proposal.proposed_file_actions[0].path == "src/pool.py"
        assert len(proposal.proposed_commands) == 1
        assert proposal.proposed_commands[0].command == "pytest tests/test_pool.py"
        assert proposal.is_authoritative is False

    def test_markdown_code_fence_stripped_and_parsed(self) -> None:
        raw_markdown = (
            '```json\n{\n  "plan": {"summary": "Markdown fenced plan"},\n'
            '  "proposed_file_actions": [],\n  "proposed_commands": []\n}\n```'
        )
        proposal = parse_and_validate_builder_response(raw_markdown)
        assert proposal.plan.summary == "Markdown fenced plan"
        assert proposal.proposed_file_actions == ()
        assert proposal.proposed_commands == ()

    def test_thinking_tags_and_surrounding_prose_stripped(self) -> None:
        raw_text = (
            "<think>Analyzing contract requirements for connection pool leak...</think>\n"
            "Here is the proposed fix:\n"
            "```json\n"
            "{\n"
            '  "plan": {"summary": "Fix leak on threshold"},\n'
            '  "proposed_file_actions": [],\n'
            '  "proposed_commands": []\n'
            "}\n"
            "```\n"
            "Hope this helps!"
        )
        proposal = parse_and_validate_builder_response(raw_text)
        assert proposal.plan.summary == "Fix leak on threshold"
        assert proposal.is_authoritative is False

    def test_missing_plan_fails_closed(self) -> None:
        raw_no_plan = '{"proposed_file_actions": [], "proposed_commands": []}'
        with pytest.raises(MalformedBuilderOutputError, match="missing required 'plan'"):
            parse_and_validate_builder_response(raw_no_plan)

    def test_malformed_json_fails_closed(self) -> None:
        with pytest.raises(MalformedBuilderOutputError, match="could not be parsed as JSON"):
            parse_and_validate_builder_response("This is not JSON text")

    def test_empty_response_fails_closed(self) -> None:
        with pytest.raises(MalformedBuilderOutputError, match="empty or non-string"):
            parse_and_validate_builder_response("")

    def test_non_dict_json_fails_closed(self) -> None:
        with pytest.raises(MalformedBuilderOutputError, match="must be a JSON object"):
            parse_and_validate_builder_response("[1, 2, 3]")

    def test_invalid_path_traversal_in_file_action_fails_closed(self) -> None:
        raw_traversal = (
            '{\n  "plan": {"summary": "Malicious path test"},\n'
            '  "proposed_file_actions": [\n    {\n'
            '      "path": "../../etc/shadow",\n      "action": "MODIFY",\n'
            '      "content": "exploit"\n    }\n  ]\n}'
        )
        with pytest.raises(InvalidProposedActionError, match="Path traversal detected"):
            parse_and_validate_builder_response(raw_traversal)

    def test_invalid_action_type_fails_closed(self) -> None:
        raw_bad_action = (
            '{\n  "plan": {"summary": "Bad action test"},\n'
            '  "proposed_file_actions": [\n    {\n'
            '      "path": "src/code.py",\n      "action": "EXECUTE",\n'
            '      "content": "bad"\n    }\n  ]\n}'
        )
        with pytest.raises(InvalidProposedActionError, match="Invalid action type"):
            parse_and_validate_builder_response(raw_bad_action)


# --- 3. Model Output Cannot Self-Award PASS/VERIFIED Authority ---


class TestNoBuilderSelfCertification:
    def test_model_cannot_self_certify_verdict(
        self,
        sample_envelope: BuilderContextEnvelope,
    ) -> None:
        # Attacking response asserting VERIFIED and PASS
        self_certifying_response = (
            '{\n  "plan": {"summary": "Self certification attempt"},\n'
            '  "proposed_file_actions": [],\n  "proposed_commands": [],\n'
            '  "verdict": "VERIFIED",\n  "status": "PASS",\n'
            '  "causal_proof": "PASSED_CAUSAL_TEST",\n  "is_authoritative": true\n}'
        )
        client = MockModelClient(response_content=self_certifying_response)
        loop = BuilderPlanCodeLoop(model_client=client)

        result: BuilderLoopResult = loop.run(sample_envelope)

        # Invariant checks:
        assert result.is_authoritative is False
        assert result.proposal.is_authoritative is False
        assert result.proposal.plan.is_authoritative is False
        assert not hasattr(result, "verdict") or getattr(result, "verdict", None) is None


# --- 4. Bounded Model-Call Behavior ---


class TestBoundedModelCalls:
    def test_bounded_model_call_limit_enforced(
        self,
        sample_envelope: BuilderContextEnvelope,
    ) -> None:
        cfg = BuilderLoopConfig(max_model_calls=1)
        client = MockModelClient()
        loop = BuilderPlanCodeLoop(model_client=client, config=cfg)

        # Call 1 succeeds
        res1 = loop.run(sample_envelope)
        assert res1 is not None
        assert loop.model_call_count == 1

        # Call 2 on same loop instance is bounded and fails closed
        with pytest.raises(BoundedModelCallExceededError, match="Model call limit"):
            loop.run(sample_envelope)

    def test_max_model_calls_bounds_validation(self) -> None:
        with pytest.raises(BuilderLoopConfigError, match="max_model_calls"):
            BuilderLoopConfig(max_model_calls=0)

        with pytest.raises(BuilderLoopConfigError, match="max_model_calls"):
            BuilderLoopConfig(max_model_calls=10)

    def test_type_error_does_not_trigger_second_invocation(
        self,
        sample_envelope: BuilderContextEnvelope,
    ) -> None:
        """Regression test for Defect 1: TypeError from model_client.complete() fails closed.

        Proves that a TypeError originating in model_client.complete() does NOT trigger
        a second invocation, ensuring exactly one attempt per permitted call.
        """
        client = MockModelClient(
            exception_to_raise=TypeError("Internal adapter TypeError simulation")
        )
        loop = BuilderPlanCodeLoop(model_client=client)

        with pytest.raises(TypeError, match="Internal adapter TypeError simulation"):
            loop.run(sample_envelope)

        assert len(client.calls) == 1
        assert loop.model_call_count == 1

    def test_provider_exception_does_not_silently_fallback(
        self,
        sample_envelope: BuilderContextEnvelope,
    ) -> None:
        """Regression test: arbitrary provider/model exceptions propagate fail-closed
        without retry.
        """
        client = MockModelClient(
            exception_to_raise=ValueError("Provider 500 internal server error")
        )
        loop = BuilderPlanCodeLoop(model_client=client)

        with pytest.raises(ValueError, match="Provider 500 internal server error"):
            loop.run(sample_envelope)

        assert len(client.calls) == 1
        assert loop.model_call_count == 1

    def test_timeout_authority_is_not_competing_or_misleading(self) -> None:
        """Proves timeout authority is owned exclusively by canonical P-05 client config.

        BuilderLoopConfig must NOT define an unused/misleading timeout_seconds attribute.
        """
        cfg = BuilderLoopConfig()
        assert not hasattr(cfg, "timeout_seconds")
        with pytest.raises(TypeError):
            BuilderLoopConfig(timeout_seconds=45.0)  # type: ignore[call-arg]


# --- 5. Timeout & Error Propagation ---


class TestTimeoutAndErrorPropagation:
    def test_model_timeout_propagates(
        self,
        sample_envelope: BuilderContextEnvelope,
    ) -> None:
        client = MockModelClient(should_timeout=True)
        loop = BuilderPlanCodeLoop(model_client=client)

        with pytest.raises(BuilderTimeoutError, match="timed out"):
            loop.run(sample_envelope)

    def test_model_adapter_failure_fails_closed(
        self,
        sample_envelope: BuilderContextEnvelope,
    ) -> None:
        client = MockModelClient(should_fail=True, error_message="HTTP 503 Provider Unavailable")
        loop = BuilderPlanCodeLoop(model_client=client)

        with pytest.raises(RuntimeError, match="HTTP 503 Provider Unavailable"):
            loop.run(sample_envelope)

    def test_sandbox_failure_fails_closed(
        self,
        sample_envelope: BuilderContextEnvelope,
    ) -> None:
        client = MockModelClient()
        sandbox = MockSandboxAdapter(exit_code=1)
        loop = BuilderPlanCodeLoop(model_client=client, sandbox_adapter=sandbox)

        with pytest.raises(SandboxExecutionFailedError, match="probe failed with exit code 1"):
            loop.run(sample_envelope)

    def test_require_sandbox_without_adapter_fails_closed(
        self,
    ) -> None:
        client = MockModelClient()
        cfg = BuilderLoopConfig(require_sandbox=True)
        with pytest.raises(BuilderLoopConfigError, match="sandbox_adapter is required"):
            BuilderPlanCodeLoop(model_client=client, sandbox_adapter=None, config=cfg)


# --- 6. Secret Redaction & Leakage Prevention ---


class TestSecretSafetyInLoop:
    def test_secret_leakage_in_prompt_fails_closed(
        self,
        sample_contract: FrozenContract,
        sample_source_identity: SourceIdentity,
    ) -> None:
        fake_secret = "sk-1234567890abcdef123"
        client = MockModelClient()
        loop = BuilderPlanCodeLoop(model_client=client)

        # Directly crafting envelope with prompt secret fails closed in loop
        tampered_env = assemble_builder_plan_code_context(
            frozen_contract=sample_contract,
            source_identity=sample_source_identity,
            allowlist=BuilderContextAllowlist.from_paths(["src/ok.py"]),
            repository_files={"src/ok.py": "# harmless code\n"},
            system_instructions=f"Instructions with secret: {fake_secret}",
        )
        with pytest.raises(SecretLeakageError):
            loop.run(tampered_env)

    def test_secret_in_model_response_fails_closed(
        self,
        sample_envelope: BuilderContextEnvelope,
    ) -> None:
        secret_content = "sk-1234567890abcdef123"
        leaking_response = (
            '{\n  "plan": {"summary": "Leaking secret plan"},\n'
            '  "proposed_file_actions": [\n    {\n'
            '      "path": "src/pool.py",\n      "action": "MODIFY",\n'
            f'      "content": "KEY = \\"{secret_content}\\""\n    }}\n  ],\n'
            '  "proposed_commands": []\n}}'.replace("}}", "}")
        )
        client = MockModelClient(response_content=leaking_response)
        loop = BuilderPlanCodeLoop(model_client=client)

        with pytest.raises(SecretLeakageError):
            loop.run(sample_envelope)


# --- 7. Contract, Context, and Source Identity Remains Bound ---


class TestIdentityPreservation:
    def test_identity_provenance_binding_in_result(
        self,
        sample_envelope: BuilderContextEnvelope,
    ) -> None:
        client = MockModelClient()
        sandbox = MockSandboxAdapter(exit_code=0)
        loop = BuilderPlanCodeLoop(
            model_client=client,
            sandbox_adapter=sandbox,
            config=BuilderLoopConfig(model_id="nvidia/Nemotron-3_5-Lightning"),
        )

        result = loop.run(sample_envelope, provenance=EvidenceProvenance.LOCAL_EXECUTION)

        # Exact unbroken binding
        assert result.frozen_contract_digest == sample_envelope.frozen_contract.contract_digest
        assert result.context_digest == sample_envelope.context_digest
        assert result.source_locator == sample_envelope.source_identity.locator
        assert result.source_commit_id == str(sample_envelope.source_identity.revision)
        assert result.source_subpath == sample_envelope.source_identity.subpath
        assert result.model_id == "nvidia/Nemotron-3_5-Lightning"
        assert result.returned_model == "nvidia/Nemotron-3_5-Lightning"
        assert result.sandbox_identity is not None
        assert result.sandbox_identity.sandbox_id == "sbx-test-0"
        assert result.sandbox_exit_code == 0
        assert result.provenance == EvidenceProvenance.LOCAL_EXECUTION
        assert result.is_authoritative is False

        # Serialization roundtrip
        d = result.to_dict()
        assert d["frozen_contract_digest"] == sample_envelope.frozen_contract.contract_digest
        assert d["context_digest"] == sample_envelope.context_digest
        assert d["is_authoritative"] is False


# --- 8. P-07.02 Does NOT Apply File Edits or Execute Arbitrary Commands ---


class TestNoMutationOrExecutionInP0702:
    def test_builder_does_not_apply_file_edits_or_commands(
        self,
        sample_envelope: BuilderContextEnvelope,
        tmp_path: Path,
    ) -> None:
        """P-07.02 MUST NOT apply proposed file edits or execute proposed commands.
        (Authority belongs to future task P-07.03).
        """
        test_file_path = tmp_path / "src" / "new_file.py"
        assert not test_file_path.exists()

        response = (
            '{\n  "plan": {"summary": "Propose creating a file and command"},\n'
            '  "proposed_file_actions": [\n    {\n'
            '      "path": "src/new_file.py",\n      "action": "CREATE",\n'
            '      "content": "print(\'new module\')\\n"\n    }\n  ],\n'
            '  "proposed_commands": [\n    {\n'
            '      "command": "rm -rf /tmp/test",\n      "rationale": "cleanup"\n    }\n  ]\n}'
        )
        client = MockModelClient(response_content=response)
        sandbox = MockSandboxAdapter(exit_code=0)
        loop = BuilderPlanCodeLoop(model_client=client, sandbox_adapter=sandbox)

        result = loop.run(sample_envelope)

        # Proposed actions are captured in proposal
        assert len(result.proposal.proposed_file_actions) == 1
        assert len(result.proposal.proposed_commands) == 1

        # BUT: file was NOT created on host filesystem
        assert not test_file_path.exists()

        # AND: sandbox ONLY executed the probe command, NEVER the model-proposed command
        assert len(sandbox.executed_commands) == 1
        assert sandbox.executed_commands[0].argv == ("echo", "BASEBREAK_BUILDER_SANDBOX_READY")
        assert "rm -rf" not in sandbox.executed_commands[0].argv


# --- 9. Provider Purity ---


class TestBuilderLoopProviderPurity:
    def test_builder_loop_has_zero_provider_imports(self) -> None:
        from basebreak.builder import loop

        src = inspect.getsource(loop)
        parsed = ast.parse(src)

        imported_modules: set[str] = set()
        for node in ast.walk(parsed):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module)

        forbidden_prefixes = (
            "basebreak.adapters",
            "openai",
            "nebius",
            "tavily",
            "anthropic",
            "requests",
            "urllib3",
            "aiohttp",
            "httpx",
        )
        for mod in imported_modules:
            for forbidden in forbidden_prefixes:
                assert not (mod == forbidden or mod.startswith(forbidden + ".")), (
                    f"Forbidden provider or adapter import found in builder/loop.py: {mod}"
                )


# --- 10. Parser Regression Safety (Blocker 1 QA Tests) ---


class TestParserRegressionSafety:
    """Dedicated regression tests for Blocker 1 (Builder JSON parser integrity)."""

    def test_valid_empty_content_survives(self) -> None:
        """Valid empty-string content '\"content\": \"\"' must NOT be corrupted."""
        from basebreak.builder.loop import parse_and_validate_builder_response

        raw_json = (
            "{\n"
            '  "plan": {"summary": "Empty content action"},\n'
            '  "proposed_file_actions": [\n'
            "    {\n"
            '      "path": "src/empty.py",\n'
            '      "action": "CREATE",\n'
            '      "content": ""\n'
            "    }\n"
            "  ]\n"
            "}"
        )
        proposal = parse_and_validate_builder_response(raw_json)
        assert len(proposal.proposed_file_actions) == 1
        assert proposal.proposed_file_actions[0].content == ""

    def test_valid_empty_rationale_survives(self) -> None:
        """Valid empty-string rationale '\"rationale\": \"\"' must NOT be corrupted."""
        from basebreak.builder.loop import parse_and_validate_builder_response

        raw_json = (
            "{\n"
            '  "plan": {"summary": "Empty rationale action"},\n'
            '  "proposed_commands": [\n'
            "    {\n"
            '      "command": "pytest",\n'
            '      "rationale": ""\n'
            "    }\n"
            "  ]\n"
            "}"
        )
        proposal = parse_and_validate_builder_response(raw_json)
        assert len(proposal.proposed_commands) == 1
        assert proposal.proposed_commands[0].rationale == ""

    def test_ordinary_valid_strings_survive_unchanged(self) -> None:
        """Ordinary valid strings survive strictly unchanged."""
        from basebreak.builder.loop import parse_and_validate_builder_response

        raw_json = (
            "{\n"
            '  "plan": {"summary": "Standard summary string"},\n'
            '  "proposed_file_actions": [\n'
            "    {\n"
            '      "path": "src/mod.py",\n'
            '      "action": "MODIFY",\n'
            '      "content": "def hello():\\n    return \'world\'\\n"\n'
            "    }\n"
            "  ]\n"
            "}"
        )
        proposal = parse_and_validate_builder_response(raw_json)
        assert proposal.plan.summary == "Standard summary string"
        assert proposal.proposed_file_actions[0].content == "def hello():\n    return 'world'\n"

    def test_escaped_quotes_survive_unmodified(self) -> None:
        """Valid escaped quotes inside string values survive unchanged."""
        from basebreak.builder.loop import parse_and_validate_builder_response

        raw_json = (
            "{\n"
            '  "plan": {"summary": "Escaped \\"quotes\\" summary"},\n'
            '  "proposed_file_actions": [\n'
            "    {\n"
            '      "path": "src/escaped.py",\n'
            '      "action": "CREATE",\n'
            '      "content": "val = \\"quoted string\\""\n'
            "    }\n"
            "  ]\n"
            "}"
        )
        proposal = parse_and_validate_builder_response(raw_json)
        assert proposal.plan.summary == 'Escaped "quotes" summary'
        assert proposal.proposed_file_actions[0].content == 'val = "quoted string"'

    def test_legitimate_strings_beginning_with_quotes_not_corrupted(self) -> None:
        """Strings beginning with escaped quotes are not corrupted."""
        from basebreak.builder.loop import parse_and_validate_builder_response

        raw_json = r"""{
  "plan": {"summary": "\"leading quote summary"},
  "proposed_file_actions": [
    {
      "path": "src/quoted.py",
      "action": "CREATE",
      "content": "\"docstring\""
    }
  ]
}"""
        proposal = parse_and_validate_builder_response(raw_json)
        assert proposal.plan.summary == '"leading quote summary'
        assert proposal.proposed_file_actions[0].content == '"docstring"'

    def test_malformed_nemotron_redundant_quotes_recovered_in_fallback(self) -> None:
        """Malformed redundant quotes pattern emitted by Nemotron is recovered in fallback."""
        from basebreak.builder.loop import parse_and_validate_builder_response

        # Malformed: "content": """"hello" -> 4 unescaped opening quotes
        malformed_json = (
            "{\n"
            '  "plan": {"summary": "Fix docstring"},\n'
            '  "proposed_file_actions": [\n'
            "    {\n"
            '      "path": "src/doc.py",\n'
            '      "action": "CREATE",\n'
            '      "content": """"hello"\n'
            "    }\n"
            "  ]\n"
            "}"
        )
        proposal = parse_and_validate_builder_response(malformed_json)
        assert proposal.plan.summary == "Fix docstring"
        assert len(proposal.proposed_file_actions) == 1
        assert proposal.proposed_file_actions[0].content == "hello"

    def test_unrelated_malformed_json_fails_closed(self) -> None:
        """Unrelated malformed JSON fails closed with MalformedBuilderOutputError."""
        from basebreak.builder.loop import (
            MalformedBuilderOutputError,
            parse_and_validate_builder_response,
        )

        bad_jsons = [
            '{"plan": {"summary": "truncated"',
            "{plan: no quotes}",
            '{"missing_plan": true}',
            '{"plan": 123}',
            '{"plan": {"summary": "ok"}, "proposed_file_actions": "not a list"}',
        ]
        for bad in bad_jsons:
            with pytest.raises(MalformedBuilderOutputError):
                parse_and_validate_builder_response(bad)
