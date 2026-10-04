"""Adversarial isolation and boundary test suite for P-08.05.

Comprehensive tests proving the mechanical trust boundary between Builder and Verifier.
Covers 14 distinct attack classes:
1. Builder sandbox/handle reuse attempt.
2. Builder workspace inheritance attempt.
3. Caller-supplied verifier trusted-input forgery.
4. Caller-created sealed witness record claiming authority.
5. Witness digest/artifact mutation.
6. Hidden witness path traversal.
7. Builder file enumeration/read attempt.
8. Builder mutation/deletion attempt against verifier-only assets.
9. Hidden witness leakage through serialized result/evidence/error surfaces.
10. Missing or ambiguous verifier sandbox identity.
11. Mutable source/ref substitution.
12. Fake LIVE_NEBIUS / provenance laundering attempt.
13. Host/simulation fallback on a required isolated execution path.
14. Regression proving existing P-07 Builder paths still work without gaining verifier visibility.
"""

from __future__ import annotations

import pytest

from basebreak.builder.context import (
    BuilderContextAllowlist,
    VerifierAssetContextError,
)
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
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.source import CommitRevision, RequestedRef, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.security.protected_surfaces import ProtectedSurfaceViolation
from basebreak.verifier.boundary import (
    REDACTED_WITNESS_ID,
    REDACTED_WITNESS_TEXT,
    VerifierAssetExclusionError,
    VerifierBoundaryEnforcer,
    WitnessLeakageInResultError,
)
from basebreak.verifier.context import (
    BuilderAuthoritySmugglingError,
    UnpinnedSourceError,
    UntrustedBuilderInputError,
    VerifierContextEnvelope,
)
from basebreak.verifier.sandbox import (
    BuilderSandboxReuseError,
    BuilderWorkspaceInheritanceError,
    HostExecutionFallbackError,
    MissingSandboxIdentityError,
    SimulationFallbackError,
    VerifierSandboxConfig,
    VerifierSandboxManager,
)
from basebreak.verifier.witness_store import (
    SealedWitnessRecord,
    TrustedWitnessVault,
    UntrustedWitnessAuthorityError,
    WitnessArtifact,
    WitnessPathSecurityError,
    WitnessTamperingError,
    build_canonical_witness_identity_payload,
    compute_seal_digest,
)

# --- Test Fixtures & Adapters ---


class IsolatedMockAdapter:
    """Mock sandbox adapter that assigns distinct identities."""

    def __init__(self, sandbox_id: str = "sbx-isolated-001") -> None:
        self.sandbox_id = sandbox_id
        self.torn_down: list[str] = []

    def create_sandbox(self, image: str, timeout_seconds: int) -> SandboxIdentity:
        return SandboxIdentity(sandbox_id=self.sandbox_id)

    def teardown_sandbox(self, sandbox_identity: SandboxIdentity) -> None:
        self.torn_down.append(sandbox_identity.sandbox_id)


class SimulatedFallbackAdapter:
    """Simulated adapter attempting to masquerade as live."""

    is_simulation = True

    def create_sandbox(self, image: str, timeout_seconds: int) -> SandboxIdentity:
        return SandboxIdentity(sandbox_id="sbx-sim-fake")


@pytest.fixture
def sample_task() -> NormalizedTask:
    raw_text = (
        "Task: Fix memory leak in connection pool.\n"
        "Requirements:\n"
        "1. Close idle connections when pool exceeds threshold."
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
) -> VerifierContextEnvelope:
    return VerifierContextEnvelope.create(
        frozen_contract=sample_contract,
        source_identity=sample_source_identity,
    )


# --- 14 Adversarial Isolation Attacks ---


def test_attack_01_builder_sandbox_handle_reuse(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Attack 1: Builder attempts to pass its own sandbox handle/ID to Verifier."""
    builder_sbx_id = "sbx-builder-compromised"
    adapter = IsolatedMockAdapter(sandbox_id=builder_sbx_id)
    manager = VerifierSandboxManager(known_builder_sandbox_ids=[builder_sbx_id])

    with pytest.raises(BuilderSandboxReuseError, match="reuse Builder sandbox"):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=adapter,
        )

    assert builder_sbx_id in adapter.torn_down


def test_attack_02_builder_workspace_inheritance() -> None:
    """Attack 2: Verifier configuration attempts to reuse or inherit Builder workspace path."""
    with pytest.raises(BuilderWorkspaceInheritanceError, match="collides with"):
        VerifierSandboxManager(config=VerifierSandboxConfig(workspace_path="/workspace/candidate"))

    with pytest.raises(BuilderWorkspaceInheritanceError, match="collides with"):
        VerifierSandboxManager(config=VerifierSandboxConfig(workspace_path="/builder_workspace"))


def test_attack_03_caller_supplied_verifier_trusted_input_forgery(
    sample_contract: FrozenContract,
    sample_source_identity: SourceIdentity,
) -> None:
    """Attack 3: Caller tries to pass Builder proposals, thoughts, or fake pass authority."""
    # Smuggling Builder thoughts/proposals
    with pytest.raises(UntrustedBuilderInputError):
        VerifierContextEnvelope.create(
            frozen_contract=sample_contract,
            source_identity=sample_source_identity,
            builder_proposal={"fake": "patch"},
        )

    with pytest.raises(UntrustedBuilderInputError):
        VerifierContextEnvelope.create(
            frozen_contract=sample_contract,
            source_identity=sample_source_identity,
            builder_reasoning="Model claims it solved the bug",
        )

    # Smuggling self-certification flags
    with pytest.raises(BuilderAuthoritySmugglingError):
        VerifierContextEnvelope.create(
            frozen_contract=sample_contract,
            source_identity=sample_source_identity,
            is_verified=True,
        )

    with pytest.raises(BuilderAuthoritySmugglingError):
        VerifierContextEnvelope.create(
            frozen_contract=sample_contract,
            source_identity=sample_source_identity,
            claims_pass=True,
        )


def test_attack_04_caller_created_sealed_witness_record_authority_forgery() -> None:
    """Attack 4: Caller instantiates a field-valid SealedWitnessRecord out of thin air."""
    vault = TrustedWitnessVault()
    art = WitnessArtifact.from_text(
        path="tests/verifier/test_forged.py",
        content="def test_forged(): assert True\n",
    )

    payload = build_canonical_witness_identity_payload(
        witness_id="wit-forged-007",
        requirement_id="REQ-001",
        frozen_contract_digest="0" * 64,
        source_commit_id="0" * 40,
        artifacts=(art,),
        created_at_utc="2026-10-04T00:00:00Z",
    )
    seal_digest = compute_seal_digest(payload)

    forged = SealedWitnessRecord(
        witness_id="wit-forged-007",
        requirement_id="REQ-001",
        frozen_contract_digest="0" * 64,
        source_commit_id="0" * 40,
        artifacts=(art,),
        seal_digest=seal_digest,
        created_at_utc="2026-10-04T00:00:00Z",
        vault_signature="0" * 64,
        is_sealed=True,
    )

    # Possession of the object or is_sealed=True grants ZERO verification authority
    with pytest.raises(UntrustedWitnessAuthorityError, match="not sealed by this trusted vault"):
        vault.verify_witness_integrity(forged)


def test_attack_05_witness_digest_artifact_mutation() -> None:
    """Attack 5: Adversary mutates witness code or seal digest after sealing."""
    vault = TrustedWitnessVault()
    art = WitnessArtifact.from_text(
        path="tests/verifier/test_genuine.py",
        content="def test_genuine(): assert True\n",
    )
    rec = vault.seal_witness(
        witness_id="wit-genuine-001",
        requirement_id="REQ-001",
        frozen_contract_digest="0" * 64,
        source_commit_id="0" * 40,
        artifacts=[art],
    )

    # 1. Mutate artifact code
    tampered_art = WitnessArtifact.from_text(
        path="tests/verifier/test_genuine.py",
        content="def test_genuine(): assert False\n",
    )
    object.__setattr__(rec, "artifacts", (tampered_art,))

    with pytest.raises(WitnessTamperingError):
        vault.verify_witness_integrity(rec)


def test_attack_06_hidden_witness_path_traversal() -> None:
    """Attack 6: Witness artifact path attempts root escape or directory traversal."""
    with pytest.raises(WitnessPathSecurityError):
        WitnessArtifact.from_text(
            path="../../../etc/shadow",
            content="root:x:0:0",
        )

    with pytest.raises(WitnessPathSecurityError):
        WitnessArtifact.from_text(
            path="tests/verifier/../../escape.py",
            content="def escape(): pass",
        )


def test_attack_07_builder_file_enumeration_read_attempt() -> None:
    """Attack 7: Builder attempts to list or read verifier assets in workspace."""
    enforcer = VerifierBoundaryEnforcer()
    vault = TrustedWitnessVault()
    art = WitnessArtifact.from_text(
        path="tests/verifier/test_isolated_challenge.py",
        content="def test_challenge(): pass\n",
    )
    vault.seal_witness(
        witness_id="wit-c-001",
        requirement_id="REQ-001",
        frozen_contract_digest="0" * 64,
        source_commit_id="0" * 40,
        artifacts=[art],
    )

    # Builder context admission is rejected
    with pytest.raises(VerifierAssetExclusionError):
        enforcer.validate_builder_context_path(art.path, vault=vault)

    # File enumeration filter completely removes verifier and witness assets
    repo_files = [
        "src/app/main.py",
        art.path,
        "src/basebreak/verifier/sandbox.py",
        "tests/verifier/test_something.py",
        "pyproject.toml",
    ]
    visible_files = enforcer.filter_repository_paths_for_builder(repo_files, vault=vault)
    assert visible_files == ["pyproject.toml", "src/app/main.py"]


def test_attack_08_builder_mutation_deletion_against_verifier_assets() -> None:
    """Attack 8: Candidate patch attempts to modify or delete verifier code."""
    enforcer = VerifierBoundaryEnforcer()
    patch = (
        "diff --git a/src/basebreak/verifier/sandbox.py b/src/basebreak/verifier/sandbox.py\n"
        "--- a/src/basebreak/verifier/sandbox.py\n"
        "+++ b/src/basebreak/verifier/sandbox.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-# verifier\n"
        "+# neutralized\n"
    )

    with pytest.raises(ProtectedSurfaceViolation, match="touches protected surface"):
        enforcer.validate_candidate_patch_isolation(patch)


def test_attack_09_hidden_witness_leakage_in_error_or_serialized_results() -> None:
    """Attack 9: Adversary inspects error logs or public results for witness secrets."""
    enforcer = VerifierBoundaryEnforcer()
    vault = TrustedWitnessVault()
    art = WitnessArtifact.from_text(
        path="tests/verifier/test_top_secret.py",
        content="SECRET_CHECK_CALL_TOKEN_ABC123()\n",
    )
    rec = vault.seal_witness(
        witness_id="wit-leak-001",
        requirement_id="REQ-001",
        frozen_contract_digest="0" * 64,
        source_commit_id="0" * 40,
        artifacts=[art],
    )

    # Error traceback is sanitized
    raw_error = (
        f"Failure at {art.path}:\n"
        f"    SECRET_CHECK_CALL_TOKEN_ABC123()\n"
        f"Witness: {rec.witness_id}, Seal: {rec.seal_digest}\n"
    )
    sanitized = enforcer.sanitize_verifier_error_output(raw_error, vault=vault)

    assert "SECRET_CHECK_CALL_TOKEN_ABC123" not in sanitized
    assert REDACTED_WITNESS_TEXT in sanitized
    assert rec.witness_id not in sanitized
    assert REDACTED_WITNESS_ID in sanitized

    # Public result object leakage is detected
    leaking_result = {"trace": "SECRET_CHECK_CALL_TOKEN_ABC123()"}
    with pytest.raises(WitnessLeakageInResultError):
        enforcer.validate_public_result_isolation(leaking_result, vault=vault)


def test_attack_10_missing_or_ambiguous_verifier_sandbox_identity(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Attack 10: Sandbox adapter returns ambiguous or empty sandbox identity."""

    class AmbiguousAdapter:
        def create_sandbox(self, image: str, timeout_seconds: int) -> str:
            return "    \t  \n"

    manager = VerifierSandboxManager()
    with pytest.raises(MissingSandboxIdentityError):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=AmbiguousAdapter(),
        )


def test_attack_11_mutable_source_ref_substitution(
    sample_contract: FrozenContract,
) -> None:
    """Attack 11: Caller substitutes mutable git branch for pinned commit revision."""
    fake_source = SourceIdentity(
        locator="github.com/example/pool-lib",
        revision=CommitRevision("0123456789abcdef0123456789abcdef01234567"),
    )
    object.__setattr__(fake_source, "revision", RequestedRef("main"))

    with pytest.raises(UnpinnedSourceError, match="must use CommitRevision"):
        VerifierContextEnvelope.create(
            frozen_contract=sample_contract,
            source_identity=fake_source,
        )


def test_attack_12_fake_live_nebius_provenance_laundering(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Attack 12: Caller claims LIVE_NEBIUS provenance with a simulated/mock adapter."""
    sim_adapter = SimulatedFallbackAdapter()
    manager = VerifierSandboxManager()

    with pytest.raises(SimulationFallbackError, match="is simulated"):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=sim_adapter,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
        )


def test_attack_13_host_or_simulation_fallback_on_isolated_path(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Attack 13: Sandbox adapter is None; runtime refuses to fall back to host."""
    manager = VerifierSandboxManager()

    with pytest.raises(HostExecutionFallbackError, match="strictly prohibited"):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=None,
        )


def test_attack_14_regression_builder_paths_work_without_verifier_visibility() -> None:
    """Attack 14: Existing P-07 Builder allowlist works normally, but rejects verifier assets."""
    # Standard builder files are permitted
    clean_allowlist = BuilderContextAllowlist.from_paths(
        ["src/pool/core.py", "tests/test_pool.py"],
        description="Clean builder context",
    )
    assert len(clean_allowlist.allowed_paths) == 2

    # Attempting to admit verifier assets into Builder context fails closed
    with pytest.raises(VerifierAssetContextError):
        BuilderContextAllowlist.from_paths(
            ["src/pool/core.py", "tests/verifier/test_witness.py"],
            description="Malicious builder context attempting verifier read",
        )
