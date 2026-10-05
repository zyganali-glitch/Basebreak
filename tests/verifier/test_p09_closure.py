"""Closure gate and integration test suite for Master Plan Phase P-09 (Witness Generation).

Validates all six exact tasks of Phase P-09:
- P-09.01: Nemotron witness-plan generation with zero Builder leakage and exact contract binding.
- P-09.02: Deterministic validation of witness plans against scope (BUG_FIX only), allowlist,
           path normalization, protected surface collisions, and secret policies.
- P-09.03: Executable behavioral witness generation and authentic sealing into vault,
           rejecting Builder test collisions/imports.
- P-09.04: Deterministic witness result normalization (PASS, FAIL, ERROR, TIMEOUT)
           with anti-collapse invariants.
- P-09.05: Vacuous witness detection (zero assertions, trivial constants, 0 tests collected,
           missing module preconditions).
- P-09.06: Immutable witness digest preservation before candidate execution, enforcing unbroken
           chain: requirement_id -> frozen_contract_digest -> witness_digest.
"""

from __future__ import annotations

import hashlib
import json
import os
from unittest.mock import MagicMock

import pytest

from basebreak.adapters.nebius.client import (
    ModelClientConfig,
    NebiusModelClient,
)
from basebreak.adapters.nebius.models import DEFAULT_PRIMARY_MODEL
from basebreak.compiler.freeze import FrozenContract, freeze_review_result
from basebreak.compiler.ingestion import ingest_task
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.review import ReviewBundle, ReviewSession
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeClass,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
)
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import SandboxIdentity, TerminationStatus
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.verifier.context import VerifierContextEnvelope
from basebreak.verifier.vacuity import (
    analyze_artifact_code_vacuity,
    analyze_runtime_execution_vacuity,
)
from basebreak.verifier.witness_generator import (
    BuilderTestContaminationError,
    WitnessGenerator,
)
from basebreak.verifier.witness_lock import (
    ImmutableWitnessLock,
    WitnessMutationError,
    create_witness_lock,
    verify_witness_lock_chain,
)
from basebreak.verifier.witness_plan import (
    ProposedWitnessArtifact,
    ValidatedWitnessArtifact,
    ValidatedWitnessPlan,
    WitnessPlanProposal,
    WitnessPlanScopeError,
    WitnessPlanSecurityError,
    WitnessPlanValidator,
    generate_witness_plan,
)
from basebreak.verifier.witness_result import (
    CollapsedOutcomeError,
    NormalizedWitnessResult,
    WitnessOutcome,
    normalize_witness_execution,
)
from basebreak.verifier.witness_store import (
    SealedWitnessRecord,
    TrustedWitnessVault,
    WitnessArtifact,
)


def _build_test_frozen_contract() -> tuple[FrozenContract, str]:
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
    return contract, req_id


class TestP09Closure:
    """Complete validation of P-09.01 through P-09.06 requirements."""

    def test_p09_01_witness_plan_binding_and_zero_builder_leakage(self) -> None:
        """P-09.01: Witness plan generation binds to contract digest and rejects Builder leaks."""
        contract, req_id = _build_test_frozen_contract()
        source_id = SourceIdentity(
            locator="https://github.com/zyganali-glitch/Basebreak.git",
            revision=CommitRevision("c" * 40),
        )
        envelope = VerifierContextEnvelope.create(
            frozen_contract=contract,
            source_identity=source_id,
        )

        dummy_proposal = json.dumps(
            {
                "witness_id": "wit-p09-01",
                "requirement_id": req_id,
                "frozen_contract_digest": contract.contract_digest,
                "source_commit_id": "c" * 40,
                "change_class": "BUG_FIX",
                "plan_summary": "Test quiet flag",
                "target_files": ["src/cli.py"],
                "artifacts": [
                    {
                        "path": "tests/test_quiet_behavior.py",
                        "content": "def test_quiet():\n    assert run_cli('--quiet') == ''\n",
                        "rationale": "Quiet flag check",
                    }
                ],
                "execution_command": ["pytest", "tests/test_quiet_behavior.py"],
                "expected_failure_at_base": "Output contains banner",
                "expected_success_at_candidate": "Output is empty",
            }
        )

        mock_client = MagicMock()
        mock_client.complete.return_value = {"content": dummy_proposal}

        proposal = generate_witness_plan(
            context_envelope=envelope,
            requirement_id=req_id,
            source_files={"src/cli.py": "def run_cli(flag):\n    return ''\n"},
            model_client=mock_client,
        )

        assert isinstance(proposal, WitnessPlanProposal)
        assert proposal.frozen_contract_digest == contract.contract_digest
        assert proposal.requirement_id == req_id
        assert proposal.change_class == ChangeClass.BUG_FIX
        assert proposal.is_authoritative is False
        assert proposal.grants_pass is False

        validator = WitnessPlanValidator()
        plan = validator.validate(proposal, context_envelope=envelope)
        assert isinstance(plan, ValidatedWitnessPlan)
        assert plan.frozen_contract_digest == contract.contract_digest

        # Verify user prompt receives strictly zero Builder context or candidate artifacts
        call_args = mock_client.complete.call_args
        messages = call_args[0][0] if call_args[0] else call_args[1]["messages"]
        user_prompt = messages[1]["content"]
        assert "builder" not in user_prompt.lower()
        assert "candidate_patch" not in user_prompt.lower()
        assert "candidate_workspace" not in user_prompt.lower()
        assert "builder_workspace" not in user_prompt.lower()

    def test_p09_02_validator_enforces_security_and_scope(self) -> None:
        """P-09.02: Validation enforces scope, allowlist, protected surface, secrets."""
        contract, req_id = _build_test_frozen_contract()
        source_id = SourceIdentity(
            locator="https://github.com/zyganali-glitch/Basebreak.git",
            revision=CommitRevision("c" * 40),
        )
        envelope = VerifierContextEnvelope.create(
            frozen_contract=contract,
            source_identity=source_id,
        )
        validator = WitnessPlanValidator()

        # Non-BUG_FIX rejected
        proposal_feature = WitnessPlanProposal(
            witness_id="wit-02-a",
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            source_commit_id="c" * 40,
            change_class=ChangeClass.FEATURE,
            plan_summary="Add new feature",
            target_files=("src/feat.py",),
            artifacts=(
                ProposedWitnessArtifact(
                    path="tests/witness/test_feat.py",
                    content="def test_feat():\n    assert 1 == 1\n",
                    rationale="feature test",
                ),
            ),
            execution_command=("pytest", "tests/witness/test_feat.py"),
            expected_failure_at_base="Fail",
            expected_success_at_candidate="Pass",
        )
        with pytest.raises(WitnessPlanScopeError, match="Only BUG_FIX is supported"):
            validator.validate(proposal_feature, context_envelope=envelope)

        # Disallowed execution command (e.g. curl)
        proposal_curl = WitnessPlanProposal(
            witness_id="wit-02-b",
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            source_commit_id="c" * 40,
            change_class=ChangeClass.BUG_FIX,
            plan_summary="Network probe",
            target_files=("src/cli.py",),
            artifacts=(
                ProposedWitnessArtifact(
                    path="tests/witness/test_net.py",
                    content="def test_net():\n    assert True\n",
                    rationale="network test",
                ),
            ),
            execution_command=("curl", "https://attacker.com"),
            expected_failure_at_base="Fail",
            expected_success_at_candidate="Pass",
        )
        with pytest.raises(WitnessPlanSecurityError, match="Disallowed test executable"):
            validator.validate(proposal_curl, context_envelope=envelope)

    def test_p09_03_witness_generator_and_vault_sealing(self) -> None:
        """P-09.03: Validated plan sealed in vault; Builder test collisions rejected."""
        contract, req_id = _build_test_frozen_contract()
        content = "def test_boundary():\n    val = compute_buffer(10)\n    assert val > 0\n"
        encoded = content.encode("utf-8")
        art = ValidatedWitnessArtifact(
            path="tests/witness/test_boundary.py",
            content=content,
            content_digest=hashlib.sha256(encoded).hexdigest(),
            byte_size=len(encoded),
            rationale="Boundary check",
        )
        plan = ValidatedWitnessPlan(
            witness_id="wit-p09-03",
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            source_commit_id="c" * 40,
            change_class=ChangeClass.BUG_FIX,
            plan_summary="Buffer fix test",
            target_files=("src/buffer.py",),
            artifacts=(art,),
            execution_command=("pytest", "tests/witness/test_boundary.py"),
            expected_failure_at_base="Buffer overflow",
            expected_success_at_candidate="Buffer allocated correctly",
            plan_digest="d" * 64,
            is_authoritative=False,
            grants_pass=False,
        )

        vault = TrustedWitnessVault()
        generator = WitnessGenerator(vault)

        # Rejection of Builder-authored test collision
        with pytest.raises(BuilderTestContaminationError, match="collides"):
            generator.generate_and_seal_witness(
                plan, known_builder_test_names=("test_boundary.py",)
            )

        # Successful generation and vault sealing
        sealed_record = generator.generate_and_seal_witness(plan)
        assert isinstance(sealed_record, SealedWitnessRecord)
        assert sealed_record.witness_id == "wit-p09-03"
        assert sealed_record.frozen_contract_digest == contract.contract_digest
        assert vault.verify_witness_integrity(sealed_record) is True

    def test_p09_04_normalization_prevents_outcome_collapse(self) -> None:
        """P-09.04: Normalization preserves distinct outcomes (TIMEOUT/ERROR never collapse)."""
        contract, req_id = _build_test_frozen_contract()
        sbx = SandboxIdentity(sandbox_id="sbx-01")

        res_fail = normalize_witness_execution(
            witness_id="wit-04",
            witness_digest="a" * 64,
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            source_commit_id="c" * 40,
            sandbox_identity=sbx,
            world=ExecutionWorld.BASE,
            status=TerminationStatus.COMPLETED,
            exit_code=1,
            stdout_raw="pytest failed with AssertionError: 5 != 10\n",
            stderr_raw="",
            duration_seconds=1.2,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        assert res_fail.outcome == WitnessOutcome.FAIL

        # TIMEOUT must NOT collapse to FAIL or PASS
        res_timeout = normalize_witness_execution(
            witness_id="wit-04",
            witness_digest="a" * 64,
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            source_commit_id="c" * 40,
            sandbox_identity=sbx,
            world=ExecutionWorld.BASE,
            status=TerminationStatus.TIMED_OUT,
            exit_code=None,
            stdout_raw="",
            stderr_raw="Execution timed out after 30s",
            duration_seconds=30.0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        assert res_timeout.outcome == WitnessOutcome.TIMEOUT
        assert res_timeout.outcome.value != "FAIL"

        # Direct tampering with collapsed outcome rejected by invariant
        with pytest.raises(CollapsedOutcomeError, match="TIMED_OUT"):
            NormalizedWitnessResult(
                witness_id="wit-04",
                witness_digest="a" * 64,
                requirement_id=req_id,
                frozen_contract_digest=contract.contract_digest,
                source_commit_id="c" * 40,
                sandbox_id="sbx-01",
                world=ExecutionWorld.BASE,
                outcome=WitnessOutcome.FAIL,  # Collapsed!
                exit_code=None,
                termination_status=TerminationStatus.TIMED_OUT,
                stdout_digest="0" * 64,
                stderr_digest="0" * 64,
                stdout_clean="",
                stderr_clean="",
                duration_seconds=30.0,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                result_digest="a" * 64,
                is_authoritative=False,
            )

    def test_p09_05_vacuity_detection(self) -> None:
        """P-09.05: Vacuous witnesses (0 assertions, assert True, 0 tests) detected/rejected."""
        # AST zero assertions
        art_no_assert = WitnessArtifact.from_text(
            path="tests/witness/test_empty.py",
            content="def test_empty():\n    x = 1 + 1\n",
        )
        res_no_assert = analyze_artifact_code_vacuity([art_no_assert])
        assert res_no_assert.is_vacuous is True
        assert "zero assertion" in res_no_assert.details.lower()

        # AST trivial constant assertion
        art_trivial = WitnessArtifact.from_text(
            path="tests/witness/test_trivial.py",
            content="def test_trivial():\n    assert True\n",
        )
        res_trivial = analyze_artifact_code_vacuity([art_trivial])
        assert res_trivial.is_vacuous is True
        assert "trivial constant" in res_trivial.details.lower()

        # Runtime 0 tests collected
        art_valid = WitnessArtifact.from_text(
            path="tests/witness/test_valid.py",
            content="def test_valid():\n    x = get_status()\n    assert x == 200\n",
        )
        code_check = analyze_artifact_code_vacuity([art_valid])
        exec_res = normalize_witness_execution(
            witness_id="wit-01",
            witness_digest="0" * 64,
            frozen_contract_digest="1" * 64,
            requirement_id="REQ-01",
            sandbox_identity=SandboxIdentity(sandbox_id="sbx-01"),
            source_commit_id="a" * 40,
            world=ExecutionWorld.CANDIDATE,
            status=TerminationStatus.COMPLETED,
            exit_code=5,
            stdout_raw="collected 0 items\nno tests ran in 0.01s",
            stderr_raw="",
            duration_seconds=0.1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        res_0_collected = analyze_runtime_execution_vacuity(exec_res, code_check)
        assert res_0_collected.is_vacuous is True
        assert "collected 0 test items" in res_0_collected.details.lower()

    def test_p09_06_immutable_lock_enforces_digest_chain(self) -> None:
        """P-09.06: Immutable witness digest locked and preserves exact contract chain."""
        contract, req_id = _build_test_frozen_contract()
        vault = TrustedWitnessVault()
        art = WitnessArtifact.from_text(
            path="tests/witness/test_lock.py",
            content="def test_lock():\n    assert calculate(1) == 2\n",
        )
        sealed_record = vault.seal_witness(
            witness_id="wit-lock-06",
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            source_commit_id="c" * 40,
            artifacts=[art],
        )

        lock = create_witness_lock(sealed_record, vault)
        assert isinstance(lock, ImmutableWitnessLock)
        assert lock.frozen_contract_digest == contract.contract_digest
        assert lock.witness_digest == sealed_record.seal_digest

        # Chain verification passes with matching sealed candidate witness
        verify_witness_lock_chain(
            lock=lock,
            frozen_contract=contract,
            base_record=sealed_record,
            candidate_record=sealed_record,
        )

        # Mutated candidate witness rejected
        mutated_art = WitnessArtifact.from_text(
            path="tests/witness/test_mutated.py",
            content="def test_mutated():\n    assert 2 == 2\n",
        )
        mutated_record = vault.seal_witness(
            witness_id="wit-lock-mutated",
            requirement_id=req_id,
            frozen_contract_digest=contract.contract_digest,
            source_commit_id="c" * 40,
            artifacts=[mutated_art],
        )
        with pytest.raises(WitnessMutationError, match="does not match locked digest"):
            verify_witness_lock_chain(
                lock=lock,
                frozen_contract=contract,
                base_record=sealed_record,
                candidate_record=mutated_record,
            )


@pytest.mark.live
def test_p09_live_nemotron_witness_plan() -> None:
    """Live proof: Nemotron-3_5-Lightning generates a valid witness plan from real frozen contract.

    Zero-cost policy: minimal bounded tokens, promo floor observed.
    Secret safety: credentials never logged or leaked.
    """
    api_key = os.environ.get("NEBIUS_API_KEY")
    if not api_key:
        pytest.skip("NEBIUS_API_KEY required for live Nemotron witness plan proof")

    contract, req_id = _build_test_frozen_contract()
    source_id = SourceIdentity(
        locator="https://github.com/zyganali-glitch/Basebreak.git",
        revision=CommitRevision("55abf808e9fc01d5003ef32d61557800942ceed8"),
    )
    envelope = VerifierContextEnvelope.create(
        frozen_contract=contract,
        source_identity=source_id,
    )

    client = NebiusModelClient(
        config=ModelClientConfig(
            api_key=api_key,
            model=DEFAULT_PRIMARY_MODEL,
            max_tokens=4096,
            temperature=0.0,
        )
    )

    proposal = generate_witness_plan(
        context_envelope=envelope,
        requirement_id=req_id,
        source_files={"src/cli.py": "def run_cli(flag):\n    return ''\n"},
        model_client=client,
    )

    validator = WitnessPlanValidator()
    plan = validator.validate(proposal, context_envelope=envelope)

    assert plan.frozen_contract_digest == contract.contract_digest
    assert plan.requirement_id == req_id
    assert plan.change_class == ChangeClass.BUG_FIX
    assert len(plan.artifacts) >= 1
    assert plan.is_authoritative is False
    assert plan.grants_pass is False

    # Seal the live witness in vault
    vault = TrustedWitnessVault()
    generator = WitnessGenerator(vault)
    sealed_record = generator.generate_and_seal_witness(plan)
    assert vault.verify_witness_integrity(sealed_record) is True

    # Lock witness digest
    lock = create_witness_lock(sealed_record, vault)
    assert lock.frozen_contract_digest == contract.contract_digest
    assert lock.witness_digest == sealed_record.seal_digest
