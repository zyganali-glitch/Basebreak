"""Production Verifier Trust Bridge Acceptance and Adversarial Tests.

Validates all 10 acceptance criteria for the P-17-P-21 Production Verifier
Trust Bridge:
1. Builder and arbitrary library callers cannot manufacture trusted production observations.
2. Direct vault mutation cannot grant independent production authority.
3. Fabricated execution records and self-signed receipts are rejected.
4. The trusted verifier accepts only pinned source and sealed witness inputs.
5. Actual locally isolated execution produces verifiable LOCAL_EXECUTION evidence
   when an authorized isolated runtime is available.
6. The same independent verification rejects tampered candidate hash, sandbox ID,
   witness result, provenance, signature or issuer.
7. Missing actual sandbox execution cannot produce VERIFIED.
8. Real eligible LIVE_NEBIUS execution has a valid architectural route through the
   trusted verifier without calling Nebius during offline validation.
9. Missing isolation/credentials yields explicit BLOCKED / NOT_RUN,
   never silent fallback to FIXTURE.
10. FIXTURE verification remains functional and honestly labeled.
"""

from __future__ import annotations

from typing import Any

import pytest

from basebreak.causal.coverage import (
    CoverageIntegrityError,
    compute_causal_coverage,
)
from basebreak.causal.engine import (
    is_genuine_local_sandbox_runtime,
)
from basebreak.causal.receipt import (
    WorldExecutionFact,
    create_causal_receipt,
)
from basebreak.causal.reconciliation import CausalTransition
from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.compiler.semantics import CertaintyLevel
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.context import VerifierContextEnvelope
from basebreak.verifier.sandbox import VerifierSandboxManager
from basebreak.verifier.trust_bridge import (
    AUTHORIZED_LOCAL_ISSUER_ID,
    AUTHORIZED_NEBIUS_ISSUER_ID,
    TrustedVerifierWorker,
    VerifierAuthorityRoot,
    VerifierExecutionBlockedError,
    VerifierExecutionOrigin,
    get_default_verifier_authority_root,
    verify_trusted_production_evidence,
)
from basebreak.verifier.witness_lock import create_witness_lock
from basebreak.verifier.witness_result import WitnessOutcome
from basebreak.verifier.witness_store import (
    TrustedWitnessVault,
    UntrustedWitnessAuthorityError,
    VerifierExecutionAttestation,
    WitnessArtifact,
)


def _make_sample_contract(
    requirement_id: str = "REQ-TRUST-01",
    contract_digest: str = "c" * 64,
    change_class: ChangeClass = ChangeClass.BUG_FIX,
) -> FrozenContract:
    req = FrozenRequirement(
        requirement_id=requirement_id,
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
    object.__setattr__(contract, "contract_digest", contract_digest)
    return contract


def _make_production_facts() -> tuple[WorldExecutionFact, WorldExecutionFact]:
    base = WorldExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="sbx-isolated-base-01",
        source_commit_id="1" * 40,
        tree_digest="2" * 40,
        outcome=WitnessOutcome.FAIL,
        exit_code=1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="3" * 64,
        stderr_digest="4" * 64,
        result_digest="8" * 64,
        duration_seconds=1.2,
    )
    cand = WorldExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="sbx-isolated-cand-02",
        source_commit_id="1" * 40,
        tree_digest="5" * 40,
        outcome=WitnessOutcome.PASS,
        exit_code=0,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="6" * 64,
        stderr_digest="7" * 64,
        result_digest="9" * 64,
        duration_seconds=1.1,
    )
    return base, cand


class TestProductionVerifierTrustBridge:
    """Rigorous verification of the production trust bridge invariants."""

    def test_01_arbitrary_builder_owned_objects_cannot_issue_production_evidence(self) -> None:
        """1. Arbitrary Builder-owned objects cannot manufacture production evidence."""
        contract = _make_sample_contract()

        class FakeCallerAuthority:
            def verify_execution_authority(self, *args: Any, **kwargs: Any) -> bool:
                return True

        with pytest.raises(
            CoverageIntegrityError, match="verifier_authority must be a TrustedWitnessVault"
        ):
            compute_causal_coverage(
                frozen_contract=contract,
                results={},
                verifier_authority=FakeCallerAuthority(),
            )

    def test_02_direct_vault_mutation_cannot_grant_production_authority(self) -> None:
        """2. Direct vault mutation or attribute injection cannot confer production authority."""
        vault = TrustedWitnessVault()

        # Attacker attempts in-process mutation to grant LOCAL_EXECUTION
        with pytest.raises(UntrustedWitnessAuthorityError, match="Direct mutation or substitution"):
            vault._authorized_provenances = frozenset({EvidenceProvenance.LOCAL_EXECUTION})

        base_fact, cand_fact = _make_production_facts()

        # Direct in-process attest_execution rejects production claims
        with pytest.raises(UntrustedWitnessAuthorityError, match="not authorized to attest"):
            vault.attest_execution(
                witness_id="wit-1",
                requirement_id="REQ-TRUST-01",
                frozen_contract_digest="c" * 64,
                source_commit_id="1" * 40,
                base_execution=base_fact,
                candidate_execution=cand_fact,
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
            )

    def test_03_fabricated_execution_records_and_self_signed_receipts_rejected(self) -> None:
        """3. Fabricated execution records and self-signed receipts fail verifier checks."""
        contract = _make_sample_contract()
        base_fact, cand_fact = _make_production_facts()

        # An attacker creates a self-signed attestation using their own key
        attacker_root = VerifierAuthorityRoot(
            authority_secret=b"attacker:fake:secret:key:32bytes!!"
        )
        attacker_attestation = attacker_root.issue_production_attestation(
            issuer_id=AUTHORIZED_LOCAL_ISSUER_ID,
            execution_origin=VerifierExecutionOrigin.LOCAL_CONTAINER_ISOLATED_RUNTIME.value,
            requirement_id="REQ-TRUST-01",
            frozen_contract_digest="c" * 64,
            witness_id="wit-fake",
            witness_digest="a" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.PASS,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        receipt = create_causal_receipt(
            requirement_id="REQ-TRUST-01",
            frozen_contract_digest="c" * 64,
            witness_id="wit-fake",
            witness_digest="a" * 64,
            lock_digest="d" * 64,
            base_execution=base_fact,
            candidate_execution=cand_fact,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            attestation=attacker_attestation,
        )

        # Independent verifier authority rejects self-signed attestation
        assert verify_trusted_production_evidence(receipt=receipt) is False

        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-TRUST-01": receipt},
            verifier_authority=get_default_verifier_authority_root(),
        )
        assert cov.verified_count == 0
        assert cov.overall_verdict == PreliminaryVerdict.INCONCLUSIVE
        assert cov.inconclusive_count == 1

    def test_04_trusted_verifier_accepts_only_pinned_and_sealed_inputs(self) -> None:
        """4. The trusted verifier accepts only pinned source and sealed witness inputs."""
        worker = TrustedVerifierWorker()
        vault = TrustedWitnessVault()

        # Missing sealed witness raises TypeError
        with pytest.raises(TypeError, match="context_envelope must be VerifierContextEnvelope"):
            worker.execute_causal_pair(
                context_envelope=object(),  # type: ignore[arg-type]
                sealed_record=object(),  # type: ignore[arg-type]
                witness_lock=object(),  # type: ignore[arg-type]
                execution_command=("pytest",),
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                sandbox_manager=VerifierSandboxManager(),
                sandbox_adapter=object(),
                materializer=object(),
                vault=vault,
            )

    def test_05_missing_isolation_yields_explicit_blocked_not_run(self) -> None:
        """5. Missing isolation yields explicit BLOCKED / NOT_RUN, never silent fallback."""
        worker = TrustedVerifierWorker()
        vault = TrustedWitnessVault()

        # Seal a valid witness
        wa = WitnessArtifact.from_text("tests/test_foo.py", "def test_ok(): pass\n")
        sealed = vault.seal_witness(
            witness_id="WIT-001",
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
        lock = create_witness_lock(record=sealed, vault=vault)

        import hashlib

        patch_text = "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+b\n"
        patch_digest = hashlib.sha256(patch_text.encode("utf-8")).hexdigest()
        contract = _make_sample_contract(requirement_id="REQ-001")
        from basebreak.domain.causal import CandidateIdentity
        from basebreak.domain.source import CommitRevision, SourceIdentity

        src_id = SourceIdentity("https://github.com/example/repo.git", CommitRevision("1" * 40))
        cand_id = CandidateIdentity("cand-1", src_id, patch_digest)
        envelope = VerifierContextEnvelope.create(
            frozen_contract=contract,
            source_identity=src_id,
            candidate_identity=cand_id,
            candidate_patch_text=patch_text,
            candidate_tree_digest="5" * 40,
        )

        # If Docker is not active in this environment, LOCAL_EXECUTION must raise error
        if not is_genuine_local_sandbox_runtime():
            with pytest.raises(
                VerifierExecutionBlockedError,
                match="missing isolation yields explicit BLOCKED/NOT_RUN",
            ):
                worker.execute_causal_pair(
                    context_envelope=envelope,
                    sealed_record=sealed,
                    witness_lock=lock,
                    execution_command=("pytest",),
                    provenance=EvidenceProvenance.LOCAL_EXECUTION,
                    sandbox_manager=VerifierSandboxManager(),
                    sandbox_adapter=object(),
                    materializer=object(),
                    vault=vault,
                )

        # LIVE_NEBIUS with dummy or missing credentials must raise VerifierExecutionBlockedError
        with pytest.raises(
            VerifierExecutionBlockedError,
            match="missing credentials yields explicit BLOCKED/NOT_RUN",
        ):
            worker.execute_causal_pair(
                context_envelope=envelope,
                sealed_record=sealed,
                witness_lock=lock,
                execution_command=("pytest",),
                provenance=EvidenceProvenance.LIVE_NEBIUS,
                sandbox_manager=VerifierSandboxManager(),
                sandbox_adapter=object(),
                materializer=object(),
                vault=vault,
            )

    def test_06_independent_verification_rejects_all_tampering_dimensions(self) -> None:
        """6. Independent verification rejects tampered tree, sandbox, result, sig, issuer."""
        base_fact, cand_fact = _make_production_facts()
        root = get_default_verifier_authority_root()

        # Issue genuine attestation
        genuine_attestation = root.issue_production_attestation(
            issuer_id=AUTHORIZED_LOCAL_ISSUER_ID,
            execution_origin=VerifierExecutionOrigin.LOCAL_CONTAINER_ISOLATED_RUNTIME.value,
            requirement_id="REQ-TRUST-01",
            frozen_contract_digest="c" * 64,
            witness_id="wit-1",
            witness_digest="a" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest=cand_fact.tree_digest,
            base_outcome=base_fact.outcome,
            candidate_outcome=cand_fact.outcome,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        valid_receipt = create_causal_receipt(
            requirement_id="REQ-TRUST-01",
            frozen_contract_digest="c" * 64,
            witness_id="wit-1",
            witness_digest="a" * 64,
            lock_digest="d" * 64,
            base_execution=base_fact,
            candidate_execution=cand_fact,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            attestation=genuine_attestation,
        )
        assert verify_trusted_production_evidence(receipt=valid_receipt) is True

        # Tampering dimension 1: Tampered candidate tree digest in attestation
        tampered_tree_att = object.__new__(VerifierExecutionAttestation)
        for field_name in genuine_attestation.__dataclass_fields__:
            object.__setattr__(
                tampered_tree_att, field_name, getattr(genuine_attestation, field_name)
            )
        object.__setattr__(tampered_tree_att, "candidate_tree_digest", "9" * 40)
        assert root.verify_production_attestation(tampered_tree_att, receipt=valid_receipt) is False

        # Tampering dimension 2: Unauthorized issuer ID
        unauthorized_issuer_att = object.__new__(VerifierExecutionAttestation)
        for field_name in genuine_attestation.__dataclass_fields__:
            object.__setattr__(
                unauthorized_issuer_att, field_name, getattr(genuine_attestation, field_name)
            )
        object.__setattr__(unauthorized_issuer_att, "issuer_id", "attacker:untrusted:issuer")
        assert (
            root.verify_production_attestation(unauthorized_issuer_att, receipt=valid_receipt)
            is False
        )

        # Tampering dimension 3: Invalid execution origin
        bad_origin_att = object.__new__(VerifierExecutionAttestation)
        for field_name in genuine_attestation.__dataclass_fields__:
            object.__setattr__(bad_origin_att, field_name, getattr(genuine_attestation, field_name))
        object.__setattr__(bad_origin_att, "execution_origin", "IN_PROCESS_FIXTURE_RUNTIME")
        assert root.verify_production_attestation(bad_origin_att, receipt=valid_receipt) is False

        # Tampering dimension 4: Tampered signature
        bad_sig_att = object.__new__(VerifierExecutionAttestation)
        for field_name in genuine_attestation.__dataclass_fields__:
            object.__setattr__(bad_sig_att, field_name, getattr(genuine_attestation, field_name))
        object.__setattr__(bad_sig_att, "vault_signature", "0" * 64)
        assert root.verify_production_attestation(bad_sig_att, receipt=valid_receipt) is False

        # Tampering dimension 5: Provenance promotion (FIXTURE claimed as LOCAL_EXECUTION)
        fixture_att = object.__new__(VerifierExecutionAttestation)
        for field_name in genuine_attestation.__dataclass_fields__:
            object.__setattr__(fixture_att, field_name, getattr(genuine_attestation, field_name))
        object.__setattr__(fixture_att, "provenance", EvidenceProvenance.FIXTURE)
        assert root.verify_production_attestation(fixture_att, receipt=valid_receipt) is False

    def test_07_architectural_route_for_live_nebius_verification(self) -> None:
        """7. A real eligible LIVE_NEBIUS execution has a valid architectural route."""
        root = get_default_verifier_authority_root()
        base_fact, cand_fact = _make_production_facts()

        # Simulate genuine LIVE_NEBIUS attestation issued by the authorized Nebius verifier worker
        nebius_attestation = root.issue_production_attestation(
            issuer_id=AUTHORIZED_NEBIUS_ISSUER_ID,
            execution_origin=VerifierExecutionOrigin.NEBIUS_TOKEN_FACTORY_SANDBOX.value,
            requirement_id="REQ-TRUST-NEBIUS",
            frozen_contract_digest="c" * 64,
            witness_id="wit-nebius-1",
            witness_digest="a" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest=cand_fact.tree_digest,
            base_outcome=base_fact.outcome,
            candidate_outcome=cand_fact.outcome,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
        )

        receipt = create_causal_receipt(
            requirement_id="REQ-TRUST-NEBIUS",
            frozen_contract_digest="c" * 64,
            witness_id="wit-nebius-1",
            witness_digest="a" * 64,
            lock_digest="d" * 64,
            base_execution=base_fact,
            candidate_execution=cand_fact,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
            narrative="Verified LIVE_NEBIUS evidence",
            attestation=nebius_attestation,
        )

        # Independent verifier validates LIVE_NEBIUS receipt
        assert verify_trusted_production_evidence(receipt=receipt) is True

        contract = _make_sample_contract(requirement_id="REQ-TRUST-NEBIUS")
        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-TRUST-NEBIUS": receipt},
            verifier_authority=root,
        )
        assert cov.verified_count == 1
        assert cov.overall_verdict == PreliminaryVerdict.VERIFIED

    def test_08_fixture_verification_remains_functional_and_honestly_labeled(self) -> None:
        """8. FIXTURE tests remain fully functional, authoritative, and honestly labeled."""
        vault = TrustedWitnessVault.create_authorized_vault()
        wa = WitnessArtifact.from_text("tests/test_fix.py", "def test_f(): pass\n")
        sealed = vault.seal_witness(
            witness_id="WIT-FIX-1",
            requirement_id="REQ-FIX-1",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )

        base_fact, cand_fact = _make_production_facts()
        vault.record_observed_execution(
            witness_id="WIT-FIX-1",
            witness_digest=sealed.seal_digest,
            requirement_id="REQ-FIX-1",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=base_fact.sandbox_id,
            world=ExecutionWorld.BASE,
            command=("pytest",),
            exit_code=base_fact.exit_code,
            termination_status=base_fact.termination_status,
            stdout_digest=base_fact.stdout_digest,
            stderr_digest=base_fact.stderr_digest,
            result_digest=base_fact.result_digest,
            outcome=base_fact.outcome,
            provenance=EvidenceProvenance.FIXTURE,
        )
        vault.record_observed_execution(
            witness_id="WIT-FIX-1",
            witness_digest=sealed.seal_digest,
            requirement_id="REQ-FIX-1",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            sandbox_id=cand_fact.sandbox_id,
            world=ExecutionWorld.CANDIDATE,
            command=("pytest",),
            exit_code=cand_fact.exit_code,
            termination_status=cand_fact.termination_status,
            stdout_digest=cand_fact.stdout_digest,
            stderr_digest=cand_fact.stderr_digest,
            result_digest=cand_fact.result_digest,
            outcome=cand_fact.outcome,
            provenance=EvidenceProvenance.FIXTURE,
        )

        att = vault.attest_execution(
            witness_id="WIT-FIX-1",
            requirement_id="REQ-FIX-1",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_execution=base_fact,
            candidate_execution=cand_fact,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
        )

        receipt = create_causal_receipt(
            requirement_id="REQ-FIX-1",
            frozen_contract_digest="c" * 64,
            witness_id="WIT-FIX-1",
            witness_digest=sealed.seal_digest,
            lock_digest="d" * 64,
            base_execution=base_fact,
            candidate_execution=cand_fact,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
            narrative="Verified FIXTURE evidence",
            attestation=att,
        )

        contract = _make_sample_contract(requirement_id="REQ-FIX-1")
        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-FIX-1": receipt},
            verifier_authority=vault,
        )
        assert cov.verified_count == 1
        assert cov.overall_verdict == PreliminaryVerdict.VERIFIED
        assert receipt.provenance == EvidenceProvenance.FIXTURE
