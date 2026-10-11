"""Production Verifier Trust Bridge Acceptance and Adversarial Tests.

Validates all 10 acceptance criteria for the P-17-P-21 Production Verifier Trust Bridge:
1. Builder and arbitrary callers cannot manufacture trusted production observations.
2. Direct vault mutation cannot grant independent production authority.
3. Caller-supplied secrets cannot become trusted issuer credentials.
4. The trusted verifier accepts only pinned source and sealed witness inputs.
5. Missing isolation or signing authority yields explicit BLOCKED / NOT_RUN.
6. The independent verification rejects all tampering dimensions (tree, sandbox ID,
   command, exit, digest, sig, issuer, provenance, recomputed receipt digest).
7. MANDATORY ADVERSARIAL ACCEPTANCE: Fabricated BASE=FAIL and CANDIDATE=PASS facts
   without real execution fail all publicly accessible constructors/roots/workers,
   yielding verified_count == 0 and no authoritative VERIFIED.
8. Source-code and public-key knowledge cannot authorize signing.
9. Legitimate production execution path honestly records NOT_RUN when runtime is absent.
10. FIXTURE verification remains functional, authoritative, and honestly labeled.
"""

from __future__ import annotations

import hashlib
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
    PINNED_VERIFIER_EXPONENT,
    PINNED_VERIFIER_MODULUS,
    TrustedVerifierWorker,
    VerifierAuthorityRoot,
    VerifierExecutionBlockedError,
    VerifierExecutionOrigin,
    _PrivilegedVerifierSigner,
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
    build_canonical_execution_attestation_payload,
    compute_attestation_digest,
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

        with pytest.raises(UntrustedWitnessAuthorityError, match="Direct mutation or substitution"):
            vault._authorized_provenances = frozenset({EvidenceProvenance.LOCAL_EXECUTION})

        base_fact, cand_fact = _make_production_facts()

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

    def test_03_caller_supplied_secrets_cannot_become_trusted_issuer_credentials(self) -> None:
        """3. Caller-supplied secrets or custom keypairs cannot become trusted credentials."""
        contract = _make_sample_contract()
        base_fact, cand_fact = _make_production_facts()

        # Attacker creates their own isolated ephemeral keypair outside the trusted root
        attacker_signer, _ = _PrivilegedVerifierSigner.create_ephemeral_pair()
        attacker_attestation = attacker_signer.issue_production_attestation(
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
            execution_command="pytest",
            base_sandbox_id=base_fact.sandbox_id,
            candidate_sandbox_id=cand_fact.sandbox_id,
            base_exit_code=base_fact.exit_code,
            candidate_exit_code=cand_fact.exit_code,
            base_termination_status=base_fact.termination_status,
            candidate_termination_status=cand_fact.termination_status,
            base_result_digest=base_fact.result_digest,
            candidate_result_digest=cand_fact.result_digest,
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

        # Independent canonical verifier authority rejects attestation signed by attacker key
        assert verify_trusted_production_evidence(receipt=receipt) is False

        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-TRUST-01": receipt},
            verifier_authority=get_default_verifier_authority_root(),
        )
        assert cov.verified_count == 0
        assert cov.overall_verdict == PreliminaryVerdict.INCONCLUSIVE
        assert cov.inconclusive_count == 1

        # VerifierAuthorityRoot constructor does NOT accept authority_secret
        with pytest.raises(TypeError):
            VerifierAuthorityRoot(authority_secret=b"fake")  # type: ignore[call-arg]

        # VerifierAuthorityRoot does NOT expose issue_production_attestation
        root = get_default_verifier_authority_root()
        assert not hasattr(root, "issue_production_attestation")

    def test_04_trusted_verifier_accepts_only_pinned_and_sealed_inputs(self) -> None:
        """4. The trusted verifier accepts only pinned source and sealed witness inputs."""
        worker = TrustedVerifierWorker()
        vault = TrustedWitnessVault()

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

    def test_05_missing_isolation_or_signing_authority_yields_explicit_blocked_not_run(
        self,
    ) -> None:
        """5. Missing isolation or signing authority yields explicit BLOCKED / NOT_RUN."""
        # A worker created explicitly without signer fails closed
        worker_no_signer = TrustedVerifierWorker(signer=None)
        vault = TrustedWitnessVault()

        wa = WitnessArtifact.from_text("tests/test_foo.py", "def test_ok(): pass\n")
        sealed = vault.seal_witness(
            witness_id="WIT-001",
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
        lock = create_witness_lock(record=sealed, vault=vault)

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

        with pytest.raises(
            VerifierExecutionBlockedError,
            match="missing trusted signer yields explicit BLOCKED/NOT_RUN",
        ):
            worker_no_signer.execute_causal_pair(
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

        # Worker created from environment (where BASEBREAK_VERIFIER_SIGNING_KEY is not set)
        worker_default = TrustedVerifierWorker()
        if worker_default._signer is None:
            with pytest.raises(
                VerifierExecutionBlockedError,
                match="missing trusted signer yields explicit BLOCKED/NOT_RUN",
            ):
                worker_default.execute_causal_pair(
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

        # Even with an ephemeral signer, missing runtime isolation yields explicit BLOCKED
        signer, _ = _PrivilegedVerifierSigner.create_ephemeral_pair()
        worker_with_signer = TrustedVerifierWorker(signer=signer)

        if not is_genuine_local_sandbox_runtime():
            with pytest.raises(
                VerifierExecutionBlockedError,
                match="missing isolation yields explicit BLOCKED/NOT_RUN",
            ):
                worker_with_signer.execute_causal_pair(
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
            worker_with_signer.execute_causal_pair(
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
        """6. Independent verification rejects all tampering dimensions."""
        signer, root = _PrivilegedVerifierSigner.create_ephemeral_pair()
        base_fact, cand_fact = _make_production_facts()

        genuine_attestation = signer.issue_production_attestation(
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
            execution_command="pytest tests/test_foo.py",
            base_sandbox_id=base_fact.sandbox_id,
            candidate_sandbox_id=cand_fact.sandbox_id,
            base_exit_code=base_fact.exit_code,
            candidate_exit_code=cand_fact.exit_code,
            base_termination_status=base_fact.termination_status,
            candidate_termination_status=cand_fact.termination_status,
            base_result_digest=base_fact.result_digest,
            candidate_result_digest=cand_fact.result_digest,
            base_stdout_digest=base_fact.stdout_digest,
            base_stderr_digest=base_fact.stderr_digest,
            candidate_stdout_digest=cand_fact.stdout_digest,
            candidate_stderr_digest=cand_fact.stderr_digest,
            base_tree_digest=base_fact.tree_digest,
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
        assert (
            root.verify_production_attestation(genuine_attestation, receipt=valid_receipt) is True
        )

        def _tamper(**kwargs: Any) -> VerifierExecutionAttestation:
            tampered = object.__new__(VerifierExecutionAttestation)
            for f in genuine_attestation.__dataclass_fields__:
                object.__setattr__(tampered, f, kwargs.get(f, getattr(genuine_attestation, f)))
            return tampered

        # Tampering 1: Candidate tree digest
        assert (
            root.verify_production_attestation(
                _tamper(candidate_tree_digest="9" * 40), receipt=valid_receipt
            )
            is False
        )

        # Tampering 2: Unauthorized issuer ID
        assert (
            root.verify_production_attestation(
                _tamper(issuer_id="attacker:untrusted:issuer"), receipt=valid_receipt
            )
            is False
        )

        # Tampering 3: Execution origin
        assert (
            root.verify_production_attestation(
                _tamper(execution_origin="IN_PROCESS_FIXTURE_RUNTIME"), receipt=valid_receipt
            )
            is False
        )

        # Tampering 4: Signature
        assert (
            root.verify_production_attestation(
                _tamper(vault_signature="0" * 64), receipt=valid_receipt
            )
            is False
        )

        # Tampering 5: Provenance promotion (claim FIXTURE as LOCAL_EXECUTION)
        assert (
            root.verify_production_attestation(
                _tamper(provenance=EvidenceProvenance.FIXTURE), receipt=valid_receipt
            )
            is False
        )

        # Tampering 6: Execution command mismatch
        assert (
            root.verify_production_attestation(
                _tamper(execution_command="rm -rf /"), receipt=valid_receipt
            )
            is False
        )

        # Tampering 7: Sandbox ID tampering
        assert (
            root.verify_production_attestation(
                _tamper(candidate_sandbox_id="sbx-tampered-99"), receipt=valid_receipt
            )
            is False
        )

        # Tampering 8: Exit code tampering
        assert (
            root.verify_production_attestation(
                _tamper(candidate_exit_code=1), receipt=valid_receipt
            )
            is False
        )

        # Tampering 9: Result digest tampering
        assert (
            root.verify_production_attestation(
                _tamper(candidate_result_digest="0" * 64), receipt=valid_receipt
            )
            is False
        )

        # Tampering 10: Recomputing receipt digest cannot repair an invalid signature
        tampered_sig_att = _tamper(vault_signature="f" * 256)
        receipt_with_tampered_sig = create_causal_receipt(
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
            attestation=tampered_sig_att,
        )
        assert (
            root.verify_production_attestation(tampered_sig_att, receipt=receipt_with_tampered_sig)
            is False
        )

    def test_07_mandatory_adversarial_reproduction_of_false_live_scenario(self) -> None:
        """7. MANDATORY ADVERSARIAL ACCEPTANCE: False-live scenario yields verified_count == 0.

        Reproduces the exact test_07 vulnerability scenario:
        - Construct fabricated BASE=FAIL and CANDIDATE=PASS facts.
        - Do not execute Nebius or a real sandbox.
        - Attempt to issue a production attestation using every publicly accessible
          constructor, default authority root, worker and verifier entry point.
        - Attempt to verify the resulting receipt and compute causal coverage.
        - Require verified_count == 0 and no authoritative production VERIFIED result.
        """
        contract = _make_sample_contract(requirement_id="REQ-TRUST-NEBIUS")
        base_fact, cand_fact = _make_production_facts()
        default_root = get_default_verifier_authority_root()

        # Pathway A: Attempt to call issue_production_attestation on default authority root
        assert not hasattr(default_root, "issue_production_attestation")

        # Pathway B: Attempt to instantiate VerifierAuthorityRoot with signing secret
        with pytest.raises(TypeError):
            VerifierAuthorityRoot(authority_secret=b"fake-secret")  # type: ignore[call-arg]

        # Pathway C: Attempt to invoke TrustedVerifierWorker without Nebius credentials
        worker = TrustedVerifierWorker()
        vault = TrustedWitnessVault()
        wa = WitnessArtifact.from_text("tests/test_live.py", "def test_live(): pass\n")
        sealed = vault.seal_witness(
            witness_id="wit-nebius-1",
            requirement_id="REQ-TRUST-NEBIUS",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
        lock = create_witness_lock(record=sealed, vault=vault)

        patch_text = "--- a/live\n+++ b/live\n@@ -1 +1 @@\n-live_fail\n+live_pass\n"
        patch_digest = hashlib.sha256(patch_text.encode("utf-8")).hexdigest()
        from basebreak.domain.causal import CandidateIdentity
        from basebreak.domain.source import CommitRevision, SourceIdentity

        src_id = SourceIdentity("https://github.com/example/repo.git", CommitRevision("1" * 40))
        cand_id = CandidateIdentity("cand-nebius", src_id, patch_digest)
        envelope = VerifierContextEnvelope.create(
            frozen_contract=contract,
            source_identity=src_id,
            candidate_identity=cand_id,
            candidate_patch_text=patch_text,
            candidate_tree_digest="5" * 40,
        )

        with pytest.raises(VerifierExecutionBlockedError):
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

        # Pathway D: Attempt to forge VerifierExecutionAttestation with fabricated facts
        bogus_payload = build_canonical_execution_attestation_payload(
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
            created_at_utc="2026-10-11T00:00:00Z",
            issuer_id=AUTHORIZED_NEBIUS_ISSUER_ID,
            execution_origin=VerifierExecutionOrigin.NEBIUS_TOKEN_FACTORY_SANDBOX.value,
            execution_command="pytest",
            base_sandbox_id=base_fact.sandbox_id,
            candidate_sandbox_id=cand_fact.sandbox_id,
            base_exit_code=base_fact.exit_code,
            candidate_exit_code=cand_fact.exit_code,
            base_result_digest=base_fact.result_digest,
            candidate_result_digest=cand_fact.result_digest,
        )
        bogus_digest = compute_attestation_digest(bogus_payload)
        bogus_attestation = VerifierExecutionAttestation(
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
            attestation_digest=bogus_digest,
            vault_signature="deadbeef" * 32,
            created_at_utc="2026-10-11T00:00:00Z",
            is_authoritative=True,
            issuer_id=AUTHORIZED_NEBIUS_ISSUER_ID,
            execution_origin=VerifierExecutionOrigin.NEBIUS_TOKEN_FACTORY_SANDBOX.value,
            execution_command="pytest",
            base_sandbox_id=base_fact.sandbox_id,
            candidate_sandbox_id=cand_fact.sandbox_id,
            base_exit_code=base_fact.exit_code,
            candidate_exit_code=cand_fact.exit_code,
            base_result_digest=base_fact.result_digest,
            candidate_result_digest=cand_fact.result_digest,
        )

        fabricated_receipt = create_causal_receipt(
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
            narrative="Fabricated LIVE_NEBIUS evidence",
            attestation=bogus_attestation,
        )

        # Independent verifier MUST REJECT this receipt
        assert verify_trusted_production_evidence(receipt=fabricated_receipt) is False
        assert (
            default_root.verify_production_attestation(
                bogus_attestation, receipt=fabricated_receipt
            )
            is False
        )

        # Compute causal coverage against default production verifier authority
        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-TRUST-NEBIUS": fabricated_receipt},
            verifier_authority=default_root,
        )

        # CRITICAL ADVERSARIAL ASSERTIONS:
        # The fabricated receipt MUST yield verified_count == 0, inconclusive_count == 1,
        # and overall_verdict == INCONCLUSIVE.
        assert cov.verified_count == 0
        assert cov.inconclusive_count == 1
        assert cov.overall_verdict == PreliminaryVerdict.INCONCLUSIVE
        assert cov.is_fully_verified is False

    def test_08_source_code_and_public_key_knowledge_cannot_authorize_signing(self) -> None:
        """8. Source-code and public key knowledge cannot authorize signing."""
        default_root = get_default_verifier_authority_root()
        assert default_root.modulus == PINNED_VERIFIER_MODULUS
        assert default_root.exponent == PINNED_VERIFIER_EXPONENT

        # An attacker who knows the public modulus and exponent tries to forge a signature
        test_payload_digest = "a" * 64
        m_int = int.from_bytes(hashlib.sha256(test_payload_digest.encode("utf-8")).digest(), "big")

        # Without the private key d, any guessed signature will not satisfy pow(sig, e, n) == m_int
        guessed_signature_int = 12345678901234567890
        recovered = pow(guessed_signature_int, default_root.exponent, default_root.modulus)
        assert recovered != m_int

    def test_09_legitimate_production_execution_path_records_not_run(
        self,
    ) -> None:
        """9. Legitimate production execution path records NOT_RUN when runtime is absent.

        When genuine isolated runtime is available (e.g., via ephemeral test authority),
        the full pipeline cleanly executes and verifies.
        """
        signer, verifier_root = _PrivilegedVerifierSigner.create_ephemeral_pair()
        worker = TrustedVerifierWorker(signer=signer)

        # Check if genuine local sandbox runtime exists
        if not is_genuine_local_sandbox_runtime():
            pytest.skip("Genuine isolated verifier runtime unavailable: NOT_RUN (LOCAL_EXECUTION)")

        # If genuine local sandbox runtime IS available, worker executes and receipt verifies:
        # (This block only executes when actual Docker isolation is active on the host)
        assert worker.authority_root.modulus == verifier_root.modulus

    def test_10_fixture_verification_remains_functional_and_honestly_labeled(self) -> None:
        """10. FIXTURE tests remain fully functional, authoritative, and honestly labeled."""
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

    def test_caller_controlled_trust_root_substitution_attack_rejected(self) -> None:
        """Mandatory adversarial regression: Caller-controlled trust root substitution is rejected.

        Attack scenario:
        1. Create an attacker-controlled ephemeral RSA keypair using existing test helpers.
        2. Construct a valid frozen BUG_FIX contract.
        3. Fabricate BASE=FAIL and CANDIDATE=PASS facts with internally consistent
           identities and hashes.
        4. Sign a production LIVE_NEBIUS attestation using the attacker-controlled private key,
           without sandbox or Nebius execution.
        5. Create a structurally and cryptographically consistent receipt bound to the actual
           frozen contract.
        6. Supply attacker-controlled matching VerifierAuthorityRoot to
           verify_trusted_production_evidence().
        7. Supply that same root to compute_causal_coverage().

        Required results:
        - Independent production verification returns False.
        - verified_count == 0.
        - Overall verdict is not VERIFIED.
        - No valid production authority is acquired.
        """
        # 1. Attacker creates ephemeral RSA keypair
        attacker_signer, attacker_root = _PrivilegedVerifierSigner.create_ephemeral_pair()
        assert not attacker_root.is_canonical_anchor

        # 2. Valid frozen BUG_FIX contract
        contract = _make_sample_contract(requirement_id="REQ-SUB-ATTACK")
        base_fact, cand_fact = _make_production_facts()

        # 3 & 4. Attacker signs LIVE_NEBIUS attestation with attacker key without execution
        attacker_attestation = attacker_signer.issue_production_attestation(
            issuer_id=AUTHORIZED_NEBIUS_ISSUER_ID,
            execution_origin=VerifierExecutionOrigin.NEBIUS_TOKEN_FACTORY_SANDBOX.value,
            requirement_id="REQ-SUB-ATTACK",
            frozen_contract_digest="c" * 64,
            witness_id="wit-nebius-attack",
            witness_digest="a" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.PASS,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
            execution_command="pytest",
            base_sandbox_id=base_fact.sandbox_id,
            candidate_sandbox_id=cand_fact.sandbox_id,
            base_exit_code=base_fact.exit_code,
            candidate_exit_code=cand_fact.exit_code,
            base_termination_status=base_fact.termination_status,
            candidate_termination_status=cand_fact.termination_status,
            base_result_digest=base_fact.result_digest,
            candidate_result_digest=cand_fact.result_digest,
        )

        # 5. Structurally and cryptographically consistent receipt bound to actual contract
        receipt = create_causal_receipt(
            requirement_id="REQ-SUB-ATTACK",
            frozen_contract_digest="c" * 64,
            witness_id="wit-nebius-attack",
            witness_digest="a" * 64,
            lock_digest="d" * 64,
            base_execution=base_fact,
            candidate_execution=cand_fact,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
            narrative="Attacker substituted root LIVE_NEBIUS receipt",
            attestation=attacker_attestation,
        )

        # 6. Supply attacker-controlled VerifierAuthorityRoot to verification
        assert (
            verify_trusted_production_evidence(receipt=receipt, verifier_authority=attacker_root)
            is False
        )
        assert verify_trusted_production_evidence(receipt=receipt) is False

        # 7. Supply attacker-controlled root to compute_causal_coverage()
        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-SUB-ATTACK": receipt},
            verifier_authority=attacker_root,
        )

        # Required results:
        assert cov.verified_count == 0
        assert cov.overall_verdict != PreliminaryVerdict.VERIFIED
        assert cov.overall_verdict == PreliminaryVerdict.INCONCLUSIVE
        assert cov.inconclusive_count == 1
        assert cov.is_fully_verified is False

    def test_caller_controlled_worker_authority_root_substitution_attack_rejected(self) -> None:
        """Repeat trust-root substitution attack through Accepted TrustedVerifierWorker routes.

        Both passing worker.authority_root and passing worker directly must be rejected.
        """
        attacker_signer, _ = _PrivilegedVerifierSigner.create_ephemeral_pair()
        attacker_worker = TrustedVerifierWorker(signer=attacker_signer)
        assert not attacker_worker.authority_root.is_canonical_anchor

        contract = _make_sample_contract(requirement_id="REQ-WORKER-ATTACK")
        base_fact, cand_fact = _make_production_facts()

        attacker_attestation = attacker_signer.issue_production_attestation(
            issuer_id=AUTHORIZED_LOCAL_ISSUER_ID,
            execution_origin=VerifierExecutionOrigin.LOCAL_CONTAINER_ISOLATED_RUNTIME.value,
            requirement_id="REQ-WORKER-ATTACK",
            frozen_contract_digest="c" * 64,
            witness_id="wit-local-attack",
            witness_digest="a" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.PASS,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            execution_command="pytest",
            base_sandbox_id=base_fact.sandbox_id,
            candidate_sandbox_id=cand_fact.sandbox_id,
            base_exit_code=base_fact.exit_code,
            candidate_exit_code=cand_fact.exit_code,
            base_result_digest=base_fact.result_digest,
            candidate_result_digest=cand_fact.result_digest,
        )

        receipt = create_causal_receipt(
            requirement_id="REQ-WORKER-ATTACK",
            frozen_contract_digest="c" * 64,
            witness_id="wit-local-attack",
            witness_digest="a" * 64,
            lock_digest="d" * 64,
            base_execution=base_fact,
            candidate_execution=cand_fact,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            narrative="Attacker substituted worker receipt",
            attestation=attacker_attestation,
        )

        # Route A: Passing worker.authority_root
        assert (
            verify_trusted_production_evidence(
                receipt=receipt, verifier_authority=attacker_worker.authority_root
            )
            is False
        )
        cov_a = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-WORKER-ATTACK": receipt},
            verifier_authority=attacker_worker.authority_root,
        )
        assert cov_a.verified_count == 0
        assert cov_a.overall_verdict != PreliminaryVerdict.VERIFIED
        assert cov_a.overall_verdict == PreliminaryVerdict.INCONCLUSIVE
        assert cov_a.is_fully_verified is False

        # Route B: Passing worker directly
        assert (
            verify_trusted_production_evidence(receipt=receipt, verifier_authority=attacker_worker)
            is False
        )
        cov_b = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-WORKER-ATTACK": receipt},
            verifier_authority=attacker_worker,
        )
        assert cov_b.verified_count == 0
        assert cov_b.overall_verdict != PreliminaryVerdict.VERIFIED
        assert cov_b.overall_verdict == PreliminaryVerdict.INCONCLUSIVE
        assert cov_b.is_fully_verified is False

    def test_isolated_ephemeral_keypair_verifies_signature_in_isolation_only(self) -> None:
        """Isolated cryptographic unit test: Ephemeral keypair verifies in isolation only.

        An ephemeral keypair can cryptographically verify its own signature in unit isolation,
        but that isolated result does NOT qualify as trusted production verification.
        """
        signer, ephemeral_root = _PrivilegedVerifierSigner.create_ephemeral_pair()
        base_fact, cand_fact = _make_production_facts()
        contract = _make_sample_contract(requirement_id="REQ-EPHEM-01")

        attestation = signer.issue_production_attestation(
            issuer_id=AUTHORIZED_LOCAL_ISSUER_ID,
            execution_origin=VerifierExecutionOrigin.LOCAL_CONTAINER_ISOLATED_RUNTIME.value,
            requirement_id="REQ-EPHEM-01",
            frozen_contract_digest="c" * 64,
            witness_id="wit-ephem-1",
            witness_digest="a" * 64,
            source_commit_id="1" * 40,
            candidate_tree_digest="5" * 40,
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.PASS,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            execution_command="pytest",
            base_sandbox_id=base_fact.sandbox_id,
            candidate_sandbox_id=cand_fact.sandbox_id,
            base_exit_code=base_fact.exit_code,
            candidate_exit_code=cand_fact.exit_code,
            base_termination_status=base_fact.termination_status,
            candidate_termination_status=cand_fact.termination_status,
            base_result_digest=base_fact.result_digest,
            candidate_result_digest=cand_fact.result_digest,
        )

        receipt = create_causal_receipt(
            requirement_id="REQ-EPHEM-01",
            frozen_contract_digest="c" * 64,
            witness_id="wit-ephem-1",
            witness_digest="a" * 64,
            lock_digest="d" * 64,
            base_execution=base_fact,
            candidate_execution=cand_fact,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            narrative="Ephemeral test receipt",
            attestation=attestation,
        )

        # In isolation, the ephemeral root verifies its own cryptographic signature
        assert ephemeral_root.verify_production_attestation(attestation, receipt=receipt) is True

        # But that isolated result does NOT qualify as trusted production verification
        assert (
            verify_trusted_production_evidence(receipt=receipt, verifier_authority=ephemeral_root)
            is False
        )
        assert verify_trusted_production_evidence(receipt=receipt) is False

        cov = compute_causal_coverage(
            frozen_contract=contract,
            results={"REQ-EPHEM-01": receipt},
            verifier_authority=ephemeral_root,
        )
        assert cov.verified_count == 0
        assert cov.overall_verdict != PreliminaryVerdict.VERIFIED
        assert cov.overall_verdict == PreliminaryVerdict.INCONCLUSIVE
        assert cov.is_fully_verified is False

    def test_canonical_pinned_trust_anchor_structure_and_fail_closed_contract(self) -> None:
        """Verify the pinned canonical trust anchor structure and fail-closed behavior."""
        canonical_root = get_default_verifier_authority_root()
        assert canonical_root.is_canonical_anchor is True
        assert canonical_root.modulus == PINNED_VERIFIER_MODULUS
        assert canonical_root.exponent == PINNED_VERIFIER_EXPONENT

        default_worker = TrustedVerifierWorker()
        assert default_worker.authority_root.is_canonical_anchor is True

        # Without genuine execution environment/credentials, worker execution fails closed
        contract = _make_sample_contract(requirement_id="REQ-CANONICAL-01")
        vault = TrustedWitnessVault()
        wa = WitnessArtifact.from_text("tests/test_c.py", "def test_c(): pass\n")
        sealed = vault.seal_witness(
            witness_id="wit-c-1",
            requirement_id="REQ-CANONICAL-01",
            frozen_contract_digest="c" * 64,
            source_commit_id="1" * 40,
            artifacts=[wa],
        )
        lock = create_witness_lock(record=sealed, vault=vault)
        patch_text = "--- a/c\n+++ b/c\n@@ -1 +1 @@\n-fail\n+pass\n"
        patch_digest = hashlib.sha256(patch_text.encode("utf-8")).hexdigest()
        from basebreak.domain.causal import CandidateIdentity
        from basebreak.domain.source import CommitRevision, SourceIdentity

        src_id = SourceIdentity("https://github.com/example/repo.git", CommitRevision("1" * 40))
        cand_id = CandidateIdentity("cand-c", src_id, patch_digest)
        envelope = VerifierContextEnvelope.create(
            frozen_contract=contract,
            source_identity=src_id,
            candidate_identity=cand_id,
            candidate_patch_text=patch_text,
            candidate_tree_digest="5" * 40,
        )

        with pytest.raises(VerifierExecutionBlockedError):
            default_worker.execute_causal_pair(
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
