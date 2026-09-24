"""Tests for run/evidence append model with immutable identifiers (P-03.02)."""

from __future__ import annotations

import dataclasses
from dataclasses import FrozenInstanceError

import pytest

from basebreak.domain.causal import (
    CandidateIdentity,
    CausalBinding,
    ExecutionWorld,
    WitnessIdentity,
)
from basebreak.domain.execution import ExecutionCommand, ExecutionResult, TerminationStatus
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.append_model import (
    EvidenceConflictError,
    EvidenceIdentity,
    EvidenceRebindingError,
    EvidenceRecord,
    EvidenceSequenceError,
    EvidenceStore,
    RunIdentity,
)
from basebreak.evidence.artifact import ArtifactDigest, DigestAlgorithm
from basebreak.security.secret_policy import REDACTION_MARKER, SecretPersistenceError


def _make_candidate(
    candidate_id: str,
    patch_digest: str = "a" * 64,
) -> CandidateIdentity:
    source = SourceIdentity(
        locator="https://github.com/example/repo",
        revision=CommitRevision("0123456789abcdef0123456789abcdef01234567"),
    )
    return CandidateIdentity(
        candidate_id=candidate_id,
        source=source,
        patch_digest=patch_digest,
        description="test candidate",
    )


def _make_causal_binding(candidate: CandidateIdentity) -> CausalBinding:
    return CausalBinding(
        requirement_id="REQ-TEST-1",
        witness=WitnessIdentity(witness_id="wit-001", digest="b" * 64, description="witness"),
        base_source=candidate.source,
        candidate=candidate,
        world=ExecutionWorld.CANDIDATE,
    )


class TestRunAndEvidenceIdentity:
    def test_run_identity_immutable(self) -> None:
        run = RunIdentity("run-12345")
        assert run.run_id == "run-12345"
        with pytest.raises(FrozenInstanceError):
            run.run_id = "run-mutated"  # type: ignore[misc]

    def test_run_identity_rejects_paths(self) -> None:
        with pytest.raises(ValueError, match="cannot be a path"):
            RunIdentity("/workspace/run-1")
        with pytest.raises(ValueError, match="cannot be a path"):
            RunIdentity("C:\\Users\\run-1")

    def test_run_identity_rejects_git_refs(self) -> None:
        with pytest.raises(ValueError, match="cannot be a git ref"):
            RunIdentity("refs/heads/main")

    def test_run_identity_rejects_empty_or_whitespace(self) -> None:
        with pytest.raises(ValueError, match="cannot be empty or whitespace only"):
            RunIdentity("")
        with pytest.raises(ValueError, match="cannot contain leading or trailing whitespace"):
            RunIdentity(" run-1 ")

    def test_evidence_identity_immutable(self) -> None:
        ev_id = EvidenceIdentity("ev-001")
        assert ev_id.evidence_id == "ev-001"
        with pytest.raises(FrozenInstanceError):
            ev_id.evidence_id = "ev-mutated"  # type: ignore[misc]

    def test_evidence_identity_rejects_invalid_strings(self) -> None:
        with pytest.raises(ValueError, match="cannot be a path"):
            EvidenceIdentity("sub/path/ev-1")
        with pytest.raises(ValueError, match="cannot contain leading or trailing whitespace"):
            EvidenceIdentity(" ev-1")


class TestEvidenceRecordFacts:
    def test_evidence_record_computes_fact_digest(self) -> None:
        run = RunIdentity("run-001")
        ev_id = EvidenceIdentity("ev-001")
        rec = EvidenceRecord(
            evidence_id=ev_id,
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            command=ExecutionCommand(argv=("pytest", "tests/unit")),
            result=ExecutionResult(
                status=TerminationStatus.COMPLETED,
                exit_code=0,
                duration_seconds=0.45,
            ),
        )
        assert rec.fact_digest is not None
        assert rec.fact_digest.algorithm == DigestAlgorithm.SHA256
        assert len(rec.fact_digest.value) == 64

    def test_tamper_evident_fact_digest_mismatch_rejected(self) -> None:
        run = RunIdentity("run-001")
        ev_id = EvidenceIdentity("ev-001")
        fake_digest = ArtifactDigest(
            algorithm=DigestAlgorithm.SHA256,
            value="0" * 64,
            byte_length=10,
        )
        with pytest.raises(ValueError, match="EvidenceRecord fact digest mismatch"):
            EvidenceRecord(
                evidence_id=ev_id,
                run_id=run,
                sequence_number=0,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                fact_digest=fake_digest,
            )

    def test_evidence_identity_is_bound_to_run(self) -> None:
        run_a = RunIdentity("run-A")
        run_b = RunIdentity("run-B")
        ev_id = EvidenceIdentity("ev-001")
        rec_a = EvidenceRecord(
            evidence_id=ev_id,
            run_id=run_a,
            sequence_number=0,
            provenance=EvidenceProvenance.FIXTURE,
        )
        assert rec_a.run_id == run_a
        assert rec_a.run_id != run_b

    def test_candidate_description_and_requested_ref_do_not_change_fact_digest(self) -> None:
        from basebreak.domain.source import RequestedRef

        src_a = SourceIdentity("repo-1", CommitRevision("a" * 40))
        src_b = SourceIdentity(
            "repo-1", CommitRevision("a" * 40), requested_ref=RequestedRef("refs/heads/feature")
        )
        cand_a = CandidateIdentity("cand-1", src_a, "b" * 64, description="desc A")
        cand_b = CandidateIdentity("cand-1", src_b, "b" * 64, description="desc B differing")

        run = RunIdentity("run-fact-desc")
        rec_a = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-1"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=cand_a,
        )
        rec_b = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-1"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=cand_b,
        )
        assert rec_a.fact_digest == rec_b.fact_digest

    def test_causal_witness_description_does_not_change_fact_digest(self) -> None:
        cand = _make_candidate("cand-1")
        run = RunIdentity("run-fact-wit")
        wit_a = WitnessIdentity("wit-1", "c" * 64, description="witness desc A")
        wit_b = WitnessIdentity("wit-1", "c" * 64, description="witness desc B")
        binding_a = CausalBinding(
            requirement_id="req-1",
            witness=wit_a,
            base_source=cand.source,
            candidate=cand,
            world=ExecutionWorld.CANDIDATE,
        )
        binding_b = CausalBinding(
            requirement_id="req-1",
            witness=wit_b,
            base_source=cand.source,
            candidate=cand,
            world=ExecutionWorld.CANDIDATE,
        )
        rec_a = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-1"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=cand,
            causal_binding=binding_a,
        )
        rec_b = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-1"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=cand,
            causal_binding=binding_b,
        )
        assert rec_a.fact_digest == rec_b.fact_digest


class TestEvidenceStoreAppendModel:
    def test_append_preserves_existing_records(self) -> None:
        run = RunIdentity("run-100")
        store = EvidenceStore(run_id=run)
        rec1 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-1"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        rec2 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-2"),
            run_id=run,
            sequence_number=1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        store.append(rec1)
        store.append(rec2)
        assert len(store) == 2
        all_recs = store.all_records()
        assert all_recs[0] == rec1
        assert all_recs[1] == rec2

    def test_deterministic_retrieval_order(self) -> None:
        run = RunIdentity("run-order")
        store = EvidenceStore(run_id=run)
        for i in range(5):
            rec = EvidenceRecord(
                evidence_id=EvidenceIdentity(f"ev-{i}"),
                run_id=run,
                sequence_number=i,
                provenance=EvidenceProvenance.FIXTURE,
            )
            store.append(rec)

        all_recs = store.all_records()
        for i in range(5):
            assert all_recs[i].sequence_number == i
            assert all_recs[i].evidence_id.evidence_id == f"ev-{i}"

    def test_idempotent_identical_duplicate_append(self) -> None:
        run = RunIdentity("run-idemp")
        store = EvidenceStore(run_id=run)
        rec = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-idemp"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        store.append(rec)
        store.append(rec)  # identical record appended again
        assert len(store) == 1

    def test_duplicate_conflicting_evidence_id_rejected(self) -> None:
        run = RunIdentity("run-conflict")
        store = EvidenceStore(run_id=run)
        rec1 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-same"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        rec2 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-same"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.FIXTURE,  # conflicting provenance!
        )
        store.append(rec1)
        with pytest.raises(
            EvidenceConflictError, match="Duplicate evidence ID 'ev-same' with conflicting contents"
        ):
            store.append(rec2)

    def test_candidate_a_evidence_cannot_be_rebound_to_candidate_b(self) -> None:
        cand_a = _make_candidate("cand-A")
        cand_b = _make_candidate("cand-B")
        run = RunIdentity("run-cand-bound")
        store = EvidenceStore(run_id=run, candidate=cand_a)

        rec_a = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-cand-a"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=cand_a,
        )
        store.append(rec_a)

        rec_b = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-cand-b"),
            run_id=run,
            sequence_number=1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=cand_b,
        )
        with pytest.raises(
            EvidenceRebindingError, match="Cannot append evidence for candidate 'cand-B'"
        ):
            store.append(rec_b)

    def test_evidence_from_run_a_cannot_be_appended_to_run_b_store(self) -> None:
        run_a = RunIdentity("run-A")
        run_b = RunIdentity("run-B")
        store_a = EvidenceStore(run_id=run_a)

        rec_b = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-from-b"),
            run_id=run_b,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        with pytest.raises(
            EvidenceRebindingError,
            match="Cannot append evidence for run 'run-B' to store bound to run 'run-A'",
        ):
            store_a.append(rec_b)

    def test_not_run_is_not_synthesized_into_successful_evidence(self) -> None:
        run = RunIdentity("run-notrun")
        store = EvidenceStore(run_id=run)
        unexecuted_rec = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-notrun"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            result=None,  # Not executed!
        )
        store.append(unexecuted_rec)

        stored = store.get("ev-notrun")
        assert stored is not None
        assert stored.result is None
        # Must never be synthesized into success
        assert stored.result != ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=0)

    def test_provenance_remains_exact_and_cannot_be_falsified(self) -> None:
        run = RunIdentity("run-prov")
        rec = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-prov"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        assert rec.provenance == EvidenceProvenance.LOCAL_EXECUTION
        assert rec.provenance.value != EvidenceProvenance.LIVE_NEBIUS.value


class TestCandidateBoundStoreBypassPrevention:
    def test_reject_record_with_no_candidate_and_no_causal_binding_in_candidate_bound_store(
        self,
    ) -> None:
        cand_a = _make_candidate("cand-A")
        store = EvidenceStore(run_id=RunIdentity("run-1"), candidate=cand_a)
        rec = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-1"),
            run_id=RunIdentity("run-1"),
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=None,
            causal_binding=None,
        )
        with pytest.raises(
            EvidenceRebindingError, match="Cannot append un-bound candidate evidence"
        ):
            store.append(rec)

    def test_reject_record_with_causal_binding_candidate_b_in_candidate_a_store(self) -> None:
        cand_a = _make_candidate("cand-A")
        cand_b = _make_candidate("cand-B")
        store = EvidenceStore(run_id=RunIdentity("run-1"), candidate=cand_a)
        binding_b = _make_causal_binding(cand_b)
        rec = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-1"),
            run_id=RunIdentity("run-1"),
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=None,
            causal_binding=binding_b,
        )
        with pytest.raises(
            EvidenceRebindingError, match="Cannot append evidence for candidate 'cand-B'"
        ):
            store.append(rec)

    def test_accept_record_with_candidate_none_and_causal_binding_candidate_a_in_candidate_a_store(
        self,
    ) -> None:
        cand_a = _make_candidate("cand-A")
        store = EvidenceStore(run_id=RunIdentity("run-1"), candidate=cand_a)
        binding_a = _make_causal_binding(cand_a)
        rec = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-1"),
            run_id=RunIdentity("run-1"),
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=None,
            causal_binding=binding_a,
        )
        store.append(rec)
        assert len(store) == 1
        assert store.get("ev-1") == rec

    def test_reject_direct_candidate_b_in_candidate_a_store(self) -> None:
        cand_a = _make_candidate("cand-A")
        cand_b = _make_candidate("cand-B")
        store = EvidenceStore(run_id=RunIdentity("run-1"), candidate=cand_a)
        rec = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-1"),
            run_id=RunIdentity("run-1"),
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=cand_b,
        )
        with pytest.raises(
            EvidenceRebindingError, match="Cannot append evidence for candidate 'cand-B'"
        ):
            store.append(rec)

    def test_accept_direct_candidate_a_in_candidate_a_store(self) -> None:
        cand_a = _make_candidate("cand-A")
        store = EvidenceStore(run_id=RunIdentity("run-1"), candidate=cand_a)
        rec = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-1"),
            run_id=RunIdentity("run-1"),
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=cand_a,
        )
        store.append(rec)
        assert len(store) == 1
        assert store.get("ev-1") == rec

    def test_reject_source_revision_change_even_when_candidate_id_matches(self) -> None:
        cand_a1 = _make_candidate("cand-A")
        source_alt = SourceIdentity(
            locator="https://github.com/example/repo",
            revision=CommitRevision("ffffffffffffffffffffffffffffffffffffffff"),
        )
        cand_a2 = CandidateIdentity(
            candidate_id="cand-A",
            source=source_alt,
            patch_digest="a" * 64,
            description="test candidate with different revision",
        )
        store = EvidenceStore(run_id=RunIdentity("run-1"), candidate=cand_a1)
        rec = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-1"),
            run_id=RunIdentity("run-1"),
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=cand_a2,
        )
        with pytest.raises(
            EvidenceRebindingError, match="Cannot append evidence for candidate 'cand-A'"
        ):
            store.append(rec)


class TestPerRunSequenceSemantics:
    def test_first_sequence_must_be_zero(self) -> None:
        run = RunIdentity("run-seq-1")
        store = EvidenceStore(run_id=run)
        rec = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-0"),
            run_id=run,
            sequence_number=1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        with pytest.raises(EvidenceSequenceError, match="Expected sequence_number 0"):
            store.append(rec)

    def test_consecutive_sequences_succeed(self) -> None:
        run = RunIdentity("run-seq-consec")
        store = EvidenceStore(run_id=run)
        for i in range(3):
            rec = EvidenceRecord(
                evidence_id=EvidenceIdentity(f"ev-{i}"),
                run_id=run,
                sequence_number=i,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
            )
            store.append(rec)
        assert len(store) == 3

    def test_duplicate_sequence_number_with_different_evidence_id_fails(self) -> None:
        run = RunIdentity("run-seq-dup")
        store = EvidenceStore(run_id=run)
        rec0 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-0"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        rec1_dup = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-different"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        store.append(rec0)
        with pytest.raises(EvidenceSequenceError, match="Expected sequence_number 1"):
            store.append(rec1_dup)

    def test_gap_in_sequence_numbers_fails(self) -> None:
        run = RunIdentity("run-seq-gap")
        store = EvidenceStore(run_id=run)
        rec0 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-0"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        rec2 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-2"),
            run_id=run,
            sequence_number=2,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        store.append(rec0)
        with pytest.raises(EvidenceSequenceError, match="Expected sequence_number 1"):
            store.append(rec2)

    def test_regression_in_sequence_numbers_fails(self) -> None:
        run = RunIdentity("run-seq-regress")
        store = EvidenceStore(run_id=run)
        rec0 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-0"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        rec1 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-1"),
            run_id=run,
            sequence_number=1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        rec_regress = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-regress"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        store.append(rec0)
        store.append(rec1)
        with pytest.raises(EvidenceSequenceError, match="Expected sequence_number 2"):
            store.append(rec_regress)

    def test_idempotent_exact_reappend_does_not_fail_or_advance_sequence(self) -> None:
        run = RunIdentity("run-seq-idemp")
        store = EvidenceStore(run_id=run)
        rec0 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-0"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        store.append(rec0)
        store.append(rec0)
        assert len(store) == 1
        rec1 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-1"),
            run_id=run,
            sequence_number=1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        store.append(rec1)
        assert len(store) == 2

    def test_idempotent_reappend_with_differing_candidate_description_succeeds(self) -> None:
        cand_orig = _make_candidate("cand-1")
        cand_desc = dataclasses.replace(cand_orig, description="new candidate description")
        run = RunIdentity("run-idemp-desc")
        store = EvidenceStore(run_id=run, candidate=cand_orig)

        rec0_orig = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-0"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=cand_orig,
        )
        rec0_desc = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-0"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=cand_desc,
        )
        assert rec0_orig.fact_digest == rec0_desc.fact_digest

        store.append(rec0_orig)
        # Idempotent re-append with differing non-authoritative description succeeds
        store.append(rec0_desc)
        assert len(store) == 1
        assert store.get("ev-0") == rec0_orig

    def test_separate_runs_each_begin_at_zero(self) -> None:
        store = EvidenceStore()
        run_a = RunIdentity("run-A")
        run_b = RunIdentity("run-B")
        rec_a0 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-a0"),
            run_id=run_a,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        rec_b0 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-b0"),
            run_id=run_b,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        rec_a1 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-a1"),
            run_id=run_a,
            sequence_number=1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        rec_b1 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-b1"),
            run_id=run_b,
            sequence_number=1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        store.append(rec_a0)
        store.append(rec_b0)
        store.append(rec_a1)
        store.append(rec_b1)
        assert len(store) == 4
        assert len(store.get_for_run("run-A")) == 2
        assert len(store.get_for_run("run-B")) == 2

    def test_retrieval_is_exact_sequence_order(self) -> None:
        store = EvidenceStore()
        run = RunIdentity("run-order")
        rec0 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-0"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        rec1 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-1"),
            run_id=run,
            sequence_number=1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        rec2 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-2"),
            run_id=run,
            sequence_number=2,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        store.append(rec0)
        store.append(rec1)
        store.append(rec2)
        recs = store.get_for_run("run-order")
        assert [r.sequence_number for r in recs] == [0, 1, 2]
        assert [r.evidence_id.evidence_id for r in recs] == ["ev-0", "ev-1", "ev-2"]


class TestSecretPersistenceBoundaryAndAtomicity:
    """Validate forbidden durable secret persistence and atomic failure in EvidenceStore."""

    def test_record_construction_rejects_secret_in_argv(self) -> None:
        synthetic_token = "sk-synthetic1234567890abcdef"
        cmd = ExecutionCommand(argv=("pytest", f"--api-key={synthetic_token}"))
        with pytest.raises(SecretPersistenceError) as exc_info:
            EvidenceRecord(
                evidence_id=EvidenceIdentity("ev-secret-argv"),
                run_id=RunIdentity("run-sec-1"),
                sequence_number=0,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                command=cmd,
            )
        err = exc_info.value
        assert "command.argv[1]" in err.path
        assert synthetic_token not in str(err)
        assert synthetic_token not in repr(err)

    def test_record_construction_rejects_secret_in_env(self) -> None:
        synthetic_key = "synthetic_api_key_xyz123"
        cmd = ExecutionCommand(
            argv=("python", "script.py"),
            env=(("NEBIUS_API_KEY", synthetic_key),),
        )
        with pytest.raises(SecretPersistenceError) as exc_info:
            EvidenceRecord(
                evidence_id=EvidenceIdentity("ev-secret-env"),
                run_id=RunIdentity("run-sec-2"),
                sequence_number=0,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                command=cmd,
            )
        err = exc_info.value
        assert "command.env[0].value" in err.path
        assert "NEBIUS_API_KEY" not in err.path
        assert synthetic_key not in str(err)
        assert synthetic_key not in repr(err)

    def test_record_construction_rejects_secret_in_candidate_description(self) -> None:
        synthetic_secret = "synthetic_candidate_secret_123"
        source = SourceIdentity(
            locator="https://github.com/repo",
            revision=CommitRevision("0" * 40),
        )
        cand = CandidateIdentity(
            candidate_id="cand-desc",
            source=source,
            patch_digest="a" * 64,
            description=f"Candidate generated with api_key={synthetic_secret}",
        )
        with pytest.raises(SecretPersistenceError) as exc_info:
            EvidenceRecord(
                evidence_id=EvidenceIdentity("ev-secret-cand"),
                run_id=RunIdentity("run-sec-3"),
                sequence_number=0,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                candidate=cand,
            )
        err = exc_info.value
        assert "candidate.description" in err.path
        assert synthetic_secret not in str(err)
        assert synthetic_secret not in repr(err)

    def test_serialization_fails_closed_on_secret(self) -> None:
        run = RunIdentity("run-sec-serial")
        ev_id = EvidenceIdentity("ev-serial-1")
        clean_cmd = ExecutionCommand(argv=("pytest",))
        rec = EvidenceRecord(
            evidence_id=ev_id,
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            command=clean_cmd,
        )
        # Normal record serializes cleanly
        d = rec.to_dict()
        assert d["evidence_id"] == "ev-serial-1"

        # Simulate a bypass where a record holds secret-bearing command
        tainted_cmd = ExecutionCommand(argv=("pytest", "sk-synthetic1234567890abcdef"))
        object.__setattr__(rec, "command", tainted_cmd)
        with pytest.raises(SecretPersistenceError) as exc_info:
            rec.to_dict()
        assert "sk-synthetic1234567890abcdef" not in str(exc_info.value)

    def test_evidence_store_append_failure_atomicity(self) -> None:
        store = EvidenceStore()
        run = RunIdentity("run-atomicity")

        # 1. Append legitimate first record at sequence 0
        rec0 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-000"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            command=ExecutionCommand(argv=("pytest", "tests/unit")),
        )
        store.append(rec0)
        assert len(store) == 1
        assert store._run_next_sequence["run-atomicity"] == 1

        # 2. Prepare record at sequence 1, tainted with secret
        rec1 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-001"),
            run_id=run,
            sequence_number=1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            command=ExecutionCommand(argv=("pytest", "tests/clean")),
        )
        tainted_cmd = ExecutionCommand(
            argv=("curl",),
            env=(("API_KEY", "synthetic_secret_token_never_persist"),),
        )
        object.__setattr__(rec1, "command", tainted_cmd)

        # 3. Attempt append - must fail closed with SecretPersistenceError
        with pytest.raises(SecretPersistenceError) as exc_info:
            store.append(rec1)
        err = exc_info.value
        assert "synthetic_secret_token_never_persist" not in str(err)

        # 4. Strict atomicity assertions:
        # - store length unchanged
        assert len(store) == 1
        # - rejected record absent from store
        assert store.get("ev-001") is None
        # - next expected sequence unchanged (still 1)
        assert store._run_next_sequence["run-atomicity"] == 1
        # - pre-existing records completely unaffected
        assert store.get("ev-000") == rec0

        # 5. Retry with safe/sanitized record at sequence 1 succeeds deterministically
        rec1_clean = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-001"),
            run_id=run,
            sequence_number=1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            command=ExecutionCommand(
                argv=("curl",),
                env=(("API_KEY", REDACTION_MARKER),),
            ),
        )
        store.append(rec1_clean)
        assert len(store) == 2
        assert store._run_next_sequence["run-atomicity"] == 2
        assert store.get("ev-001") == rec1_clean
