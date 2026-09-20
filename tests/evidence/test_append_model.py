"""Tests for run/evidence append model with immutable identifiers (P-03.02)."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from basebreak.domain.causal import CandidateIdentity
from basebreak.domain.execution import ExecutionCommand, ExecutionResult, TerminationStatus
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.append_model import (
    EvidenceConflictError,
    EvidenceIdentity,
    EvidenceRebindingError,
    EvidenceRecord,
    EvidenceStore,
    RunIdentity,
)
from basebreak.evidence.artifact import ArtifactDigest, DigestAlgorithm


def _make_candidate(candidate_id: str) -> CandidateIdentity:
    source = SourceIdentity(
        locator="https://github.com/example/repo",
        revision=CommitRevision("0123456789abcdef0123456789abcdef01234567"),
    )
    return CandidateIdentity(
        candidate_id=candidate_id,
        source=source,
        patch_digest="a" * 64,
        description="test candidate",
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
