"""Tests for evidence provenance validation and forbidden state transitions (P-03.04)."""

from __future__ import annotations

import dataclasses

import pytest

from basebreak.domain.execution import ExecutionResult, TerminationStatus
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.evidence import (
    EvidenceConflictError,
    EvidenceIdentity,
    EvidenceRecord,
    EvidenceStore,
    ProvenanceLaunderingError,
    ProvenanceTransitionError,
    RunIdentity,
    assert_provenance_not_verdict,
    has_execution_result,
    is_live_execution,
    is_recorded_live,
    is_successful_execution,
    validate_provenance_derivation,
    validate_provenance_transition,
)


class TestProvenanceTransitionsAndDerivations:
    def test_fixture_cannot_transition_to_local_execution(self) -> None:
        with pytest.raises(ProvenanceLaunderingError, match="Forbidden provenance transition"):
            validate_provenance_transition(
                EvidenceProvenance.FIXTURE, EvidenceProvenance.LOCAL_EXECUTION
            )

    def test_fixture_cannot_transition_to_live_nebius(self) -> None:
        with pytest.raises(ProvenanceLaunderingError, match="Forbidden provenance transition"):
            validate_provenance_transition(
                EvidenceProvenance.FIXTURE, EvidenceProvenance.LIVE_NEBIUS
            )

    def test_local_execution_cannot_transition_to_live_nebius(self) -> None:
        with pytest.raises(ProvenanceLaunderingError, match="Forbidden provenance transition"):
            validate_provenance_transition(
                EvidenceProvenance.LOCAL_EXECUTION, EvidenceProvenance.LIVE_NEBIUS
            )

    def test_recorded_live_cannot_transition_to_live_nebius(self) -> None:
        with pytest.raises(ProvenanceLaunderingError, match="Forbidden provenance transition"):
            validate_provenance_transition(
                EvidenceProvenance.RECORDED_LIVE, EvidenceProvenance.LIVE_NEBIUS
            )

    def test_same_provenance_transition_passes(self) -> None:
        # Identity validation is no-op
        validate_provenance_transition(
            EvidenceProvenance.LOCAL_EXECUTION, EvidenceProvenance.LOCAL_EXECUTION
        )
        validate_provenance_transition(
            EvidenceProvenance.LIVE_NEBIUS, EvidenceProvenance.LIVE_NEBIUS
        )

    def test_fixture_cannot_derive_non_fixture(self) -> None:
        src_id = EvidenceIdentity("ev-src-1")
        derived_id = EvidenceIdentity("ev-der-1")
        with pytest.raises(
            ProvenanceLaunderingError, match="Cannot derive 'LOCAL_EXECUTION' from FIXTURE"
        ):
            validate_provenance_derivation(
                EvidenceProvenance.FIXTURE,
                EvidenceProvenance.LOCAL_EXECUTION,
                src_id,
                derived_id,
            )
        with pytest.raises(
            ProvenanceLaunderingError, match="Cannot derive 'LIVE_NEBIUS' from FIXTURE"
        ):
            validate_provenance_derivation(
                EvidenceProvenance.FIXTURE,
                EvidenceProvenance.LIVE_NEBIUS,
                src_id,
                derived_id,
            )

    def test_non_live_cannot_derive_live_nebius(self) -> None:
        src_id = EvidenceIdentity("ev-src-2")
        derived_id = EvidenceIdentity("ev-der-2")
        with pytest.raises(
            ProvenanceLaunderingError, match="Cannot derive LIVE_NEBIUS from non-live source"
        ):
            validate_provenance_derivation(
                EvidenceProvenance.LOCAL_EXECUTION,
                EvidenceProvenance.LIVE_NEBIUS,
                src_id,
                derived_id,
            )
        with pytest.raises(
            ProvenanceLaunderingError, match="Cannot derive LIVE_NEBIUS from non-live source"
        ):
            validate_provenance_derivation(
                EvidenceProvenance.RECORDED_LIVE,
                EvidenceProvenance.LIVE_NEBIUS,
                src_id,
                derived_id,
            )

    def test_derivation_cannot_reuse_source_evidence_id(self) -> None:
        same_id = EvidenceIdentity("ev-same-id")
        with pytest.raises(
            ProvenanceTransitionError, match="Derived evidence cannot reuse source evidence_id"
        ):
            validate_provenance_derivation(
                EvidenceProvenance.FIXTURE,
                EvidenceProvenance.FIXTURE,
                same_id,
                same_id,
            )

    def test_valid_fixture_derivation_with_distinct_id(self) -> None:
        src_id = EvidenceIdentity("ev-src-3")
        der_id = EvidenceIdentity("ev-der-3")
        validate_provenance_derivation(
            EvidenceProvenance.FIXTURE,
            EvidenceProvenance.FIXTURE,
            src_id,
            der_id,
        )


class TestRecordedLiveVsLiveNebiusDistinction:
    def test_recorded_live_is_not_live_execution(self) -> None:
        assert not is_live_execution(EvidenceProvenance.RECORDED_LIVE)
        assert is_recorded_live(EvidenceProvenance.RECORDED_LIVE)

    def test_live_nebius_is_live_execution(self) -> None:
        assert is_live_execution(EvidenceProvenance.LIVE_NEBIUS)
        assert not is_recorded_live(EvidenceProvenance.LIVE_NEBIUS)

    def test_local_execution_and_fixture_are_not_live(self) -> None:
        assert not is_live_execution(EvidenceProvenance.LOCAL_EXECUTION)
        assert not is_live_execution(EvidenceProvenance.FIXTURE)
        assert not is_recorded_live(EvidenceProvenance.LOCAL_EXECUTION)
        assert not is_recorded_live(EvidenceProvenance.FIXTURE)


class TestEvidenceStoreProvenanceConflict:
    def test_same_evidence_id_with_changed_provenance_rejected(self) -> None:
        run = RunIdentity("run-prov-conflict")
        store = EvidenceStore(run_id=run)

        rec_fixture = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-conflict-1"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.FIXTURE,
        )
        store.append(rec_fixture)

        # Attempt to append record with same evidence_id but upgraded provenance
        rec_live = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-conflict-1"),
            run_id=run,
            sequence_number=1,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
        )
        with pytest.raises(EvidenceConflictError, match="conflicting provenance"):
            store.append(rec_live)


class TestProvenanceNotVerdictDecoupling:
    def test_provenance_never_dictates_verdict(self) -> None:
        # Live execution does not imply PASS/VERIFIED
        assert_provenance_not_verdict(
            EvidenceProvenance.LIVE_NEBIUS, PreliminaryVerdict.CONTRADICTED
        )
        assert_provenance_not_verdict(EvidenceProvenance.LIVE_NEBIUS, PreliminaryVerdict.VERIFIED)
        assert_provenance_not_verdict(EvidenceProvenance.FIXTURE, PreliminaryVerdict.NOT_RUN)

    def test_frozen_record_prevents_in_place_provenance_mutation(self) -> None:
        run = RunIdentity("run-frozen")
        rec = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-frozen-1"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.FIXTURE,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            rec.provenance = EvidenceProvenance.LIVE_NEBIUS  # type: ignore[misc]


class TestExecutionStateIntegrity:
    def test_result_none_cannot_be_synthesized_into_success(self) -> None:
        run = RunIdentity("run-exec-state")
        rec_unexecuted = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-unexec"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            result=None,
        )
        assert not has_execution_result(rec_unexecuted)
        assert not is_successful_execution(rec_unexecuted)

    def test_failed_execution_is_not_success(self) -> None:
        run = RunIdentity("run-exec-state-2")
        failed_result = ExecutionResult(
            status=TerminationStatus.COMPLETED,
            exit_code=1,
            duration_seconds=0.05,
        )
        rec_failed = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-failed"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            result=failed_result,
        )
        assert has_execution_result(rec_failed)
        assert not is_successful_execution(rec_failed)

    def test_successful_execution_identified(self) -> None:
        run = RunIdentity("run-exec-state-3")
        ok_result = ExecutionResult(
            status=TerminationStatus.COMPLETED,
            exit_code=0,
            duration_seconds=0.01,
        )
        rec_ok = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-ok"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            result=ok_result,
        )
        assert has_execution_result(rec_ok)
        assert is_successful_execution(rec_ok)
