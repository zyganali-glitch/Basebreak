"""Tests for deterministic verdict-input snapshot binding (P-03.05)."""

from __future__ import annotations

import dataclasses

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
from basebreak.evidence import (
    ArtifactDigest,
    ArtifactReference,
    DigestAlgorithm,
    EvidenceConflictError,
    EvidenceIdentity,
    EvidenceRebindingError,
    EvidenceRecord,
    EvidenceSequenceError,
    EvidenceStore,
    RunIdentity,
    VerdictInputSnapshot,
    compute_bytes_digest,
)


def _make_candidate(
    cid: str = "cand-1",
    rev: str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    patch_bytes: bytes = b"diff --git a/foo b/foo\n",
) -> CandidateIdentity:
    source = SourceIdentity("repo-1", CommitRevision(rev))
    patch_digest = compute_bytes_digest(patch_bytes).value
    return CandidateIdentity(cid, source, patch_digest)


def _make_record(
    eid: str,
    run: RunIdentity,
    seq: int,
    cand: CandidateIdentity,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
    artifact_data: bytes = b"artifact content",
) -> EvidenceRecord:
    art_digest = compute_bytes_digest(artifact_data)
    art_ref = ArtifactReference(art_digest, "text/plain")
    return EvidenceRecord(
        evidence_id=EvidenceIdentity(eid),
        run_id=run,
        sequence_number=seq,
        provenance=provenance,
        candidate=cand,
        command=ExecutionCommand(("pytest", "-q")),
        result=ExecutionResult(
            status=TerminationStatus.COMPLETED, exit_code=0, duration_seconds=1.0
        ),
        artifacts=(art_ref,),
    )


class TestVerdictInputSnapshotDeterministicDigest:
    def test_identical_snapshots_produce_identical_digest(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-snap-1")
        rec0 = _make_record("ev-0", run, 0, cand)
        rec1 = _make_record("ev-1", run, 1, cand)

        snap1 = VerdictInputSnapshot(
            candidate=cand,
            run_id=run,
            requirement_id="req-core-1",
            records=(rec0, rec1),
            description="Run 1 analysis",
        )
        snap2 = VerdictInputSnapshot(
            candidate=cand,
            run_id=run,
            requirement_id="req-core-1",
            records=(rec0, rec1),
            description="Run 2 different description prose",
        )

        assert snap1.snapshot_digest is not None
        assert snap2.snapshot_digest is not None
        # Digest must be completely identical despite differing non-authoritative description prose
        assert snap1.snapshot_digest == snap2.snapshot_digest
        assert snap1.snapshot_digest.value == snap2.snapshot_digest.value

    def test_candidate_revision_change_changes_digest(self) -> None:
        cand_a = _make_candidate(rev="1111111111111111111111111111111111111111")
        cand_b = _make_candidate(rev="2222222222222222222222222222222222222222")
        run = RunIdentity("run-rev-diff")
        rec_a = _make_record("ev-0", run, 0, cand_a)
        rec_b = _make_record("ev-0", run, 0, cand_b)

        snap_a = VerdictInputSnapshot(
            candidate=cand_a,
            run_id=run,
            requirement_id="req-1",
            records=(rec_a,),
        )
        snap_b = VerdictInputSnapshot(
            candidate=cand_b,
            run_id=run,
            requirement_id="req-1",
            records=(rec_b,),
        )
        assert snap_a.snapshot_digest != snap_b.snapshot_digest

    def test_candidate_patch_digest_change_changes_digest(self) -> None:
        cand_a = _make_candidate(patch_bytes=b"patch A")
        cand_b = _make_candidate(patch_bytes=b"patch B")
        run = RunIdentity("run-patch-diff")
        rec_a = _make_record("ev-0", run, 0, cand_a)
        rec_b = _make_record("ev-0", run, 0, cand_b)

        snap_a = VerdictInputSnapshot(
            candidate=cand_a, run_id=run, requirement_id="req-1", records=(rec_a,)
        )
        snap_b = VerdictInputSnapshot(
            candidate=cand_b, run_id=run, requirement_id="req-1", records=(rec_b,)
        )
        assert snap_a.snapshot_digest != snap_b.snapshot_digest

    def test_run_id_change_changes_digest(self) -> None:
        cand = _make_candidate()
        run1 = RunIdentity("run-id-1")
        run2 = RunIdentity("run-id-2")
        rec1 = _make_record("ev-0", run1, 0, cand)
        rec2 = _make_record("ev-0", run2, 0, cand)

        snap1 = VerdictInputSnapshot(
            candidate=cand, run_id=run1, requirement_id="req-1", records=(rec1,)
        )
        snap2 = VerdictInputSnapshot(
            candidate=cand, run_id=run2, requirement_id="req-1", records=(rec2,)
        )
        assert snap1.snapshot_digest != snap2.snapshot_digest

    def test_evidence_fact_digest_change_changes_digest(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-fact-diff")
        # Different artifact contents will produce different fact digests
        rec1 = _make_record("ev-0", run, 0, cand, artifact_data=b"first output")
        rec2 = _make_record("ev-0", run, 0, cand, artifact_data=b"second differing output")
        assert rec1.fact_digest != rec2.fact_digest

        snap1 = VerdictInputSnapshot(
            candidate=cand, run_id=run, requirement_id="req-1", records=(rec1,)
        )
        snap2 = VerdictInputSnapshot(
            candidate=cand, run_id=run, requirement_id="req-1", records=(rec2,)
        )
        assert snap1.snapshot_digest != snap2.snapshot_digest

    def test_provenance_change_changes_digest(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-prov-diff")
        rec_local = _make_record(
            "ev-0", run, 0, cand, provenance=EvidenceProvenance.LOCAL_EXECUTION
        )
        rec_live = _make_record("ev-0", run, 0, cand, provenance=EvidenceProvenance.LIVE_NEBIUS)

        snap_local = VerdictInputSnapshot(
            candidate=cand, run_id=run, requirement_id="req-1", records=(rec_local,)
        )
        snap_live = VerdictInputSnapshot(
            candidate=cand, run_id=run, requirement_id="req-1", records=(rec_live,)
        )
        assert snap_local.snapshot_digest != snap_live.snapshot_digest

    def test_reordering_attack_rejected_or_changes_digest(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-order-diff")
        rec0 = _make_record("ev-0", run, 0, cand)
        rec1 = _make_record("ev-1", run, 1, cand)

        # Inverted sequence numbers (rec1 before rec0) must be rejected by sequence validation
        with pytest.raises(EvidenceSequenceError, match="sequence out of order"):
            VerdictInputSnapshot(
                candidate=cand, run_id=run, requirement_id="req-1", records=(rec1, rec0)
            )

    def test_wrong_declared_digest_rejected(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-tamper-digest")
        rec = _make_record("ev-0", run, 0, cand)
        fake_digest = ArtifactDigest(DigestAlgorithm.SHA256, "0" * 64, 42)

        with pytest.raises(ValueError, match="Snapshot digest mismatch"):
            VerdictInputSnapshot(
                candidate=cand,
                run_id=run,
                requirement_id="req-1",
                records=(rec,),
                snapshot_digest=fake_digest,
            )

    def test_candidate_description_does_not_change_snapshot_digest(self) -> None:
        cand_a = _make_candidate(cid="cand-desc", rev="a" * 40)
        cand_a_desc = dataclasses.replace(cand_a, description="modified candidate description")
        run = RunIdentity("run-desc-snap")
        rec_a = _make_record("ev-0", run, 0, cand_a)
        rec_a_desc = _make_record("ev-0", run, 0, cand_a_desc)

        snap_a = VerdictInputSnapshot(
            candidate=cand_a, run_id=run, requirement_id="req-1", records=(rec_a,)
        )
        snap_a_desc = VerdictInputSnapshot(
            candidate=cand_a_desc, run_id=run, requirement_id="req-1", records=(rec_a_desc,)
        )
        assert snap_a.snapshot_digest == snap_a_desc.snapshot_digest

    def test_source_requested_ref_does_not_change_snapshot_digest(self) -> None:
        from basebreak.domain.source import RequestedRef

        src_no_ref = SourceIdentity("repo-1", CommitRevision("a" * 40))
        src_with_ref = SourceIdentity(
            "repo-1", CommitRevision("a" * 40), requested_ref=RequestedRef("refs/heads/feature")
        )
        cand_no_ref = CandidateIdentity("cand-ref", src_no_ref, "d" * 64)
        cand_with_ref = CandidateIdentity("cand-ref", src_with_ref, "d" * 64)
        run = RunIdentity("run-ref-snap")
        rec_no_ref = _make_record("ev-0", run, 0, cand_no_ref)
        rec_with_ref = _make_record("ev-0", run, 0, cand_with_ref)

        snap_no_ref = VerdictInputSnapshot(
            candidate=cand_no_ref, run_id=run, requirement_id="req-1", records=(rec_no_ref,)
        )
        snap_with_ref = VerdictInputSnapshot(
            candidate=cand_with_ref, run_id=run, requirement_id="req-1", records=(rec_with_ref,)
        )
        assert snap_no_ref.snapshot_digest == snap_with_ref.snapshot_digest

    def test_witness_description_does_not_change_snapshot_digest(self) -> None:
        cand = _make_candidate(cid="cand-wit-desc")
        run = RunIdentity("run-wit-desc")
        wit_a = WitnessIdentity("wit-1", "b" * 64, "original witness description")
        wit_b = WitnessIdentity("wit-1", "b" * 64, "altered witness description")
        binding_a = CausalBinding(
            requirement_id="req-wit",
            witness=wit_a,
            base_source=cand.source,
            candidate=cand,
            world=ExecutionWorld.CANDIDATE,
        )
        binding_b = CausalBinding(
            requirement_id="req-wit",
            witness=wit_b,
            base_source=cand.source,
            candidate=cand,
            world=ExecutionWorld.CANDIDATE,
        )
        rec = _make_record("ev-0", run, 0, cand)
        snap_a = VerdictInputSnapshot(
            candidate=cand,
            run_id=run,
            requirement_id="req-wit",
            records=(rec,),
            causal_binding=binding_a,
        )
        snap_b = VerdictInputSnapshot(
            candidate=cand,
            run_id=run,
            requirement_id="req-wit",
            records=(rec,),
            causal_binding=binding_b,
        )
        assert snap_a.snapshot_digest == snap_b.snapshot_digest


class TestVerdictInputSnapshotRebindingRejection:
    def test_cross_run_evidence_rejected(self) -> None:
        cand = _make_candidate()
        run_a = RunIdentity("run-authorized-a")
        run_b = RunIdentity("run-foreign-b")

        rec_a = _make_record("ev-0", run_a, 0, cand)
        rec_b = _make_record("ev-1", run_b, 1, cand)  # From foreign run

        with pytest.raises(EvidenceRebindingError, match="Cross-run evidence rejected"):
            VerdictInputSnapshot(
                candidate=cand,
                run_id=run_a,
                requirement_id="req-1",
                records=(rec_a, rec_b),
            )

    def test_cross_candidate_evidence_rejected(self) -> None:
        cand_a = _make_candidate(cid="cand-authorized")
        cand_b = _make_candidate(cid="cand-foreign")
        run = RunIdentity("run-cross-cand")

        rec_a = _make_record("ev-0", run, 0, cand_a)
        rec_b = _make_record("ev-1", run, 1, cand_b)  # From foreign candidate

        with pytest.raises(EvidenceRebindingError, match="Cross-candidate evidence rejected"):
            VerdictInputSnapshot(
                candidate=cand_a,
                run_id=run,
                requirement_id="req-1",
                records=(rec_a, rec_b),
            )

    def test_candidate_unbound_evidence_rejected(self) -> None:
        cand = _make_candidate(cid="cand-auth")
        run = RunIdentity("run-unbound")
        rec_unbound = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-unbound"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=None,
            causal_binding=None,
        )
        with pytest.raises(EvidenceRebindingError, match="Candidate-unbound evidence rejected"):
            VerdictInputSnapshot(
                candidate=cand,
                run_id=run,
                requirement_id="req-1",
                records=(rec_unbound,),
            )

    def test_causal_binding_record_accepted_when_matching_candidate(self) -> None:
        cand = _make_candidate(cid="cand-auth")
        run = RunIdentity("run-causal-match")
        witness = WitnessIdentity("wit-1", "a" * 64, "test witness")
        binding = CausalBinding(
            requirement_id="req-causal",
            witness=witness,
            base_source=cand.source,
            candidate=cand,
            world=ExecutionWorld.CANDIDATE,
        )
        rec_causal = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-causal"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=None,
            causal_binding=binding,
        )
        snap = VerdictInputSnapshot(
            candidate=cand,
            run_id=run,
            requirement_id="req-causal",
            records=(rec_causal,),
            causal_binding=binding,
        )
        assert len(snap.records) == 1
        assert snap.snapshot_digest is not None

    def test_causal_binding_record_rejected_when_mismatched_candidate(self) -> None:
        cand_auth = _make_candidate(cid="cand-auth")
        cand_foreign = _make_candidate(cid="cand-foreign")
        run = RunIdentity("run-causal-mismatch")
        witness = WitnessIdentity("wit-1", "a" * 64, "test witness")
        foreign_binding = CausalBinding(
            requirement_id="req-causal",
            witness=witness,
            base_source=cand_foreign.source,
            candidate=cand_foreign,
            world=ExecutionWorld.CANDIDATE,
        )
        rec_foreign = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-foreign"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=None,
            causal_binding=foreign_binding,
        )
        with pytest.raises(EvidenceRebindingError, match="Cross-candidate evidence rejected"):
            VerdictInputSnapshot(
                candidate=cand_auth,
                run_id=run,
                requirement_id="req-causal",
                records=(rec_foreign,),
            )

    def test_duplicate_evidence_identity_in_snapshot_rejected(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-dup-id")
        rec0 = _make_record("ev-same", run, 0, cand)
        rec1 = _make_record("ev-same", run, 1, cand)
        with pytest.raises(EvidenceConflictError, match="Duplicate evidence identity 'ev-same'"):
            VerdictInputSnapshot(
                candidate=cand,
                run_id=run,
                requirement_id="req-1",
                records=(rec0, rec1),
            )


class TestVerdictInputSnapshotEmptyAndStoreBinding:
    def test_empty_records_rejected_by_default(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-empty")
        with pytest.raises(ValueError, match="requires at least one evidence record"):
            VerdictInputSnapshot(
                candidate=cand,
                run_id=run,
                requirement_id="req-1",
                records=(),
            )

    def test_empty_records_unconditionally_rejected(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-empty-unconditional")
        with pytest.raises(ValueError, match="requires at least one evidence record"):
            VerdictInputSnapshot(
                candidate=cand,
                run_id=run,
                requirement_id="req-1",
                records=(),
                description="NOT_RUN execution placeholder",
            )

    def test_from_store_constructs_valid_snapshot(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-store-bound")
        store = EvidenceStore(run_id=run, candidate=cand)

        rec0 = _make_record("ev-0", run, 0, cand)
        rec1 = _make_record("ev-1", run, 1, cand)
        store.append(rec0)
        store.append(rec1)

        snap = VerdictInputSnapshot.from_store(store, requirement_id="req-store-1")
        assert len(snap.records) == 2
        assert snap.candidate == cand
        assert snap.run_id == run
        assert snap.snapshot_digest is not None

    def test_causal_binding_consistency_enforced(self) -> None:
        cand = _make_candidate(cid="cand-causal")
        run = RunIdentity("run-causal")
        rec = _make_record("ev-0", run, 0, cand)
        witness = WitnessIdentity("wit-1", "a" * 64, "test witness")

        binding = CausalBinding(
            requirement_id="req-causal",
            witness=witness,
            base_source=cand.source,
            candidate=cand,
            world=ExecutionWorld.CANDIDATE,
        )

        snap = VerdictInputSnapshot(
            candidate=cand,
            run_id=run,
            requirement_id="req-causal",
            records=(rec,),
            causal_binding=binding,
        )
        assert snap.causal_binding == binding

        # Mismatched candidate in causal_binding rejected
        foreign_cand = _make_candidate(cid="cand-foreign")
        bad_binding = CausalBinding(
            requirement_id="req-causal",
            witness=witness,
            base_source=foreign_cand.source,
            candidate=foreign_cand,
            world=ExecutionWorld.CANDIDATE,
        )
        with pytest.raises(ValueError, match="Causal binding candidate .* does not match"):
            VerdictInputSnapshot(
                candidate=cand,
                run_id=run,
                requirement_id="req-causal",
                records=(rec,),
                causal_binding=bad_binding,
            )

    def test_frozen_snapshot_prevents_in_place_mutation(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-frozen-snap")
        rec = _make_record("ev-0", run, 0, cand)
        snap = VerdictInputSnapshot(
            candidate=cand, run_id=run, requirement_id="req-1", records=(rec,)
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            snap.requirement_id = "req-modified"  # type: ignore[misc]

    def test_to_dict_serialization(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-dict")
        rec = _make_record("ev-0", run, 0, cand)
        snap = VerdictInputSnapshot(
            candidate=cand, run_id=run, requirement_id="req-1", records=(rec,)
        )
        d = snap.to_dict()
        assert d["run_id"] == "run-dict"
        assert d["requirement_id"] == "req-1"
        assert d["schema_version"] == "1.0"
        assert len(d["records"]) == 1
        assert "snapshot_digest" in d
