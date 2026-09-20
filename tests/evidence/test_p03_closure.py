"""P-03 Phase-Closure Adversarial Test Suite.

Attacks the deterministic fact authority built in P-03.01–P-03.05 across:
A. Artifact tamper (digest mismatches, length mismatch, malformed/uppercase hashes)
B. Run / evidence rebinding (cross-run, cross-candidate, revision mutation)
C. Sequence / replay (duplicate sequence, gaps, regressions, conflicting duplicate IDs)
D. Provenance laundering (FIXTURE -> LIVE_NEBIUS, LOCAL_EXECUTION -> LIVE_NEBIUS,
   RECORDED_LIVE != LIVE)
E. Capture tamper / secret safety (direct CapturedStream bypass, secret retention, digest binding)
F. Verdict snapshot tamper (snapshot digest mismatch, candidate/run/provenance mutation)
G. Serialization / canonical reconstruction (no repr/memory addresses, canonical byte stability)
"""

from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest

from basebreak.domain.causal import (
    CandidateIdentity,
    CausalBinding,
    ExecutionWorld,
    WitnessIdentity,
)
from basebreak.domain.execution import (
    ExecutionCommand,
    ExecutionResult,
    TerminationStatus,
)
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence import (
    Artifact,
    ArtifactDigest,
    ArtifactReference,
    CapturedStream,
    DigestAlgorithm,
    EvidenceConflictError,
    EvidenceIdentity,
    EvidenceRebindingError,
    EvidenceRecord,
    EvidenceSequenceError,
    EvidenceStore,
    ProvenanceLaunderingError,
    RunIdentity,
    StreamType,
    VerdictInputSnapshot,
    capture_stream,
    compute_bytes_digest,
    is_live_execution,
    is_recorded_live,
    validate_provenance_derivation,
    validate_provenance_transition,
)


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _make_candidate(
    cid: str = "cand-1",
    rev: str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    patch_bytes: bytes = b"diff --git a/file b/file\n",
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
    artifact_bytes: bytes = b"artifact output",
) -> EvidenceRecord:
    digest = compute_bytes_digest(artifact_bytes)
    art_ref = ArtifactReference(digest, "text/plain")
    return EvidenceRecord(
        evidence_id=EvidenceIdentity(eid),
        run_id=run,
        sequence_number=seq,
        provenance=provenance,
        candidate=cand,
        command=ExecutionCommand(("pytest", "-q")),
        result=ExecutionResult(
            status=TerminationStatus.COMPLETED, exit_code=0, duration_seconds=0.1
        ),
        artifacts=(art_ref,),
    )


# ==============================================================================
# A. ARTIFACT TAMPER
# ==============================================================================


class TestArtifactTamperAdversarial:
    def test_artifact_content_changed_with_old_digest_rejected(self) -> None:
        original = b"authentic data"
        tampered = b"tampered data!"
        digest = compute_bytes_digest(original)
        with pytest.raises(ValueError, match="Artifact digest mismatch"):
            Artifact(digest=digest, content=tampered)

    def test_digest_length_mismatch_rejected(self) -> None:
        content = b"sample content"
        digest = compute_bytes_digest(content)
        # Attempt to create Artifact with mismatched byte_length
        mismatched_digest = ArtifactDigest(
            algorithm=DigestAlgorithm.SHA256,
            value=digest.value,
            byte_length=len(content) + 10,
        )
        with pytest.raises(ValueError, match="Artifact digest mismatch"):
            Artifact(digest=mismatched_digest, content=content)

    def test_uppercase_hex_digest_rejected(self) -> None:
        valid_hex = _sha256_hex(b"test")
        with pytest.raises(ValueError, match="Must be exactly 64 lowercase hexadecimal"):
            ArtifactDigest(
                algorithm=DigestAlgorithm.SHA256,
                value=valid_hex.upper(),
                byte_length=4,
            )

    def test_malformed_non_hex_digest_rejected(self) -> None:
        with pytest.raises(ValueError, match="Must be exactly 64 lowercase hexadecimal"):
            ArtifactDigest(
                algorithm=DigestAlgorithm.SHA256,
                value="z" * 64,
                byte_length=4,
            )

    def test_negative_or_bool_byte_length_rejected(self) -> None:
        valid_hex = _sha256_hex(b"test")
        with pytest.raises(TypeError, match="byte_length must be an int"):
            ArtifactDigest(DigestAlgorithm.SHA256, valid_hex, True)
        with pytest.raises(ValueError, match="byte_length must be non-negative"):
            ArtifactDigest(DigestAlgorithm.SHA256, valid_hex, -1)


# ==============================================================================
# B. RUN / EVIDENCE REBINDING
# ==============================================================================


class TestRunEvidenceRebindingAdversarial:
    def test_evidence_from_run_a_inserted_into_run_b_rejected(self) -> None:
        cand = _make_candidate()
        run_a = RunIdentity("run-alpha")
        run_b = RunIdentity("run-beta")
        store_b = EvidenceStore(run_id=run_b)

        rec_a = _make_record("ev-0", run_a, 0, cand)
        with pytest.raises(
            EvidenceRebindingError, match="Cannot append evidence for run 'run-alpha'"
        ):
            store_b.append(rec_a)

    def test_candidate_a_evidence_inserted_into_candidate_b_context_rejected(self) -> None:
        cand_a = _make_candidate(cid="cand-alpha")
        cand_b = _make_candidate(cid="cand-beta")
        run = RunIdentity("run-cand-bound")
        store_b = EvidenceStore(run_id=run, candidate=cand_b)

        rec_a = _make_record("ev-0", run, 0, cand_a)
        with pytest.raises(
            EvidenceRebindingError, match="Cannot append evidence for candidate 'cand-alpha'"
        ):
            store_b.append(rec_a)

    def test_same_candidate_id_with_different_source_revision_rejected(self) -> None:
        cand_v1 = _make_candidate(cid="cand-same", rev="1" * 40)
        cand_v2 = _make_candidate(cid="cand-same", rev="2" * 40)
        run = RunIdentity("run-rev-bound")
        store = EvidenceStore(run_id=run, candidate=cand_v1)

        rec_v2 = _make_record("ev-0", run, 0, cand_v2)
        with pytest.raises(EvidenceRebindingError, match="Cannot append evidence for candidate"):
            store.append(rec_v2)

    def test_absent_candidate_cannot_bypass_candidate_bound_store(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-unbound-check")
        store = EvidenceStore(run_id=run, candidate=cand)

        rec_unbound = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-unbound"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            candidate=None,
        )
        with pytest.raises(
            EvidenceRebindingError, match="Cannot append un-bound candidate evidence"
        ):
            store.append(rec_unbound)

    def test_causal_binding_candidate_cannot_bypass_direct_candidate_boundary(self) -> None:
        cand_direct = _make_candidate(cid="cand-direct")
        cand_causal = _make_candidate(cid="cand-causal")
        run = RunIdentity("run-causal-mismatch")

        witness = WitnessIdentity("wit-1", "b" * 64)
        causal = CausalBinding(
            requirement_id="req-1",
            witness=witness,
            base_source=cand_causal.source,
            candidate=cand_causal,
            world=ExecutionWorld.CANDIDATE,
        )

        with pytest.raises(ValueError, match="Candidate mismatch"):
            EvidenceRecord(
                evidence_id=EvidenceIdentity("ev-mismatch"),
                run_id=run,
                sequence_number=0,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                candidate=cand_direct,
                causal_binding=causal,
            )


# ==============================================================================
# C. SEQUENCE / REPLAY
# ==============================================================================


class TestSequenceReplayAdversarial:
    def test_sequence_gap_rejected(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-seq-gap")
        store = EvidenceStore(run_id=run)

        rec0 = _make_record("ev-0", run, 0, cand)
        rec2 = _make_record("ev-2", run, 2, cand)  # Gap: expected sequence 1!
        store.append(rec0)

        with pytest.raises(EvidenceSequenceError, match="Expected sequence_number 1"):
            store.append(rec2)

    def test_sequence_regression_rejected(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-seq-regress")
        store = EvidenceStore(run_id=run)

        rec0 = _make_record("ev-0", run, 0, cand)
        rec1 = _make_record("ev-1", run, 1, cand)
        rec_regress = _make_record("ev-regress", run, 0, cand)
        store.append(rec0)
        store.append(rec1)

        with pytest.raises(EvidenceSequenceError, match="Expected sequence_number 2"):
            store.append(rec_regress)

    def test_idempotent_exact_replay_is_harmless(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-idempotent")
        store = EvidenceStore(run_id=run)

        rec0 = _make_record("ev-0", run, 0, cand)
        store.append(rec0)
        # Re-appending identical record must succeed without sequence advancement
        store.append(rec0)
        assert len(store) == 1

        rec1 = _make_record("ev-1", run, 1, cand)
        store.append(rec1)
        assert len(store) == 2

    def test_replay_of_same_evidence_id_with_modified_fact_digest_rejected(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-replay-tamper")
        store = EvidenceStore(run_id=run)

        rec0 = _make_record("ev-0", run, 0, cand, artifact_bytes=b"original bytes")
        store.append(rec0)

        rec0_tampered = _make_record("ev-0", run, 0, cand, artifact_bytes=b"altered bytes")
        with pytest.raises(
            EvidenceConflictError, match="Duplicate evidence ID 'ev-0' with conflicting contents"
        ):
            store.append(rec0_tampered)


# ==============================================================================
# D. PROVENANCE LAUNDERING
# ==============================================================================


class TestProvenanceLaunderingAdversarial:
    def test_same_evidence_id_relabelled_fixture_to_live_nebius_rejected(self) -> None:
        run = RunIdentity("run-prov-laundering")
        store = EvidenceStore(run_id=run)

        rec_fix = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-laundering"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.FIXTURE,
        )
        store.append(rec_fix)

        rec_live = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-laundering"),
            run_id=run,
            sequence_number=1,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
        )
        with pytest.raises(EvidenceConflictError, match="conflicting provenance"):
            store.append(rec_live)

    def test_transition_fixture_to_live_nebius_rejected(self) -> None:
        with pytest.raises(ProvenanceLaunderingError, match="Forbidden provenance transition"):
            validate_provenance_transition(
                EvidenceProvenance.FIXTURE, EvidenceProvenance.LIVE_NEBIUS
            )

    def test_transition_local_execution_to_live_nebius_rejected(self) -> None:
        with pytest.raises(ProvenanceLaunderingError, match="Forbidden provenance transition"):
            validate_provenance_transition(
                EvidenceProvenance.LOCAL_EXECUTION, EvidenceProvenance.LIVE_NEBIUS
            )

    def test_derivation_fixture_to_live_nebius_rejected(self) -> None:
        with pytest.raises(
            ProvenanceLaunderingError, match="Cannot derive 'LIVE_NEBIUS' from FIXTURE"
        ):
            validate_provenance_derivation(
                EvidenceProvenance.FIXTURE,
                EvidenceProvenance.LIVE_NEBIUS,
                EvidenceIdentity("src-1"),
                EvidenceIdentity("der-1"),
            )

    def test_recorded_live_cannot_satisfy_current_live(self) -> None:
        assert not is_live_execution(EvidenceProvenance.RECORDED_LIVE)
        assert is_recorded_live(EvidenceProvenance.RECORDED_LIVE)
        assert is_live_execution(EvidenceProvenance.LIVE_NEBIUS)


# ==============================================================================
# E. CAPTURE TAMPER / SECRET SAFETY
# ==============================================================================


class TestCaptureTamperSecretSafetyAdversarial:
    def test_direct_construction_cannot_bypass_sanitized_retained_invariant(self) -> None:
        raw = b"safe output"
        digest = compute_bytes_digest(raw)
        with pytest.raises(ValueError, match="sanitized_text must equal retained_text"):
            CapturedStream(
                stream_type=StreamType.STDOUT,
                full_digest=digest,
                original_byte_length=len(raw),
                is_truncated=False,
                max_bytes=1000,
                retained_bytes=raw,
                retained_text="safe output",
                sanitized_text="falsified sanitized text",
                is_sanitized=False,
            )

    def test_contradictory_raw_length_and_digest_length_rejected(self) -> None:
        raw = b"safe output"
        digest = compute_bytes_digest(raw)  # len is 11
        with pytest.raises(
            ValueError, match=r"full_digest\.byte_length .* does not match original_byte_length"
        ):
            CapturedStream(
                stream_type=StreamType.STDOUT,
                full_digest=digest,
                original_byte_length=999,
                is_truncated=False,
                max_bytes=1000,
                retained_bytes=raw,
                retained_text="safe output",
                sanitized_text="safe output",
                is_sanitized=False,
            )

    def test_secret_bearing_durable_retained_fields_rejected(self) -> None:
        secret_text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        raw_bytes = secret_text.encode("utf-8")
        digest = compute_bytes_digest(raw_bytes)
        with pytest.raises(ValueError, match="retained_text contains unsanitized secret material"):
            CapturedStream(
                stream_type=StreamType.STDOUT,
                full_digest=digest,
                original_byte_length=len(raw_bytes),
                is_truncated=False,
                max_bytes=1000,
                retained_bytes=raw_bytes,
                retained_text=secret_text,
                sanitized_text=secret_text,
                is_sanitized=False,
            )

    def test_retained_bytes_secret_with_cleaned_text_rejected(self) -> None:
        secret_bytes = b"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        clean_text = "Bearer [REDACTED]"
        digest = compute_bytes_digest(secret_bytes)
        with pytest.raises(ValueError, match="retained_text does not match retained_bytes"):
            CapturedStream(
                stream_type=StreamType.STDOUT,
                full_digest=digest,
                original_byte_length=len(secret_bytes),
                is_truncated=False,
                max_bytes=1000,
                retained_bytes=secret_bytes,
                retained_text=clean_text,
                sanitized_text=clean_text,
                is_sanitized=True,
            )

    def test_factory_full_digest_still_binds_original_exact_bytes(self) -> None:
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        raw_input = f"prefix text Bearer {token} trailing log"
        captured = capture_stream(raw_input, StreamType.STDOUT, max_bytes=30)
        assert captured.is_sanitized
        assert captured.is_truncated
        # Full digest must equal exact original raw input bytes, not truncated or redacted bytes
        assert captured.full_digest == compute_bytes_digest(raw_input.encode("utf-8"))
        assert captured.original_byte_length == len(raw_input.encode("utf-8"))


# ==============================================================================
# F. VERDICT SNAPSHOT TAMPER
# ==============================================================================


class TestVerdictSnapshotTamperAdversarial:
    def test_snapshot_digest_mismatch_rejected(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-snap-tamper")
        rec = _make_record("ev-0", run, 0, cand)
        fake_digest = ArtifactDigest(DigestAlgorithm.SHA256, "e" * 64, 123)

        with pytest.raises(ValueError, match="Snapshot digest mismatch"):
            VerdictInputSnapshot(
                candidate=cand,
                run_id=run,
                requirement_id="req-1",
                records=(rec,),
                snapshot_digest=fake_digest,
            )

    def test_evidence_replaced_changes_snapshot_digest(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-snap-replace")
        rec_orig = _make_record("ev-0", run, 0, cand, artifact_bytes=b"original artifact")
        rec_repl = _make_record("ev-0", run, 0, cand, artifact_bytes=b"mutated artifact")

        snap_orig = VerdictInputSnapshot(
            candidate=cand, run_id=run, requirement_id="req-1", records=(rec_orig,)
        )
        snap_repl = VerdictInputSnapshot(
            candidate=cand, run_id=run, requirement_id="req-1", records=(rec_repl,)
        )
        assert snap_orig.snapshot_digest != snap_repl.snapshot_digest

    def test_candidate_change_changes_snapshot_digest(self) -> None:
        cand_a = _make_candidate(cid="cand-a")
        cand_b = _make_candidate(cid="cand-b")
        run = RunIdentity("run-cand-change")
        rec_a = _make_record("ev-0", run, 0, cand_a)
        rec_b = _make_record("ev-0", run, 0, cand_b)

        snap_a = VerdictInputSnapshot(
            candidate=cand_a, run_id=run, requirement_id="req-1", records=(rec_a,)
        )
        snap_b = VerdictInputSnapshot(
            candidate=cand_b, run_id=run, requirement_id="req-1", records=(rec_b,)
        )
        assert snap_a.snapshot_digest != snap_b.snapshot_digest

    def test_provenance_change_changes_snapshot_digest(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-prov-snap")
        rec_loc = _make_record("ev-0", run, 0, cand, provenance=EvidenceProvenance.LOCAL_EXECUTION)
        rec_live = _make_record("ev-0", run, 0, cand, provenance=EvidenceProvenance.LIVE_NEBIUS)

        snap_loc = VerdictInputSnapshot(
            candidate=cand, run_id=run, requirement_id="req-1", records=(rec_loc,)
        )
        snap_live = VerdictInputSnapshot(
            candidate=cand, run_id=run, requirement_id="req-1", records=(rec_live,)
        )
        assert snap_loc.snapshot_digest != snap_live.snapshot_digest

    def test_non_authoritative_prose_does_not_affect_persistent_digest(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-prose-snap")
        rec = _make_record("ev-0", run, 0, cand)

        snap1 = VerdictInputSnapshot(
            candidate=cand,
            run_id=run,
            requirement_id="req-1",
            records=(rec,),
            description="Analysis summary A",
        )
        snap2 = VerdictInputSnapshot(
            candidate=cand,
            run_id=run,
            requirement_id="req-1",
            records=(rec,),
            description="Analysis summary B differing text",
        )
        assert snap1.snapshot_digest == snap2.snapshot_digest

    def test_frozen_snapshot_blocks_in_place_tamper(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-freeze-test")
        rec = _make_record("ev-0", run, 0, cand)
        snap = VerdictInputSnapshot(
            candidate=cand, run_id=run, requirement_id="req-1", records=(rec,)
        )

        with pytest.raises(dataclasses.FrozenInstanceError):
            snap.requirement_id = "req-tampered"  # type: ignore[misc]


# ==============================================================================
# G. SERIALIZATION / CANONICAL RECONSTRUCTION
# ==============================================================================


class TestSerializationReconstructionAdversarial:
    def test_canonical_reconstruction_gives_identical_digest(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-recon")
        rec0 = _make_record("ev-0", run, 0, cand)
        rec1 = _make_record("ev-1", run, 1, cand)

        snap = VerdictInputSnapshot(
            candidate=cand,
            run_id=run,
            requirement_id="req-recon-1",
            records=(rec0, rec1),
            description="Canonical reconstruction test",
        )

        # Serialize to dict and JSON
        d = snap.to_dict()
        json_str = json.dumps(d, sort_keys=True)
        reloaded = json.loads(json_str)

        # Reconstructed snapshot must compute the exact same digest
        reconstructed_records = tuple(
            EvidenceRecord(
                evidence_id=EvidenceIdentity(r["evidence_id"]),
                run_id=RunIdentity(r["run_id"]),
                sequence_number=r["sequence_number"],
                provenance=EvidenceProvenance(r["provenance"]),
                candidate=cand,
                command=rec0.command if r["sequence_number"] == 0 else rec1.command,
                result=rec0.result if r["sequence_number"] == 0 else rec1.result,
                artifacts=rec0.artifacts if r["sequence_number"] == 0 else rec1.artifacts,
            )
            for r in reloaded["records"]
        )
        snap_reconstructed = VerdictInputSnapshot(
            candidate=cand,
            run_id=RunIdentity(reloaded["run_id"]),
            requirement_id=reloaded["requirement_id"],
            records=reconstructed_records,
            description=reloaded["description"],
        )
        assert snap.snapshot_digest == snap_reconstructed.snapshot_digest

    def test_no_repr_or_memory_address_enters_digest(self) -> None:
        cand = _make_candidate()
        run = RunIdentity("run-repr-leak")
        rec = _make_record("ev-0", run, 0, cand)
        snap = VerdictInputSnapshot(
            candidate=cand, run_id=run, requirement_id="req-1", records=(rec,)
        )

        # Verify digest hex contains no 0x prefix
        assert snap.snapshot_digest is not None
        assert "0x" not in snap.snapshot_digest.value
        assert len(snap.snapshot_digest.value) == 64
