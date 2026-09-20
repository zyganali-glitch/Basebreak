"""Tests for content-addressed artifact hashing and canonical serialization (P-03.01)."""

from __future__ import annotations

import hashlib
import json

import pytest

from basebreak.domain.causal import CandidateIdentity
from basebreak.domain.execution import ExecutionCommand, ExecutionResult, TerminationStatus
from basebreak.domain.serialization import from_canonical_json, to_canonical_json
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.task import AcceptanceRequirement, EngineeringTask
from basebreak.evidence.artifact import (
    Artifact,
    ArtifactDigest,
    ArtifactReference,
    DigestAlgorithm,
    artifact_from_bytes,
    artifact_from_domain_object,
    artifact_from_text,
    compute_bytes_digest,
    compute_domain_digest,
    compute_text_digest,
    to_canonical_artifact_json,
)


class TestExactByteSemantics:
    def test_same_bytes_produce_same_digest(self) -> None:
        data = b"deterministic bytes for Basebreak\x00\xff\xfe"
        digest1 = compute_bytes_digest(data)
        digest2 = compute_bytes_digest(data)
        assert digest1 == digest2
        assert digest1.value == hashlib.sha256(data).hexdigest()
        assert digest1.byte_length == len(data)
        assert digest1.algorithm == DigestAlgorithm.SHA256

    def test_changed_byte_produces_changed_digest(self) -> None:
        data_a = b"hello world"
        data_b = b"hello World"  # 1 byte change
        digest_a = compute_bytes_digest(data_a)
        digest_b = compute_bytes_digest(data_b)
        assert digest_a != digest_b
        assert digest_a.value != digest_b.value
        assert digest_a.byte_length == digest_b.byte_length

    def test_empty_bytes_produce_known_sha256(self) -> None:
        empty = b""
        digest = compute_bytes_digest(empty)
        expected_hex = hashlib.sha256(empty).hexdigest()
        assert digest.value == expected_hex
        assert digest.byte_length == 0

    def test_no_silent_normalization_of_binary_bytes(self) -> None:
        crlf_bytes = b"line1\r\nline2\r\n"
        lf_bytes = b"line1\nline2\n"
        digest_crlf = compute_bytes_digest(crlf_bytes)
        digest_lf = compute_bytes_digest(lf_bytes)
        assert digest_crlf != digest_lf

    def test_text_convenience_helper_utf8(self) -> None:
        text = "Basebreak: Türkçe ve English 🚀"
        digest_text = compute_text_digest(text)
        digest_bytes = compute_bytes_digest(text.encode("utf-8"))
        assert digest_text == digest_bytes

    def test_text_helper_rejects_non_utf8(self) -> None:
        with pytest.raises(
            ValueError, match="Basebreak canonical text encoding is strictly 'utf-8'"
        ):
            compute_text_digest("test", encoding="latin-1")


class TestCanonicalDomainSerializationHashing:
    def test_canonical_domain_object_digest_stability(self) -> None:
        task = EngineeringTask(
            task_id="BB-101",
            title="Fix auth vulnerability",
            description="Prevent session fixation",
            requirements=(
                AcceptanceRequirement(
                    requirement_id="REQ-1",
                    statement="Invalidate old session upon login",
                ),
            ),
        )
        digest1 = compute_domain_digest(task)
        digest2 = compute_domain_digest(task)
        assert digest1 == digest2

        # Round-trip through canonical JSON and recompute
        json_str = to_canonical_json(task)
        reconstructed = from_canonical_json(json_str)
        digest_reconstructed = compute_domain_digest(reconstructed)
        assert digest1 == digest_reconstructed

    def test_dict_insertion_order_cannot_alter_canonical_object_digest(self) -> None:
        cmd1 = ExecutionCommand(
            argv=("pytest", "-v"),
            cwd="workspace",
            env=(("B_VAR", "2"), ("A_VAR", "1")),
        )
        cmd2 = ExecutionCommand(
            argv=("pytest", "-v"),
            cwd="workspace",
            env=(("B_VAR", "2"), ("A_VAR", "1")),
        )
        assert compute_domain_digest(cmd1) == compute_domain_digest(cmd2)

    def test_memory_address_does_not_leak_into_digest(self) -> None:
        res1 = ExecutionResult(
            status=TerminationStatus.COMPLETED, exit_code=0, duration_seconds=1.23
        )
        res2 = ExecutionResult(
            status=TerminationStatus.COMPLETED, exit_code=0, duration_seconds=1.23
        )
        assert id(res1) != id(res2)
        d1 = compute_domain_digest(res1)
        d2 = compute_domain_digest(res2)
        assert d1 == d2
        assert "0x" not in d1.value


class TestStrictValidation:
    def test_reject_uppercase_hex_digest(self) -> None:
        valid_lower = hashlib.sha256(b"sample").hexdigest()
        uppercase_val = valid_lower.upper()
        with pytest.raises(ValueError, match="Invalid SHA-256 digest"):
            ArtifactDigest(
                algorithm=DigestAlgorithm.SHA256,
                value=uppercase_val,
                byte_length=6,
            )

    def test_reject_wrong_digest_length(self) -> None:
        with pytest.raises(ValueError, match="Invalid SHA-256 digest"):
            ArtifactDigest(
                algorithm=DigestAlgorithm.SHA256,
                value="a" * 63,
                byte_length=10,
            )
        with pytest.raises(ValueError, match="Invalid SHA-256 digest"):
            ArtifactDigest(
                algorithm=DigestAlgorithm.SHA256,
                value="a" * 65,
                byte_length=10,
            )

    def test_reject_non_hex_characters(self) -> None:
        with pytest.raises(ValueError, match="Invalid SHA-256 digest"):
            ArtifactDigest(
                algorithm=DigestAlgorithm.SHA256,
                value="g" * 64,
                byte_length=10,
            )

    def test_reject_bool_for_byte_length(self) -> None:
        valid_hex = hashlib.sha256(b"sample").hexdigest()
        with pytest.raises(TypeError, match="byte_length must be an int \\(not bool\\)"):
            ArtifactDigest(
                algorithm=DigestAlgorithm.SHA256,
                value=valid_hex,
                byte_length=True,
            )

    def test_reject_negative_byte_length(self) -> None:
        valid_hex = hashlib.sha256(b"sample").hexdigest()
        with pytest.raises(ValueError, match="byte_length must be non-negative"):
            ArtifactDigest(
                algorithm=DigestAlgorithm.SHA256,
                value=valid_hex,
                byte_length=-1,
            )

    def test_reject_wrong_algorithm_type(self) -> None:
        valid_hex = hashlib.sha256(b"sample").hexdigest()
        with pytest.raises(TypeError, match="algorithm must be a DigestAlgorithm enum instance"):
            ArtifactDigest(
                algorithm="sha256",  # type: ignore[arg-type]
                value=valid_hex,
                byte_length=6,
            )


class TestArtifactContract:
    def test_artifact_creation_and_reference(self) -> None:
        raw = b"raw execution output content"
        artifact = artifact_from_bytes(raw, media_type="text/plain")
        assert artifact.content == raw
        assert artifact.digest.byte_length == len(raw)
        assert artifact.media_type == "text/plain"

        ref = artifact.reference
        assert ref.digest == artifact.digest
        assert ref.media_type == "text/plain"

    def test_artifact_digest_mismatch_rejected(self) -> None:
        raw = b"actual content"
        wrong_digest = ArtifactDigest(
            algorithm=DigestAlgorithm.SHA256,
            value="0" * 64,
            byte_length=len(raw),
        )
        with pytest.raises(ValueError, match="Artifact digest mismatch"):
            Artifact(content=raw, digest=wrong_digest)

    def test_artifact_from_text(self) -> None:
        text = "console output log"
        art = artifact_from_text(text)
        assert art.content == text.encode("utf-8")
        assert art.media_type == "text/plain; charset=utf-8"
        assert art.digest.byte_length == len(text.encode("utf-8"))

    def test_artifact_from_domain_object(self) -> None:
        source = SourceIdentity(
            locator="https://github.com/example/repo",
            revision=CommitRevision("0123456789abcdef0123456789abcdef01234567"),
        )
        cand = CandidateIdentity(
            candidate_id="cand-001",
            source=source,
            patch_digest="a" * 64,
            description="test candidate",
        )
        art = artifact_from_domain_object(cand)
        assert art.media_type == "application/json"
        assert art.digest == compute_domain_digest(cand)

    def test_artifact_digest_dict_roundtrip(self) -> None:
        d = compute_bytes_digest(b"hello")
        d_dict = d.to_dict()
        reconstructed = ArtifactDigest.from_dict(d_dict)
        assert d == reconstructed

    def test_artifact_reference_dict_roundtrip(self) -> None:
        d = compute_bytes_digest(b"hello")
        ref = ArtifactReference(digest=d, media_type="text/plain")
        ref_dict = ref.to_dict()
        reconstructed = ArtifactReference.from_dict(ref_dict)
        assert ref == reconstructed

    def test_canonical_artifact_json_deterministic(self) -> None:
        d = compute_bytes_digest(b"hello")
        ref = ArtifactReference(digest=d, media_type="text/plain")
        json_str = to_canonical_artifact_json(ref)
        data = json.loads(json_str)
        assert data["digest"]["value"] == d.value
        assert data["media_type"] == "text/plain"
