"""Tests for canonical deterministic serialization and schema compatibility."""

from typing import Any

import pytest

from basebreak.domain.causal import (
    CandidateIdentity,
    CausalBinding,
    CounterfactualIdentity,
    ExecutionWorld,
    WitnessIdentity,
)
from basebreak.domain.execution import (
    ExecutionCommand,
    ExecutionResult,
    SandboxIdentity,
    TerminationStatus,
)
from basebreak.domain.semantics import (
    ChangeClass,
    get_verification_requirements,
)
from basebreak.domain.serialization import (
    SCHEMA_VERSION,
    SchemaTypeError,
    SchemaValidationError,
    SchemaVersionError,
    from_canonical_bytes,
    from_canonical_json,
    from_dict,
    to_canonical_bytes,
    to_canonical_json,
    to_dict,
)
from basebreak.domain.source import CommitRevision, RequestedRef, SourceIdentity
from basebreak.domain.task import AcceptanceRequirement, EngineeringTask
from basebreak.domain.verdict import (
    EvidenceProvenance,
    PreliminaryVerdict,
    PreliminaryVerdictRecord,
)

_HEX_40_A = "a" * 40
_HEX_40_B = "b" * 40
_HEX_64_A = "1" * 64
_HEX_64_B = "2" * 64


class TestDeterministicSerializationRoundTrip:
    @pytest.mark.parametrize(
        "obj",
        [
            CommitRevision(_HEX_40_A),
            CommitRevision(_HEX_64_A),
            RequestedRef("main"),
            SourceIdentity(
                locator="https://github.com/example/repo",
                revision=CommitRevision(_HEX_40_A),
            ),
            SourceIdentity(
                locator="https://github.com/example/repo",
                revision=CommitRevision(_HEX_40_B),
                subpath="src/sub",
                requested_ref=RequestedRef("v1.0"),
            ),
            AcceptanceRequirement(
                requirement_id="req_01",
                statement="Must pass boundary test",
            ),
            EngineeringTask(
                task_id="task_01",
                title="Fix buffer overflow",
                description="Security fix in parser",
                requirements=(
                    AcceptanceRequirement(requirement_id="req_01", statement="Stmt 1"),
                    AcceptanceRequirement(requirement_id="req_02", statement="Stmt 2"),
                ),
            ),
            ChangeClass.BUG_FIX,
            ChangeClass.SECURITY_FIX,
            get_verification_requirements(ChangeClass.BUG_FIX),
            get_verification_requirements(ChangeClass.PERFORMANCE),
            TerminationStatus.COMPLETED,
            TerminationStatus.TIMED_OUT,
            ExecutionCommand(
                argv=("python", "-m", "pytest", "tests/"),
                cwd="sub/dir",
                env=(("KEY_A", "val_a"), ("KEY_B", "val_b")),
            ),
            ExecutionResult(
                status=TerminationStatus.COMPLETED,
                exit_code=0,
                duration_seconds=1.234,
            ),
            SandboxIdentity(
                sandbox_id="sb_001",
                description="Clean sandbox",
            ),
            WitnessIdentity(
                witness_id="wit_01",
                digest=_HEX_64_A,
                description="Witness check",
            ),
            CandidateIdentity(
                candidate_id="cand_01",
                source=SourceIdentity(
                    locator="https://github.com/example/repo",
                    revision=CommitRevision(_HEX_40_B),
                ),
                patch_digest=_HEX_64_B,
                description="Candidate patch",
            ),
            ExecutionWorld.BASE,
            ExecutionWorld.CANDIDATE,
            ExecutionWorld.COUNTERFACTUAL,
            CounterfactualIdentity(
                counterfactual_id="cf_01",
                target_candidate=CandidateIdentity(
                    candidate_id="cand_01",
                    source=SourceIdentity(
                        locator="https://github.com/example/repo",
                        revision=CommitRevision(_HEX_40_B),
                    ),
                ),
                delta_digest=_HEX_64_A,
                description="Counterfactual run",
            ),
            CausalBinding(
                requirement_id="req_01",
                witness=WitnessIdentity(witness_id="wit_01", digest=_HEX_64_A),
                base_source=SourceIdentity(
                    locator="https://github.com/example/repo",
                    revision=CommitRevision(_HEX_40_A),
                ),
                candidate=CandidateIdentity(
                    candidate_id="cand_01",
                    source=SourceIdentity(
                        locator="https://github.com/example/repo",
                        revision=CommitRevision(_HEX_40_B),
                    ),
                ),
                world=ExecutionWorld.BASE,
            ),
            CausalBinding(
                requirement_id="req_01",
                witness=WitnessIdentity(witness_id="wit_01", digest=_HEX_64_A),
                base_source=SourceIdentity(
                    locator="https://github.com/example/repo",
                    revision=CommitRevision(_HEX_40_A),
                ),
                candidate=CandidateIdentity(
                    candidate_id="cand_01",
                    source=SourceIdentity(
                        locator="https://github.com/example/repo",
                        revision=CommitRevision(_HEX_40_B),
                    ),
                ),
                world=ExecutionWorld.COUNTERFACTUAL,
                counterfactual=CounterfactualIdentity(
                    counterfactual_id="cf_01",
                    target_candidate=CandidateIdentity(
                        candidate_id="cand_01",
                        source=SourceIdentity(
                            locator="https://github.com/example/repo",
                            revision=CommitRevision(_HEX_40_B),
                        ),
                    ),
                ),
            ),
            EvidenceProvenance.FIXTURE,
            EvidenceProvenance.LOCAL_EXECUTION,
            EvidenceProvenance.LIVE_NEBIUS,
            EvidenceProvenance.RECORDED_LIVE,
            PreliminaryVerdict.VERIFIED,
            PreliminaryVerdict.BLOCKED,
            PreliminaryVerdict.NOT_RUN,
            PreliminaryVerdictRecord(
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.LIVE_NEBIUS,
                requirement_id="req_01",
                narrative="All invariants confirmed",
                model_confidence=0.98,
            ),
        ],
    )
    def test_round_trip_equality(self, obj: Any) -> None:
        # JSON string round-trip
        json_str = to_canonical_json(obj)
        reconstructed = from_canonical_json(json_str)
        assert reconstructed == obj

        # Bytes round-trip
        raw_bytes = to_canonical_bytes(obj)
        reconstructed_bytes = from_canonical_bytes(raw_bytes)
        assert reconstructed_bytes == obj

    def test_canonical_json_determinism(self) -> None:
        cmd1 = ExecutionCommand(
            argv=("test",),
            env=(("Z_KEY", "z"), ("A_KEY", "a")),
        )
        cmd2 = ExecutionCommand(
            argv=("test",),
            env=(("A_KEY", "a"), ("Z_KEY", "z")),
        )
        assert to_canonical_json(cmd1) == to_canonical_json(cmd2)
        assert to_canonical_bytes(cmd1) == to_canonical_bytes(cmd2)

    def test_exact_hex_hashes_survive_round_trip(self) -> None:
        rev = CommitRevision(_HEX_64_A)
        reconstructed = from_canonical_json(to_canonical_json(rev))
        assert reconstructed.commit_id == _HEX_64_A


class TestProvenanceVerdictSeparationInSerialization:
    def test_provenance_round_trip_does_not_modify_verdict(self) -> None:
        rec = PreliminaryVerdictRecord(
            verdict=PreliminaryVerdict.NOT_RUN,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
            requirement_id="req_01",
        )
        data = to_dict(rec)
        reconstructed = from_dict(data)
        assert reconstructed.verdict == PreliminaryVerdict.NOT_RUN
        assert reconstructed.provenance == EvidenceProvenance.LIVE_NEBIUS
        assert reconstructed.is_verified is False
        assert reconstructed.is_not_run is True

    def test_fixture_cannot_become_live_nebius_after_round_trip(self) -> None:
        rec = PreliminaryVerdictRecord(
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
            requirement_id="req_01",
        )
        reconstructed = from_canonical_json(to_canonical_json(rec))
        assert reconstructed.provenance == EvidenceProvenance.FIXTURE
        assert reconstructed.provenance != EvidenceProvenance.LIVE_NEBIUS
        assert reconstructed.is_live is False

    def test_recorded_live_cannot_become_live_nebius_after_round_trip(self) -> None:
        rec = PreliminaryVerdictRecord(
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.RECORDED_LIVE,
            requirement_id="req_01",
        )
        reconstructed = from_canonical_json(to_canonical_json(rec))
        assert reconstructed.provenance == EvidenceProvenance.RECORDED_LIVE
        assert reconstructed.provenance != EvidenceProvenance.LIVE_NEBIUS
        assert reconstructed.is_live is False


class TestSchemaCompatibilityAndValidation:
    def test_current_schema_version_is_one(self) -> None:
        assert SCHEMA_VERSION == 1

    def test_rejects_unsupported_schema_version(self) -> None:
        envelope = {
            "schema_version": 2,
            "schema_type": "CommitRevision",
            "payload": {"commit_id": _HEX_40_A},
        }
        with pytest.raises(SchemaVersionError, match="Unsupported schema version: 2"):
            from_dict(envelope)

    def test_rejects_non_integer_schema_version(self) -> None:
        envelope = {
            "schema_version": "1",
            "schema_type": "CommitRevision",
            "payload": {"commit_id": _HEX_40_A},
        }
        with pytest.raises(SchemaValidationError, match="schema_version must be an integer"):
            from_dict(envelope)

        envelope_bool = {
            "schema_version": True,
            "schema_type": "CommitRevision",
            "payload": {"commit_id": _HEX_40_A},
        }
        with pytest.raises(SchemaValidationError, match="schema_version must be an integer"):
            from_dict(envelope_bool)

    def test_rejects_missing_schema_version(self) -> None:
        envelope = {
            "schema_type": "CommitRevision",
            "payload": {"commit_id": _HEX_40_A},
        }
        with pytest.raises(SchemaValidationError, match="Missing required 'schema_version'"):
            from_dict(envelope)

    def test_rejects_unknown_schema_type(self) -> None:
        envelope = {
            "schema_version": 1,
            "schema_type": "NonExistentModel",
            "payload": {},
        }
        with pytest.raises(SchemaTypeError, match="Unknown schema_type"):
            from_dict(envelope)

    def test_rejects_unsupported_object_type_on_serialize(self) -> None:
        class UnregisteredClass:
            pass

        with pytest.raises(SchemaTypeError, match="Unsupported domain object type"):
            to_dict(UnregisteredClass())

    def test_rejects_missing_payload(self) -> None:
        envelope = {
            "schema_version": 1,
            "schema_type": "CommitRevision",
        }
        with pytest.raises(SchemaValidationError, match="Missing required 'payload'"):
            from_dict(envelope)

    def test_rejects_non_dict_payload(self) -> None:
        envelope = {
            "schema_version": 1,
            "schema_type": "CommitRevision",
            "payload": "invalid_payload",
        }
        with pytest.raises(SchemaValidationError, match="payload must be a dict"):
            from_dict(envelope)

    def test_rejects_malformed_json_string(self) -> None:
        with pytest.raises(SchemaValidationError, match="Invalid JSON string"):
            from_canonical_json("not valid json {")

    def test_rejects_non_string_json_input(self) -> None:
        with pytest.raises(TypeError, match="json_str must be a string"):
            from_canonical_json(123)  # type: ignore[arg-type]

    def test_rejects_non_bytes_input(self) -> None:
        with pytest.raises(TypeError, match="data must be bytes or bytearray"):
            from_canonical_bytes("not bytes")  # type: ignore[arg-type]


class TestExecutionEnvStrictDeserialization:
    """Adversarial tests for ExecutionCommand env deserialization."""

    def test_rejects_non_string_env_value(self) -> None:
        # Non-string value in dict envelope
        envelope = {
            "schema_version": 1,
            "schema_type": "ExecutionCommand",
            "payload": {
                "argv": ["python", "main.py"],
                "env": [["PORT", 8080]],
            },
        }
        with pytest.raises(SchemaValidationError, match="env keys and values must be strings"):
            from_dict(envelope)

        # Non-string None value in JSON
        bad_json = (
            '{"schema_version":1,"schema_type":"ExecutionCommand",'
            '"payload":{"argv":["python"],"env":[["DEBUG",null]]}}'
        )
        with pytest.raises(SchemaValidationError, match="env keys and values must be strings"):
            from_canonical_json(bad_json)

    def test_rejects_non_string_env_key(self) -> None:
        envelope = {
            "schema_version": 1,
            "schema_type": "ExecutionCommand",
            "payload": {
                "argv": ["python", "main.py"],
                "env": [[123, "value"]],
            },
        }
        with pytest.raises(SchemaValidationError, match="env keys and values must be strings"):
            from_dict(envelope)

        bad_json = (
            '{"schema_version":1,"schema_type":"ExecutionCommand",'
            '"payload":{"argv":["python"],"env":[[true,"val"]]}}'
        )
        with pytest.raises(SchemaValidationError, match="env keys and values must be strings"):
            from_canonical_json(bad_json)

    def test_rejects_duplicate_env_keys(self) -> None:
        envelope = {
            "schema_version": 1,
            "schema_type": "ExecutionCommand",
            "payload": {
                "argv": ["python"],
                "env": [["DUPLICATE", "v1"], ["DUPLICATE", "v2"]],
            },
        }
        with pytest.raises(
            SchemaValidationError, match="Duplicate environment key detected: 'DUPLICATE'"
        ):
            from_dict(envelope)

    def test_logically_identical_env_pair_order_normalizes_identically(self) -> None:
        envelope_a = {
            "schema_version": 1,
            "schema_type": "ExecutionCommand",
            "payload": {
                "argv": ["python"],
                "env": [["Z_VAR", "z"], ["A_VAR", "a"]],
            },
        }
        envelope_b = {
            "schema_version": 1,
            "schema_type": "ExecutionCommand",
            "payload": {
                "argv": ["python"],
                "env": [["A_VAR", "a"], ["Z_VAR", "z"]],
            },
        }
        cmd_a: ExecutionCommand = from_dict(envelope_a)
        cmd_b: ExecutionCommand = from_dict(envelope_b)
        assert cmd_a == cmd_b
        assert cmd_a.env == (("A_VAR", "a"), ("Z_VAR", "z"))
        assert to_canonical_json(cmd_a) == to_canonical_json(cmd_b)

    def test_rejects_arbitrary_object_without_repr_conversion(self) -> None:
        sentinel_obj = object()
        envelope = {
            "schema_version": 1,
            "schema_type": "ExecutionCommand",
            "payload": {
                "argv": ["python"],
                "env": [["OBJ_KEY", sentinel_obj]],
            },
        }
        with pytest.raises(SchemaValidationError, match="env keys and values must be strings"):
            from_dict(envelope)

    def test_no_memory_address_leakage_in_reconstructed_command(self) -> None:
        envelope = {
            "schema_version": 1,
            "schema_type": "ExecutionCommand",
            "payload": {
                "argv": ["python"],
                "env": [["KEY", "clean_value"]],
            },
        }
        cmd: ExecutionCommand = from_dict(envelope)
        for k, v in cmd.env:
            assert "0x" not in v
            assert "object at" not in v
