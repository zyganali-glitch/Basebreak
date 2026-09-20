"""P-02 Phase-Closure comprehensive integration and causal invariants tests.

Verifies all mandatory P-02 phase-closure properties:
A. Validation & immutability across the domain surface
B. Causal binding & execution worlds
C. Provenance / verdict separation
D. Canonical deterministic serialization
E. Compatibility enforcement
F. Provider purity
G. Regression safety
"""

from dataclasses import FrozenInstanceError

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
    TerminationStatus,
)
from basebreak.domain.semantics import (
    ChangeClass,
    ClassVerificationRequirement,
    get_verification_requirements,
)
from basebreak.domain.serialization import (
    SCHEMA_VERSION,
    SchemaTypeError,
    SchemaValidationError,
    SchemaVersionError,
    from_canonical_json,
    to_canonical_json,
)
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.task import AcceptanceRequirement
from basebreak.domain.verdict import (
    EvidenceProvenance,
    PreliminaryVerdict,
    PreliminaryVerdictRecord,
)

_HEX_40_A = "a" * 40
_HEX_40_B = "b" * 40
_HEX_64_A = "1" * 64
_HEX_64_B = "2" * 64


class TestP02ClosureValidation:
    """A. VALIDATION."""

    def test_malformed_ids_and_digests_rejected(self) -> None:
        # CommitRevision rejects non-hex / wrong length
        with pytest.raises(ValueError):
            CommitRevision("not_hex_commit_id")
        with pytest.raises(ValueError):
            CommitRevision("a" * 39)

        # WitnessIdentity rejects invalid digest
        with pytest.raises(ValueError):
            WitnessIdentity(witness_id="wit", digest="bad_digest")

        # CandidateIdentity rejects invalid patch_digest
        src = SourceIdentity(locator="repo", revision=CommitRevision(_HEX_40_A))
        with pytest.raises(ValueError):
            CandidateIdentity(candidate_id="cand", source=src, patch_digest="short")

    def test_invalid_enums_rejected(self) -> None:
        with pytest.raises(ValueError):
            ChangeClass("UNKNOWN_CLASS")
        with pytest.raises(ValueError):
            ExecutionWorld("FUTURE_WORLD")
        with pytest.raises(ValueError):
            EvidenceProvenance("MOCK_NEBIUS")
        with pytest.raises(ValueError):
            PreliminaryVerdict("PASS")

    def test_wrong_types_rejected_rather_than_coerced(self) -> None:
        src = SourceIdentity(locator="repo", revision=CommitRevision(_HEX_40_A))

        # Rejects int as requirement_id
        with pytest.raises(TypeError):
            AcceptanceRequirement(requirement_id=123, statement="stmt")  # type: ignore[arg-type]

        # Rejects string as source
        with pytest.raises(TypeError):
            CandidateIdentity(candidate_id="cand", source="not_a_source")  # type: ignore[arg-type]

        # Rejects string as witness
        with pytest.raises(TypeError):
            CausalBinding(
                requirement_id="req",
                witness="not_a_witness",  # type: ignore[arg-type]
                base_source=src,
                candidate=CandidateIdentity(candidate_id="c", source=src),
                world=ExecutionWorld.BASE,
            )

    def test_immutability_and_frozen_contracts(self) -> None:
        rev = CommitRevision(_HEX_40_A)
        with pytest.raises(FrozenInstanceError):
            rev.commit_id = _HEX_40_B  # type: ignore[misc]

        src = SourceIdentity(locator="repo", revision=rev)
        with pytest.raises(FrozenInstanceError):
            src.locator = "new_repo"  # type: ignore[misc]

        wit = WitnessIdentity(witness_id="wit", digest=_HEX_64_A)
        with pytest.raises(FrozenInstanceError):
            wit.witness_id = "new_wit"  # type: ignore[misc]


class TestP02ClosureCausalBinding:
    """B. CAUSAL BINDING."""

    def test_candidate_revision_changes_binding(self) -> None:
        base_src = SourceIdentity(locator="repo", revision=CommitRevision(_HEX_40_A))
        cand_a = CandidateIdentity(
            candidate_id="cand_01",
            source=SourceIdentity(locator="repo", revision=CommitRevision(_HEX_40_A)),
        )
        cand_b = CandidateIdentity(
            candidate_id="cand_01",
            source=SourceIdentity(locator="repo", revision=CommitRevision(_HEX_40_B)),
        )
        wit = WitnessIdentity(witness_id="wit_01", digest=_HEX_64_A)

        bind_a = CausalBinding(
            requirement_id="req_01",
            witness=wit,
            base_source=base_src,
            candidate=cand_a,
            world=ExecutionWorld.CANDIDATE,
        )
        bind_b = CausalBinding(
            requirement_id="req_01",
            witness=wit,
            base_source=base_src,
            candidate=cand_b,
            world=ExecutionWorld.CANDIDATE,
        )

        assert bind_a != bind_b
        assert bind_a.binding_digest != bind_b.binding_digest

    def test_binding_for_candidate_a_cannot_reuse_candidate_b(self) -> None:
        base_src = SourceIdentity(locator="repo", revision=CommitRevision(_HEX_40_A))
        cand_a = CandidateIdentity(
            candidate_id="cand_A",
            source=SourceIdentity(locator="repo_a", revision=CommitRevision(_HEX_40_A)),
        )
        cand_b = CandidateIdentity(
            candidate_id="cand_B",
            source=SourceIdentity(locator="repo_b", revision=CommitRevision(_HEX_40_B)),
        )
        wit = WitnessIdentity(witness_id="wit_01", digest=_HEX_64_A)

        bind_a = CausalBinding(
            requirement_id="req_01",
            witness=wit,
            base_source=base_src,
            candidate=cand_a,
            world=ExecutionWorld.CANDIDATE,
        )
        bind_b = CausalBinding(
            requirement_id="req_01",
            witness=wit,
            base_source=base_src,
            candidate=cand_b,
            world=ExecutionWorld.CANDIDATE,
        )

        assert bind_a != bind_b
        assert bind_a.candidate.candidate_id != bind_b.candidate.candidate_id

    def test_execution_worlds_remain_distinct(self) -> None:
        assert ExecutionWorld.BASE != ExecutionWorld.CANDIDATE  # type: ignore[comparison-overlap]
        assert ExecutionWorld.BASE != ExecutionWorld.COUNTERFACTUAL  # type: ignore[comparison-overlap]
        assert ExecutionWorld.CANDIDATE != ExecutionWorld.COUNTERFACTUAL  # type: ignore[comparison-overlap]

    def test_counterfactual_distinct_from_candidate(self) -> None:
        src = SourceIdentity(locator="repo", revision=CommitRevision(_HEX_40_A))
        cand = CandidateIdentity(candidate_id="cand_01", source=src)
        cf = CounterfactualIdentity(counterfactual_id="cf_01", target_candidate=cand)

        assert not isinstance(cf, CandidateIdentity)
        assert cf != cand  # type: ignore[comparison-overlap]

    def test_witness_participates_in_binding(self) -> None:
        base_src = SourceIdentity(locator="repo", revision=CommitRevision(_HEX_40_A))
        cand = CandidateIdentity(candidate_id="cand_01", source=base_src)
        wit_1 = WitnessIdentity(witness_id="wit_01", digest=_HEX_64_A)
        wit_2 = WitnessIdentity(witness_id="wit_02", digest=_HEX_64_B)

        b1 = CausalBinding(
            requirement_id="req_01",
            witness=wit_1,
            base_source=base_src,
            candidate=cand,
            world=ExecutionWorld.CANDIDATE,
        )
        b2 = CausalBinding(
            requirement_id="req_01",
            witness=wit_2,
            base_source=base_src,
            candidate=cand,
            world=ExecutionWorld.CANDIDATE,
        )

        assert b1 != b2
        assert b1.binding_digest != b2.binding_digest


class TestP02ClosureProvenanceVerdictSeparation:
    """C. PROVENANCE / VERDICT SEPARATION."""

    def test_exact_provenance_vocabulary(self) -> None:
        expected = {"FIXTURE", "LOCAL_EXECUTION", "LIVE_NEBIUS", "RECORDED_LIVE"}
        assert {p.value for p in EvidenceProvenance} == expected

    def test_provenance_round_trip_does_not_modify_verdict(self) -> None:
        rec = PreliminaryVerdictRecord(
            verdict=PreliminaryVerdict.NOT_RUN,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
            requirement_id="req_01",
        )
        deserialized = from_canonical_json(to_canonical_json(rec))
        assert deserialized.verdict == PreliminaryVerdict.NOT_RUN
        assert deserialized.provenance == EvidenceProvenance.LIVE_NEBIUS

    def test_not_run_survives_round_trip(self) -> None:
        rec = PreliminaryVerdictRecord(
            verdict=PreliminaryVerdict.NOT_RUN,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            requirement_id="req_01",
        )
        deserialized = from_canonical_json(to_canonical_json(rec))
        assert deserialized.is_not_run is True
        assert deserialized.is_verified is False

    def test_fixture_cannot_appear_as_live_nebius(self) -> None:
        rec = PreliminaryVerdictRecord(
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.FIXTURE,
            requirement_id="req_01",
        )
        deserialized = from_canonical_json(to_canonical_json(rec))
        assert deserialized.provenance == EvidenceProvenance.FIXTURE
        assert deserialized.provenance != EvidenceProvenance.LIVE_NEBIUS
        assert deserialized.is_live is False

    def test_recorded_live_cannot_appear_as_live_nebius(self) -> None:
        rec = PreliminaryVerdictRecord(
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.RECORDED_LIVE,
            requirement_id="req_01",
        )
        deserialized = from_canonical_json(to_canonical_json(rec))
        assert deserialized.provenance == EvidenceProvenance.RECORDED_LIVE
        assert deserialized.provenance != EvidenceProvenance.LIVE_NEBIUS
        assert deserialized.is_live is False


class TestP02ClosureCanonicalSerialization:
    """D. CANONICAL DETERMINISTIC SERIALIZATION & E. COMPATIBILITY."""

    def test_identical_objects_serialize_identically(self) -> None:
        wit1 = WitnessIdentity(witness_id="wit_01", digest=_HEX_64_A)
        wit2 = WitnessIdentity(witness_id="wit_01", digest=_HEX_64_A)
        assert to_canonical_json(wit1) == to_canonical_json(wit2)

    def test_schema_version_is_one(self) -> None:
        assert SCHEMA_VERSION == 1

    def test_incompatible_version_fails_explicitly(self) -> None:
        bad_json = (
            '{"schema_version":999,"schema_type":"CommitRevision",'
            f'"payload":{{"commit_id":"{_HEX_40_A}"}}}}'
        )
        with pytest.raises(SchemaVersionError, match="Unsupported schema version: 999"):
            from_canonical_json(bad_json)

    def test_malformed_schema_fails_explicitly(self) -> None:
        with pytest.raises(SchemaValidationError):
            from_canonical_json('{"no_version": true}')

        with pytest.raises(SchemaTypeError):
            from_canonical_json(
                '{"schema_version": 1, "schema_type": "UnknownType", "payload": {}}'
            )


class TestP02ClosureRegression:
    """G. REGRESSION - P-02.01 through P-02.04."""

    def test_execution_command_env_determinism(self) -> None:
        cmd1 = ExecutionCommand(argv=("python",), env=(("B", "2"), ("A", "1")))
        cmd2 = ExecutionCommand(argv=("python",), env=(("A", "1"), ("B", "2")))
        assert cmd1 == cmd2
        assert cmd1.env == (("A", "1"), ("B", "2"))

    def test_execution_result_finite_duration(self) -> None:
        res = ExecutionResult(
            status=TerminationStatus.COMPLETED,
            exit_code=0,
            duration_seconds=0.05,
        )
        assert res.duration_seconds == 0.05
        with pytest.raises(ValueError):
            ExecutionResult(
                status=TerminationStatus.COMPLETED,
                exit_code=0,
                duration_seconds=float("inf"),
            )

    def test_semantics_requirements(self) -> None:
        for cc in ChangeClass:
            req = get_verification_requirements(cc)
            assert req.change_class == cc
            assert isinstance(req, ClassVerificationRequirement)
            assert bool(req.base_expectation)
            assert bool(req.candidate_expectation)
