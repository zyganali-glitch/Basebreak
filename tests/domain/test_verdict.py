"""Tests for evidence provenance and preliminary verdict domain contracts."""

from dataclasses import FrozenInstanceError

import pytest

from basebreak.domain.causal import (
    CandidateIdentity,
    CausalBinding,
    ExecutionWorld,
    WitnessIdentity,
)
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import (
    EvidenceProvenance,
    PreliminaryVerdict,
    PreliminaryVerdictRecord,
)

_HEX_40_A = "a" * 40
_HEX_40_B = "b" * 40
_HEX_64_A = "1" * 64


@pytest.fixture
def causal_binding() -> CausalBinding:
    base = SourceIdentity(
        locator="https://github.com/example/repo",
        revision=CommitRevision(_HEX_40_A),
    )
    cand = CandidateIdentity(
        candidate_id="cand_01",
        source=SourceIdentity(
            locator="https://github.com/example/repo",
            revision=CommitRevision(_HEX_40_B),
        ),
    )
    wit = WitnessIdentity(witness_id="wit_01", digest=_HEX_64_A)
    return CausalBinding(
        requirement_id="req_001",
        witness=wit,
        base_source=base,
        candidate=cand,
        world=ExecutionWorld.CANDIDATE,
    )


class TestEvidenceProvenance:
    def test_exact_provenance_members(self) -> None:
        expected = {
            EvidenceProvenance.FIXTURE,
            EvidenceProvenance.LOCAL_EXECUTION,
            EvidenceProvenance.LIVE_NEBIUS,
            EvidenceProvenance.RECORDED_LIVE,
        }
        assert set(EvidenceProvenance) == expected
        assert len(EvidenceProvenance) == 4

    def test_exact_provenance_values(self) -> None:
        assert EvidenceProvenance.FIXTURE.value == "FIXTURE"
        assert EvidenceProvenance.LOCAL_EXECUTION.value == "LOCAL_EXECUTION"
        assert EvidenceProvenance.LIVE_NEBIUS.value == "LIVE_NEBIUS"
        assert EvidenceProvenance.RECORDED_LIVE.value == "RECORDED_LIVE"

    def test_fixture_distinct_from_live_nebius(self) -> None:
        assert EvidenceProvenance.FIXTURE != EvidenceProvenance.LIVE_NEBIUS  # type: ignore[comparison-overlap]
        assert EvidenceProvenance.RECORDED_LIVE != EvidenceProvenance.LIVE_NEBIUS  # type: ignore[comparison-overlap]

    def test_rejects_unknown_provenance(self) -> None:
        with pytest.raises(ValueError):
            EvidenceProvenance("MOCK")
        with pytest.raises(ValueError):
            EvidenceProvenance("SIMULATION")
        with pytest.raises(ValueError):
            EvidenceProvenance("live_nebius")


class TestPreliminaryVerdict:
    def test_exact_verdict_members(self) -> None:
        expected = {
            PreliminaryVerdict.VERIFIED,
            PreliminaryVerdict.PARTIALLY_VERIFIED,
            PreliminaryVerdict.CONTRADICTED,
            PreliminaryVerdict.INCONCLUSIVE,
            PreliminaryVerdict.NOT_RUN,
            PreliminaryVerdict.BLOCKED,
        }
        assert set(PreliminaryVerdict) == expected
        assert len(PreliminaryVerdict) == 6

    def test_exact_verdict_values(self) -> None:
        assert PreliminaryVerdict.VERIFIED.value == "VERIFIED"
        assert PreliminaryVerdict.PARTIALLY_VERIFIED.value == "PARTIALLY_VERIFIED"
        assert PreliminaryVerdict.CONTRADICTED.value == "CONTRADICTED"
        assert PreliminaryVerdict.INCONCLUSIVE.value == "INCONCLUSIVE"
        assert PreliminaryVerdict.NOT_RUN.value == "NOT_RUN"
        assert PreliminaryVerdict.BLOCKED.value == "BLOCKED"

    def test_blocked_distinct_from_not_run(self) -> None:
        assert PreliminaryVerdict.BLOCKED != PreliminaryVerdict.NOT_RUN  # type: ignore[comparison-overlap]

    def test_rejects_unknown_verdict(self) -> None:
        with pytest.raises(ValueError):
            PreliminaryVerdict("PASS")
        with pytest.raises(ValueError):
            PreliminaryVerdict("FAIL")
        with pytest.raises(ValueError):
            PreliminaryVerdict("verified")


class TestPreliminaryVerdictRecord:
    def test_valid_record_without_binding(self) -> None:
        rec = PreliminaryVerdictRecord(
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            requirement_id="req_001",
            narrative="Behavioral witness satisfied",
            model_confidence=0.95,
        )
        assert rec.verdict == PreliminaryVerdict.VERIFIED
        assert rec.provenance == EvidenceProvenance.LOCAL_EXECUTION
        assert rec.requirement_id == "req_001"
        assert rec.causal_binding is None
        assert rec.is_verified is True
        assert rec.is_blocked is False
        assert rec.is_not_run is False
        assert rec.is_live is False

    def test_valid_record_with_binding(self, causal_binding: CausalBinding) -> None:
        rec = PreliminaryVerdictRecord(
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
            requirement_id="req_001",
            causal_binding=causal_binding,
        )
        assert rec.causal_binding == causal_binding
        assert rec.is_live is True
        assert rec.is_verified is True

    def test_immutability(self) -> None:
        rec = PreliminaryVerdictRecord(
            verdict=PreliminaryVerdict.NOT_RUN,
            provenance=EvidenceProvenance.FIXTURE,
            requirement_id="req_001",
        )
        with pytest.raises(FrozenInstanceError):
            rec.verdict = PreliminaryVerdict.VERIFIED  # type: ignore[misc]

    def test_not_run_never_verified_even_with_high_confidence(self) -> None:
        rec = PreliminaryVerdictRecord(
            verdict=PreliminaryVerdict.NOT_RUN,
            provenance=EvidenceProvenance.FIXTURE,
            requirement_id="req_001",
            narrative="Model claims this definitely passed without running",
            model_confidence=1.0,
        )
        assert rec.is_verified is False
        assert rec.is_not_run is True
        assert rec.verdict != PreliminaryVerdict.VERIFIED

    def test_blocked_is_not_verified_and_distinct_from_not_run(self) -> None:
        rec = PreliminaryVerdictRecord(
            verdict=PreliminaryVerdict.BLOCKED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            requirement_id="req_001",
            narrative="Pre-condition sandbox creation failed",
        )
        assert rec.is_verified is False
        assert rec.is_blocked is True
        assert rec.is_not_run is False

    def test_provenance_and_verdict_orthogonality(self) -> None:
        # Prove that any provenance can combine with any verdict
        for prov in EvidenceProvenance:
            for verd in PreliminaryVerdict:
                rec = PreliminaryVerdictRecord(
                    verdict=verd,
                    provenance=prov,
                    requirement_id="req_orthogonal",
                )
                assert rec.provenance == prov
                assert rec.verdict == verd

    def test_rejects_invalid_types(self) -> None:
        with pytest.raises(TypeError, match="verdict must be an instance of PreliminaryVerdict"):
            PreliminaryVerdictRecord(
                verdict="VERIFIED",  # type: ignore[arg-type]
                provenance=EvidenceProvenance.FIXTURE,
                requirement_id="req_001",
            )
        with pytest.raises(TypeError, match="provenance must be an instance of EvidenceProvenance"):
            PreliminaryVerdictRecord(
                verdict=PreliminaryVerdict.VERIFIED,
                provenance="FIXTURE",  # type: ignore[arg-type]
                requirement_id="req_001",
            )

    def test_rejects_requirement_id_mismatch(self, causal_binding: CausalBinding) -> None:
        with pytest.raises(ValueError, match="does not match requirement_id"):
            PreliminaryVerdictRecord(
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.LIVE_NEBIUS,
                requirement_id="different_req_id",
                causal_binding=causal_binding,
            )

    def test_rejects_invalid_model_confidence(self) -> None:
        with pytest.raises(ValueError, match="between 0.0 and 1.0"):
            PreliminaryVerdictRecord(
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.FIXTURE,
                requirement_id="req_001",
                model_confidence=1.5,
            )
        with pytest.raises(ValueError, match="between 0.0 and 1.0"):
            PreliminaryVerdictRecord(
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.FIXTURE,
                requirement_id="req_001",
                model_confidence=-0.1,
            )
        with pytest.raises(TypeError, match="model_confidence must be a number or None"):
            PreliminaryVerdictRecord(
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.FIXTURE,
                requirement_id="req_001",
                model_confidence=True,
            )
        with pytest.raises(TypeError, match="model_confidence must be a number or None"):
            PreliminaryVerdictRecord(
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.FIXTURE,
                requirement_id="req_001",
                model_confidence="not_a_number",  # type: ignore[arg-type]
            )

    def test_str_representation(self) -> None:
        rec = PreliminaryVerdictRecord(
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
            requirement_id="req_001",
        )
        assert str(rec) == "[LIVE_NEBIUS] req_001: VERIFIED"
