"""Tests for witness, candidate, counterfactual, and causal binding domain contracts."""

from dataclasses import FrozenInstanceError

import pytest

from basebreak.domain.causal import (
    CandidateIdentity,
    CausalBinding,
    CounterfactualIdentity,
    ExecutionWorld,
    WitnessIdentity,
)
from basebreak.domain.source import CommitRevision, RequestedRef, SourceIdentity

_HEX_40_A = "a" * 40
_HEX_40_B = "b" * 40
_HEX_64_A = "1" * 64
_HEX_64_B = "2" * 64


@pytest.fixture
def base_source() -> SourceIdentity:
    return SourceIdentity(
        locator="https://github.com/example/repo",
        revision=CommitRevision(_HEX_40_A),
        subpath=None,
        requested_ref=RequestedRef("main"),
    )


@pytest.fixture
def candidate_identity(base_source: SourceIdentity) -> CandidateIdentity:
    cand_source = SourceIdentity(
        locator="https://github.com/example/repo",
        revision=CommitRevision(_HEX_40_B),
        subpath=None,
        requested_ref=RequestedRef("feature-patch"),
    )
    return CandidateIdentity(
        candidate_id="cand_001",
        source=cand_source,
        patch_digest=_HEX_64_A,
        description="Candidate patch implementation",
    )


@pytest.fixture
def witness_identity() -> WitnessIdentity:
    return WitnessIdentity(
        witness_id="wit_behavior_01",
        digest=_HEX_64_A,
        description="Independent behavioral witness",
    )


class TestWitnessIdentity:
    def test_valid_witness_identity(self) -> None:
        wit = WitnessIdentity(witness_id="wit_01", digest=_HEX_64_A, description="Desc")
        assert wit.witness_id == "wit_01"
        assert wit.digest == _HEX_64_A
        assert wit.description == "Desc"
        assert "wit_01" in str(wit)

    def test_valid_40_char_digest(self) -> None:
        wit = WitnessIdentity(witness_id="wit_40", digest=_HEX_40_A)
        assert wit.digest == _HEX_40_A

    def test_immutability(self) -> None:
        wit = WitnessIdentity(witness_id="wit_01", digest=_HEX_64_A)
        with pytest.raises(FrozenInstanceError):
            wit.witness_id = "new_id"  # type: ignore[misc]

    def test_rejects_empty_or_whitespace_witness_id(self) -> None:
        with pytest.raises(ValueError, match="witness_id must not be empty"):
            WitnessIdentity(witness_id="", digest=_HEX_64_A)
        with pytest.raises(ValueError, match="leading or trailing whitespace"):
            WitnessIdentity(witness_id=" wit_01 ", digest=_HEX_64_A)

    def test_rejects_non_string_witness_id(self) -> None:
        with pytest.raises(TypeError, match="witness_id must be a string"):
            WitnessIdentity(witness_id=123, digest=_HEX_64_A)  # type: ignore[arg-type]

    def test_rejects_invalid_digest(self) -> None:
        with pytest.raises(ValueError, match="40 or 64-character"):
            WitnessIdentity(witness_id="wit_01", digest="abc")
        with pytest.raises(ValueError, match="lowercase hexadecimal"):
            WitnessIdentity(witness_id="wit_01", digest="Z" * 64)
        with pytest.raises(TypeError, match="digest must be a string"):
            WitnessIdentity(witness_id="wit_01", digest=None)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="leading or trailing whitespace"):
            WitnessIdentity(witness_id="wit_01", digest=f" {_HEX_64_A} ")

    def test_rejects_non_string_description(self) -> None:
        with pytest.raises(TypeError, match="description must be a string"):
            WitnessIdentity(witness_id="wit_01", digest=_HEX_64_A, description=123)  # type: ignore[arg-type]

    def test_witness_identity_distinct_from_result_or_verdict(self) -> None:
        wit = WitnessIdentity(witness_id="wit_01", digest=_HEX_64_A)
        assert not hasattr(wit, "exit_code")
        assert not hasattr(wit, "verdict")
        assert not hasattr(wit, "status")


class TestCandidateIdentity:
    def test_valid_candidate_identity(self, candidate_identity: CandidateIdentity) -> None:
        assert candidate_identity.candidate_id == "cand_001"
        assert candidate_identity.resolved_commit_id == _HEX_40_B
        assert candidate_identity.patch_digest == _HEX_64_A
        assert "cand_001" in str(candidate_identity)

    def test_candidate_without_patch_digest(self, base_source: SourceIdentity) -> None:
        cand = CandidateIdentity(candidate_id="cand_no_patch", source=base_source)
        assert cand.patch_digest is None
        assert cand.resolved_commit_id == _HEX_40_A

    def test_immutability(self, candidate_identity: CandidateIdentity) -> None:
        with pytest.raises(FrozenInstanceError):
            candidate_identity.candidate_id = "new_id"  # type: ignore[misc]

    def test_rejects_empty_or_whitespace_candidate_id(self, base_source: SourceIdentity) -> None:
        with pytest.raises(ValueError, match="candidate_id must not be empty"):
            CandidateIdentity(candidate_id="", source=base_source)
        with pytest.raises(ValueError, match="leading or trailing whitespace"):
            CandidateIdentity(candidate_id=" cand_01 ", source=base_source)

    def test_rejects_non_source_identity(self) -> None:
        with pytest.raises(TypeError, match="source must be an instance of SourceIdentity"):
            CandidateIdentity(candidate_id="cand_01", source="invalid")  # type: ignore[arg-type]

    def test_rejects_invalid_patch_digest(self, base_source: SourceIdentity) -> None:
        with pytest.raises(ValueError, match="40 or 64-character"):
            CandidateIdentity(candidate_id="cand_01", source=base_source, patch_digest="short")
        with pytest.raises(ValueError, match="lowercase hexadecimal"):
            CandidateIdentity(candidate_id="cand_01", source=base_source, patch_digest="G" * 64)


class TestExecutionWorld:
    def test_members(self) -> None:
        assert set(ExecutionWorld) == {
            ExecutionWorld.BASE,
            ExecutionWorld.CANDIDATE,
            ExecutionWorld.COUNTERFACTUAL,
        }

    def test_exact_values(self) -> None:
        assert ExecutionWorld.BASE.value == "BASE"
        assert ExecutionWorld.CANDIDATE.value == "CANDIDATE"
        assert ExecutionWorld.COUNTERFACTUAL.value == "COUNTERFACTUAL"


class TestCounterfactualIdentity:
    def test_valid_counterfactual_identity(self, candidate_identity: CandidateIdentity) -> None:
        cf = CounterfactualIdentity(
            counterfactual_id="cf_001",
            target_candidate=candidate_identity,
            delta_digest=_HEX_64_B,
            description="Patch delta reverted",
        )
        assert cf.counterfactual_id == "cf_001"
        assert cf.target_candidate == candidate_identity
        assert cf.delta_digest == _HEX_64_B
        assert "cf_001" in str(cf)

    def test_counterfactual_distinct_from_candidate(
        self, candidate_identity: CandidateIdentity
    ) -> None:
        cf = CounterfactualIdentity(
            counterfactual_id="cf_001",
            target_candidate=candidate_identity,
        )
        assert not isinstance(cf, CandidateIdentity)
        assert cf != candidate_identity  # type: ignore[comparison-overlap]

    def test_rejects_invalid_target_candidate(self) -> None:
        with pytest.raises(TypeError, match="target_candidate must be CandidateIdentity"):
            CounterfactualIdentity(counterfactual_id="cf_01", target_candidate="invalid")  # type: ignore[arg-type]

    def test_rejects_empty_or_whitespace_counterfactual_id(
        self, candidate_identity: CandidateIdentity
    ) -> None:
        with pytest.raises(ValueError, match="counterfactual_id must not be empty"):
            CounterfactualIdentity(counterfactual_id="", target_candidate=candidate_identity)
        with pytest.raises(ValueError, match="leading or trailing whitespace"):
            CounterfactualIdentity(counterfactual_id=" cf_01 ", target_candidate=candidate_identity)

    def test_rejects_invalid_delta_digest(self, candidate_identity: CandidateIdentity) -> None:
        with pytest.raises(ValueError, match="40 or 64-character"):
            CounterfactualIdentity(
                counterfactual_id="cf_01",
                target_candidate=candidate_identity,
                delta_digest="bad",
            )


class TestCausalBinding:
    def test_valid_base_binding(
        self,
        witness_identity: WitnessIdentity,
        base_source: SourceIdentity,
        candidate_identity: CandidateIdentity,
    ) -> None:
        binding = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_source,
            candidate=candidate_identity,
            world=ExecutionWorld.BASE,
        )
        assert binding.requirement_id == "req_001"
        assert binding.world == ExecutionWorld.BASE
        assert binding.counterfactual is None
        assert len(binding.binding_digest) == 64

    def test_valid_candidate_binding(
        self,
        witness_identity: WitnessIdentity,
        base_source: SourceIdentity,
        candidate_identity: CandidateIdentity,
    ) -> None:
        binding = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_source,
            candidate=candidate_identity,
            world=ExecutionWorld.CANDIDATE,
        )
        assert binding.world == ExecutionWorld.CANDIDATE
        assert binding.counterfactual is None

    def test_valid_counterfactual_binding(
        self,
        witness_identity: WitnessIdentity,
        base_source: SourceIdentity,
        candidate_identity: CandidateIdentity,
    ) -> None:
        cf = CounterfactualIdentity(
            counterfactual_id="cf_001",
            target_candidate=candidate_identity,
        )
        binding = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_source,
            candidate=candidate_identity,
            world=ExecutionWorld.COUNTERFACTUAL,
            counterfactual=cf,
        )
        assert binding.world == ExecutionWorld.COUNTERFACTUAL
        assert binding.counterfactual == cf

    def test_counterfactual_world_requires_counterfactual_identity(
        self,
        witness_identity: WitnessIdentity,
        base_source: SourceIdentity,
        candidate_identity: CandidateIdentity,
    ) -> None:
        with pytest.raises(ValueError, match="counterfactual identity is required"):
            CausalBinding(
                requirement_id="req_001",
                witness=witness_identity,
                base_source=base_source,
                candidate=candidate_identity,
                world=ExecutionWorld.COUNTERFACTUAL,
                counterfactual=None,
            )

    def test_non_counterfactual_world_forbids_counterfactual_identity(
        self,
        witness_identity: WitnessIdentity,
        base_source: SourceIdentity,
        candidate_identity: CandidateIdentity,
    ) -> None:
        cf = CounterfactualIdentity(
            counterfactual_id="cf_001",
            target_candidate=candidate_identity,
        )
        with pytest.raises(
            ValueError, match="counterfactual must be None when execution world is BASE"
        ):
            CausalBinding(
                requirement_id="req_001",
                witness=witness_identity,
                base_source=base_source,
                candidate=candidate_identity,
                world=ExecutionWorld.BASE,
                counterfactual=cf,
            )
        with pytest.raises(
            ValueError, match="counterfactual must be None when execution world is CANDIDATE"
        ):
            CausalBinding(
                requirement_id="req_001",
                witness=witness_identity,
                base_source=base_source,
                candidate=candidate_identity,
                world=ExecutionWorld.CANDIDATE,
                counterfactual=cf,
            )

    def test_counterfactual_target_mismatch_rejected(
        self,
        witness_identity: WitnessIdentity,
        base_source: SourceIdentity,
        candidate_identity: CandidateIdentity,
    ) -> None:
        other_candidate = CandidateIdentity(
            candidate_id="cand_other",
            source=SourceIdentity(
                locator="https://github.com/example/other",
                revision=CommitRevision(_HEX_40_A),
            ),
        )
        cf_for_other = CounterfactualIdentity(
            counterfactual_id="cf_other",
            target_candidate=other_candidate,
        )
        with pytest.raises(
            ValueError, match="counterfactual.target_candidate must match candidate"
        ):
            CausalBinding(
                requirement_id="req_001",
                witness=witness_identity,
                base_source=base_source,
                candidate=candidate_identity,
                world=ExecutionWorld.COUNTERFACTUAL,
                counterfactual=cf_for_other,
            )

    def test_candidate_revision_participates_in_equality_and_digest(
        self,
        witness_identity: WitnessIdentity,
        base_source: SourceIdentity,
    ) -> None:
        cand_a = CandidateIdentity(
            candidate_id="cand_001",
            source=SourceIdentity(
                locator="https://github.com/example/repo",
                revision=CommitRevision(_HEX_40_A),
            ),
        )
        cand_b = CandidateIdentity(
            candidate_id="cand_001",
            source=SourceIdentity(
                locator="https://github.com/example/repo",
                revision=CommitRevision(_HEX_40_B),
            ),
        )
        binding_a = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_source,
            candidate=cand_a,
            world=ExecutionWorld.CANDIDATE,
        )
        binding_b = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_source,
            candidate=cand_b,
            world=ExecutionWorld.CANDIDATE,
        )
        assert binding_a != binding_b
        assert hash(binding_a) != hash(binding_b)
        assert binding_a.binding_digest != binding_b.binding_digest

    def test_witness_participates_in_equality_and_digest(
        self,
        base_source: SourceIdentity,
        candidate_identity: CandidateIdentity,
    ) -> None:
        wit_a = WitnessIdentity(witness_id="wit_a", digest=_HEX_64_A)
        wit_b = WitnessIdentity(witness_id="wit_b", digest=_HEX_64_B)
        binding_a = CausalBinding(
            requirement_id="req_001",
            witness=wit_a,
            base_source=base_source,
            candidate=candidate_identity,
            world=ExecutionWorld.CANDIDATE,
        )
        binding_b = CausalBinding(
            requirement_id="req_001",
            witness=wit_b,
            base_source=base_source,
            candidate=candidate_identity,
            world=ExecutionWorld.CANDIDATE,
        )
        assert binding_a != binding_b
        assert hash(binding_a) != hash(binding_b)
        assert binding_a.binding_digest != binding_b.binding_digest

    def test_execution_worlds_remain_distinct(
        self,
        witness_identity: WitnessIdentity,
        base_source: SourceIdentity,
        candidate_identity: CandidateIdentity,
    ) -> None:
        binding_base = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_source,
            candidate=candidate_identity,
            world=ExecutionWorld.BASE,
        )
        binding_candidate = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_source,
            candidate=candidate_identity,
            world=ExecutionWorld.CANDIDATE,
        )
        assert binding_base != binding_candidate
        assert binding_base.binding_digest != binding_candidate.binding_digest

    def test_base_source_subpath_changes_binding_digest(
        self,
        witness_identity: WitnessIdentity,
        candidate_identity: CandidateIdentity,
    ) -> None:
        base_no_sub = SourceIdentity(
            locator="https://github.com/example/repo",
            revision=CommitRevision(_HEX_40_A),
            subpath=None,
        )
        base_with_sub = SourceIdentity(
            locator="https://github.com/example/repo",
            revision=CommitRevision(_HEX_40_A),
            subpath="packages/core",
        )
        binding_1 = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_no_sub,
            candidate=candidate_identity,
            world=ExecutionWorld.CANDIDATE,
        )
        binding_2 = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_with_sub,
            candidate=candidate_identity,
            world=ExecutionWorld.CANDIDATE,
        )
        assert binding_1.binding_digest != binding_2.binding_digest

    def test_candidate_source_subpath_changes_binding_digest(
        self,
        witness_identity: WitnessIdentity,
        base_source: SourceIdentity,
    ) -> None:
        cand_no_sub = CandidateIdentity(
            candidate_id="cand_001",
            source=SourceIdentity(
                locator="https://github.com/example/repo",
                revision=CommitRevision(_HEX_40_B),
                subpath=None,
            ),
        )
        cand_with_sub = CandidateIdentity(
            candidate_id="cand_001",
            source=SourceIdentity(
                locator="https://github.com/example/repo",
                revision=CommitRevision(_HEX_40_B),
                subpath="src/submod",
            ),
        )
        binding_1 = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_source,
            candidate=cand_no_sub,
            world=ExecutionWorld.CANDIDATE,
        )
        binding_2 = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_source,
            candidate=cand_with_sub,
            world=ExecutionWorld.CANDIDATE,
        )
        assert binding_1.binding_digest != binding_2.binding_digest

    def test_counterfactual_delta_digest_changes_binding_digest(
        self,
        witness_identity: WitnessIdentity,
        base_source: SourceIdentity,
        candidate_identity: CandidateIdentity,
    ) -> None:
        cf_1 = CounterfactualIdentity(
            counterfactual_id="cf_001",
            target_candidate=candidate_identity,
            delta_digest=_HEX_64_A,
        )
        cf_2 = CounterfactualIdentity(
            counterfactual_id="cf_001",
            target_candidate=candidate_identity,
            delta_digest=_HEX_64_B,
        )
        binding_1 = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_source,
            candidate=candidate_identity,
            world=ExecutionWorld.COUNTERFACTUAL,
            counterfactual=cf_1,
        )
        binding_2 = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_source,
            candidate=candidate_identity,
            world=ExecutionWorld.COUNTERFACTUAL,
            counterfactual=cf_2,
        )
        assert binding_1.binding_digest != binding_2.binding_digest

    def test_same_logical_binding_always_gives_same_digest(
        self,
        witness_identity: WitnessIdentity,
        base_source: SourceIdentity,
        candidate_identity: CandidateIdentity,
    ) -> None:
        b1 = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_source,
            candidate=candidate_identity,
            world=ExecutionWorld.CANDIDATE,
        )
        b2 = CausalBinding(
            requirement_id="req_001",
            witness=witness_identity,
            base_source=base_source,
            candidate=candidate_identity,
            world=ExecutionWorld.CANDIDATE,
        )
        assert b1.binding_digest == b2.binding_digest

    def test_delimiter_bearing_identifiers_do_not_collide(
        self,
        base_source: SourceIdentity,
        candidate_identity: CandidateIdentity,
    ) -> None:
        # Deliberately construct two bindings where field boundaries shift around ':'
        # Under raw colon joining: "req:wit" + ":" + "01" == "req" + ":" + "wit:01"
        wit_1 = WitnessIdentity(witness_id="01", digest=_HEX_64_A)
        wit_2 = WitnessIdentity(witness_id="wit:01", digest=_HEX_64_A)

        b1 = CausalBinding(
            requirement_id="req:wit",
            witness=wit_1,
            base_source=base_source,
            candidate=candidate_identity,
            world=ExecutionWorld.CANDIDATE,
        )
        b2 = CausalBinding(
            requirement_id="req",
            witness=wit_2,
            base_source=base_source,
            candidate=candidate_identity,
            world=ExecutionWorld.CANDIDATE,
        )
        assert b1.binding_digest != b2.binding_digest

    def test_non_authoritative_prose_does_not_change_binding_digest(
        self,
        witness_identity: WitnessIdentity,
    ) -> None:
        base_1 = SourceIdentity(
            locator="https://github.com/example/repo",
            revision=CommitRevision(_HEX_40_A),
            requested_ref=RequestedRef("main"),
        )
        base_2 = SourceIdentity(
            locator="https://github.com/example/repo",
            revision=CommitRevision(_HEX_40_A),
            requested_ref=RequestedRef("develop"),  # Non-authoritative
        )

        cand_1 = CandidateIdentity(
            candidate_id="cand_001",
            source=base_1,
            description="First description",  # Non-authoritative
        )
        cand_2 = CandidateIdentity(
            candidate_id="cand_001",
            source=base_2,
            description="Completely different description",  # Non-authoritative
        )

        wit_1 = WitnessIdentity(
            witness_id="wit_01",
            digest=_HEX_64_A,
            description="Witness description A",  # Non-authoritative
        )
        wit_2 = WitnessIdentity(
            witness_id="wit_01",
            digest=_HEX_64_A,
            description="Witness description B",  # Non-authoritative
        )

        b1 = CausalBinding(
            requirement_id="req_001",
            witness=wit_1,
            base_source=base_1,
            candidate=cand_1,
            world=ExecutionWorld.CANDIDATE,
        )
        b2 = CausalBinding(
            requirement_id="req_001",
            witness=wit_2,
            base_source=base_2,
            candidate=cand_2,
            world=ExecutionWorld.CANDIDATE,
        )
        # Causal digest must be identical because all authoritative identity facts match!
        assert b1.binding_digest == b2.binding_digest
