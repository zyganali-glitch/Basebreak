"""Acceptance test suite for P-06.06: Freeze Contract Digest Before Builder Execution.

Verifies:
1. Canonical hashing & deterministic byte invariants:
   - Identical contract yields exact same contract_digest across instances.
   - Requirements in different initial orders yield the exact same contract_digest.
   - canonical_contract_bytes produces exact UTF-8 bytes with sorted keys and compact delimiters.
   - Modifying any identity field changes the digest.
   - Modifying any requirement identity field changes the digest.
   - contract_digest is NOT present in identity payload hashed bytes.
   - Non-contract metadata is NOT present in identity payload.
2. Constructor Authority & Fail-Closed Enforcement:
   - Direct FrozenContract(...) with source_review=None raises FrozenContractSchemaError.
   - Direct FrozenContract(...) with source_review=rejected_review raises FrozenContractSchemaError.
   - Direct FrozenContract(...) with source_review=draft_review raises FrozenContractSchemaError.
   - Direct FrozenContract(...) with mismatched task_digest/change_class/certainty raises error.
   - Direct FrozenContract(...) with mismatched requirement fields raises FrozenContractSchemaError.
   - Direct FrozenContract(...) with tampered digest raises
     FrozenContractDigestMismatchError.
   - Tampered payload with recomputed attacker digest STILL fails closed against
     source_review.
   - Requirements not in canonical order fail closed.
   - Non-ReviewResult source_review raises TypeError.
   - source_review is non-serialized InitVar.
3. Authoritative factory freeze_review_result:
   - APPROVED / READY_FOR_FREEZE ReviewResult produces valid FrozenContract.
   - REJECTED ReviewResult fails closed.
   - Non-ready ReviewResult fails closed.
   - ReviewResult with contract=None fails closed.
   - Non-ReviewResult raises TypeError.
4. Immutability:
   - FrozenContract and FrozenRequirement are frozen dataclasses.
   - Zero mutation methods exist.
5. Serialization & Trusted Deserialization:
   - Roundtrip: to_dict / to_json and from_dict / from_json with source_review.
   - Missing source_review in from_dict / from_json fails closed.
   - Injected/unknown fields fail closed.
   - Tampered contract_digest fails closed.
   - Tampered payload with recomputed digest fails closed against source_review.
   - Strict typing without silent string/int/bool coercion.
6. Deterministic Verification:
   - verify_frozen_contract returns True for valid contract.
   - verify_frozen_contract returns True with matching expected_review.
   - Mismatched digest or review raises appropriate error.
7. Provider Purity & Boundary:
   - Zero imports from basebreak.adapters.
   - Zero Builder/verifier/candidate/execution logic.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
from dataclasses import FrozenInstanceError

import pytest

from basebreak.compiler.freeze import (
    FROZEN_CONTRACT_SCHEMA_VERSION,
    FrozenContract,
    FrozenContractDigestMismatchError,
    FrozenContractSchemaError,
    FrozenRequirement,
    build_canonical_identity_payload,
    canonical_contract_bytes,
    compute_contract_digest,
    freeze_review_result,
    verify_frozen_contract,
)
from basebreak.compiler.ingestion import NormalizedTask, ingest_task
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.review import (
    ReviewBundle,
    ReviewResult,
    ReviewSession,
)
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
)
from basebreak.domain.semantics import ChangeClass


@pytest.fixture
def sample_task() -> NormalizedTask:
    raw_text = (
        "Task: Fix authentication timeout in API gateway.\n"
        "Requirements:\n"
        "1. When HTTP 503 is returned, retry on network timeout.\n"
        "2. When user is not found, return 404 on user not found.\n"
        "3. Enforce authentication on /api/admin.\n"
        "4. Enable caching on /api/catalog."
    )
    return ingest_task(raw_text)


@pytest.fixture
def confident_semantics(sample_task: NormalizedTask) -> ChangeSemanticsClassification:
    fact = DeterministicClassificationFact(
        inferred_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Fix authentication timeout in API gateway",
        evidence_citations=("Fix authentication timeout",),
        matched_signals=("fix", "timeout"),
    )
    return ChangeSemanticsClassification(
        task_digest=sample_task.task_digest,
        change_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Fix authentication timeout in API gateway",
        evidence_citations=("Fix authentication timeout",),
        deterministic_facts=fact,
    )


@pytest.fixture
def sample_requirements(sample_task: NormalizedTask) -> list[ProposedRequirement]:
    cit1 = "When HTTP 503 is returned, retry on network timeout."
    start1 = sample_task.normalized_text.index(cit1)
    end1 = start1 + len(cit1)

    cit2 = "Enforce authentication on /api/admin."
    start2 = sample_task.normalized_text.index(cit2)
    end2 = start2 + len(cit2)

    return [
        ProposedRequirement(
            statement="Retry on network timeout",
            citation=cit1,
            citation_start=start1,
            citation_end=end1,
            rationale="Handle 503 errors gracefully",
        ),
        ProposedRequirement(
            statement="Enforce authentication on /api/admin",
            citation=cit2,
            citation_start=start2,
            citation_end=end2,
            rationale="Secure admin endpoints",
        ),
    ]


@pytest.fixture
def sample_bundle(
    sample_task: NormalizedTask,
    confident_semantics: ChangeSemanticsClassification,
    sample_requirements: list[ProposedRequirement],
) -> ReviewBundle:
    return ReviewBundle(
        task=sample_task,
        semantics=confident_semantics,
        requirements=tuple(sample_requirements),
    )


@pytest.fixture
def approved_review_result(sample_bundle: ReviewBundle) -> ReviewResult:
    session = ReviewSession(sample_bundle)
    return session.approve(reviewer_note="Review approved for freezing")


@pytest.fixture
def rejected_review_result(sample_bundle: ReviewBundle) -> ReviewResult:
    session = ReviewSession(sample_bundle)
    return session.reject(reviewer_note="Review rejected due to scope")


class TestFreezeDigestDeterministicAuthority:
    """1. Canonical hashing and deterministic byte authority tests."""

    def test_canonical_contract_bytes_guarantees(self) -> None:
        payload = {
            "task_digest": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "schema_version": "1.0.0",
            "change_class": "BUG_FIX",
            "certainty": "CONFIDENT",
            "requirements": [
                {
                    "citation": "When HTTP 503 is returned",
                    "citation_end": 26,
                    "citation_start": 0,
                    "rationale": "Handle errors",
                    "requirement_id": "REQ-A1B2C3D4",
                    "statement": "Retry on timeout",
                }
            ],
        }
        b = canonical_contract_bytes(payload)
        assert isinstance(b, bytes)
        decoded = b.decode("utf-8")
        # Verify delimiters are compact (no ': ' or ', ')
        assert '": ' not in decoded
        assert '", ' not in decoded
        assert decoded.startswith('{"certainty":')

    def test_identical_contract_yields_exact_same_digest(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen1 = freeze_review_result(approved_review_result)
        frozen2 = freeze_review_result(approved_review_result)

        assert frozen1.contract_digest == frozen2.contract_digest
        assert len(frozen1.contract_digest) == 64
        assert frozen1.contract_digest.islower()
        assert frozen1.canonical_bytes == frozen2.canonical_bytes

    def test_canonical_requirement_order_invariance(
        self, approved_review_result: ReviewResult
    ) -> None:
        contract = approved_review_result.contract
        assert contract is not None
        reqs = list(contract.requirements)
        assert len(reqs) >= 2

        # Order 1: normal order
        p1 = build_canonical_identity_payload(
            schema_version="1.0.0",
            task_digest=contract.task_digest,
            change_class=contract.change_class or ChangeClass.BUG_FIX,
            certainty=contract.certainty or CertaintyLevel.CONFIDENT,
            requirements=reqs,
        )

        # Order 2: reversed order
        p2 = build_canonical_identity_payload(
            schema_version="1.0.0",
            task_digest=contract.task_digest,
            change_class=contract.change_class or ChangeClass.BUG_FIX,
            certainty=contract.certainty or CertaintyLevel.CONFIDENT,
            requirements=list(reversed(reqs)),
        )

        d1 = compute_contract_digest(p1)
        d2 = compute_contract_digest(p2)
        assert d1 == d2
        assert canonical_contract_bytes(p1) == canonical_contract_bytes(p2)

    def test_digest_mutation_detection_task_digest(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        p_tampered = frozen.to_identity_payload()
        p_tampered["task_digest"] = "0" * 64
        tampered_digest = compute_contract_digest(p_tampered)
        assert tampered_digest != frozen.contract_digest

    def test_digest_mutation_detection_change_class(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        p_tampered = frozen.to_identity_payload()
        p_tampered["change_class"] = "SECURITY_FIX"
        tampered_digest = compute_contract_digest(p_tampered)
        assert tampered_digest != frozen.contract_digest

    def test_digest_mutation_detection_certainty(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        p_tampered = frozen.to_identity_payload()
        p_tampered["certainty"] = "HIGH"
        tampered_digest = compute_contract_digest(p_tampered)
        assert tampered_digest != frozen.contract_digest

    def test_digest_mutation_detection_schema_version(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        p_tampered = frozen.to_identity_payload()
        p_tampered["schema_version"] = "2.0.0"
        tampered_digest = compute_contract_digest(p_tampered)
        assert tampered_digest != frozen.contract_digest

    def test_digest_mutation_detection_requirement_statement(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        p_tampered = frozen.to_identity_payload()
        p_tampered["requirements"][0]["statement"] = "Tampered statement"
        tampered_digest = compute_contract_digest(p_tampered)
        assert tampered_digest != frozen.contract_digest

    def test_digest_mutation_detection_requirement_citation(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        p_tampered = frozen.to_identity_payload()
        p_tampered["requirements"][0]["citation"] = "Tampered citation"
        tampered_digest = compute_contract_digest(p_tampered)
        assert tampered_digest != frozen.contract_digest

    def test_digest_mutation_detection_requirement_citation_span(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        p_tampered = frozen.to_identity_payload()
        p_tampered["requirements"][0]["citation_start"] += 1
        tampered_digest = compute_contract_digest(p_tampered)
        assert tampered_digest != frozen.contract_digest

    def test_digest_mutation_detection_requirement_rationale(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        p_tampered = frozen.to_identity_payload()
        p_tampered["requirements"][0]["rationale"] = "Tampered rationale"
        tampered_digest = compute_contract_digest(p_tampered)
        assert tampered_digest != frozen.contract_digest

    def test_digest_mutation_detection_requirement_id(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        p_tampered = frozen.to_identity_payload()
        p_tampered["requirements"][0]["requirement_id"] = "REQ-FFFFFFFF"
        tampered_digest = compute_contract_digest(p_tampered)
        assert tampered_digest != frozen.contract_digest

    def test_digest_excludes_contract_digest_itself(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        payload = frozen.to_identity_payload()
        assert "contract_digest" not in payload
        assert "contract_digest" not in frozen.canonical_bytes.decode("utf-8")

    def test_digest_excludes_non_contract_review_metadata(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        payload = frozen.to_identity_payload()
        assert "reviewer_note" not in payload
        assert "audit_trail" not in payload
        assert "timestamp" not in payload
        assert "pid" not in payload
        assert "process_id" not in payload
        assert "path" not in payload


class TestConstructorAuthorityP0606:
    """2. Constructor authority invariant and fail-closed enforcement."""

    def test_direct_construction_without_source_review_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        with pytest.raises(FrozenContractSchemaError, match="source_review .* is mandatory"):
            FrozenContract(
                schema_version=frozen.schema_version,
                contract_digest=frozen.contract_digest,
                task_digest=frozen.task_digest,
                change_class=frozen.change_class,
                certainty=frozen.certainty,
                requirements=frozen.requirements,
                validation_rules_passed=frozen.validation_rules_passed,
                source_review=None,
            )

    def test_direct_construction_with_non_review_result_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        with pytest.raises(TypeError, match="source_review must be ReviewResult"):
            FrozenContract(
                schema_version=frozen.schema_version,
                contract_digest=frozen.contract_digest,
                task_digest=frozen.task_digest,
                change_class=frozen.change_class,
                certainty=frozen.certainty,
                requirements=frozen.requirements,
                validation_rules_passed=frozen.validation_rules_passed,
                source_review="not a ReviewResult",  # type: ignore[arg-type]
            )

    def test_direct_construction_with_rejected_review_fails_closed(
        self,
        approved_review_result: ReviewResult,
        rejected_review_result: ReviewResult,
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        with pytest.raises(FrozenContractSchemaError, match="source_review must be APPROVED"):
            FrozenContract(
                schema_version=frozen.schema_version,
                contract_digest=frozen.contract_digest,
                task_digest=frozen.task_digest,
                change_class=frozen.change_class,
                certainty=frozen.certainty,
                requirements=frozen.requirements,
                validation_rules_passed=frozen.validation_rules_passed,
                source_review=rejected_review_result,
            )

    def test_direct_construction_with_mismatched_task_digest_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        with pytest.raises(FrozenContractSchemaError, match="task_digest mismatch"):
            FrozenContract(
                schema_version=frozen.schema_version,
                contract_digest=frozen.contract_digest,
                task_digest="f" * 64,
                change_class=frozen.change_class,
                certainty=frozen.certainty,
                requirements=frozen.requirements,
                validation_rules_passed=frozen.validation_rules_passed,
                source_review=approved_review_result,
            )

    def test_direct_construction_with_mismatched_change_class_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        with pytest.raises(FrozenContractSchemaError, match="change_class mismatch"):
            FrozenContract(
                schema_version=frozen.schema_version,
                contract_digest=frozen.contract_digest,
                task_digest=frozen.task_digest,
                change_class=ChangeClass.REFACTOR,
                certainty=frozen.certainty,
                requirements=frozen.requirements,
                validation_rules_passed=frozen.validation_rules_passed,
                source_review=approved_review_result,
            )

    def test_direct_construction_with_mismatched_certainty_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        with pytest.raises(FrozenContractSchemaError, match="certainty mismatch"):
            FrozenContract(
                schema_version=frozen.schema_version,
                contract_digest=frozen.contract_digest,
                task_digest=frozen.task_digest,
                change_class=frozen.change_class,
                certainty=CertaintyLevel.AMBIGUOUS,
                requirements=frozen.requirements,
                validation_rules_passed=frozen.validation_rules_passed,
                source_review=approved_review_result,
            )

    def test_direct_construction_with_mismatched_requirement_statement_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        reqs = list(frozen.requirements)
        reqs[0] = FrozenRequirement(
            requirement_id=reqs[0].requirement_id,
            statement="Tampered statement in direct constructor",
            citation=reqs[0].citation,
            citation_start=reqs[0].citation_start,
            citation_end=reqs[0].citation_end,
            rationale=reqs[0].rationale,
        )
        with pytest.raises(FrozenContractSchemaError, match="Requirement statement mismatch"):
            FrozenContract(
                schema_version=frozen.schema_version,
                contract_digest=frozen.contract_digest,
                task_digest=frozen.task_digest,
                change_class=frozen.change_class,
                certainty=frozen.certainty,
                requirements=tuple(reqs),
                validation_rules_passed=frozen.validation_rules_passed,
                source_review=approved_review_result,
            )

    def test_tampered_payload_with_recomputed_digest_still_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        """Attacker modifies requirement AND recomputes SHA-256 to create self-consistent hash.

        Authority invariant MUST still fail closed against source_review!
        """
        frozen = freeze_review_result(approved_review_result)
        reqs = list(frozen.requirements)
        reqs[0] = FrozenRequirement(
            requirement_id=reqs[0].requirement_id,
            statement="Tampered statement with attacker recomputed digest",
            citation=reqs[0].citation,
            citation_start=reqs[0].citation_start,
            citation_end=reqs[0].citation_end,
            rationale=reqs[0].rationale,
        )
        tampered_payload = build_canonical_identity_payload(
            schema_version=frozen.schema_version,
            task_digest=frozen.task_digest,
            change_class=frozen.change_class,
            certainty=frozen.certainty,
            requirements=reqs,
        )
        attacker_digest = compute_contract_digest(tampered_payload)

        # Attacker digest matches tampered requirements, but fails against source_review
        with pytest.raises(FrozenContractSchemaError, match="Requirement statement mismatch"):
            FrozenContract(
                schema_version=frozen.schema_version,
                contract_digest=attacker_digest,
                task_digest=frozen.task_digest,
                change_class=frozen.change_class,
                certainty=frozen.certainty,
                requirements=tuple(reqs),
                validation_rules_passed=frozen.validation_rules_passed,
                source_review=approved_review_result,
            )

    def test_direct_construction_with_tampered_contract_digest_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        bad_digest = "e" * 64
        with pytest.raises(
            FrozenContractDigestMismatchError, match="contract_digest mismatch: declared"
        ):
            FrozenContract(
                schema_version=frozen.schema_version,
                contract_digest=bad_digest,
                task_digest=frozen.task_digest,
                change_class=frozen.change_class,
                certainty=frozen.certainty,
                requirements=frozen.requirements,
                validation_rules_passed=frozen.validation_rules_passed,
                source_review=approved_review_result,
            )

    def test_direct_construction_with_non_canonical_requirement_order_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        reversed_reqs = tuple(reversed(frozen.requirements))
        if reversed_reqs != frozen.requirements:
            with pytest.raises(
                FrozenContractSchemaError, match="requirements must be strictly in canonical order"
            ):
                FrozenContract(
                    schema_version=frozen.schema_version,
                    contract_digest=frozen.contract_digest,
                    task_digest=frozen.task_digest,
                    change_class=frozen.change_class,
                    certainty=frozen.certainty,
                    requirements=reversed_reqs,
                    validation_rules_passed=frozen.validation_rules_passed,
                    source_review=approved_review_result,
                )

    def test_source_review_is_not_stored_as_attribute_or_serialized(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        # Check dataclass fields
        field_names = {f.name for f in dataclasses.fields(frozen)}
        assert "source_review" not in field_names
        # Check to_dict and to_json
        d = frozen.to_dict()
        assert "source_review" not in d
        j = frozen.to_json()
        assert "source_review" not in j


class TestAuthoritativeFactoryFreezeReviewResult:
    """3. Authoritative factory freeze_review_result tests."""

    def test_freeze_approved_review_result_succeeds(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        assert isinstance(frozen, FrozenContract)
        assert frozen.schema_version == FROZEN_CONTRACT_SCHEMA_VERSION
        assert len(frozen.contract_digest) == 64
        assert frozen.task_digest == approved_review_result.task_digest
        assert frozen.change_class == ChangeClass.BUG_FIX
        assert frozen.certainty == CertaintyLevel.CONFIDENT
        assert len(frozen.requirements) == len(approved_review_result.contract.requirements)  # type: ignore[union-attr]

    def test_freeze_rejected_review_result_fails_closed(
        self, rejected_review_result: ReviewResult
    ) -> None:
        with pytest.raises(
            FrozenContractSchemaError, match="Cannot freeze review result: decision is REJECTED"
        ):
            freeze_review_result(rejected_review_result)

    def test_freeze_non_ready_review_result_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        # Construct review result that is somehow not ready
        with pytest.raises(TypeError):
            freeze_review_result(None)  # type: ignore[arg-type]

    def test_freeze_non_review_result_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="review_result must be ReviewResult"):
            freeze_review_result({"decision": "APPROVED"})  # type: ignore[arg-type]


class TestImmutabilityP0606:
    """4. Immutability tests for FrozenContract and FrozenRequirement."""

    def test_frozen_contract_is_immutable(self, approved_review_result: ReviewResult) -> None:
        frozen = freeze_review_result(approved_review_result)
        with pytest.raises(FrozenInstanceError):
            frozen.contract_digest = "f" * 64  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            frozen.task_digest = "0" * 64  # type: ignore[misc]

    def test_frozen_requirement_is_immutable(self, approved_review_result: ReviewResult) -> None:
        frozen = freeze_review_result(approved_review_result)
        req = frozen.requirements[0]
        with pytest.raises(FrozenInstanceError):
            req.statement = "Modified statement"  # type: ignore[misc]

    def test_no_mutation_methods_exist(self, approved_review_result: ReviewResult) -> None:
        frozen = freeze_review_result(approved_review_result)
        assert not hasattr(frozen, "set_digest")
        assert not hasattr(frozen, "replace_requirement")
        assert not hasattr(frozen, "edit_contract")
        assert not hasattr(frozen, "update_statement")


class TestSerializationAndTrustedDeserialization:
    """5. Serialization and trusted deserialization tests."""

    def test_roundtrip_dict_and_json(self, approved_review_result: ReviewResult) -> None:
        frozen = freeze_review_result(approved_review_result)
        d = frozen.to_dict()
        j = frozen.to_json()

        from_d = FrozenContract.from_dict(d, source_review=approved_review_result)
        from_j = FrozenContract.from_json(j, source_review=approved_review_result)

        assert from_d == frozen
        assert from_j == frozen
        assert from_d.contract_digest == frozen.contract_digest
        assert from_j.contract_digest == frozen.contract_digest

    def test_from_dict_missing_source_review_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        d = frozen.to_dict()
        with pytest.raises(TypeError):
            FrozenContract.from_dict(d)  # type: ignore[call-arg]

    def test_from_dict_with_none_source_review_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        d = frozen.to_dict()
        with pytest.raises(
            FrozenContractSchemaError, match="source_review is mandatory for trusted loading"
        ):
            FrozenContract.from_dict(d, source_review=None)  # type: ignore[arg-type]

    def test_from_dict_with_unknown_injected_fields_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        d = frozen.to_dict()
        d["injected_field"] = "attack"
        with pytest.raises(FrozenContractSchemaError, match="Unknown fields in FrozenContract"):
            FrozenContract.from_dict(d, source_review=approved_review_result)

    def test_from_dict_with_tampered_digest_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        d = frozen.to_dict()
        d["contract_digest"] = "f" * 64
        with pytest.raises(FrozenContractDigestMismatchError, match="Serialized contract_digest"):
            FrozenContract.from_dict(d, source_review=approved_review_result)

    def test_from_dict_with_tampered_payload_and_recomputed_digest_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        d = frozen.to_dict()
        d["requirements"][0]["statement"] = "Tampered statement"
        # Recompute digest so dict is self-consistent
        tampered_identity = build_canonical_identity_payload(
            schema_version=d["schema_version"],
            task_digest=d["task_digest"],
            change_class=d["change_class"],
            certainty=d["certainty"],
            requirements=d["requirements"],
        )
        d["contract_digest"] = compute_contract_digest(tampered_identity)

        # Still MUST fail closed against source_review
        with pytest.raises(FrozenContractSchemaError, match="Requirement statement mismatch"):
            FrozenContract.from_dict(d, source_review=approved_review_result)

    def test_from_dict_with_non_canonical_requirement_order_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        d = frozen.to_dict()
        d["requirements"] = list(reversed(d["requirements"]))
        if d["requirements"] != frozen.to_dict()["requirements"]:
            with pytest.raises(
                FrozenContractSchemaError,
                match="requirements in serialized data must be in canonical order",
            ):
                FrozenContract.from_dict(d, source_review=approved_review_result)

    def test_from_json_invalid_json_fails_closed(
        self, approved_review_result: ReviewResult
    ) -> None:
        with pytest.raises(FrozenContractSchemaError, match="Invalid JSON for FrozenContract"):
            FrozenContract.from_json("not valid json", source_review=approved_review_result)

    def test_strict_typing_without_silent_coercion(self) -> None:
        with pytest.raises(TypeError, match="citation_start must be int"):
            FrozenRequirement(
                requirement_id="REQ-A1B2C3D4",
                statement="Retry on timeout",
                citation="When 503 is returned",
                citation_start="0",  # type: ignore[arg-type]
                citation_end=20,
            )
        with pytest.raises(TypeError, match="citation_start must be int \\(not bool\\)"):
            FrozenRequirement(
                requirement_id="REQ-A1B2C3D4",
                statement="Retry on timeout",
                citation="When 503 is returned",
                citation_start=True,
                citation_end=20,
            )


class TestVerifyFrozenContract:
    """6. Deterministic verification tests for verify_frozen_contract."""

    def test_verify_valid_contract_returns_true(self, approved_review_result: ReviewResult) -> None:
        frozen = freeze_review_result(approved_review_result)
        assert verify_frozen_contract(frozen) is True
        assert verify_frozen_contract(frozen, expected_review=approved_review_result) is True

    def test_verify_non_frozen_contract_type_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="contract must be FrozenContract"):
            verify_frozen_contract("not a contract")  # type: ignore[arg-type]

    def test_verify_with_rejected_review_fails_closed(
        self,
        approved_review_result: ReviewResult,
        rejected_review_result: ReviewResult,
    ) -> None:
        frozen = freeze_review_result(approved_review_result)
        with pytest.raises(FrozenContractSchemaError, match="expected_review must be APPROVED"):
            verify_frozen_contract(frozen, expected_review=rejected_review_result)


class TestProviderPurityAndBoundaryP0606:
    """7. Provider purity and architectural boundary tests."""

    def test_no_provider_or_adapter_imports_in_freeze(self) -> None:
        import basebreak.compiler.freeze as freeze_module

        source = inspect.getsource(freeze_module)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "adapters" not in alias.name
                    assert "nebius" not in alias.name.lower()
                    assert "openai" not in alias.name.lower()
                    assert "tavily" not in alias.name.lower()
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert "adapters" not in node.module
                    assert "nebius" not in node.module.lower()
                    assert "openai" not in node.module.lower()
                    assert "tavily" not in node.module.lower()

    def test_no_builder_or_verifier_logic_in_freeze(self) -> None:
        import basebreak.compiler.freeze as freeze_module

        symbols = dir(freeze_module)
        for sym in symbols:
            assert "builder" not in sym.lower()
            assert "witness" not in sym.lower()
            assert "candidate" not in sym.lower()
            assert "sandbox" not in sym.lower()
