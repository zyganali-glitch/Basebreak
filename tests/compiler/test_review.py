"""Acceptance test suite for P-06.05: Human-Editable Contract Review Surface.

Verifies:
A. review bundle strict round-trip;
B. task identity preserved exactly;
C. deterministic P-06.03 semantics preserved exactly;
D. requirements displayed in stable deterministic order;
E. human statement edit re-runs P-06.04 validation;
F. statement edit that creates forbidden action fails closed;
G. statement edit introducing unsupported endpoint scope fails closed;
H. statement edit introducing unsupported repo-path scope fails closed;
I. citation edit with wrong span fails closed;
J. valid citation+span edit succeeds;
K. add requirement revalidates and derives deterministic ID;
L. remove requirement revalidates remaining contract;
M. edited content cannot retain a stale content-derived requirement ID as authority;
N. duplicate/ID collision behavior remains P-06.04-controlled;
O. contradiction introduced by human edit fails closed;
P. APPROVED decision only possible after successful deterministic revalidation;
Q. REJECTED decision cannot be treated as ready for freeze;
R. AMBIGUOUS semantics cannot be approved;
S. UNKNOWN semantics cannot be approved;
T. raw/normalized task text cannot be silently changed through review edit commands;
U. authoritative change_class cannot be silently edited through CLI;
V. invalid/malformed review JSON fails closed;
W. wrong field types fail closed without coercion;
X. output ordering/serialization stable;
Y. failed review does not write an approved artifact (tested in CLI test too);
Z. diagnostics are secret-safe;
AA. zero provider/model/network/sandbox behavior;
AB. zero P-06.06 digest/freeze field exists;
AC. P-06.07/P-07 symbols are not introduced.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect

import pytest

from basebreak.compiler.ingestion import NormalizedTask, ingest_task
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.review import (
    FORBIDDEN_P0606_FIELDS,
    ReviewApprovalError,
    ReviewBundle,
    ReviewDecision,
    ReviewOperationError,
    ReviewResult,
    ReviewSchemaError,
    ReviewSession,
    ReviewStatus,
    create_review_bundle_from_contract,
)
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
)
from basebreak.compiler.validator import (
    ContractValidationError,
    ContradictoryRequirementsError,
    DuplicateRequirementIdError,
    ForbiddenActionViolationError,
    InvalidCitationError,
    RequirementCountLimitExceededError,
    UnresolvedChangeClassError,
    UnsupportedScopeError,
    ValidatedContract,
    derive_requirement_id,
    validate_contract,
)
from basebreak.domain.semantics import ChangeClass
from basebreak.security.secret_policy import REDACTION_MARKER


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
def ambiguous_semantics(sample_task: NormalizedTask) -> ChangeSemanticsClassification:
    fact = DeterministicClassificationFact(
        inferred_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.AMBIGUOUS,
        confidence=0.5,
        alternative_classes=(ChangeClass.FEATURE,),
        rationale="Both fix and add signals",
        evidence_citations=(),
        matched_signals=("fix", "add"),
    )
    return ChangeSemanticsClassification(
        task_digest=sample_task.task_digest,
        change_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.AMBIGUOUS,
        confidence=0.5,
        alternative_classes=(ChangeClass.FEATURE,),
        rationale="Both fix and add signals",
        evidence_citations=(),
        deterministic_facts=fact,
    )


@pytest.fixture
def unknown_semantics(sample_task: NormalizedTask) -> ChangeSemanticsClassification:
    fact = DeterministicClassificationFact(
        inferred_class=None,
        certainty=CertaintyLevel.UNKNOWN,
        confidence=0.0,
        alternative_classes=(),
        rationale="No clear signals",
        evidence_citations=(),
        matched_signals=(),
    )
    return ChangeSemanticsClassification(
        task_digest=sample_task.task_digest,
        change_class=None,
        certainty=CertaintyLevel.UNKNOWN,
        confidence=0.0,
        alternative_classes=(),
        rationale="No clear signals",
        evidence_citations=(),
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


class TestReviewCoreP0605:
    """Comprehensive test suite for P-06.05 review core logic."""

    # A. review bundle strict round-trip
    def test_A_review_bundle_strict_round_trip(self, sample_bundle: ReviewBundle) -> None:
        bundle_dict = sample_bundle.to_dict()
        bundle_json = sample_bundle.to_json()

        reconstructed_from_dict = ReviewBundle.from_dict(bundle_dict)
        reconstructed_from_json = ReviewBundle.from_json(bundle_json)

        assert reconstructed_from_dict == sample_bundle
        assert reconstructed_from_json == sample_bundle
        assert reconstructed_from_dict.to_dict() == bundle_dict

    # B. task identity preserved exactly
    def test_B_task_identity_preserved_exactly(self, sample_bundle: ReviewBundle) -> None:
        session = ReviewSession(sample_bundle)
        session.edit_statement(0, "Retry on network timeout when 503 occurs")
        result = session.approve(reviewer_note="Looks good")

        assert session.task.task_digest == sample_bundle.task.task_digest
        assert session.task.raw_digest == sample_bundle.task.raw_digest
        assert session.task.raw_text == sample_bundle.task.raw_text
        assert session.task.normalized_text == sample_bundle.task.normalized_text
        assert result.task_digest == sample_bundle.task.task_digest

    # C. deterministic P-06.03 semantics preserved exactly
    def test_C_deterministic_semantics_preserved_exactly(self, sample_bundle: ReviewBundle) -> None:
        session = ReviewSession(sample_bundle)
        session.edit_statement(0, "Retry on network timeout when 503 occurs")
        result = session.approve()

        assert session.semantics.change_class == sample_bundle.semantics.change_class
        assert session.semantics.certainty == sample_bundle.semantics.certainty
        assert session.semantics.confidence == sample_bundle.semantics.confidence
        assert session.semantics.deterministic_facts == sample_bundle.semantics.deterministic_facts
        assert result.contract is not None
        assert result.contract.change_class == sample_bundle.semantics.change_class

    # D. requirements displayed in stable deterministic order
    def test_D_requirements_displayed_in_stable_deterministic_order(
        self, sample_bundle: ReviewBundle
    ) -> None:
        session = ReviewSession(sample_bundle)
        display = session.get_requirements_display()

        assert len(display) == len(sample_bundle.requirements)
        for item in display:
            assert "index" in item
            assert "requirement_id" in item
            assert item["requirement_id"].startswith("REQ-")
            assert "statement" in item
            assert "citation" in item
            assert "citation_start" in item
            assert "citation_end" in item

        contract = session.revalidate()
        req_ids = [r.requirement_id for r in contract.requirements]
        assert req_ids == sorted(req_ids)

    # E. human statement edit re-runs P-06.04 validation
    def test_E_human_statement_edit_reruns_validation(self, sample_bundle: ReviewBundle) -> None:
        session = ReviewSession(sample_bundle)
        initial_contract = session.revalidate()
        old_id = initial_contract.requirements[0].requirement_id

        session.edit_statement(0, "Retry on network timeout when 503 is returned")
        new_contract = session.revalidate()

        # Validation must have run and produced a newly derived requirement ID
        new_req_ids = [r.requirement_id for r in new_contract.requirements]
        assert old_id not in new_req_ids
        assert len(new_contract.requirements) == 2
        assert "SCOPE-001" in new_contract.validation_rules_passed

    # F. statement edit that creates forbidden action fails closed
    def test_F_statement_edit_forbidden_action_fails_closed(
        self, sample_bundle: ReviewBundle
    ) -> None:
        session = ReviewSession(sample_bundle)
        # Edit statement to violate test-weakening rule FORBIDDEN-001
        session.edit_statement(0, "Delete failing test assertions to ensure pipeline passes")

        with pytest.raises(ForbiddenActionViolationError, match="FORBIDDEN-001"):
            session.revalidate()

        with pytest.raises(ReviewApprovalError, match="FORBIDDEN-001"):
            session.approve()

    # G. statement edit introducing unsupported endpoint scope fails closed
    def test_G_statement_edit_unsupported_endpoint_scope_fails(
        self, sample_bundle: ReviewBundle
    ) -> None:
        session = ReviewSession(sample_bundle)
        # /api/billing is NOT mentioned anywhere in the task text
        session.edit_statement(0, "Enforce authentication on /api/billing")

        with pytest.raises(UnsupportedScopeError, match="endpoint scope"):
            session.revalidate()

        with pytest.raises(ReviewApprovalError, match="endpoint scope"):
            session.approve()

    # H. statement edit introducing unsupported repo-path scope fails closed
    def test_H_statement_edit_unsupported_repo_path_scope_fails(
        self, sample_bundle: ReviewBundle
    ) -> None:
        session = ReviewSession(sample_bundle)
        # src/unrelated/daemon.py is NOT mentioned in task text
        session.edit_statement(0, "Modify src/unrelated/daemon.py to increase timeout")

        with pytest.raises(UnsupportedScopeError, match="repository path scope"):
            session.revalidate()

        with pytest.raises(ReviewApprovalError, match="repository path scope"):
            session.approve()

    # I. citation edit with wrong span fails closed
    def test_I_citation_edit_with_wrong_span_fails_closed(
        self, sample_bundle: ReviewBundle
    ) -> None:
        session = ReviewSession(sample_bundle)
        # Citation text does NOT match slice [0:10] in sample_task
        session.edit_citation(
            0,
            new_citation="When HTTP 503 is returned, retry on network timeout.",
            citation_start=0,
            citation_end=10,
        )

        with pytest.raises(InvalidCitationError):
            session.revalidate()

        with pytest.raises(ReviewApprovalError):
            session.approve()

    # J. valid citation+span edit succeeds
    def test_J_valid_citation_and_span_edit_succeeds(
        self, sample_bundle: ReviewBundle, sample_task: NormalizedTask
    ) -> None:
        session = ReviewSession(sample_bundle)
        # Pick another valid verbatim citation from task text
        new_cit = "Enable caching on /api/catalog."
        start = sample_task.normalized_text.index(new_cit)
        end = start + len(new_cit)

        session.edit_citation(0, new_citation=new_cit, citation_start=start, citation_end=end)
        session.edit_statement(0, "Enable caching on /api/catalog")

        contract = session.revalidate()
        assert any(r.citation == new_cit for r in contract.requirements)

    # K. add requirement revalidates and derives deterministic ID
    def test_K_add_requirement_revalidates_and_derives_id(
        self, sample_bundle: ReviewBundle, sample_task: NormalizedTask
    ) -> None:
        session = ReviewSession(sample_bundle)
        cit = "Enable caching on /api/catalog."
        start = sample_task.normalized_text.index(cit)
        end = start + len(cit)

        expected_id = derive_requirement_id("Enable caching on /api/catalog", cit, start, end)

        session.add_requirement(
            statement="Enable caching on /api/catalog",
            citation=cit,
            citation_start=start,
            citation_end=end,
            rationale="Performance enhancement",
        )

        assert len(session.requirements) == 3
        contract = session.revalidate()
        assert len(contract.requirements) == 3
        assert any(r.requirement_id == expected_id for r in contract.requirements)

    # L. remove requirement revalidates remaining contract
    def test_L_remove_requirement_revalidates_remaining_contract(
        self, sample_bundle: ReviewBundle
    ) -> None:
        session = ReviewSession(sample_bundle)
        session.remove_requirement(1)

        assert len(session.requirements) == 1
        contract = session.revalidate()
        assert len(contract.requirements) == 1

        # Removing all requirements must fail due to MIN_REQUIREMENTS_COUNT
        session.remove_requirement(0)
        assert len(session.requirements) == 0
        with pytest.raises(RequirementCountLimitExceededError):
            session.revalidate()

    # M. edited content cannot retain a stale content-derived requirement ID as authority
    # M. edited content cannot retain a stale content-derived requirement ID as authority
    def test_M_edited_content_cannot_retain_stale_id_as_authority(
        self,
        sample_bundle: ReviewBundle,
        sample_task: NormalizedTask,
        confident_semantics: ChangeSemanticsClassification,
    ) -> None:
        session = ReviewSession(sample_bundle)
        initial_contract = session.revalidate()
        old_req = initial_contract.requirements[0]
        stale_id = old_req.requirement_id

        # Edit statement
        session.edit_statement(0, "Retry on network timeout with exponential backoff")
        new_contract = session.revalidate()

        # The new contract MUST have re-derived the ID; the stale ID must NOT be retained
        assert not any(r.requirement_id == stale_id for r in new_contract.requirements)
        expected_new_id = derive_requirement_id(
            "Retry on network timeout with exponential backoff",
            old_req.citation,
            old_req.citation_start,
            old_req.citation_end,
        )
        assert any(r.requirement_id == expected_new_id for r in new_contract.requirements)

        # Trusted in-memory conversion: ValidatedContract -> create_review_bundle_from_contract
        # explicitly converts ValidatedRequirement to ProposedRequirement, discarding requirement_id
        bundle_from_contract = create_review_bundle_from_contract(
            sample_task, confident_semantics, initial_contract
        )
        for req in bundle_from_contract.requirements:
            assert isinstance(req, ProposedRequirement)
            assert not hasattr(req, "requirement_id")

        # Serialized schema: arbitrary ReviewBundle JSON containing requirement_id must FAIL CLOSED
        tampered_data = sample_bundle.to_dict()
        tampered_data["requirements"][0]["statement"] = "Edited statement without updating ID"
        tampered_data["requirements"][0]["requirement_id"] = stale_id  # asserted stale ID

        with pytest.raises(ReviewSchemaError, match="Unknown field.*requirement_id"):
            ReviewBundle.from_dict(tampered_data)

    # N. duplicate/ID collision behavior remains P-06.04-controlled
    def test_N_duplicate_id_collision_fails_closed(self, sample_bundle: ReviewBundle) -> None:
        session = ReviewSession(sample_bundle)
        # Duplicate requirement 0
        req0 = session.requirements[0]
        session.add_requirement(
            statement=req0.statement,
            citation=req0.citation,
            citation_start=req0.citation_start,
            citation_end=req0.citation_end,
            rationale=req0.rationale,
        )

        with pytest.raises(DuplicateRequirementIdError):
            session.revalidate()

        with pytest.raises(ReviewApprovalError):
            session.approve()

    # O. contradiction introduced by human edit fails closed
    def test_O_contradiction_introduced_by_human_edit_fails_closed(
        self, sample_bundle: ReviewBundle, sample_task: NormalizedTask
    ) -> None:
        session = ReviewSession(sample_bundle)
        cit1 = "When HTTP 503 is returned, retry on network timeout."
        start1 = sample_task.normalized_text.index(cit1)
        end1 = start1 + len(cit1)

        # Edit req 0 to demand retry on network timeout
        session.edit_statement(0, "Retry on network timeout")
        # Add req forbidding retry on network timeout -> CONTRADICTION-RETRY
        session.add_requirement(
            statement="Never retry on network timeout",
            citation=cit1,
            citation_start=start1,
            citation_end=end1,
        )

        with pytest.raises(ContradictoryRequirementsError, match="CONTRADICTION-RETRY"):
            session.revalidate()

        with pytest.raises(ReviewApprovalError, match="CONTRADICTION-RETRY"):
            session.approve()

    # P. APPROVED decision only possible after successful deterministic revalidation
    def test_P_approved_decision_requires_successful_revalidation(
        self, sample_bundle: ReviewBundle
    ) -> None:
        session = ReviewSession(sample_bundle)
        result = session.approve(reviewer_note="Review passed successfully")

        assert result.decision == ReviewDecision.APPROVED
        assert result.status == ReviewStatus.READY_FOR_FREEZE
        assert result.is_ready_for_freeze is True
        assert result.contract is not None
        assert isinstance(result.contract, ValidatedContract)
        assert result.reviewer_note == "Review passed successfully"
        assert result.task_digest == sample_bundle.task.task_digest

    # Q. REJECTED decision cannot be treated as ready for freeze
    def test_Q_rejected_decision_cannot_be_ready_for_freeze(
        self, sample_bundle: ReviewBundle
    ) -> None:
        session = ReviewSession(sample_bundle)
        result = session.reject(reviewer_note="Requirements do not match intent")

        assert result.decision == ReviewDecision.REJECTED
        assert result.status == ReviewStatus.REJECTED
        assert result.is_ready_for_freeze is False
        assert result.contract is None
        assert result.reviewer_note == "Requirements do not match intent"

    # R. AMBIGUOUS semantics cannot be approved
    def test_R_ambiguous_semantics_cannot_be_approved(
        self,
        sample_task: NormalizedTask,
        ambiguous_semantics: ChangeSemanticsClassification,
        sample_requirements: list[ProposedRequirement],
    ) -> None:
        bundle = ReviewBundle(
            task=sample_task,
            semantics=ambiguous_semantics,
            requirements=tuple(sample_requirements),
        )
        session = ReviewSession(bundle)

        with pytest.raises(UnresolvedChangeClassError, match="AMBIGUOUS"):
            session.revalidate()

        with pytest.raises(UnresolvedChangeClassError, match="AMBIGUOUS"):
            session.approve()

    # S. UNKNOWN semantics cannot be approved
    def test_S_unknown_semantics_cannot_be_approved(
        self,
        sample_task: NormalizedTask,
        unknown_semantics: ChangeSemanticsClassification,
        sample_requirements: list[ProposedRequirement],
    ) -> None:
        bundle = ReviewBundle(
            task=sample_task,
            semantics=unknown_semantics,
            requirements=tuple(sample_requirements),
        )
        session = ReviewSession(bundle)

        with pytest.raises(UnresolvedChangeClassError, match="UNKNOWN"):
            session.revalidate()

        with pytest.raises(UnresolvedChangeClassError, match="UNKNOWN"):
            session.approve()

    # T. raw/normalized task text cannot be silently changed through review edit commands
    def test_T_task_text_cannot_be_silently_changed(self, sample_bundle: ReviewBundle) -> None:
        session = ReviewSession(sample_bundle)
        # Verify ReviewSession has NO methods to edit task
        assert not hasattr(session, "edit_task")
        assert not hasattr(session, "edit_raw_text")
        assert not hasattr(session, "edit_normalized_text")

        # Modifying task in dictionary causes digest verification to fail upon deserialization
        tampered_data = sample_bundle.to_dict()
        tampered_data["task"]["raw_text"] = "Tampered raw text"
        with pytest.raises(ReviewSchemaError, match="raw_digest mismatch"):
            ReviewBundle.from_dict(tampered_data)

    # U. authoritative change_class cannot be silently edited through CLI
    def test_U_authoritative_change_class_cannot_be_silently_edited(
        self, sample_bundle: ReviewBundle
    ) -> None:
        session = ReviewSession(sample_bundle)
        # Verify ReviewSession has NO methods to edit change_class
        assert not hasattr(session, "edit_change_class")
        assert not hasattr(session, "edit_semantics")

        # Tampering with change_class causes P-06.03 classification consistency to fail
        tampered_data = sample_bundle.to_dict()
        tampered_data["semantics"]["change_class"] = "FEATURE"
        with pytest.raises(ReviewSchemaError, match="mismatch|does not match"):
            ReviewBundle.from_dict(tampered_data)

    # V. invalid/malformed review JSON fails closed
    def test_V_invalid_malformed_json_fails_closed(self) -> None:
        with pytest.raises(ReviewSchemaError, match="Invalid JSON"):
            ReviewBundle.from_json("invalid json {")

        with pytest.raises(ReviewSchemaError, match="Missing required fields"):
            ReviewBundle.from_dict({"task": {}})

        with pytest.raises(ReviewSchemaError, match="Unknown fields"):
            ReviewBundle.from_dict(
                {
                    "task": {},
                    "semantics": {},
                    "requirements": [],
                    "unexpected_extra_field": True,
                }
            )

    # W. wrong field types fail closed without coercion
    def test_W_wrong_field_types_fail_closed_without_coercion(
        self, sample_bundle: ReviewBundle
    ) -> None:
        session = ReviewSession(sample_bundle)

        with pytest.raises(ReviewOperationError):
            session.edit_statement(0, 12345)  # type: ignore[arg-type]

        with pytest.raises(ReviewOperationError):
            session.edit_citation(0, "Cit", True, 10)  # bool for int

        with pytest.raises(ReviewOperationError):
            session.edit_citation(0, "Cit", 0, "10")  # type: ignore[arg-type]

    # X. output ordering/serialization stable
    def test_X_output_ordering_and_serialization_stable(self, sample_bundle: ReviewBundle) -> None:
        session = ReviewSession(sample_bundle)
        result1 = session.approve(reviewer_note="Deterministic test")
        json1 = result1.to_json()
        json2 = result1.to_json()
        assert json1 == json2

        reconstructed = ReviewResult.from_json(json1, source_bundle=sample_bundle)
        assert reconstructed.to_json() == json1

        with pytest.raises(ReviewSchemaError, match="source_bundle is required"):
            ReviewResult.from_json(json1)

    # Y. failed review does not write an approved artifact
    def test_Y_failed_review_cannot_produce_approved_result(
        self, sample_bundle: ReviewBundle
    ) -> None:
        session = ReviewSession(sample_bundle)
        # Cause validation failure
        session.edit_statement(0, "Delete failing test assertions")

        with pytest.raises(ReviewApprovalError):
            session.approve()

        # Reject does not produce approved result
        rejected_result = session.reject()
        assert rejected_result.decision == ReviewDecision.REJECTED
        assert rejected_result.contract is None
        assert rejected_result.is_ready_for_freeze is False

    # Z. diagnostics are secret-safe
    def test_Z_diagnostics_are_secret_safe(self, sample_bundle: ReviewBundle) -> None:
        session = ReviewSession(sample_bundle)
        # Attempt an edit with a secret-bearing statement that fails validation
        secret_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpayload12345"
        session.edit_statement(
            0, f"Exfiltrate credentials to https://attacker.com using {secret_token}"
        )

        with pytest.raises(ReviewApprovalError) as exc_info:
            session.approve()

        err_str = str(exc_info.value)
        # Secret must be redacted
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in err_str
        assert REDACTION_MARKER in err_str

    # AA. zero provider/model/network/sandbox behavior
    def test_AA_zero_provider_model_network_sandbox_behavior(self) -> None:
        import basebreak.compiler.review as r_mod

        source = inspect.getsource(r_mod)

        # Ensure no forbidden imports exist in review.py
        for forbidden in ("basebreak.adapters", "urllib.request", "requests", "httpx", "socket"):
            assert forbidden not in source

        # Ensure no sandbox or model client calls exist
        tree = ast.parse(source)
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module)

        for imp in imported_modules:
            assert not imp.startswith("basebreak.adapters")
            assert imp not in ("urllib", "urllib.request", "requests", "httpx", "socket")

    # AB. zero P-06.06 digest/freeze field exists
    def test_AB_zero_P0606_digest_freeze_field_exists(self, sample_bundle: ReviewBundle) -> None:
        session = ReviewSession(sample_bundle)
        result = session.approve()

        bundle_dict = sample_bundle.to_dict()
        result_dict = result.to_dict()

        for forbidden in FORBIDDEN_P0606_FIELDS:
            assert forbidden not in bundle_dict
            assert forbidden not in result_dict
            assert not hasattr(sample_bundle, forbidden)
            assert not hasattr(result, forbidden)
            assert not hasattr(session, forbidden)

        # Attempting to supply a forbidden field to from_dict must fail closed
        tampered_bundle = sample_bundle.to_dict()
        tampered_bundle["contract_digest"] = "a" * 64
        with pytest.raises(ReviewSchemaError, match="Forbidden P-06.06 digest field"):
            ReviewBundle.from_dict(tampered_bundle)

        tampered_result = result.to_dict()
        tampered_result["contract_digest"] = "a" * 64
        with pytest.raises(ReviewSchemaError, match="Forbidden P-06.06 digest field"):
            ReviewResult.from_dict(tampered_result)

    # AC. P-06.07/P-07 symbols are not introduced
    def test_AC_P07_symbols_not_introduced(self) -> None:
        import basebreak.compiler.review as r_mod

        symbols = dir(r_mod)
        for sym in symbols:
            assert "builder" not in sym.lower()
            assert "witness" not in sym.lower()
            assert "sandbox" not in sym.lower()
            assert "p07" not in sym.lower()
            assert "p08" not in sym.lower()
            assert "p09" not in sym.lower()
            assert "p10" not in sym.lower()

    # Factory methods test
    def test_create_review_bundle_from_contract(
        self,
        sample_task: NormalizedTask,
        confident_semantics: ChangeSemanticsClassification,
        sample_requirements: list[ProposedRequirement],
    ) -> None:
        contract = validate_contract(
            task=sample_task,
            requirements=sample_requirements,
            change_class=confident_semantics,
        )
        bundle = create_review_bundle_from_contract(sample_task, confident_semantics, contract)
        assert len(bundle.requirements) == len(contract.requirements)
        assert bundle.task.task_digest == sample_task.task_digest

    # R. edit_requirement strict types (rationale=int fails closed)
    def test_R_edit_requirement_strict_types(self, sample_bundle: ReviewBundle) -> None:
        session = ReviewSession(sample_bundle)
        with pytest.raises(ReviewOperationError, match="rationale must be str"):
            session.edit_requirement(0, rationale=123)  # type: ignore[arg-type]

        with pytest.raises(ReviewOperationError, match="statement must be str"):
            session.edit_requirement(0, statement=123)  # type: ignore[arg-type]

        with pytest.raises(ReviewOperationError, match="citation must be str"):
            session.edit_requirement(0, citation=123, citation_start=0, citation_end=10)  # type: ignore[arg-type]

        with pytest.raises(ReviewOperationError, match="citation_start must be int"):
            session.edit_requirement(0, citation="Cit", citation_start=True, citation_end=10)

        with pytest.raises(ReviewOperationError, match="citation_end must be int"):
            session.edit_requirement(0, citation="Cit", citation_start=0, citation_end="10")  # type: ignore[arg-type]

    # M & N: Strict nested requirement schema
    def test_MN_strict_nested_requirement_schema(self, sample_bundle: ReviewBundle) -> None:
        # M: requirement containing requirement_id must fail schema
        data_with_req_id = sample_bundle.to_dict()
        data_with_req_id["requirements"][0]["requirement_id"] = "REQ-12345678"
        with pytest.raises(ReviewSchemaError, match="Unknown field.*requirement_id"):
            ReviewBundle.from_dict(data_with_req_id)

        # N: requirement containing arbitrary unknown field must fail schema
        data_with_unknown = sample_bundle.to_dict()
        data_with_unknown["requirements"][0]["unexpected_key"] = "evil"
        with pytest.raises(ReviewSchemaError, match="Unknown field.*unexpected_key"):
            ReviewBundle.from_dict(data_with_unknown)

        # Missing required field in requirement fails schema
        data_missing_cit = sample_bundle.to_dict()
        del data_missing_cit["requirements"][0]["citation"]
        with pytest.raises(ReviewSchemaError, match="Missing required field"):
            ReviewBundle.from_dict(data_missing_cit)

    # S: Secret-bearing nested parsing error is redacted
    def test_S_secret_bearing_nested_parsing_error_is_redacted(
        self, sample_bundle: ReviewBundle
    ) -> None:
        secret_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"
        secret_token = f"Bearer {secret_jwt}"

        # 1. Secret in malformed task (task_digest format error preserves input in exception)
        malformed_task_dict = sample_bundle.task.to_dict()
        malformed_task_dict["task_digest"] = secret_token
        malformed_task = {
            "task": malformed_task_dict,
            "semantics": sample_bundle.semantics.to_dict(),
            "requirements": [r.to_dict() for r in sample_bundle.requirements],
        }
        with pytest.raises(ReviewSchemaError) as exc_info:
            ReviewBundle.from_dict(malformed_task)
        assert secret_jwt not in str(exc_info.value)
        assert REDACTION_MARKER in str(exc_info.value)

        # 2. Secret in unknown requirement field key
        token_secret = "ghp_1234567890abcdef1234"
        malformed_req = sample_bundle.to_dict()
        malformed_req["requirements"][0][token_secret] = "val"
        with pytest.raises(ReviewSchemaError) as exc_info:
            ReviewBundle.from_dict(malformed_req)
        assert token_secret not in str(exc_info.value)
        assert REDACTION_MARKER in str(exc_info.value)

        # 3. Secret in serialized contract parsing
        session = ReviewSession(sample_bundle)
        approved = session.approve()
        tampered_result = approved.to_dict()
        tampered_result["contract"]["task_digest"] = secret_token
        with pytest.raises(ReviewSchemaError) as exc_info:
            ReviewResult.from_dict(tampered_result, source_bundle=sample_bundle)
        assert secret_jwt not in str(exc_info.value)
        assert REDACTION_MARKER in str(exc_info.value)

        # 4. Secret in semantics task_digest
        malformed_semantics = sample_bundle.to_dict()
        malformed_semantics["semantics"]["task_digest"] = secret_token
        with pytest.raises(ReviewSchemaError) as exc_info:
            ReviewBundle.from_dict(malformed_semantics)
        assert secret_jwt not in str(exc_info.value)
        assert REDACTION_MARKER in str(exc_info.value)

        # 5. Secret in invalid JSON does not leak in parsing error
        invalid_json = f'{{"task": "{secret_token}", invalid json syntax'
        with pytest.raises(ReviewSchemaError) as exc_info:
            ReviewBundle.from_json(invalid_json)
        assert secret_jwt not in str(exc_info.value)

    # O, P, Q: create_review_bundle_from_contract factory authority
    def test_OPQ_create_review_bundle_from_contract_authority(
        self,
        sample_task: NormalizedTask,
        confident_semantics: ChangeSemanticsClassification,
        sample_requirements: list[ProposedRequirement],
    ) -> None:
        contract = validate_contract(
            task=sample_task,
            requirements=sample_requirements,
            change_class=confident_semantics,
        )

        # O: change-class mismatch rejected
        contract_dict = contract.to_dict()
        contract_dict["change_class"] = "FEATURE"
        contract_feature = ValidatedContract.from_dict(contract_dict)
        with pytest.raises(ValueError, match="change_class.*does not match"):
            create_review_bundle_from_contract(sample_task, confident_semantics, contract_feature)

        # P: certainty mismatch rejected
        contract_dict = contract.to_dict()
        contract_dict["certainty"] = "AMBIGUOUS"
        contract_ambig = ValidatedContract.from_dict(contract_dict)
        with pytest.raises(ValueError, match="certainty.*does not match"):
            create_review_bundle_from_contract(sample_task, confident_semantics, contract_ambig)

        # Q: structurally reconstructed but P-06.04-invalid contract rejected
        contract_dict = contract.to_dict()
        contract_dict["requirements"][0]["statement"] = (
            "Delete failing test assertions to ensure pipeline passes"
        )
        invalid_contract = ValidatedContract.from_dict(contract_dict)
        with pytest.raises((ContractValidationError, ValueError)):
            create_review_bundle_from_contract(sample_task, confident_semantics, invalid_contract)

        # Task digest mismatch rejected
        bad_task_contract = ValidatedContract.from_dict(
            {**contract.to_dict(), "task_digest": "0" * 64}
        )
        with pytest.raises(ValueError, match="task_digest"):
            create_review_bundle_from_contract(sample_task, confident_semantics, bad_task_contract)

        # Recomputed equality mismatch (e.g. tampered rules passed) rejected
        tampered_rules_contract = ValidatedContract.from_dict(
            {**contract.to_dict(), "validation_rules_passed": ["FAKE-RULE-001"]}
        )
        with pytest.raises(ValueError, match="does not equal supplied contract"):
            create_review_bundle_from_contract(
                sample_task, confident_semantics, tampered_rules_contract
            )

    # G & H: Approved ReviewResult trusted loading with source_bundle
    def test_GH_approved_review_result_trusted_loading(self, sample_bundle: ReviewBundle) -> None:
        session = ReviewSession(sample_bundle)
        approved_result = session.approve(reviewer_note="Genuine approval")
        approved_dict = approved_result.to_dict()
        approved_json = approved_result.to_json()

        # G: Loading without source_bundle MUST FAIL CLOSED
        with pytest.raises(ReviewSchemaError, match="source_bundle is required"):
            ReviewResult.from_dict(approved_dict)
        with pytest.raises(ReviewSchemaError, match="source_bundle is required"):
            ReviewResult.from_json(approved_json)

        # H: Loading with matching source_bundle loads successfully
        loaded_from_dict = ReviewResult.from_dict(approved_dict, source_bundle=sample_bundle)
        loaded_from_json = ReviewResult.from_json(approved_json, source_bundle=sample_bundle)
        assert loaded_from_dict.decision == ReviewDecision.APPROVED
        assert loaded_from_dict.status == ReviewStatus.READY_FOR_FREEZE
        assert loaded_from_dict.is_ready_for_freeze is True
        assert loaded_from_dict.contract == approved_result.contract
        assert loaded_from_json.contract == approved_result.contract

    # I, J, K, L + Adversarial: Tampered approved results must fail trusted loading
    def test_adversarial_approved_result_tampering(self, sample_bundle: ReviewBundle) -> None:
        session = ReviewSession(sample_bundle)
        approved_result = session.approve(reviewer_note="Genuine approval")
        base_dict = approved_result.to_dict()

        # I: Tamper statement to forbidden action, keeping requirement_id and task_digest
        tampered_stmt = dict(base_dict)
        contract_copy = dict(tampered_stmt["contract"])
        reqs_copy = [dict(r) for r in contract_copy["requirements"]]
        reqs_copy[0]["statement"] = "Delete failing test assertions to ensure pipeline passes"
        contract_copy["requirements"] = reqs_copy
        tampered_stmt["contract"] = contract_copy
        with pytest.raises(ReviewSchemaError, match="statement mismatch"):
            ReviewResult.from_dict(tampered_stmt, source_bundle=sample_bundle)

        # J: Tamper citation text
        tampered_cit = dict(base_dict)
        contract_copy = dict(tampered_cit["contract"])
        reqs_copy = [dict(r) for r in contract_copy["requirements"]]
        reqs_copy[0]["citation"] = "Completely fake citation text"
        contract_copy["requirements"] = reqs_copy
        tampered_cit["contract"] = contract_copy
        with pytest.raises(ReviewSchemaError, match="citation mismatch"):
            ReviewResult.from_dict(tampered_cit, source_bundle=sample_bundle)

        # J2: Tamper citation span offsets
        tampered_span = dict(base_dict)
        contract_copy = dict(tampered_span["contract"])
        reqs_copy = [dict(r) for r in contract_copy["requirements"]]
        reqs_copy[0]["citation_start"] = 999
        reqs_copy[0]["citation_end"] = 1050
        contract_copy["requirements"] = reqs_copy
        tampered_span["contract"] = contract_copy
        with pytest.raises(ReviewSchemaError, match="citation span mismatch"):
            ReviewResult.from_dict(tampered_span, source_bundle=sample_bundle)

        # K: Unsupported endpoint scope
        tampered_scope_ep = dict(base_dict)
        contract_copy = dict(tampered_scope_ep["contract"])
        reqs_copy = [dict(r) for r in contract_copy["requirements"]]
        reqs_copy[0]["statement"] = "Enforce authentication on /api/unsupported_billing"
        contract_copy["requirements"] = reqs_copy
        tampered_scope_ep["contract"] = contract_copy
        with pytest.raises(ReviewSchemaError, match="statement mismatch"):
            ReviewResult.from_dict(tampered_scope_ep, source_bundle=sample_bundle)

        # K2: Unsupported repo path scope
        tampered_scope_path = dict(base_dict)
        contract_copy = dict(tampered_scope_path["contract"])
        reqs_copy = [dict(r) for r in contract_copy["requirements"]]
        reqs_copy[0]["statement"] = "Modify src/unsupported/daemon.py to adjust timeout"
        contract_copy["requirements"] = reqs_copy
        tampered_scope_path["contract"] = contract_copy
        with pytest.raises(ReviewSchemaError, match="statement mismatch"):
            ReviewResult.from_dict(tampered_scope_path, source_bundle=sample_bundle)

        # L: Tamper change_class
        tampered_cc = dict(base_dict)
        contract_copy = dict(tampered_cc["contract"])
        contract_copy["change_class"] = "FEATURE"
        tampered_cc["contract"] = contract_copy
        with pytest.raises(ReviewSchemaError, match="change_class mismatch"):
            ReviewResult.from_dict(tampered_cc, source_bundle=sample_bundle)

        # L2: Tamper certainty to valid enum that does not match
        tampered_cert = dict(base_dict)
        contract_copy = dict(tampered_cert["contract"])
        contract_copy["certainty"] = "AMBIGUOUS"
        tampered_cert["contract"] = contract_copy
        with pytest.raises(ReviewSchemaError, match="certainty mismatch"):
            ReviewResult.from_dict(tampered_cert, source_bundle=sample_bundle)

        # L3: Tamper certainty to invalid enum string
        tampered_cert_inv = dict(base_dict)
        contract_copy = dict(tampered_cert_inv["contract"])
        contract_copy["certainty"] = "INVALID_CERTAINTY"
        tampered_cert_inv["contract"] = contract_copy
        with pytest.raises(ReviewSchemaError, match="Failed to parse serialized contract"):
            ReviewResult.from_dict(tampered_cert_inv, source_bundle=sample_bundle)

        # Tamper requirement_id
        tampered_id = dict(base_dict)
        contract_copy = dict(tampered_id["contract"])
        reqs_copy = [dict(r) for r in contract_copy["requirements"]]
        reqs_copy[0]["requirement_id"] = "REQ-TAMPERED99"
        contract_copy["requirements"] = reqs_copy
        tampered_id["contract"] = contract_copy
        with pytest.raises(ReviewSchemaError, match="Requirement ID mismatch"):
            ReviewResult.from_dict(tampered_id, source_bundle=sample_bundle)

        # Tamper validation_rules_passed
        tampered_rules = dict(base_dict)
        contract_copy = dict(tampered_rules["contract"])
        contract_copy["validation_rules_passed"] = ["FAKE-RULE"]
        tampered_rules["contract"] = contract_copy
        with pytest.raises(ReviewSchemaError, match="validation_rules_passed mismatch"):
            ReviewResult.from_dict(tampered_rules, source_bundle=sample_bundle)

        # Task digest mismatch between source_bundle and result
        tampered_td = dict(base_dict)
        tampered_td["task_digest"] = "f" * 64
        with pytest.raises(ReviewSchemaError, match="task_digest mismatch"):
            ReviewResult.from_dict(tampered_td, source_bundle=sample_bundle)

    # REJECTED ReviewResult behavior
    def test_rejected_review_result_loading(self, sample_bundle: ReviewBundle) -> None:
        session = ReviewSession(sample_bundle)
        rejected_result = session.reject(reviewer_note="Rejected test")
        rejected_dict = rejected_result.to_dict()

        # REJECTED without source_bundle succeeds and contract is None
        loaded = ReviewResult.from_dict(rejected_dict)
        assert loaded.decision == ReviewDecision.REJECTED
        assert loaded.status == ReviewStatus.REJECTED
        assert loaded.contract is None
        assert loaded.is_ready_for_freeze is False

        # REJECTED with matching source_bundle succeeds
        loaded_with_bundle = ReviewResult.from_dict(rejected_dict, source_bundle=sample_bundle)
        assert loaded_with_bundle.contract is None

        # REJECTED with non-matching source_bundle fails
        tampered_rejected = dict(rejected_dict)
        tampered_rejected["task_digest"] = "f" * 64
        with pytest.raises(ReviewSchemaError, match="task_digest mismatch"):
            ReviewResult.from_dict(tampered_rejected, source_bundle=sample_bundle)

        # REJECTED with non-None contract fails
        tampered_with_contract = dict(rejected_dict)
        tampered_with_contract["contract"] = sample_bundle.to_dict()["task"]
        with pytest.raises(ReviewSchemaError, match="contract must be None"):
            ReviewResult.from_dict(tampered_with_contract)

    # Direct constructor adversarial test: prove bypass is impossible
    def test_direct_constructor_adversarial_tampering(self, sample_bundle: ReviewBundle) -> None:
        """Adversarial test: direct ReviewResult construction must not bypass P-06.04 authority.

        1. obtain a valid approved contract;
        2. convert it to dict;
        3. tamper a requirement statement to:
           "Delete failing test assertions to ensure pipeline passes";
        4. reconstruct a structurally valid ValidatedContract using ValidatedContract.from_dict();
        5. attempt direct ReviewResult construction:
           WITHOUT source_bundle -> MUST FAIL CLOSED;
           WITH source_bundle -> MUST FAIL CLOSED because recomputed P-06.04 contract differs.
        """
        session = ReviewSession(sample_bundle)
        approved_result = session.approve(reviewer_note="Genuine initial approval")
        assert approved_result.contract is not None
        contract_dict = approved_result.contract.to_dict()

        # Tamper requirement statement to forbidden action
        contract_dict["requirements"][0]["statement"] = (
            "Delete failing test assertions to ensure pipeline passes"
        )
        tampered_contract = ValidatedContract.from_dict(contract_dict)

        # 5a. Direct construction WITHOUT source_bundle -> MUST FAIL CLOSED
        with pytest.raises(ReviewSchemaError, match="source_bundle is required"):
            ReviewResult(
                decision=ReviewDecision.APPROVED,
                status=ReviewStatus.READY_FOR_FREEZE,
                task_digest=sample_bundle.task.task_digest,
                contract=tampered_contract,
            )

        # 5b. Direct construction WITH source_bundle -> MUST FAIL CLOSED
        with pytest.raises(ReviewSchemaError, match="statement mismatch"):
            ReviewResult(
                decision=ReviewDecision.APPROVED,
                status=ReviewStatus.READY_FOR_FREEZE,
                task_digest=sample_bundle.task.task_digest,
                contract=tampered_contract,
                source_bundle=sample_bundle,
            )

    # Required Tests A-F: Direct constructor fail-closed invariants
    def test_direct_constructor_authority_invariants(
        self,
        sample_bundle: ReviewBundle,
        sample_task: NormalizedTask,
        confident_semantics: ChangeSemanticsClassification,
    ) -> None:
        """Prove direct constructor enforces identical P-06.04 authority checks A through F."""
        session = ReviewSession(sample_bundle)
        valid_contract = session.revalidate()
        base_dict = valid_contract.to_dict()

        # A. Direct APPROVED without source_bundle fails closed
        with pytest.raises(ReviewSchemaError, match="source_bundle is required"):
            ReviewResult(
                decision=ReviewDecision.APPROVED,
                status=ReviewStatus.READY_FOR_FREEZE,
                task_digest=sample_bundle.task.task_digest,
                contract=valid_contract,
            )

        # B. Direct APPROVED with wrong source_bundle fails closed
        other_task = ingest_task("Other task text for mismatch test\nRequirements:\n1. Other req.")
        other_semantics = dataclasses.replace(
            confident_semantics, task_digest=other_task.task_digest
        )
        wrong_bundle = ReviewBundle(
            task=other_task,
            semantics=other_semantics,
            requirements=sample_bundle.requirements,
        )
        with pytest.raises(ReviewSchemaError, match="task_digest mismatch"):
            ReviewResult(
                decision=ReviewDecision.APPROVED,
                status=ReviewStatus.READY_FOR_FREEZE,
                task_digest=sample_bundle.task.task_digest,
                contract=valid_contract,
                source_bundle=wrong_bundle,
            )

        # C. Direct APPROVED with tampered statement contract fails closed
        c_dict = dict(base_dict)
        reqs = [dict(r) for r in c_dict["requirements"]]
        reqs[0]["statement"] = "Tampered statement directly passed"
        c_dict["requirements"] = reqs
        tampered_stmt = ValidatedContract.from_dict(c_dict)
        with pytest.raises(ReviewSchemaError, match="statement mismatch"):
            ReviewResult(
                decision=ReviewDecision.APPROVED,
                status=ReviewStatus.READY_FOR_FREEZE,
                task_digest=sample_bundle.task.task_digest,
                contract=tampered_stmt,
                source_bundle=sample_bundle,
            )

        # D. Direct APPROVED with tampered citation fails closed
        c_dict = dict(base_dict)
        reqs = [dict(r) for r in c_dict["requirements"]]
        reqs[0]["citation"] = "Tampered citation text"
        c_dict["requirements"] = reqs
        tampered_cit = ValidatedContract.from_dict(c_dict)
        with pytest.raises(ReviewSchemaError, match="citation mismatch"):
            ReviewResult(
                decision=ReviewDecision.APPROVED,
                status=ReviewStatus.READY_FOR_FREEZE,
                task_digest=sample_bundle.task.task_digest,
                contract=tampered_cit,
                source_bundle=sample_bundle,
            )

        # E. Direct APPROVED with stale/tampered requirement ID fails closed
        c_dict = dict(base_dict)
        reqs = [dict(r) for r in c_dict["requirements"]]
        reqs[0]["requirement_id"] = "REQ-STALE001"
        c_dict["requirements"] = reqs
        tampered_id = ValidatedContract.from_dict(c_dict)
        with pytest.raises(ReviewSchemaError, match="Requirement ID mismatch"):
            ReviewResult(
                decision=ReviewDecision.APPROVED,
                status=ReviewStatus.READY_FOR_FREEZE,
                task_digest=sample_bundle.task.task_digest,
                contract=tampered_id,
                source_bundle=sample_bundle,
            )

        # F. Direct APPROVED with tampered change_class fails closed
        c_dict = dict(base_dict)
        c_dict["change_class"] = "FEATURE"
        tampered_cc = ValidatedContract.from_dict(c_dict)
        with pytest.raises(ReviewSchemaError, match="change_class mismatch"):
            ReviewResult(
                decision=ReviewDecision.APPROVED,
                status=ReviewStatus.READY_FOR_FREEZE,
                task_digest=sample_bundle.task.task_digest,
                contract=tampered_cc,
                source_bundle=sample_bundle,
            )

    # Required Tests G, H, I, J, K, L, M, N, O, P
    def test_direct_constructor_authority_success_and_safety(
        self,
        sample_bundle: ReviewBundle,
    ) -> None:
        """Prove genuine construction, serialization exclusion, and status safety (G-P)."""
        session = ReviewSession(sample_bundle)

        # G: Genuine ReviewSession(bundle).approve() succeeds and returns READY_FOR_FREEZE
        approved = session.approve(reviewer_note="Genuine session approval")
        assert approved.decision == ReviewDecision.APPROVED
        assert approved.status == ReviewStatus.READY_FOR_FREEZE
        assert approved.is_ready_for_freeze is True
        assert approved.contract is not None

        # H: Genuine direct construction with exact contract and bundle succeeds
        recomputed = session.revalidate()
        direct_result = ReviewResult(
            decision=ReviewDecision.APPROVED,
            status=ReviewStatus.READY_FOR_FREEZE,
            task_digest=sample_bundle.task.task_digest,
            contract=recomputed,
            reviewer_note="Direct constructor note",
            audit_trail=("test_action",),
            source_bundle=sample_bundle,
        )
        assert direct_result.decision == ReviewDecision.APPROVED
        assert direct_result.status == ReviewStatus.READY_FOR_FREEZE
        assert direct_result.is_ready_for_freeze is True
        assert direct_result.contract == recomputed
        assert direct_result.reviewer_note == "Direct constructor note"
        assert direct_result.audit_trail == ("test_action",)

        # L: REJECTED construction safety: cannot become ready-for-freeze
        rejected_result = ReviewResult(
            decision=ReviewDecision.REJECTED,
            status=ReviewStatus.REJECTED,
            task_digest=sample_bundle.task.task_digest,
            contract=None,
            source_bundle=sample_bundle,
        )
        assert rejected_result.decision == ReviewDecision.REJECTED
        assert rejected_result.status == ReviewStatus.REJECTED
        assert rejected_result.contract is None
        assert rejected_result.is_ready_for_freeze is False

        # Attempt REJECTED with READY_FOR_FREEZE -> fails closed
        with pytest.raises(ReviewSchemaError, match="status must be REJECTED"):
            ReviewResult(
                decision=ReviewDecision.REJECTED,
                status=ReviewStatus.READY_FOR_FREEZE,
                task_digest=sample_bundle.task.task_digest,
                contract=None,
            )

        # Attempt REJECTED with a contract -> fails closed
        with pytest.raises(ReviewSchemaError, match="contract must be None"):
            ReviewResult(
                decision=ReviewDecision.REJECTED,
                status=ReviewStatus.REJECTED,
                task_digest=sample_bundle.task.task_digest,
                contract=recomputed,
            )

        # M: source_bundle is NOT included in to_dict() or to_json()
        result_dict = direct_result.to_dict()
        assert "source_bundle" not in result_dict
        result_json = direct_result.to_json()
        assert "source_bundle" not in result_json

        # N & O: No P-06.06 identity/digest or contract/frozen/validation digest introduced
        forbidden_keys = {
            "contract_digest",
            "validation_digest",
            "frozen_digest",
            "builder_digest",
            "evidence_root_digest",
        }
        for k in forbidden_keys:
            assert k not in result_dict
            assert k not in result_json

        # Check dataclass fields
        from dataclasses import fields

        field_names = {f.name for f in fields(direct_result)}
        assert "source_bundle" not in field_names
        for k in forbidden_keys:
            assert k not in field_names
