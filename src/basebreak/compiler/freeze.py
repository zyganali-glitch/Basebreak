"""Deterministic verification contract freezing and digest binding.

P-06.06: Freeze contract digest before Builder execution under the Basebreak
causal verification authority model.

Authority Model & Invariants:
1. P-06.06 creates the immutable contract root that exists BEFORE Builder execution.
   Thesis: The Builder must never be able to silently change what it is supposed to prove.
2. The frozen contract root binds:
   human-approved contract -> deterministic acceptance requirements -> immutable contract digest.
3. The only valid authority source for freezing is a genuine ReviewResult with:
   - decision == ReviewDecision.APPROVED
   - status == ReviewStatus.READY_FOR_FREEZE
   - is_ready_for_freeze == True
   - contract is not None
4. Constructor authority invariant:
   All construction paths capable of producing an authoritative FrozenContract
   must bind back to the APPROVED ReviewResult (via source_review InitVar).
   Direct construction with missing source_review, tampered payload, or non-matching
   ReviewResult fails closed.
5. Canonical requirement order:
   Requirements are strictly ordered by requirement_id.
6. Canonical identity bytes:
   Explicit deterministic JSON serialization (sorted keys, compact delimiters, UTF-8).
7. SHA-256 contract digest:
   Exactly 64 lowercase hexadecimal characters computed over the identity payload
   excluding the contract_digest itself.
8. Immutability:
   FrozenContract and FrozenRequirement are immutable dataclasses (frozen=True, slots=True).
   Zero mutation methods.
9. Zero model calls, zero provider imports, zero sandbox calls, zero network calls.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import InitVar, dataclass
from typing import Any

from basebreak.compiler.review import (
    ReviewDecision,
    ReviewResult,
    ReviewStatus,
)
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeClass,
)
from basebreak.compiler.validator import (
    MAX_CITATION_LENGTH,
    MAX_RATIONALE_LENGTH,
    MAX_REQUIREMENT_ID_LENGTH,
    MAX_STATEMENT_LENGTH,
    ValidatedContract,
    ValidatedRequirement,
)
from basebreak.security.secret_policy import redact_log_text

# Canonical schema version for frozen contracts
FROZEN_CONTRACT_SCHEMA_VERSION: str = "1.0.0"

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_REQUIREMENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]+$")


class FrozenContractError(Exception):
    """Base exception for frozen contract errors."""


class FrozenContractSchemaError(FrozenContractError):
    """Raised when frozen contract payload or schema is malformed or invalid."""


class FrozenContractDigestMismatchError(FrozenContractError):
    """Raised when declared contract_digest does not match recomputed SHA-256 digest."""


def canonical_contract_bytes(payload: Mapping[str, Any]) -> bytes:
    """Encode identity payload as canonical deterministic UTF-8 JSON bytes.

    Guarantees:
    - Alphabetically sorted dictionary keys (sort_keys=True)
    - Compact delimiters without whitespace (separators=(",", ":"))
    - Unescaped UTF-8 characters (ensure_ascii=False)
    - UTF-8 binary encoding
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_contract_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest (64 lowercase hex characters).

    The payload must be the identity payload (without contract_digest).
    """
    raw_bytes = canonical_contract_bytes(payload)
    return hashlib.sha256(raw_bytes).hexdigest()


def build_canonical_identity_payload(
    *,
    schema_version: str,
    task_digest: str,
    change_class: ChangeClass | str,
    certainty: CertaintyLevel | str,
    requirements: Sequence[FrozenRequirement | ValidatedRequirement | Mapping[str, Any]],
) -> dict[str, Any]:
    """Build deterministic identity payload dictionary for cryptographic hashing.

    Orders requirements strictly by requirement_id and formats each requirement
    with its bound identity fields.
    """
    cc_val = change_class.value if isinstance(change_class, ChangeClass) else str(change_class)
    cert_val = certainty.value if isinstance(certainty, CertaintyLevel) else str(certainty)

    raw_req_dicts: list[dict[str, Any]] = []
    for r in requirements:
        if isinstance(r, (FrozenRequirement, ValidatedRequirement)):
            raw_req_dicts.append(
                {
                    "citation": r.citation,
                    "citation_end": r.citation_end,
                    "citation_start": r.citation_start,
                    "rationale": r.rationale,
                    "requirement_id": r.requirement_id,
                    "statement": r.statement,
                }
            )
        elif isinstance(r, Mapping):
            raw_req_dicts.append(
                {
                    "citation": r["citation"],
                    "citation_end": r["citation_end"],
                    "citation_start": r["citation_start"],
                    "rationale": r.get("rationale", ""),
                    "requirement_id": r["requirement_id"],
                    "statement": r["statement"],
                }
            )
        else:
            raise TypeError(f"Unsupported requirement type: {type(r).__name__}")

    # Canonical sorting strictly by requirement_id
    sorted_reqs = sorted(raw_req_dicts, key=lambda req: req["requirement_id"])

    return {
        "certainty": cert_val,
        "change_class": cc_val,
        "requirements": sorted_reqs,
        "schema_version": str(schema_version),
        "task_digest": str(task_digest),
    }


@dataclass(frozen=True, slots=True)
class FrozenRequirement:
    """An immutable, frozen atomic acceptance requirement.

    Attributes:
        requirement_id: Deterministic, non-empty identifier (e.g. REQ-A1B2C3D4).
        statement: Verifiable requirement statement bounded by size.
        citation: Exact verbatim substring from normalized task text.
        citation_start: 0-indexed character start offset in normalized task text.
        citation_end: 0-indexed character end offset in normalized task text.
        rationale: Brief justification or explanation.
    """

    requirement_id: str
    statement: str
    citation: str
    citation_start: int
    citation_end: int
    rationale: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.requirement_id, str):
            raise TypeError(f"requirement_id must be str, got {type(self.requirement_id).__name__}")
        req_id = self.requirement_id.strip()
        if not req_id:
            raise FrozenContractSchemaError("requirement_id must not be empty or whitespace-only")
        if req_id != self.requirement_id:
            raise FrozenContractSchemaError(
                "requirement_id must not have leading or trailing whitespace"
            )
        if len(self.requirement_id) > MAX_REQUIREMENT_ID_LENGTH:
            raise FrozenContractSchemaError(
                f"requirement_id exceeds maximum length "
                f"({len(self.requirement_id)} > {MAX_REQUIREMENT_ID_LENGTH})"
            )
        if not _REQUIREMENT_ID_PATTERN.match(self.requirement_id):
            raise FrozenContractSchemaError(
                f"requirement_id {self.requirement_id!r} does not match allowed pattern"
            )

        if not isinstance(self.statement, str):
            raise TypeError(f"statement must be str, got {type(self.statement).__name__}")
        stmt = self.statement.strip()
        if not stmt:
            raise FrozenContractSchemaError("statement must not be empty or whitespace-only")
        if stmt != self.statement:
            object.__setattr__(self, "statement", stmt)
        if len(self.statement) > MAX_STATEMENT_LENGTH:
            raise FrozenContractSchemaError(
                f"statement length exceeds maximum allowed "
                f"({len(self.statement)} > {MAX_STATEMENT_LENGTH})"
            )

        if not isinstance(self.citation, str):
            raise TypeError(f"citation must be str, got {type(self.citation).__name__}")
        cit = self.citation.strip()
        if not cit:
            raise FrozenContractSchemaError("citation must not be empty or whitespace-only")
        if len(self.citation) > MAX_CITATION_LENGTH:
            raise FrozenContractSchemaError(
                f"citation length exceeds maximum allowed "
                f"({len(self.citation)} > {MAX_CITATION_LENGTH})"
            )

        if isinstance(self.citation_start, bool) or not isinstance(self.citation_start, int):
            raise TypeError(
                f"citation_start must be int (not bool), got {type(self.citation_start).__name__}"
            )
        if isinstance(self.citation_end, bool) or not isinstance(self.citation_end, int):
            raise TypeError(
                f"citation_end must be int (not bool), got {type(self.citation_end).__name__}"
            )
        if self.citation_start < 0 or self.citation_end < self.citation_start:
            raise FrozenContractSchemaError(
                f"Invalid citation span: [{self.citation_start}:{self.citation_end}]"
            )

        if not isinstance(self.rationale, str):
            raise TypeError(f"rationale must be str, got {type(self.rationale).__name__}")
        if len(self.rationale) > MAX_RATIONALE_LENGTH:
            raise FrozenContractSchemaError(
                f"rationale length exceeds maximum allowed "
                f"({len(self.rationale)} > {MAX_RATIONALE_LENGTH})"
            )

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary representation."""
        return {
            "citation": self.citation,
            "citation_end": self.citation_end,
            "citation_start": self.citation_start,
            "rationale": self.rationale,
            "requirement_id": self.requirement_id,
            "statement": self.statement,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> FrozenRequirement:
        """Construct from dictionary with strict schema validation."""
        if not isinstance(data, Mapping):
            raise TypeError(f"Expected mapping for FrozenRequirement, got {type(data).__name__}")
        required = {"requirement_id", "statement", "citation", "citation_start", "citation_end"}
        missing = required - set(data.keys())
        if missing:
            raise FrozenContractSchemaError(
                f"Missing required fields for FrozenRequirement: {sorted(missing)}"
            )
        unknown = set(data.keys()) - (required | {"rationale"})
        if unknown:
            safe_unknown = redact_log_text(str(sorted(unknown)))
            raise FrozenContractSchemaError(f"Unknown fields in FrozenRequirement: {safe_unknown}")

        req_id = data["requirement_id"]
        if not isinstance(req_id, str):
            raise TypeError(f"requirement_id must be str, got {type(req_id).__name__}")
        stmt = data["statement"]
        if not isinstance(stmt, str):
            raise TypeError(f"statement must be str, got {type(stmt).__name__}")
        cit = data["citation"]
        if not isinstance(cit, str):
            raise TypeError(f"citation must be str, got {type(cit).__name__}")
        c_start = data["citation_start"]
        if isinstance(c_start, bool) or not isinstance(c_start, int):
            raise TypeError(f"citation_start must be int (not bool), got {type(c_start).__name__}")
        c_end = data["citation_end"]
        if isinstance(c_end, bool) or not isinstance(c_end, int):
            raise TypeError(f"citation_end must be int (not bool), got {type(c_end).__name__}")
        rationale = data.get("rationale", "")
        if not isinstance(rationale, str):
            raise TypeError(f"rationale must be str, got {type(rationale).__name__}")

        return cls(
            requirement_id=req_id,
            statement=stmt,
            citation=cit,
            citation_start=c_start,
            citation_end=c_end,
            rationale=rationale,
        )

    @classmethod
    def from_validated_requirement(cls, req: ValidatedRequirement) -> FrozenRequirement:
        """Construct from authoritative ValidatedRequirement."""
        if not isinstance(req, ValidatedRequirement):
            raise TypeError(f"Expected ValidatedRequirement, got {type(req).__name__}")
        return cls(
            requirement_id=req.requirement_id,
            statement=req.statement,
            citation=req.citation,
            citation_start=req.citation_start,
            citation_end=req.citation_end,
            rationale=req.rationale,
        )


@dataclass(frozen=True, slots=True)
class FrozenContract:
    """An immutable, cryptographically sealed verification contract root.

    Establishes the immutable root link of the causal evidence chain:
    requirement -> frozen contract digest -> witness digest -> execution evidence.

    Constructor Authority:
    Every construction path MUST supply an authoritative APPROVED ReviewResult
    as `source_review`. Direct construction with missing source_review, tampered payload,
    or non-matching ReviewResult fails closed.
    """

    schema_version: str
    contract_digest: str
    task_digest: str
    change_class: ChangeClass
    certainty: CertaintyLevel
    requirements: tuple[FrozenRequirement, ...]
    validation_rules_passed: tuple[str, ...] = ()
    source_review: InitVar[ReviewResult | None] = None

    def __post_init__(self, source_review: ReviewResult | None = None) -> None:
        # 1. Authority source check: source_review is strictly required
        if source_review is None:
            raise FrozenContractSchemaError(
                "source_review (ReviewResult) is mandatory "
                "to construct an authoritative FrozenContract"
            )
        if not isinstance(source_review, ReviewResult):
            raise TypeError(
                f"source_review must be ReviewResult, got {type(source_review).__name__}"
            )
        if source_review.decision != ReviewDecision.APPROVED:
            raise FrozenContractSchemaError(
                f"source_review must be APPROVED, got decision={source_review.decision.value}"
            )
        if source_review.status != ReviewStatus.READY_FOR_FREEZE:
            raise FrozenContractSchemaError(
                f"source_review status must be READY_FOR_FREEZE, got {source_review.status.value}"
            )
        if not source_review.is_ready_for_freeze:
            raise FrozenContractSchemaError("source_review is_ready_for_freeze must be True")
        if source_review.contract is None:
            raise FrozenContractSchemaError("source_review.contract must not be None")

        ref_contract: ValidatedContract = source_review.contract

        # 2. Basic field types and patterns
        if not isinstance(self.schema_version, str) or not self.schema_version:
            raise TypeError(
                f"schema_version must be non-empty str, got {type(self.schema_version).__name__}"
            )
        if self.schema_version != FROZEN_CONTRACT_SCHEMA_VERSION:
            raise FrozenContractSchemaError(
                f"Unsupported schema_version: {self.schema_version!r}, "
                f"expected {FROZEN_CONTRACT_SCHEMA_VERSION!r}"
            )

        if not isinstance(self.contract_digest, str):
            raise TypeError(
                f"contract_digest must be str, got {type(self.contract_digest).__name__}"
            )
        if not _DIGEST_PATTERN.match(self.contract_digest):
            raise FrozenContractSchemaError(
                "contract_digest must be a 64-char lowercase hex string, "
                f"got {self.contract_digest!r}"
            )

        if not isinstance(self.task_digest, str):
            raise TypeError(f"task_digest must be str, got {type(self.task_digest).__name__}")
        if not _DIGEST_PATTERN.match(self.task_digest):
            raise FrozenContractSchemaError(
                f"task_digest must be a 64-char lowercase hex string, got {self.task_digest!r}"
            )

        # Convert / normalize enum values if necessary
        if isinstance(self.change_class, str):
            try:
                object.__setattr__(self, "change_class", ChangeClass(self.change_class))
            except ValueError:
                raise FrozenContractSchemaError(
                    f"Invalid ChangeClass: {self.change_class!r}"
                ) from None
        elif not isinstance(self.change_class, ChangeClass):
            raise TypeError(
                f"change_class must be ChangeClass, got {type(self.change_class).__name__}"
            )

        if isinstance(self.certainty, str):
            try:
                object.__setattr__(self, "certainty", CertaintyLevel(self.certainty))
            except ValueError:
                raise FrozenContractSchemaError(
                    f"Invalid CertaintyLevel: {self.certainty!r}"
                ) from None
        elif not isinstance(self.certainty, CertaintyLevel):
            raise TypeError(
                f"certainty must be CertaintyLevel, got {type(self.certainty).__name__}"
            )

        # Ensure requirements is tuple[FrozenRequirement, ...]
        if not isinstance(self.requirements, tuple):
            if isinstance(self.requirements, Sequence) and not isinstance(
                self.requirements, (str, bytes)
            ):
                object.__setattr__(self, "requirements", tuple(self.requirements))
            else:
                raise TypeError(
                    "requirements must be tuple of FrozenRequirement, "
                    f"got {type(self.requirements).__name__}"
                )

        for idx, r in enumerate(self.requirements):
            if not isinstance(r, FrozenRequirement):
                raise TypeError(
                    f"requirement at index {idx} must be FrozenRequirement, got {type(r).__name__}"
                )

        # Ensure requirements are in canonical requirement_id order
        req_ids = [r.requirement_id for r in self.requirements]
        if req_ids != sorted(req_ids):
            raise FrozenContractSchemaError(
                "requirements must be strictly in canonical order sorted by requirement_id"
            )

        # Check duplicates
        if len(req_ids) != len(set(req_ids)):
            raise FrozenContractSchemaError("Duplicate requirement_id detected in requirements")

        # Ensure validation_rules_passed is tuple[str, ...]
        if not isinstance(self.validation_rules_passed, tuple):
            if isinstance(self.validation_rules_passed, Sequence) and not isinstance(
                self.validation_rules_passed, (str, bytes)
            ):
                object.__setattr__(
                    self, "validation_rules_passed", tuple(self.validation_rules_passed)
                )
            else:
                raise TypeError("validation_rules_passed must be tuple of str")

        # 3. Exact field-by-field verification against authoritative source_review.contract
        if self.task_digest != ref_contract.task_digest:
            raise FrozenContractSchemaError(
                f"task_digest mismatch between FrozenContract ({self.task_digest}) "
                f"and source_review.contract ({ref_contract.task_digest})"
            )

        if self.change_class != ref_contract.change_class:
            raise FrozenContractSchemaError(
                f"change_class mismatch between FrozenContract ({self.change_class}) "
                f"and source_review.contract ({ref_contract.change_class})"
            )

        if self.certainty != ref_contract.certainty:
            raise FrozenContractSchemaError(
                f"certainty mismatch between FrozenContract ({self.certainty}) "
                f"and source_review.contract ({ref_contract.certainty})"
            )

        # Reference requirements sorted by requirement_id
        ref_sorted_reqs = tuple(sorted(ref_contract.requirements, key=lambda r: r.requirement_id))
        if len(self.requirements) != len(ref_sorted_reqs):
            raise FrozenContractSchemaError(
                f"Requirements count mismatch: {len(self.requirements)} != {len(ref_sorted_reqs)}"
            )

        for idx, (f_req, c_req) in enumerate(zip(self.requirements, ref_sorted_reqs)):
            if f_req.requirement_id != c_req.requirement_id:
                raise FrozenContractSchemaError(
                    f"Requirement ID mismatch at index {idx}: "
                    f"{f_req.requirement_id!r} != {c_req.requirement_id!r}"
                )
            if f_req.statement != c_req.statement:
                raise FrozenContractSchemaError(
                    f"Requirement statement mismatch for {f_req.requirement_id!r}"
                )
            if f_req.citation != c_req.citation:
                raise FrozenContractSchemaError(
                    f"Requirement citation mismatch for {f_req.requirement_id!r}"
                )
            if (
                f_req.citation_start != c_req.citation_start
                or f_req.citation_end != c_req.citation_end
            ):
                raise FrozenContractSchemaError(
                    f"Requirement citation span mismatch for {f_req.requirement_id!r}"
                )
            if f_req.rationale != c_req.rationale:
                raise FrozenContractSchemaError(
                    f"Requirement rationale mismatch for {f_req.requirement_id!r}"
                )

        if self.validation_rules_passed != ref_contract.validation_rules_passed:
            raise FrozenContractSchemaError(
                "validation_rules_passed mismatch between FrozenContract and source_review.contract"
            )

        # 4. Deterministic digest recomputation and verification
        expected_payload = self.to_identity_payload()
        recomputed_digest = compute_contract_digest(expected_payload)
        if self.contract_digest != recomputed_digest:
            raise FrozenContractDigestMismatchError(
                f"contract_digest mismatch: declared {self.contract_digest!r} "
                f"!= recomputed {recomputed_digest!r}"
            )

    @property
    def canonical_bytes(self) -> bytes:
        """Deterministic canonical UTF-8 bytes of the identity payload."""
        return canonical_contract_bytes(self.to_identity_payload())

    def to_identity_payload(self) -> dict[str, Any]:
        """Deterministic identity payload dictionary for cryptographic hashing.

        Strictly excludes contract_digest and non-identity metadata.
        """
        return build_canonical_identity_payload(
            schema_version=self.schema_version,
            task_digest=self.task_digest,
            change_class=self.change_class,
            certainty=self.certainty,
            requirements=self.requirements,
        )

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization with sorted keys."""
        return {
            "certainty": self.certainty.value,
            "change_class": self.change_class.value,
            "contract_digest": self.contract_digest,
            "requirements": [r.to_dict() for r in self.requirements],
            "schema_version": self.schema_version,
            "task_digest": self.task_digest,
            "validation_rules_passed": list(self.validation_rules_passed),
        }

    def to_json(self) -> str:
        """Deterministic JSON string serialization with 2-space indentation."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        source_review: ReviewResult,
    ) -> FrozenContract:
        """Construct FrozenContract from dictionary with strict schema and authority verification.

        Requires source_review: ReviewResult. Arbitrary self-consistent JSON without
        matching source_review is rejected.
        """
        if not isinstance(data, Mapping):
            raise TypeError(f"Expected mapping for FrozenContract, got {type(data).__name__}")
        if source_review is None:
            raise FrozenContractSchemaError("source_review is mandatory for trusted loading")
        if not isinstance(source_review, ReviewResult):
            raise TypeError(
                f"source_review must be ReviewResult, got {type(source_review).__name__}"
            )

        required_keys = {
            "schema_version",
            "contract_digest",
            "task_digest",
            "change_class",
            "certainty",
            "requirements",
        }
        missing = required_keys - set(data.keys())
        if missing:
            raise FrozenContractSchemaError(
                f"Missing required fields for FrozenContract: {sorted(missing)}"
            )

        allowed_keys = required_keys | {"validation_rules_passed"}
        unknown = set(data.keys()) - allowed_keys
        if unknown:
            safe_unknown = redact_log_text(str(sorted(unknown)))
            raise FrozenContractSchemaError(f"Unknown fields in FrozenContract: {safe_unknown}")

        raw_sv = data["schema_version"]
        if not isinstance(raw_sv, str):
            raise TypeError(f"schema_version must be str, got {type(raw_sv).__name__}")
        if raw_sv != FROZEN_CONTRACT_SCHEMA_VERSION:
            raise FrozenContractSchemaError(f"Unsupported schema_version: {raw_sv!r}")

        raw_cd = data["contract_digest"]
        if not isinstance(raw_cd, str):
            raise TypeError(f"contract_digest must be str, got {type(raw_cd).__name__}")
        if not _DIGEST_PATTERN.match(raw_cd):
            raise FrozenContractSchemaError(f"Invalid contract_digest format: {raw_cd!r}")

        raw_td = data["task_digest"]
        if not isinstance(raw_td, str):
            raise TypeError(f"task_digest must be str, got {type(raw_td).__name__}")
        if not _DIGEST_PATTERN.match(raw_td):
            raise FrozenContractSchemaError(f"Invalid task_digest format: {raw_td!r}")

        raw_cc = data["change_class"]
        if isinstance(raw_cc, ChangeClass):
            change_class = raw_cc
        elif isinstance(raw_cc, str):
            try:
                change_class = ChangeClass(raw_cc)
            except ValueError:
                raise FrozenContractSchemaError(f"Invalid ChangeClass: {raw_cc!r}") from None
        else:
            raise TypeError(f"change_class must be ChangeClass or str, got {type(raw_cc).__name__}")

        raw_cert = data["certainty"]
        if isinstance(raw_cert, CertaintyLevel):
            certainty = raw_cert
        elif isinstance(raw_cert, str):
            try:
                certainty = CertaintyLevel(raw_cert)
            except ValueError:
                raise FrozenContractSchemaError(f"Invalid CertaintyLevel: {raw_cert!r}") from None
        else:
            raise TypeError(
                f"certainty must be CertaintyLevel or str, got {type(raw_cert).__name__}"
            )

        raw_reqs = data["requirements"]
        if not isinstance(raw_reqs, (list, tuple)):
            raise TypeError(f"requirements must be list or tuple, got {type(raw_reqs).__name__}")

        requirements: list[FrozenRequirement] = []
        for idx, item in enumerate(raw_reqs):
            if not isinstance(item, Mapping):
                raise TypeError(
                    f"Requirement at index {idx} must be mapping, got {type(item).__name__}"
                )
            req = FrozenRequirement.from_dict(item)
            requirements.append(req)

        # Canonical requirement_id ordering check
        req_ids = [r.requirement_id for r in requirements]
        if req_ids != sorted(req_ids):
            raise FrozenContractSchemaError(
                "requirements in serialized data must be in canonical order "
                "sorted by requirement_id"
            )

        # Check self-consistency of declared digest against data
        identity_payload = build_canonical_identity_payload(
            schema_version=raw_sv,
            task_digest=raw_td,
            change_class=change_class,
            certainty=certainty,
            requirements=requirements,
        )
        data_recomputed_digest = compute_contract_digest(identity_payload)
        if raw_cd != data_recomputed_digest:
            raise FrozenContractDigestMismatchError(
                f"Serialized contract_digest {raw_cd!r} does not match "
                f"recomputed digest from payload {data_recomputed_digest!r}"
            )

        raw_rules = data.get("validation_rules_passed", ())
        if not isinstance(raw_rules, (list, tuple)):
            raise TypeError(
                f"validation_rules_passed must be list or tuple, got {type(raw_rules).__name__}"
            )
        rules_passed: list[str] = []
        for r in raw_rules:
            if not isinstance(r, str):
                raise TypeError(
                    f"validation_rules_passed items must be str, got {type(r).__name__}"
                )
            rules_passed.append(r)

        # Construct through constructor authority path with source_review
        return cls(
            schema_version=raw_sv,
            contract_digest=raw_cd,
            task_digest=raw_td,
            change_class=change_class,
            certainty=certainty,
            requirements=tuple(requirements),
            validation_rules_passed=tuple(rules_passed),
            source_review=source_review,
        )

    @classmethod
    def from_json(
        cls,
        json_str: str,
        *,
        source_review: ReviewResult,
    ) -> FrozenContract:
        """Construct from JSON string with strict schema validation and trusted loading."""
        if not isinstance(json_str, str):
            raise TypeError(f"json_str must be str, got {type(json_str).__name__}")
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            safe_err = redact_log_text(str(e))
            raise FrozenContractSchemaError(f"Invalid JSON for FrozenContract: {safe_err}") from e
        return cls.from_dict(data, source_review=source_review)


def freeze_review_result(review_result: ReviewResult) -> FrozenContract:
    """Authoritatively freeze an approved ReviewResult into an immutable FrozenContract.

    Authority Invariants:
    1. review_result must be ReviewDecision.APPROVED.
    2. review_result must be ReviewStatus.READY_FOR_FREEZE.
    3. review_result.is_ready_for_freeze must be True.
    4. review_result.contract must not be None.
    5. Identity payload is derived exclusively from review_result.contract.
    6. Requirements are ordered canonically by requirement_id.
    7. Cryptographic SHA-256 digest is computed from canonical bytes.
    8. FrozenContract is constructed with source_review=review_result,
       re-enforcing the constructor authority invariant.
    """
    if not isinstance(review_result, ReviewResult):
        raise TypeError(f"review_result must be ReviewResult, got {type(review_result).__name__}")

    if review_result.decision != ReviewDecision.APPROVED:
        raise FrozenContractSchemaError(
            f"Cannot freeze review result: decision is {review_result.decision.value}, "
            "expected APPROVED"
        )
    if review_result.status != ReviewStatus.READY_FOR_FREEZE:
        raise FrozenContractSchemaError(
            f"Cannot freeze review result: status is {review_result.status.value}, "
            "expected READY_FOR_FREEZE"
        )
    if not review_result.is_ready_for_freeze:
        raise FrozenContractSchemaError("Cannot freeze review result: is_ready_for_freeze is False")
    if review_result.contract is None:
        raise FrozenContractSchemaError("Cannot freeze review result: contract is None")

    contract = review_result.contract

    if contract.change_class is None:
        raise FrozenContractSchemaError("Cannot freeze contract: change_class is None")
    if contract.certainty is None:
        raise FrozenContractSchemaError("Cannot freeze contract: certainty is None")

    # Canonical ordering strictly by requirement_id
    sorted_reqs = tuple(
        sorted(
            [FrozenRequirement.from_validated_requirement(r) for r in contract.requirements],
            key=lambda r: r.requirement_id,
        )
    )

    identity_payload = build_canonical_identity_payload(
        schema_version=FROZEN_CONTRACT_SCHEMA_VERSION,
        task_digest=contract.task_digest,
        change_class=contract.change_class,
        certainty=contract.certainty,
        requirements=sorted_reqs,
    )
    contract_digest = compute_contract_digest(identity_payload)

    return FrozenContract(
        schema_version=FROZEN_CONTRACT_SCHEMA_VERSION,
        contract_digest=contract_digest,
        task_digest=contract.task_digest,
        change_class=contract.change_class,
        certainty=contract.certainty,
        requirements=sorted_reqs,
        validation_rules_passed=contract.validation_rules_passed,
        source_review=review_result,
    )


def verify_frozen_contract(
    contract: FrozenContract,
    *,
    expected_review: ReviewResult | None = None,
) -> bool:
    """Deterministically verify structural integrity, canonical order, and digest of FrozenContract.

    If expected_review is provided, also verifies that the FrozenContract binds
    authoritatively to that approved ReviewResult.

    Raises:
        FrozenContractError: on any structural, schema, or authority violation.
        FrozenContractDigestMismatchError: if digest does not match recomputation.
    """
    if not isinstance(contract, FrozenContract):
        raise TypeError(f"contract must be FrozenContract, got {type(contract).__name__}")

    # 1. Digest format check
    if not _DIGEST_PATTERN.match(contract.contract_digest):
        raise FrozenContractSchemaError(
            f"Invalid contract_digest format: {contract.contract_digest!r}"
        )

    # 2. Canonical requirement ordering check
    req_ids = [r.requirement_id for r in contract.requirements]
    if req_ids != sorted(req_ids):
        raise FrozenContractSchemaError("requirements are not in canonical requirement_id order")
    if len(req_ids) != len(set(req_ids)):
        raise FrozenContractSchemaError("Duplicate requirement_id detected")

    # 3. Cryptographic digest verification
    identity_payload = contract.to_identity_payload()
    recomputed_digest = compute_contract_digest(identity_payload)
    if contract.contract_digest != recomputed_digest:
        raise FrozenContractDigestMismatchError(
            f"contract_digest mismatch: declared {contract.contract_digest!r} "
            f"!= recomputed {recomputed_digest!r}"
        )

    # 4. Expected review verification if provided
    if expected_review is not None:
        if not isinstance(expected_review, ReviewResult):
            raise TypeError(
                f"expected_review must be ReviewResult, got {type(expected_review).__name__}"
            )
        if expected_review.decision != ReviewDecision.APPROVED:
            raise FrozenContractSchemaError(
                f"expected_review must be APPROVED, got {expected_review.decision.value}"
            )
        if expected_review.status != ReviewStatus.READY_FOR_FREEZE:
            raise FrozenContractSchemaError(
                "expected_review status must be READY_FOR_FREEZE, "
                f"got {expected_review.status.value}"
            )
        if not expected_review.is_ready_for_freeze or expected_review.contract is None:
            raise FrozenContractSchemaError("expected_review is not ready for freeze")

        ref = expected_review.contract
        if contract.task_digest != ref.task_digest:
            raise FrozenContractSchemaError(
                f"task_digest mismatch: {contract.task_digest} != {ref.task_digest}"
            )
        if contract.change_class != ref.change_class:
            raise FrozenContractSchemaError(
                f"change_class mismatch: {contract.change_class} != {ref.change_class}"
            )
        if contract.certainty != ref.certainty:
            raise FrozenContractSchemaError(
                f"certainty mismatch: {contract.certainty} != {ref.certainty}"
            )

        ref_sorted_reqs = tuple(sorted(ref.requirements, key=lambda r: r.requirement_id))
        if len(contract.requirements) != len(ref_sorted_reqs):
            raise FrozenContractSchemaError("Requirements count mismatch against expected_review")

        for idx, (f_req, c_req) in enumerate(zip(contract.requirements, ref_sorted_reqs)):
            if f_req.requirement_id != c_req.requirement_id:
                raise FrozenContractSchemaError(
                    f"Requirement ID mismatch at {idx}: "
                    f"{f_req.requirement_id!r} != {c_req.requirement_id!r}"
                )
            if f_req.statement != c_req.statement:
                raise FrozenContractSchemaError(f"Statement mismatch for {f_req.requirement_id}")
            if f_req.citation != c_req.citation:
                raise FrozenContractSchemaError(f"Citation mismatch for {f_req.requirement_id}")
            if (
                f_req.citation_start != c_req.citation_start
                or f_req.citation_end != c_req.citation_end
            ):
                raise FrozenContractSchemaError(
                    f"Citation span mismatch for {f_req.requirement_id}"
                )
            if f_req.rationale != c_req.rationale:
                raise FrozenContractSchemaError(f"Rationale mismatch for {f_req.requirement_id}")

        if contract.validation_rules_passed != ref.validation_rules_passed:
            raise FrozenContractSchemaError(
                "validation_rules_passed mismatch against expected_review"
            )

    return True
