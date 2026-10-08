"""Deterministic semantic verification receipt contracts and tamper detection.

P-13: Expanded change-semantics receipt architecture binding all canonical classes:
BUG_FIX, FEATURE, SECURITY_FIX, REFACTOR, PERFORMANCE, DEP_API_CHANGE.

Core Invariants:
1. Complete cryptographic chain: Unambiguously binds:
   change_class -> requirement_id -> frozen_contract_digest -> witness_digest ->
   lock_digest -> source_commit_id -> candidate_tree_digest -> execution facts ->
   class_specific_payload -> transition -> verdict -> receipt_digest.
2. Canonical serialization: Computes deterministic SHA-256 receipt digest over
   canonical JSON bytes with sorted keys and compact separators.
3. Tamper detection: Any modification to any field immediately invalidates receipt_digest.
4. Authority boundary: Caller-asserted receipts claiming unverified authority fail closed
   (is_authoritative is strictly False).
5. Strict provenance: Preserves exact provenance enum (FIXTURE, LOCAL_EXECUTION,
   LIVE_NEBIUS, RECORDED_LIVE).
6. Model prose never overrides deterministic result state.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from basebreak.causal.receipt import WorldExecutionFact
from basebreak.causal.reconciliation import CausalTransition
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.witness_result import WitnessOutcome

SEMANTIC_RECEIPT_SCHEMA_VERSION: str = "1.0.0"

_HEX_40_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")
_REQUIREMENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]+$")


class SemanticReceiptError(Exception):
    """Base exception for semantic verification receipt errors."""


class SemanticReceiptTamperingError(SemanticReceiptError):
    """Raised when receipt facts do not match the cryptographic receipt digest."""


class SemanticReceiptIntegrityError(SemanticReceiptError):
    """Raised when receipt fields violate domain or format constraints."""


def build_canonical_semantic_receipt_payload(
    *,
    schema_version: str,
    change_class: ChangeClass,
    requirement_id: str,
    frozen_contract_digest: str,
    witness_id: str,
    witness_digest: str,
    lock_digest: str,
    source_commit_id: str,
    candidate_tree_digest: str,
    base_execution: WorldExecutionFact | None,
    candidate_execution: WorldExecutionFact | None,
    class_specific_payload: Mapping[str, Any],
    transition: CausalTransition,
    verdict: PreliminaryVerdict,
    is_causally_verified: bool,
    provenance: EvidenceProvenance,
    narrative: str,
    created_at_utc: str,
) -> dict[str, Any]:
    """Construct canonical identity dictionary for cryptographic receipt digest."""
    payload: dict[str, Any] = {
        "base_execution": base_execution.to_dict() if base_execution is not None else None,
        "candidate_execution": (
            candidate_execution.to_dict() if candidate_execution is not None else None
        ),
        "candidate_tree_digest": candidate_tree_digest.strip().lower(),
        "change_class": change_class.value,
        "class_specific_payload": dict(class_specific_payload),
        "created_at_utc": created_at_utc.strip(),
        "frozen_contract_digest": frozen_contract_digest.strip().lower(),
        "is_causally_verified": is_causally_verified,
        "lock_digest": lock_digest.strip().lower(),
        "narrative": narrative.strip(),
        "provenance": provenance.value,
        "requirement_id": requirement_id.strip(),
        "schema_version": schema_version.strip(),
        "source_commit_id": source_commit_id.strip().lower(),
        "transition": transition.value,
        "verdict": verdict.value,
        "witness_digest": witness_digest.strip().lower(),
        "witness_id": witness_id.strip(),
    }
    return payload


def canonical_semantic_receipt_bytes(payload: Mapping[str, Any]) -> bytes:
    """Encode receipt payload into deterministic UTF-8 JSON bytes."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_semantic_receipt_digest(payload: Mapping[str, Any]) -> str:
    """Compute SHA-256 digest over canonical receipt bytes."""
    canonical_bytes = canonical_semantic_receipt_bytes(payload)
    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class SemanticVerificationReceipt:
    """Immutable, cryptographically verifiable receipt of a change-semantics verification."""

    schema_version: str
    change_class: ChangeClass
    requirement_id: str
    frozen_contract_digest: str
    witness_id: str
    witness_digest: str
    lock_digest: str
    source_commit_id: str
    candidate_tree_digest: str
    base_execution: WorldExecutionFact | None
    candidate_execution: WorldExecutionFact | None
    class_specific_payload: dict[str, Any]
    transition: CausalTransition
    verdict: PreliminaryVerdict
    is_causally_verified: bool
    provenance: EvidenceProvenance
    narrative: str
    created_at_utc: str
    receipt_digest: str
    is_authoritative: bool = False  # Invariant: zero self-certification

    def __post_init__(self) -> None:
        if not isinstance(self.change_class, ChangeClass):
            raise TypeError(
                f"change_class must be ChangeClass, got {type(self.change_class).__name__}"
            )
        if not isinstance(self.requirement_id, str) or not _REQUIREMENT_ID_PATTERN.match(
            self.requirement_id
        ):
            raise SemanticReceiptIntegrityError(
                f"requirement_id {self.requirement_id!r} does not match allowed pattern"
            )
        if not isinstance(self.frozen_contract_digest, str) or not _HEX_64_PATTERN.match(
            self.frozen_contract_digest
        ):
            raise SemanticReceiptIntegrityError(
                "frozen_contract_digest must be a 64-char hex string"
            )
        if not isinstance(self.witness_id, str) or not self.witness_id.strip():
            raise SemanticReceiptIntegrityError("witness_id must be a non-empty string")
        if not isinstance(self.witness_digest, str) or not _HEX_64_PATTERN.match(
            self.witness_digest
        ):
            raise SemanticReceiptIntegrityError("witness_digest must be a 64-char hex string")
        if not isinstance(self.lock_digest, str) or not _HEX_64_PATTERN.match(self.lock_digest):
            raise SemanticReceiptIntegrityError("lock_digest must be a 64-char hex string")
        if not isinstance(self.source_commit_id, str) or not _HEX_40_PATTERN.match(
            self.source_commit_id
        ):
            raise SemanticReceiptIntegrityError("source_commit_id must be a 40-char commit SHA")
        if not isinstance(self.candidate_tree_digest, str) or not _HEX_40_OR_64_PATTERN.match(
            self.candidate_tree_digest
        ):
            raise SemanticReceiptIntegrityError(
                "candidate_tree_digest must be 40 or 64 hex characters"
            )
        if self.base_execution is not None and not isinstance(
            self.base_execution, WorldExecutionFact
        ):
            raise TypeError(
                f"base_execution must be WorldExecutionFact or None, "
                f"got {type(self.base_execution).__name__}"
            )
        if self.candidate_execution is not None and not isinstance(
            self.candidate_execution, WorldExecutionFact
        ):
            raise TypeError(
                f"candidate_execution must be WorldExecutionFact or None, "
                f"got {type(self.candidate_execution).__name__}"
            )
        if not isinstance(self.class_specific_payload, dict):
            raise TypeError("class_specific_payload must be a dict")
        if not isinstance(self.transition, CausalTransition):
            raise TypeError(
                f"transition must be CausalTransition, got {type(self.transition).__name__}"
            )
        if not isinstance(self.verdict, PreliminaryVerdict):
            raise TypeError(
                f"verdict must be PreliminaryVerdict, got {type(self.verdict).__name__}"
            )
        if not isinstance(self.is_causally_verified, bool):
            raise TypeError("is_causally_verified must be a boolean")
        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError(
                f"provenance must be EvidenceProvenance, got {type(self.provenance).__name__}"
            )
        if not isinstance(self.receipt_digest, str) or not _HEX_64_PATTERN.match(
            self.receipt_digest
        ):
            raise SemanticReceiptIntegrityError("receipt_digest must be a 64-char hex string")

        if self.is_authoritative is not False:
            raise SemanticReceiptIntegrityError(
                "is_authoritative must be False (zero self-certification)"
            )

        # Transition-to-verdict consistency check
        positive_transitions = (
            CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            CausalTransition.CAUSAL_TRIPLET_VERIFIED,
            CausalTransition.FEATURE_VERIFIED,
            CausalTransition.SECURITY_FIX_VERIFIED,
            CausalTransition.REFACTOR_VERIFIED,
            CausalTransition.PERFORMANCE_VERIFIED,
            CausalTransition.DEP_API_CHANGE_VERIFIED,
        )
        expected_verified = (
            self.transition in positive_transitions and self.verdict == PreliminaryVerdict.VERIFIED
        )
        if self.is_causally_verified != expected_verified:
            raise SemanticReceiptIntegrityError(
                f"is_causally_verified mismatch: declared {self.is_causally_verified}, "
                f"expected {expected_verified} for transition {self.transition.value}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert to canonical dictionary representation."""
        payload = build_canonical_semantic_receipt_payload(
            schema_version=self.schema_version,
            change_class=self.change_class,
            requirement_id=self.requirement_id,
            frozen_contract_digest=self.frozen_contract_digest,
            witness_id=self.witness_id,
            witness_digest=self.witness_digest,
            lock_digest=self.lock_digest,
            source_commit_id=self.source_commit_id,
            candidate_tree_digest=self.candidate_tree_digest,
            base_execution=self.base_execution,
            candidate_execution=self.candidate_execution,
            class_specific_payload=self.class_specific_payload,
            transition=self.transition,
            verdict=self.verdict,
            is_causally_verified=self.is_causally_verified,
            provenance=self.provenance,
            narrative=self.narrative,
            created_at_utc=self.created_at_utc,
        )
        payload["is_authoritative"] = False
        payload["receipt_digest"] = self.receipt_digest
        return payload

    def to_json(self) -> str:
        """Convert to canonical JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SemanticVerificationReceipt:
        """Construct from dictionary with strict validation and tamper detection."""
        if not isinstance(data, Mapping):
            raise TypeError(
                f"Expected mapping for SemanticVerificationReceipt, got {type(data).__name__}"
            )

        required_keys = {
            "schema_version",
            "change_class",
            "requirement_id",
            "frozen_contract_digest",
            "witness_id",
            "witness_digest",
            "lock_digest",
            "source_commit_id",
            "candidate_tree_digest",
            "base_execution",
            "candidate_execution",
            "class_specific_payload",
            "transition",
            "verdict",
            "is_causally_verified",
            "provenance",
            "narrative",
            "created_at_utc",
            "receipt_digest",
        }
        missing = required_keys - set(data.keys())
        if missing:
            raise SemanticReceiptIntegrityError(
                f"Missing required receipt fields: {sorted(missing)}"
            )

        base_exec: WorldExecutionFact | None = None
        if data["base_execution"] is not None:
            b_dict = data["base_execution"]
            base_exec = WorldExecutionFact(
                world=ExecutionWorld(b_dict["world"]),
                sandbox_id=b_dict["sandbox_id"],
                source_commit_id=b_dict["source_commit_id"],
                tree_digest=b_dict["tree_digest"],
                outcome=WitnessOutcome(b_dict["outcome"]),
                exit_code=b_dict["exit_code"],
                termination_status=TerminationStatus(b_dict["termination_status"]),
                stdout_digest=b_dict["stdout_digest"],
                stderr_digest=b_dict["stderr_digest"],
                result_digest=b_dict["result_digest"],
                duration_seconds=b_dict["duration_seconds"],
            )

        cand_exec: WorldExecutionFact | None = None
        if data["candidate_execution"] is not None:
            c_dict = data["candidate_execution"]
            cand_exec = WorldExecutionFact(
                world=ExecutionWorld(c_dict["world"]),
                sandbox_id=c_dict["sandbox_id"],
                source_commit_id=c_dict["source_commit_id"],
                tree_digest=c_dict["tree_digest"],
                outcome=WitnessOutcome(c_dict["outcome"]),
                exit_code=c_dict["exit_code"],
                termination_status=TerminationStatus(c_dict["termination_status"]),
                stdout_digest=c_dict["stdout_digest"],
                stderr_digest=c_dict["stderr_digest"],
                result_digest=c_dict["result_digest"],
                duration_seconds=c_dict["duration_seconds"],
            )

        receipt = cls(
            schema_version=str(data["schema_version"]),
            change_class=ChangeClass(data["change_class"]),
            requirement_id=str(data["requirement_id"]),
            frozen_contract_digest=str(data["frozen_contract_digest"]),
            witness_id=str(data["witness_id"]),
            witness_digest=str(data["witness_digest"]),
            lock_digest=str(data["lock_digest"]),
            source_commit_id=str(data["source_commit_id"]),
            candidate_tree_digest=str(data["candidate_tree_digest"]),
            base_execution=base_exec,
            candidate_execution=cand_exec,
            class_specific_payload=dict(data["class_specific_payload"]),
            transition=CausalTransition(data["transition"]),
            verdict=PreliminaryVerdict(data["verdict"]),
            is_causally_verified=bool(data["is_causally_verified"]),
            provenance=EvidenceProvenance(data["provenance"]),
            narrative=str(data["narrative"]),
            created_at_utc=str(data["created_at_utc"]),
            receipt_digest=str(data["receipt_digest"]),
            is_authoritative=False,
        )

        verify_semantic_receipt_integrity(receipt)
        return receipt

    @classmethod
    def from_json(cls, json_str: str) -> SemanticVerificationReceipt:
        """Deserialize from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)


def create_semantic_receipt(
    *,
    change_class: ChangeClass,
    requirement_id: str,
    frozen_contract_digest: str,
    witness_id: str,
    witness_digest: str,
    lock_digest: str,
    source_commit_id: str,
    candidate_tree_digest: str,
    base_execution: WorldExecutionFact | None,
    candidate_execution: WorldExecutionFact | None,
    class_specific_payload: Mapping[str, Any],
    transition: CausalTransition,
    verdict: PreliminaryVerdict,
    is_causally_verified: bool,
    provenance: EvidenceProvenance,
    narrative: str,
    created_at_utc: str | None = None,
) -> SemanticVerificationReceipt:
    """Factory creating an authenticated SemanticVerificationReceipt with deterministic SHA-256."""
    if created_at_utc is None:
        created_at_utc = datetime.now(timezone.utc).isoformat()

    identity_payload = build_canonical_semantic_receipt_payload(
        schema_version=SEMANTIC_RECEIPT_SCHEMA_VERSION,
        change_class=change_class,
        requirement_id=requirement_id,
        frozen_contract_digest=frozen_contract_digest,
        witness_id=witness_id,
        witness_digest=witness_digest,
        lock_digest=lock_digest,
        source_commit_id=source_commit_id,
        candidate_tree_digest=candidate_tree_digest,
        base_execution=base_execution,
        candidate_execution=candidate_execution,
        class_specific_payload=class_specific_payload,
        transition=transition,
        verdict=verdict,
        is_causally_verified=is_causally_verified,
        provenance=provenance,
        narrative=narrative,
        created_at_utc=created_at_utc,
    )
    receipt_digest = compute_semantic_receipt_digest(identity_payload)

    return SemanticVerificationReceipt(
        schema_version=SEMANTIC_RECEIPT_SCHEMA_VERSION,
        change_class=change_class,
        requirement_id=requirement_id,
        frozen_contract_digest=frozen_contract_digest,
        witness_id=witness_id,
        witness_digest=witness_digest,
        lock_digest=lock_digest,
        source_commit_id=source_commit_id,
        candidate_tree_digest=candidate_tree_digest,
        base_execution=base_execution,
        candidate_execution=candidate_execution,
        class_specific_payload=dict(class_specific_payload),
        transition=transition,
        verdict=verdict,
        is_causally_verified=is_causally_verified,
        provenance=provenance,
        narrative=narrative,
        created_at_utc=created_at_utc,
        receipt_digest=receipt_digest,
        is_authoritative=False,
    )


def verify_semantic_receipt_integrity(receipt: SemanticVerificationReceipt) -> bool:
    """Verify cryptographic integrity of receipt facts against receipt_digest."""
    if not isinstance(receipt, SemanticVerificationReceipt):
        raise TypeError(f"Expected SemanticVerificationReceipt, got {type(receipt).__name__}")

    expected_payload = build_canonical_semantic_receipt_payload(
        schema_version=receipt.schema_version,
        change_class=receipt.change_class,
        requirement_id=receipt.requirement_id,
        frozen_contract_digest=receipt.frozen_contract_digest,
        witness_id=receipt.witness_id,
        witness_digest=receipt.witness_digest,
        lock_digest=receipt.lock_digest,
        source_commit_id=receipt.source_commit_id,
        candidate_tree_digest=receipt.candidate_tree_digest,
        base_execution=receipt.base_execution,
        candidate_execution=receipt.candidate_execution,
        class_specific_payload=receipt.class_specific_payload,
        transition=receipt.transition,
        verdict=receipt.verdict,
        is_causally_verified=receipt.is_causally_verified,
        provenance=receipt.provenance,
        narrative=receipt.narrative,
        created_at_utc=receipt.created_at_utc,
    )

    recomputed_digest = compute_semantic_receipt_digest(expected_payload)
    if recomputed_digest != receipt.receipt_digest:
        raise SemanticReceiptTamperingError(
            f"Receipt digest mismatch: recorded {receipt.receipt_digest}, "
            f"recomputed {recomputed_digest}"
        )

    return True
