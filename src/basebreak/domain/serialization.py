"""Canonical deterministic serialization and schema compatibility for domain contracts.

Provides provider-neutral deterministic JSON serialization and deserialization
for all Basebreak domain contracts. Guarantees canonical representation, key sorting,
explicit schema versioning, and strict validation without reliance on Python's
built-in salted hash() or arbitrary object repr().
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

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
    ClassVerificationRequirement,
)
from basebreak.domain.source import CommitRevision, RequestedRef, SourceIdentity
from basebreak.domain.task import AcceptanceRequirement, EngineeringTask
from basebreak.domain.verdict import (
    EvidenceProvenance,
    PreliminaryVerdict,
    PreliminaryVerdictRecord,
)

SCHEMA_VERSION: int = 1
SUPPORTED_SCHEMA_VERSIONS: frozenset[int] = frozenset({1})


class SerializationError(Exception):
    """Base exception for domain serialization and schema errors."""


class SchemaVersionError(SerializationError):
    """Raised when an unsupported schema version is encountered."""


class SchemaTypeError(SerializationError):
    """Raised when an unknown or unsupported schema type is encountered."""


class SchemaValidationError(SerializationError):
    """Raised when serialized data is malformed or violates schema validation rules."""


# --- Serializer Functions ---


def _serialize_commit_revision(obj: CommitRevision) -> dict[str, Any]:
    return {"commit_id": obj.commit_id}


def _serialize_requested_ref(obj: RequestedRef) -> dict[str, Any]:
    return {"name": obj.name}


def _serialize_source_identity(obj: SourceIdentity) -> dict[str, Any]:
    return {
        "locator": obj.locator,
        "revision": _serialize_commit_revision(obj.revision),
        "subpath": obj.subpath,
        "requested_ref": _serialize_requested_ref(obj.requested_ref) if obj.requested_ref else None,
    }


def _serialize_acceptance_requirement(obj: AcceptanceRequirement) -> dict[str, Any]:
    return {
        "requirement_id": obj.requirement_id,
        "statement": obj.statement,
    }


def _serialize_engineering_task(obj: EngineeringTask) -> dict[str, Any]:
    return {
        "task_id": obj.task_id,
        "title": obj.title,
        "description": obj.description,
        "requirements": [_serialize_acceptance_requirement(req) for req in obj.requirements],
    }


def _serialize_change_class(obj: ChangeClass) -> dict[str, Any]:
    return {"value": obj.value}


def _serialize_class_verification_requirement(
    obj: ClassVerificationRequirement,
) -> dict[str, Any]:
    return {
        "change_class": obj.change_class.value,
        "base_expectation": obj.base_expectation,
        "candidate_expectation": obj.candidate_expectation,
        "requires_equivalence": obj.requires_equivalence,
        "requires_measured_delta": obj.requires_measured_delta,
        "requires_regression_safety": obj.requires_regression_safety,
        "description": obj.description,
    }


def _serialize_termination_status(obj: TerminationStatus) -> dict[str, Any]:
    return {"value": obj.value}


def _serialize_execution_command(obj: ExecutionCommand) -> dict[str, Any]:
    return {
        "argv": list(obj.argv),
        "cwd": obj.cwd,
        "env": [[k, v] for k, v in obj.env],
    }


def _serialize_execution_result(obj: ExecutionResult) -> dict[str, Any]:
    return {
        "status": obj.status.value,
        "exit_code": obj.exit_code,
        "duration_seconds": obj.duration_seconds,
    }


def _serialize_sandbox_identity(obj: SandboxIdentity) -> dict[str, Any]:
    return {
        "sandbox_id": obj.sandbox_id,
        "description": obj.description,
    }


def _serialize_witness_identity(obj: WitnessIdentity) -> dict[str, Any]:
    return {
        "witness_id": obj.witness_id,
        "digest": obj.digest,
        "description": obj.description,
    }


def _serialize_candidate_identity(obj: CandidateIdentity) -> dict[str, Any]:
    return {
        "candidate_id": obj.candidate_id,
        "source": _serialize_source_identity(obj.source),
        "patch_digest": obj.patch_digest,
        "description": obj.description,
    }


def _serialize_execution_world(obj: ExecutionWorld) -> dict[str, Any]:
    return {"value": obj.value}


def _serialize_counterfactual_identity(obj: CounterfactualIdentity) -> dict[str, Any]:
    return {
        "counterfactual_id": obj.counterfactual_id,
        "target_candidate": _serialize_candidate_identity(obj.target_candidate),
        "delta_digest": obj.delta_digest,
        "description": obj.description,
    }


def _serialize_causal_binding(obj: CausalBinding) -> dict[str, Any]:
    return {
        "requirement_id": obj.requirement_id,
        "witness": _serialize_witness_identity(obj.witness),
        "base_source": _serialize_source_identity(obj.base_source),
        "candidate": _serialize_candidate_identity(obj.candidate),
        "world": obj.world.value,
        "counterfactual": _serialize_counterfactual_identity(obj.counterfactual)
        if obj.counterfactual
        else None,
    }


def _serialize_evidence_provenance(obj: EvidenceProvenance) -> dict[str, Any]:
    return {"value": obj.value}


def _serialize_preliminary_verdict(obj: PreliminaryVerdict) -> dict[str, Any]:
    return {"value": obj.value}


def _serialize_preliminary_verdict_record(obj: PreliminaryVerdictRecord) -> dict[str, Any]:
    return {
        "verdict": obj.verdict.value,
        "provenance": obj.provenance.value,
        "requirement_id": obj.requirement_id,
        "causal_binding": _serialize_causal_binding(obj.causal_binding)
        if obj.causal_binding
        else None,
        "narrative": obj.narrative,
        "model_confidence": obj.model_confidence,
    }


_SERIALIZERS: dict[type[Any], tuple[str, Callable[[Any], dict[str, Any]]]] = {
    CommitRevision: ("CommitRevision", _serialize_commit_revision),
    RequestedRef: ("RequestedRef", _serialize_requested_ref),
    SourceIdentity: ("SourceIdentity", _serialize_source_identity),
    AcceptanceRequirement: ("AcceptanceRequirement", _serialize_acceptance_requirement),
    EngineeringTask: ("EngineeringTask", _serialize_engineering_task),
    ChangeClass: ("ChangeClass", _serialize_change_class),
    ClassVerificationRequirement: (
        "ClassVerificationRequirement",
        _serialize_class_verification_requirement,
    ),
    TerminationStatus: ("TerminationStatus", _serialize_termination_status),
    ExecutionCommand: ("ExecutionCommand", _serialize_execution_command),
    ExecutionResult: ("ExecutionResult", _serialize_execution_result),
    SandboxIdentity: ("SandboxIdentity", _serialize_sandbox_identity),
    WitnessIdentity: ("WitnessIdentity", _serialize_witness_identity),
    CandidateIdentity: ("CandidateIdentity", _serialize_candidate_identity),
    ExecutionWorld: ("ExecutionWorld", _serialize_execution_world),
    CounterfactualIdentity: ("CounterfactualIdentity", _serialize_counterfactual_identity),
    CausalBinding: ("CausalBinding", _serialize_causal_binding),
    EvidenceProvenance: ("EvidenceProvenance", _serialize_evidence_provenance),
    PreliminaryVerdict: ("PreliminaryVerdict", _serialize_preliminary_verdict),
    PreliminaryVerdictRecord: (
        "PreliminaryVerdictRecord",
        _serialize_preliminary_verdict_record,
    ),
}


# --- Deserializer Functions ---


def _deserialize_commit_revision(payload: dict[str, Any]) -> CommitRevision:
    return CommitRevision(commit_id=payload["commit_id"])


def _deserialize_requested_ref(payload: dict[str, Any]) -> RequestedRef:
    return RequestedRef(name=payload["name"])


def _deserialize_source_identity(payload: dict[str, Any]) -> SourceIdentity:
    req_ref_data = payload.get("requested_ref")
    req_ref = _deserialize_requested_ref(req_ref_data) if req_ref_data else None
    return SourceIdentity(
        locator=payload["locator"],
        revision=_deserialize_commit_revision(payload["revision"]),
        subpath=payload.get("subpath"),
        requested_ref=req_ref,
    )


def _deserialize_acceptance_requirement(payload: dict[str, Any]) -> AcceptanceRequirement:
    return AcceptanceRequirement(
        requirement_id=payload["requirement_id"],
        statement=payload["statement"],
    )


def _deserialize_engineering_task(payload: dict[str, Any]) -> EngineeringTask:
    raw_reqs = payload.get("requirements", [])
    reqs = tuple(_deserialize_acceptance_requirement(r) for r in raw_reqs)
    return EngineeringTask(
        task_id=payload["task_id"],
        title=payload["title"],
        description=payload.get("description", ""),
        requirements=reqs,
    )


def _deserialize_change_class(payload: dict[str, Any]) -> ChangeClass:
    return ChangeClass(payload["value"])


def _deserialize_class_verification_requirement(
    payload: dict[str, Any],
) -> ClassVerificationRequirement:
    return ClassVerificationRequirement(
        change_class=ChangeClass(payload["change_class"]),
        base_expectation=payload["base_expectation"],
        candidate_expectation=payload["candidate_expectation"],
        requires_equivalence=payload.get("requires_equivalence", False),
        requires_measured_delta=payload.get("requires_measured_delta", False),
        requires_regression_safety=payload.get("requires_regression_safety", False),
        description=payload.get("description", ""),
    )


def _deserialize_termination_status(payload: dict[str, Any]) -> TerminationStatus:
    return TerminationStatus(payload["value"])


def _deserialize_execution_command(payload: dict[str, Any]) -> ExecutionCommand:
    raw_env = payload.get("env", ())
    if not isinstance(raw_env, (list, tuple)):
        raise TypeError(
            f"env must be a sequence of (key, value) pairs, got {type(raw_env).__name__}"
        )

    if "argv" not in payload:
        raise KeyError("argv")
    raw_argv = payload["argv"]
    if not isinstance(raw_argv, (list, tuple)):
        raise TypeError(f"argv must be a sequence of strings, got {type(raw_argv).__name__}")

    env_pairs: list[tuple[Any, Any]] = []
    for idx, item in enumerate(raw_env):
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise TypeError(f"env element at index {idx} must be a (key, value) pair")
        k, v = item
        env_pairs.append((k, v))

    return ExecutionCommand(
        argv=tuple(raw_argv),
        cwd=payload.get("cwd"),
        env=tuple(env_pairs),
    )


def _deserialize_execution_result(payload: dict[str, Any]) -> ExecutionResult:
    return ExecutionResult(
        status=TerminationStatus(payload["status"]),
        exit_code=payload.get("exit_code"),
        duration_seconds=payload.get("duration_seconds"),
    )


def _deserialize_sandbox_identity(payload: dict[str, Any]) -> SandboxIdentity:
    return SandboxIdentity(
        sandbox_id=payload["sandbox_id"],
        description=payload.get("description", ""),
    )


def _deserialize_witness_identity(payload: dict[str, Any]) -> WitnessIdentity:
    return WitnessIdentity(
        witness_id=payload["witness_id"],
        digest=payload["digest"],
        description=payload.get("description", ""),
    )


def _deserialize_candidate_identity(payload: dict[str, Any]) -> CandidateIdentity:
    return CandidateIdentity(
        candidate_id=payload["candidate_id"],
        source=_deserialize_source_identity(payload["source"]),
        patch_digest=payload.get("patch_digest"),
        description=payload.get("description", ""),
    )


def _deserialize_execution_world(payload: dict[str, Any]) -> ExecutionWorld:
    return ExecutionWorld(payload["value"])


def _deserialize_counterfactual_identity(payload: dict[str, Any]) -> CounterfactualIdentity:
    return CounterfactualIdentity(
        counterfactual_id=payload["counterfactual_id"],
        target_candidate=_deserialize_candidate_identity(payload["target_candidate"]),
        delta_digest=payload.get("delta_digest"),
        description=payload.get("description", ""),
    )


def _deserialize_causal_binding(payload: dict[str, Any]) -> CausalBinding:
    cf_data = payload.get("counterfactual")
    cf = _deserialize_counterfactual_identity(cf_data) if cf_data else None
    return CausalBinding(
        requirement_id=payload["requirement_id"],
        witness=_deserialize_witness_identity(payload["witness"]),
        base_source=_deserialize_source_identity(payload["base_source"]),
        candidate=_deserialize_candidate_identity(payload["candidate"]),
        world=ExecutionWorld(payload["world"]),
        counterfactual=cf,
    )


def _deserialize_evidence_provenance(payload: dict[str, Any]) -> EvidenceProvenance:
    return EvidenceProvenance(payload["value"])


def _deserialize_preliminary_verdict(payload: dict[str, Any]) -> PreliminaryVerdict:
    return PreliminaryVerdict(payload["value"])


def _deserialize_preliminary_verdict_record(payload: dict[str, Any]) -> PreliminaryVerdictRecord:
    binding_data = payload.get("causal_binding")
    binding = _deserialize_causal_binding(binding_data) if binding_data else None
    return PreliminaryVerdictRecord(
        verdict=PreliminaryVerdict(payload["verdict"]),
        provenance=EvidenceProvenance(payload["provenance"]),
        requirement_id=payload["requirement_id"],
        causal_binding=binding,
        narrative=payload.get("narrative", ""),
        model_confidence=payload.get("model_confidence"),
    )


_DESERIALIZERS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "CommitRevision": _deserialize_commit_revision,
    "RequestedRef": _deserialize_requested_ref,
    "SourceIdentity": _deserialize_source_identity,
    "AcceptanceRequirement": _deserialize_acceptance_requirement,
    "EngineeringTask": _deserialize_engineering_task,
    "ChangeClass": _deserialize_change_class,
    "ClassVerificationRequirement": _deserialize_class_verification_requirement,
    "TerminationStatus": _deserialize_termination_status,
    "ExecutionCommand": _deserialize_execution_command,
    "ExecutionResult": _deserialize_execution_result,
    "SandboxIdentity": _deserialize_sandbox_identity,
    "WitnessIdentity": _deserialize_witness_identity,
    "CandidateIdentity": _deserialize_candidate_identity,
    "ExecutionWorld": _deserialize_execution_world,
    "CounterfactualIdentity": _deserialize_counterfactual_identity,
    "CausalBinding": _deserialize_causal_binding,
    "EvidenceProvenance": _deserialize_evidence_provenance,
    "PreliminaryVerdict": _deserialize_preliminary_verdict,
    "PreliminaryVerdictRecord": _deserialize_preliminary_verdict_record,
}


# --- Public API ---


def to_dict(obj: Any) -> dict[str, Any]:
    """Convert a domain object to a serialized dictionary with version envelope."""
    obj_type = type(obj)
    if obj_type not in _SERIALIZERS:
        raise SchemaTypeError(
            f"Unsupported domain object type for serialization: {obj_type.__name__}"
        )
    schema_type, serializer = _SERIALIZERS[obj_type]
    return {
        "schema_version": SCHEMA_VERSION,
        "schema_type": schema_type,
        "payload": serializer(obj),
    }


def from_dict(envelope: dict[str, Any]) -> Any:
    """Reconstruct a domain object from a serialized dictionary with version envelope."""
    if not isinstance(envelope, dict):
        raise SchemaValidationError(f"Expected dict envelope, got {type(envelope).__name__}")

    if "schema_version" not in envelope:
        raise SchemaValidationError("Missing required 'schema_version' in envelope")

    version = envelope["schema_version"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise SchemaValidationError(
            f"schema_version must be an integer, got {type(version).__name__}"
        )

    if version not in SUPPORTED_SCHEMA_VERSIONS:
        supported = sorted(SUPPORTED_SCHEMA_VERSIONS)
        raise SchemaVersionError(
            f"Unsupported schema version: {version}. Supported versions: {supported}"
        )

    if "schema_type" not in envelope:
        raise SchemaValidationError("Missing required 'schema_type' in envelope")

    schema_type = envelope["schema_type"]
    if not isinstance(schema_type, str):
        raise SchemaValidationError("schema_type must be a string")

    if schema_type not in _DESERIALIZERS:
        raise SchemaTypeError(f"Unknown schema_type: {schema_type!r}")

    if "payload" not in envelope:
        raise SchemaValidationError("Missing required 'payload' in envelope")

    payload = envelope["payload"]
    if not isinstance(payload, dict):
        raise SchemaValidationError(f"payload must be a dict, got {type(payload).__name__}")

    deserializer = _DESERIALIZERS[schema_type]
    try:
        return deserializer(payload)
    except (TypeError, ValueError, KeyError) as exc:
        raise SchemaValidationError(f"Failed to deserialize {schema_type}: {exc}") from exc


def to_canonical_json(obj: Any) -> str:
    """Serialize a domain object to a canonical JSON string.

    Guarantees:
    - field ordering sorted alphabetically recursively;
    - compact delimiters without extraneous whitespace;
    - UTF-8 encoding without ASCII escapes;
    - explicit schema version and type metadata;
    - deterministic output invariant across Python runtimes and dict ordering.
    """
    envelope = to_dict(obj)
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def from_canonical_json(json_str: str) -> Any:
    """Deserialize a domain object from a canonical JSON string."""
    if not isinstance(json_str, str):
        raise TypeError(f"json_str must be a string, got {type(json_str).__name__}")
    try:
        envelope = json.loads(json_str)
    except Exception as exc:
        raise SchemaValidationError(f"Invalid JSON string: {exc}") from exc
    return from_dict(envelope)


def to_canonical_bytes(obj: Any) -> bytes:
    """Serialize a domain object to canonical UTF-8 bytes."""
    return to_canonical_json(obj).encode("utf-8")


def from_canonical_bytes(data: bytes) -> Any:
    """Deserialize a domain object from UTF-8 bytes."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"data must be bytes or bytearray, got {type(data).__name__}")
    try:
        json_str = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SchemaValidationError(f"Invalid UTF-8 byte stream: {exc}") from exc
    return from_canonical_json(json_str)
