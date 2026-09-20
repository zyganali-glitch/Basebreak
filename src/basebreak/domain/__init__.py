"""Domain contracts for Basebreak."""

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
    get_verification_requirements,
)
from basebreak.domain.serialization import (
    SCHEMA_VERSION,
    SchemaTypeError,
    SchemaValidationError,
    SchemaVersionError,
    SerializationError,
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

__all__ = [
    "AcceptanceRequirement",
    "CandidateIdentity",
    "CausalBinding",
    "ChangeClass",
    "ClassVerificationRequirement",
    "CommitRevision",
    "CounterfactualIdentity",
    "EngineeringTask",
    "EvidenceProvenance",
    "ExecutionCommand",
    "ExecutionResult",
    "ExecutionWorld",
    "PreliminaryVerdict",
    "PreliminaryVerdictRecord",
    "RequestedRef",
    "SCHEMA_VERSION",
    "SandboxIdentity",
    "SchemaTypeError",
    "SchemaValidationError",
    "SchemaVersionError",
    "SerializationError",
    "SourceIdentity",
    "TerminationStatus",
    "WitnessIdentity",
    "from_canonical_bytes",
    "from_canonical_json",
    "from_dict",
    "get_verification_requirements",
    "to_canonical_bytes",
    "to_canonical_json",
    "to_dict",
]
