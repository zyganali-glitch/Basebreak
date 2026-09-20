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
from basebreak.domain.source import CommitRevision, RequestedRef, SourceIdentity
from basebreak.domain.task import AcceptanceRequirement, EngineeringTask

__all__ = [
    "AcceptanceRequirement",
    "CandidateIdentity",
    "CausalBinding",
    "ChangeClass",
    "ClassVerificationRequirement",
    "CommitRevision",
    "CounterfactualIdentity",
    "EngineeringTask",
    "ExecutionCommand",
    "ExecutionResult",
    "ExecutionWorld",
    "RequestedRef",
    "SandboxIdentity",
    "SourceIdentity",
    "TerminationStatus",
    "WitnessIdentity",
    "get_verification_requirements",
]
