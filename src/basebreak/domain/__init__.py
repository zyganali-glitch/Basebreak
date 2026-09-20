"""Domain contracts for Basebreak."""

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
    "ChangeClass",
    "ClassVerificationRequirement",
    "CommitRevision",
    "EngineeringTask",
    "ExecutionCommand",
    "ExecutionResult",
    "RequestedRef",
    "SandboxIdentity",
    "SourceIdentity",
    "TerminationStatus",
    "get_verification_requirements",
]
