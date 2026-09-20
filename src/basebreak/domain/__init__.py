"""Domain contracts for Basebreak."""

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
    "RequestedRef",
    "SourceIdentity",
    "get_verification_requirements",
]
