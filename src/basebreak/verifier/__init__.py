"""Verifier isolation, sealed witness boundary, and execution contracts.

P-08: Verifier Isolation & Sealed Challenge Boundary.
"""

from basebreak.verifier.context import (
    VERIFIER_CONTEXT_SCHEMA_VERSION,
    BuilderAuthoritySmugglingError,
    MutableWorkspacePathError,
    UnpinnedSourceError,
    UntrustedBuilderInputError,
    VerifierContextEnvelope,
    VerifierContextError,
    VerifierDigestMismatchError,
    VerifierExecutionPolicy,
    VerifierInputClassification,
)
from basebreak.verifier.sandbox import (
    DEFAULT_VERIFIER_SANDBOX_IMAGE,
    DEFAULT_VERIFIER_TIMEOUT_SECONDS,
    DEFAULT_VERIFIER_WORKSPACE_PATH,
    BuilderSandboxReuseError,
    BuilderWorkspaceInheritanceError,
    HostExecutionFallbackError,
    MissingSandboxIdentityError,
    SimulationFallbackError,
    VerifierMaterializationError,
    VerifierSandboxConfig,
    VerifierSandboxError,
    VerifierSandboxManager,
    VerifierSandboxSession,
    VerifierTreeDigestMismatchError,
)

__all__ = [
    "DEFAULT_VERIFIER_SANDBOX_IMAGE",
    "DEFAULT_VERIFIER_TIMEOUT_SECONDS",
    "DEFAULT_VERIFIER_WORKSPACE_PATH",
    "VERIFIER_CONTEXT_SCHEMA_VERSION",
    "BuilderAuthoritySmugglingError",
    "BuilderSandboxReuseError",
    "BuilderWorkspaceInheritanceError",
    "HostExecutionFallbackError",
    "MissingSandboxIdentityError",
    "MutableWorkspacePathError",
    "SimulationFallbackError",
    "UnpinnedSourceError",
    "UntrustedBuilderInputError",
    "VerifierContextEnvelope",
    "VerifierContextError",
    "VerifierDigestMismatchError",
    "VerifierExecutionPolicy",
    "VerifierInputClassification",
    "VerifierMaterializationError",
    "VerifierSandboxConfig",
    "VerifierSandboxError",
    "VerifierSandboxManager",
    "VerifierSandboxSession",
    "VerifierTreeDigestMismatchError",
]
