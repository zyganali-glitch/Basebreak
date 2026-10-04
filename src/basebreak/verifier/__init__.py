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

__all__ = [
    "VERIFIER_CONTEXT_SCHEMA_VERSION",
    "BuilderAuthoritySmugglingError",
    "MutableWorkspacePathError",
    "UnpinnedSourceError",
    "UntrustedBuilderInputError",
    "VerifierContextEnvelope",
    "VerifierContextError",
    "VerifierDigestMismatchError",
    "VerifierExecutionPolicy",
    "VerifierInputClassification",
]
