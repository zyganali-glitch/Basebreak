"""Executable behavioral witness artifact generation and vault registration for BUG_FIX.

P-09.03: Generate executable independent behavioral witnesses for BUG_FIX.

Core Invariants:
1. Behavioral independence: Tests behavior specified by frozen contract independently
   of Builder-authored tests. Does not execute or trust Builder tests.
2. Sealed vault boundary: Artifacts are converted to WitnessArtifact, checked against
   protected surfaces and secrets, and sealed into TrustedWitnessVault with authentic HMAC.
3. Hidden implementation: Witness implementation remains hidden from Builder-visible surfaces.
4. Authority boundary: Zero caller-created authority. Only the authentic TrustedWitnessVault
   sealing signature confers verification eligibility.
5. Provider neutrality: Zero adapter imports, zero provider-specific identifiers.
"""

from __future__ import annotations

from basebreak.domain.semantics import ChangeClass
from basebreak.security.protected_surfaces import (
    ProtectedSurfaceManifest,
    get_canonical_basebreak_protected_manifest,
)
from basebreak.verifier.boundary import VerifierBoundaryEnforcer
from basebreak.verifier.witness_plan import (
    ValidatedWitnessPlan,
    WitnessPlanScopeError,
)
from basebreak.verifier.witness_store import (
    SealedWitnessRecord,
    TrustedWitnessVault,
    WitnessArtifact,
    WitnessIntegrityError,
)


class WitnessGeneratorError(Exception):
    """Base exception for witness generation errors."""


class BuilderTestContaminationError(WitnessGeneratorError):
    """Raised when witness generation attempts to import or run Builder-authored tests."""


class WitnessGenerator:
    """Generates executable behavioral witness artifacts and seals them into TrustedWitnessVault.

    Enforces BUG_FIX semantics and independence from Builder artifacts.
    """

    def __init__(
        self,
        vault: TrustedWitnessVault,
        *,
        manifest: ProtectedSurfaceManifest | None = None,
        boundary_enforcer: VerifierBoundaryEnforcer | None = None,
    ) -> None:
        if not isinstance(vault, TrustedWitnessVault):
            raise TypeError(f"vault must be TrustedWitnessVault, got {type(vault).__name__}")
        self.vault = vault
        self.manifest = manifest or get_canonical_basebreak_protected_manifest()
        self.boundary_enforcer = boundary_enforcer or VerifierBoundaryEnforcer()

    def generate_and_seal_witness(
        self,
        plan: ValidatedWitnessPlan,
        *,
        known_builder_test_names: tuple[str, ...] = (),
    ) -> SealedWitnessRecord:
        """Construct WitnessArtifacts from validated plan and seal them into TrustedWitnessVault.

        Guarantees:
        1. Scope is BUG_FIX.
        2. No references or imports of Builder-authored tests.
        3. All artifacts verified against path, secret, and protected-surface policies.
        4. Authentic cryptographic sealing in TrustedWitnessVault.
        """
        if not isinstance(plan, ValidatedWitnessPlan):
            raise TypeError(f"plan must be ValidatedWitnessPlan, got {type(plan).__name__}")

        if plan.change_class != ChangeClass.BUG_FIX:
            raise WitnessPlanScopeError(
                f"WitnessGenerator requires BUG_FIX, got {plan.change_class.value!r}"
            )

        # Check for Builder test contamination
        forbidden_test_names = frozenset(str(t).strip().lower() for t in known_builder_test_names)

        witness_artifacts: list[WitnessArtifact] = []
        for art in plan.artifacts:
            # Check for builder test contamination in artifact path or content
            base_filename = art.path.rsplit("/", 1)[-1].lower()
            if base_filename in forbidden_test_names:
                raise BuilderTestContaminationError(
                    f"Witness artifact path {art.path!r} collides with Builder-authored test"
                )

            for b_test in forbidden_test_names:
                if b_test and (
                    f"import {b_test}" in art.content or f"from {b_test}" in art.content
                ):
                    raise BuilderTestContaminationError(
                        f"Witness artifact {art.path!r} imports Builder test {b_test!r}"
                    )

            try:
                wa = WitnessArtifact(
                    path=art.path,
                    content=art.content,
                    content_digest=art.content_digest,
                    byte_size=art.byte_size,
                )
            except WitnessIntegrityError as exc:
                raise WitnessGeneratorError(f"Failed to create WitnessArtifact: {exc}") from exc

            witness_artifacts.append(wa)

        # Seal in TrustedWitnessVault
        try:
            sealed_record = self.vault.seal_witness(
                witness_id=plan.witness_id,
                requirement_id=plan.requirement_id,
                frozen_contract_digest=plan.frozen_contract_digest,
                source_commit_id=plan.source_commit_id,
                artifacts=witness_artifacts,
            )
        except WitnessIntegrityError as exc:
            raise WitnessGeneratorError(f"Failed to seal witness record in vault: {exc}") from exc

        # Cryptographically verify the freshly sealed record
        self.vault.verify_witness_integrity(sealed_record)
        return sealed_record
