"""Bounded deterministic region selection without model authority over verdict.

P-11.02: Select bounded relevant patch region without model authority over verdict.

Enforces:
1. Zero model authority: Model proposals, prose, ranking, or confidence possess
   zero verdict authority.
2. Deterministic validation: All proposed files and hunks are strictly validated
   against the exact parsed candidate patch.
3. Cryptographic binding: Exact candidate snapshot, source identity, frozen contract,
   and sealed witness digests are mechanically preserved.
4. Fail-closed: Nonexistent, ambiguous, overlapping, or empty selections raise explicit
   typed errors.
5. Protected surface and secret safety: Any selection violating protected surface
   or secret policies is rejected immediately.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from basebreak.builder.capture import CandidateSnapshot
from basebreak.causal.subtraction import (
    CallerAuthorityError,
    CandidateDeltaSubtractor,
    CounterfactualDeltaPlan,
    DigestTamperingError,
    EmptySubtractionError,
    SubtractionRequest,
    SubtractionStrategyType,
    UnsupportedStrategyError,
    parse_candidate_patch,
)
from basebreak.security.protected_surfaces import normalize_repo_path

_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class ModelRegionProposal:
    """Untrusted model proposal for candidate-delta subtraction.

    Carries model-suggested files or hunks to subtract. Possesses ZERO authority:
    any attempt to assert authority or grant verification fails closed.
    """

    strategy_type: SubtractionStrategyType
    proposed_files: tuple[str, ...] = ()
    proposed_hunk_ids: tuple[str, ...] = ()
    model_confidence: float | None = None
    model_reasoning: str = ""
    is_authoritative: bool = False
    grants_pass: bool = False
    is_causally_verified: bool = False

    def __post_init__(self) -> None:
        if self.is_authoritative is not False:
            raise CallerAuthorityError(
                "ModelRegionProposal cannot assert authority: is_authoritative must be False"
            )
        if self.grants_pass is not False:
            raise CallerAuthorityError(
                "ModelRegionProposal cannot grant pass: grants_pass must be False"
            )
        if self.is_causally_verified is not False:
            raise CallerAuthorityError(
                "ModelRegionProposal cannot assert verification: is_causally_verified must be False"
            )

        if not isinstance(self.strategy_type, SubtractionStrategyType):
            if isinstance(self.strategy_type, str):
                try:
                    object.__setattr__(
                        self, "strategy_type", SubtractionStrategyType(self.strategy_type)
                    )
                except ValueError as exc:
                    raise UnsupportedStrategyError(
                        f"Unknown strategy_type: {self.strategy_type!r}"
                    ) from exc
            else:
                tname = type(self.strategy_type).__name__
                raise TypeError(f"strategy_type must be SubtractionStrategyType, got {tname}")

        if not isinstance(self.proposed_files, tuple):
            if isinstance(self.proposed_files, Sequence):
                object.__setattr__(
                    self, "proposed_files", tuple(str(f) for f in self.proposed_files)
                )
            else:
                raise TypeError("proposed_files must be a sequence of strings")

        if not isinstance(self.proposed_hunk_ids, tuple):
            if isinstance(self.proposed_hunk_ids, Sequence):
                object.__setattr__(
                    self, "proposed_hunk_ids", tuple(str(h) for h in self.proposed_hunk_ids)
                )
            else:
                raise TypeError("proposed_hunk_ids must be a sequence of strings")

        if self.model_confidence is not None:
            if isinstance(self.model_confidence, bool) or not isinstance(
                self.model_confidence, (int, float)
            ):
                raise TypeError("model_confidence must be a float or None")
            if not (0.0 <= float(self.model_confidence) <= 1.0):
                raise ValueError(
                    f"model_confidence must be between 0.0 and 1.0, got {self.model_confidence}"
                )

        if not isinstance(self.model_reasoning, str):
            raise TypeError("model_reasoning must be a string")


@dataclass(frozen=True, slots=True)
class ValidatedRegionSelection:
    """Deterministic, validated selection of patch region for counterfactual construction.

    Contains the verified plan and the normalized selected targets.
    Possesses ZERO authority over causal verdict.
    """

    strategy_type: SubtractionStrategyType
    selected_files: tuple[str, ...]
    selected_hunk_ids: tuple[str, ...]
    plan: CounterfactualDeltaPlan
    model_reasoning: str = ""
    is_authoritative: bool = False
    grants_pass: bool = False
    is_causally_verified: bool = False

    def __post_init__(self) -> None:
        if self.is_authoritative is not False:
            raise CallerAuthorityError("ValidatedRegionSelection is_authoritative must be False")
        if self.grants_pass is not False:
            raise CallerAuthorityError("ValidatedRegionSelection grants_pass must be False")
        if self.is_causally_verified is not False:
            raise CallerAuthorityError(
                "ValidatedRegionSelection is_causally_verified must be False"
            )
        if not isinstance(self.plan, CounterfactualDeltaPlan):
            raise TypeError(f"plan must be CounterfactualDeltaPlan, got {type(self.plan).__name__}")
        if not isinstance(self.strategy_type, SubtractionStrategyType):
            raise TypeError("strategy_type must be SubtractionStrategyType")


class BoundedRegionSelector:
    """Deterministic bounded selector validating region proposals against candidate truth.

    Guarantees:
    1. Zero model authority: Model proposals, confidence, or explanations cannot force selection.
    2. Deterministic validation: Proposed files and hunks are strictly validated against
       the candidate patch and repo structure.
    3. No silent widening: Cannot silently fall back to full patch if a requested hunk is invalid.
    4. Exact cryptographic binding: Preserves exact candidate, contract, and witness digests.
    """

    @classmethod
    def validate_and_plan_from_proposal(
        cls,
        *,
        proposal: ModelRegionProposal,
        snapshot: CandidateSnapshot,
        frozen_contract_digest: str,
        sealed_witness_digest: str,
        counterfactual_id: str | None = None,
        description: str = "",
    ) -> ValidatedRegionSelection:
        """Validate an untrusted model proposal against a candidate snapshot and construct plan.

        Fails closed if:
        - Proposal claims authority or verification
        - Proposed strategy is unknown or unsupported
        - Proposed files or hunks do not exist in candidate patch
        - Proposed hunks overlap or are ambiguous
        - Proposed selection touches protected surface or contains secrets
        - Proposed selection would result in empty subtraction
        """
        if not isinstance(proposal, ModelRegionProposal):
            raise TypeError(f"proposal must be ModelRegionProposal, got {type(proposal).__name__}")
        if not isinstance(snapshot, CandidateSnapshot):
            raise TypeError(f"snapshot must be CandidateSnapshot, got {type(snapshot).__name__}")

        # Parse candidate patch to validate proposed elements exist
        parsed_patch = parse_candidate_patch(snapshot.patch_text)

        # Build SubtractionRequest from proposal
        request = SubtractionRequest(
            strategy_type=proposal.strategy_type,
            target_files=proposal.proposed_files,
            target_hunk_ids=proposal.proposed_hunk_ids,
            is_authoritative=False,
            grants_pass=False,
            is_causally_verified=False,
            description=proposal.model_reasoning,
        )

        # Additional deterministic checks specific to bounded selection
        if proposal.strategy_type == SubtractionStrategyType.FILE_LEVEL_REVERT:
            if not proposal.proposed_files:
                raise EmptySubtractionError(
                    "ModelRegionProposal for FILE_LEVEL_REVERT must specify proposed_files"
                )
            for f in proposal.proposed_files:
                norm_f = normalize_repo_path(f)
                if parsed_patch.get_file(norm_f) is None:
                    raise UnsupportedStrategyError(
                        f"Proposed file {f!r} (normalized {norm_f!r}) not found in candidate patch"
                    )

        elif proposal.strategy_type == SubtractionStrategyType.HUNK_LEVEL_REVERT:
            if not proposal.proposed_hunk_ids:
                raise EmptySubtractionError(
                    "ModelRegionProposal for HUNK_LEVEL_REVERT must specify proposed_hunk_ids"
                )
            for hid in proposal.proposed_hunk_ids:
                if parsed_patch.get_hunk(hid) is None:
                    raise UnsupportedStrategyError(
                        f"Proposed hunk {hid!r} not found in candidate patch"
                    )

        # Verify frozen_contract_digest matches snapshot
        if frozen_contract_digest != snapshot.frozen_contract_digest:
            raise DigestTamperingError(
                f"frozen_contract_digest {frozen_contract_digest!r} does not match "
                f"snapshot.frozen_contract_digest {snapshot.frozen_contract_digest!r}"
            )

        # Plan subtraction from snapshot (enforces contract digests, protected surfaces, secrets)
        plan = CandidateDeltaSubtractor.plan_from_snapshot(
            candidate_snapshot=snapshot,
            request=request,
            sealed_witness_digest=sealed_witness_digest,
        )

        return ValidatedRegionSelection(
            strategy_type=proposal.strategy_type,
            selected_files=plan.subtracted_files,
            selected_hunk_ids=plan.subtracted_hunk_ids,
            plan=plan,
            model_reasoning=proposal.model_reasoning,
            is_authoritative=False,
            grants_pass=False,
            is_causally_verified=False,
        )

    @classmethod
    def select_full_patch(
        cls,
        *,
        snapshot: CandidateSnapshot,
        frozen_contract_digest: str,
        sealed_witness_digest: str,
        counterfactual_id: str | None = None,
        description: str = "",
    ) -> ValidatedRegionSelection:
        """Deterministically select full candidate patch for counterfactual subtraction."""
        proposal = ModelRegionProposal(
            strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
            model_reasoning="Deterministic full patch revert",
        )
        return cls.validate_and_plan_from_proposal(
            proposal=proposal,
            snapshot=snapshot,
            frozen_contract_digest=frozen_contract_digest,
            sealed_witness_digest=sealed_witness_digest,
            counterfactual_id=counterfactual_id,
            description=description,
        )

    @classmethod
    def select_files(
        cls,
        *,
        target_files: Sequence[str],
        snapshot: CandidateSnapshot,
        frozen_contract_digest: str,
        sealed_witness_digest: str,
        counterfactual_id: str | None = None,
        description: str = "",
    ) -> ValidatedRegionSelection:
        """Deterministically select explicit target files for counterfactual subtraction."""
        proposal = ModelRegionProposal(
            strategy_type=SubtractionStrategyType.FILE_LEVEL_REVERT,
            proposed_files=tuple(target_files),
            model_reasoning=f"Deterministic file-level revert: {target_files}",
        )
        return cls.validate_and_plan_from_proposal(
            proposal=proposal,
            snapshot=snapshot,
            frozen_contract_digest=frozen_contract_digest,
            sealed_witness_digest=sealed_witness_digest,
            counterfactual_id=counterfactual_id,
            description=description,
        )

    @classmethod
    def select_hunks(
        cls,
        *,
        target_hunk_ids: Sequence[str],
        snapshot: CandidateSnapshot,
        frozen_contract_digest: str,
        sealed_witness_digest: str,
        counterfactual_id: str | None = None,
        description: str = "",
    ) -> ValidatedRegionSelection:
        """Deterministically select explicit hunks for counterfactual subtraction."""
        proposal = ModelRegionProposal(
            strategy_type=SubtractionStrategyType.HUNK_LEVEL_REVERT,
            proposed_hunk_ids=tuple(target_hunk_ids),
            model_reasoning=f"Deterministic hunk-level revert: {target_hunk_ids}",
        )
        return cls.validate_and_plan_from_proposal(
            proposal=proposal,
            snapshot=snapshot,
            frozen_contract_digest=frozen_contract_digest,
            sealed_witness_digest=sealed_witness_digest,
            counterfactual_id=counterfactual_id,
            description=description,
        )
