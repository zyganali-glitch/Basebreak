"""Deterministic model and strategy routing based on verified provider facts.

P-26.04: Model routing decision logic based strictly on measured facts and provider truth.
Routes requests deterministically to appropriate verification strategies and verified models
based on change classification, security risk tier, reasoning requirements, and budget constraints.
No speculative routing, unmeasured optimality claims, or unverified model assumptions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from basebreak.adapters.nebius.models import (
    CANDIDATE_DEEP_MODEL,
    DEFAULT_PRIMARY_MODEL,
)
from basebreak.domain.semantics import ChangeClass


class UnsupportedModelError(ValueError):
    """Raised when an unverified or unsupported model ID is requested."""


class UnmeasuredOptimalityError(ValueError):
    """Raised when an empirical optimality claim is attempted without measured provider evidence."""


class StaleModelEligibilityError(ValueError):
    """Raised when relying on unverified or stale provider eligibility assumptions."""


class RiskTier(str, Enum):
    """Risk tier of target change determining model capability requirements."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ModelEligibilityStatus(str, Enum):
    """Verified provider eligibility status on Nebius Token Factory."""

    LIVE_PROVEN = "LIVE_PROVEN"
    CATALOG_CONFIRMED = "CATALOG_CONFIRMED"
    UNVERIFIED = "UNVERIFIED"


VERIFIED_PROVIDER_MODELS: dict[str, ModelEligibilityStatus] = {
    DEFAULT_PRIMARY_MODEL: ModelEligibilityStatus.LIVE_PROVEN,
    CANDIDATE_DEEP_MODEL: ModelEligibilityStatus.CATALOG_CONFIRMED,
}


@dataclass(frozen=True, slots=True)
class WorkloadProfile:
    """Factual attributes of the verification task used for routing decisions."""

    change_class: ChangeClass
    risk_tier: RiskTier
    requires_deep_reasoning: bool = False
    token_budget: int = 16384
    has_security_boundary_impact: bool = False
    requested_model_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["change_class"] = self.change_class.value
        d["risk_tier"] = self.risk_tier.value
        return d


@dataclass(frozen=True, slots=True)
class ModelRouteDecision:
    """Deterministic routing decision specifying model, strategy, and parameter bounds."""

    builder_model_id: str
    verifier_strategy: str
    temperature: float
    max_tokens: int
    rationale: str
    is_empirically_optimal: bool = False
    model_eligibility: str = "LIVE_PROVEN"
    has_measured_evidence: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ModelRouter:
    """Fact-based deterministic router for Builder model and Verifier strategy selection."""

    DEFAULT_BUILDER_MODEL: str = DEFAULT_PRIMARY_MODEL

    @classmethod
    def route_workload(
        cls,
        profile: WorkloadProfile,
        *,
        claim_empirical_optimality: bool = False,
    ) -> ModelRouteDecision:
        """Route workload to verified model and verifier strategy based on factual profile.

        Fails closed if an unverified model is requested or if empirical optimality is
        claimed without measured benchmark evidence.
        """
        if claim_empirical_optimality:
            raise UnmeasuredOptimalityError(
                "Cannot claim empirical optimality without measured quality/cost benchmark "
                "evidence on target Nebius provider endpoints."
            )

        # 1. Model resolution: preserve verified provider configuration
        if profile.requested_model_id is not None:
            if profile.requested_model_id not in VERIFIED_PROVIDER_MODELS:
                verified_list = list(VERIFIED_PROVIDER_MODELS.keys())
                raise UnsupportedModelError(
                    f"Model '{profile.requested_model_id}' is not verified or supported on "
                    f"Nebius Token Factory. Verified models: {verified_list}"
                )
            selected_model = profile.requested_model_id
            eligibility = VERIFIED_PROVIDER_MODELS[selected_model].value
        else:
            selected_model = cls.DEFAULT_BUILDER_MODEL
            eligibility = ModelEligibilityStatus.LIVE_PROVEN.value

        # 2. Strategy resolution based on deterministic risk policy
        if profile.risk_tier == RiskTier.CRITICAL or profile.has_security_boundary_impact:
            return ModelRouteDecision(
                builder_model_id=selected_model,
                verifier_strategy="TEMPLATE_GUIDED",
                temperature=0.0,
                max_tokens=min(profile.token_budget, 4096),
                rationale=(
                    f"Critical risk or security boundary impact mandates deterministic "
                    f"strategy TEMPLATE_GUIDED with verified model {selected_model}."
                ),
                is_empirically_optimal=False,
                model_eligibility=eligibility,
                has_measured_evidence=False,
            )

        if profile.requires_deep_reasoning or (
            profile.change_class == ChangeClass.BUG_FIX and profile.risk_tier == RiskTier.HIGH
        ):
            return ModelRouteDecision(
                builder_model_id=selected_model,
                verifier_strategy="MULTI_TURN_REFLECTION",
                temperature=0.2,
                max_tokens=min(profile.token_budget, 4096),
                rationale=(
                    f"High-risk bug fix or complex reasoning mandates MULTI_TURN_REFLECTION "
                    f"strategy with verified model {selected_model}."
                ),
                is_empirically_optimal=False,
                model_eligibility=eligibility,
                has_measured_evidence=False,
            )

        if profile.change_class == ChangeClass.BUG_FIX:
            return ModelRouteDecision(
                builder_model_id=selected_model,
                verifier_strategy="MULTI_TURN_REFLECTION",
                temperature=0.2,
                max_tokens=min(profile.token_budget, 2048),
                rationale=(
                    f"Standard bug fix routes to MULTI_TURN_REFLECTION strategy "
                    f"with verified model {selected_model}."
                ),
                is_empirically_optimal=False,
                model_eligibility=eligibility,
                has_measured_evidence=False,
            )

        return ModelRouteDecision(
            builder_model_id=selected_model,
            verifier_strategy="SINGLE_SHOT",
            temperature=0.3,
            max_tokens=min(profile.token_budget, 2048),
            rationale=(
                f"Low-risk or non-bug modification routes to SINGLE_SHOT strategy "
                f"with verified model {selected_model}."
            ),
            is_empirically_optimal=False,
            model_eligibility=eligibility,
            has_measured_evidence=False,
        )
