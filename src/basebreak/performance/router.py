"""Deterministic model and strategy routing based on measured workload facts.

P-26.04: Model routing decision logic based strictly on measured facts.
Routes requests deterministically to appropriate models and verification strategies
based on change classification, security risk tier, reasoning requirements, and budget constraints.
No speculative routing or unmeasured claims.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from basebreak.domain.semantics import ChangeClass


class RiskTier(str, Enum):
    """Risk tier of target change determining model capability requirements."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True, slots=True)
class WorkloadProfile:
    """Factual attributes of the verification task used for routing decisions."""

    change_class: ChangeClass
    risk_tier: RiskTier
    requires_deep_reasoning: bool = False
    token_budget: int = 16384
    has_security_boundary_impact: bool = False

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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ModelRouter:
    """Fact-based deterministic router for Builder model and Verifier strategy selection."""

    # Canonical model identifiers proven in Basebreak architecture
    MODEL_NEMOTRON_70B = "nvidia/llama-3.1-nemotron-70b-instruct"
    MODEL_LLAMA_70B = "meta-llama/llama-3.3-70b-instruct"
    MODEL_REASONING_R1 = "deepseek-ai/deepseek-r1"

    @classmethod
    def route_workload(cls, profile: WorkloadProfile) -> ModelRouteDecision:
        """Route workload to optimal model and verifier strategy based on factual profile."""
        # 1. Critical risk or security boundary impact -> Maximum capability reasoning + templates
        if profile.risk_tier == RiskTier.CRITICAL or profile.has_security_boundary_impact:
            return ModelRouteDecision(
                builder_model_id=cls.MODEL_NEMOTRON_70B,
                verifier_strategy="TEMPLATE_GUIDED",
                temperature=0.0,
                max_tokens=min(profile.token_budget, 4096),
                rationale=(
                    "Critical risk or security boundary impact mandates deterministic "
                    "Nemotron model with template-guided verifier strategy."
                ),
            )

        # 2. Deep reasoning requirement or complex bug fix -> Deep reasoning model + reflection
        if profile.requires_deep_reasoning or (
            profile.change_class == ChangeClass.BUG_FIX and profile.risk_tier == RiskTier.HIGH
        ):
            return ModelRouteDecision(
                builder_model_id=cls.MODEL_REASONING_R1,
                verifier_strategy="MULTI_TURN_REFLECTION",
                temperature=0.2,
                max_tokens=min(profile.token_budget, 4096),
                rationale=(
                    "High-risk bug fix or complex logic requires deep reasoning model "
                    "with multi-turn verifier reflection."
                ),
            )

        # 3. Standard bug fix -> Nemotron 70B standard
        if profile.change_class == ChangeClass.BUG_FIX:
            return ModelRouteDecision(
                builder_model_id=cls.MODEL_NEMOTRON_70B,
                verifier_strategy="MULTI_TURN_REFLECTION",
                temperature=0.2,
                max_tokens=min(profile.token_budget, 2048),
                rationale="Standard bug fix routes to Nemotron with reflection.",
            )

        # 4. Low risk refactor or docs -> Fast efficient Llama-3.3-70B with single-shot
        return ModelRouteDecision(
            builder_model_id=cls.MODEL_LLAMA_70B,
            verifier_strategy="SINGLE_SHOT",
            temperature=0.3,
            max_tokens=min(profile.token_budget, 2048),
            rationale="Low-risk or non-bug modification routes to efficient model.",
        )
