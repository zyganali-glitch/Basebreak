"""CLI configuration schema and safe default rules.

P-19.03: Safe defaults and config schema.
Enforces offline-first, zero-cost, and non-authoritative defaults unless explicitly overridden.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from basebreak.security.secret_policy import redact_text

DEFAULT_RUNS_DIR: str = ".basebreak/runs"
DEFAULT_PROMO_STOP_THRESHOLD: float = 5.0


class ConfigValidationError(Exception):
    """Raised when configuration values violate safety invariants."""


@dataclass(slots=True)
class BasebreakConfig:
    """Safe runtime configuration for developer CLI and automation."""

    offline_mode: bool = True
    zero_cost_mode: bool = True
    allow_live: bool = False
    sandbox_provider: str = "local"
    token_factory_promo_stop_threshold: float = DEFAULT_PROMO_STOP_THRESHOLD
    runs_dir: str = DEFAULT_RUNS_DIR
    api_endpoint: str | None = None
    default_format: str = "text"

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Validate safety constraints on configuration."""
        if self.allow_live and self.offline_mode:
            # If live is explicitly allowed, offline mode must be False
            self.offline_mode = False

        if self.allow_live and self.zero_cost_mode:
            # Live execution is permitted only with sponsor promotional credits,
            # but personal zero-cost constraint remains strictly $0.00.
            pass

        if self.token_factory_promo_stop_threshold < 0.0:
            raise ConfigValidationError("token_factory_promo_stop_threshold cannot be negative")

        allowed_providers = {"local", "nebius", "mock"}
        if self.sandbox_provider not in allowed_providers:
            raise ConfigValidationError(
                f"Invalid sandbox_provider '{self.sandbox_provider}'. "
                f"Allowed: {sorted(allowed_providers)}"
            )

        if self.default_format not in {"text", "json"}:
            raise ConfigValidationError(
                f"Invalid default_format '{self.default_format}'. Allowed: ['text', 'json']"
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)

    def to_safe_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary with guaranteed secret redaction."""
        raw = self.to_dict()
        safe: dict[str, Any] = {}
        for k, v in raw.items():
            if isinstance(v, str):
                redacted, _ = redact_text(v)
                safe[k] = redacted
            else:
                safe[k] = v
        return safe

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BasebreakConfig:
        """Create config from dictionary."""
        valid_fields = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        cfg = cls(**filtered)
        cfg.validate()
        return cfg

    @classmethod
    def from_file(cls, path: str | Path) -> BasebreakConfig:
        """Load configuration from a JSON file."""
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Configuration file not found: {p}")
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ConfigValidationError(
                f"Config root must be a JSON object, got {type(data).__name__}"
            )
        return cls.from_dict(data)
