"""Nebius Token Factory model identifiers, endpoints, and bounding constants.

Authority:
- LIVE_PROVEN in P-01.02: nvidia/Nemotron-3_5-Lightning
- CATALOG_CONFIRMED (not yet live validated): nvidia/nemotron-3-super-120b-a12b
- Proven endpoint: https://api.tokenfactory.nebius.com/v1/chat/completions
"""

from __future__ import annotations

# Primary live-proven model from P-01.02
DEFAULT_PRIMARY_MODEL: str = "nvidia/Nemotron-3_5-Lightning"

# Catalog-confirmed deep model; NOT yet live validated; MUST NOT be default
CANDIDATE_DEEP_MODEL: str = "nvidia/nemotron-3-super-120b-a12b"

# Model context lengths verified from provider catalog (total sequence capacity: prompt + output)
MODEL_CONTEXT_LENGTHS: dict[str, int] = {
    DEFAULT_PRIMARY_MODEL: 1_048_576,
    CANDIDATE_DEEP_MODEL: 1_048_576,
}

# Maximum output (completion) tokens supported by the provider/model architecture.
# The context length (1,048,576) defines the total sequence capacity (prompt + output),
# whereas output generation is bounded by the architecture's maximum generation
# length (262,144 tokens).
# 1,048,576 context tokens do NOT authorize 1,048,576 output tokens.
MODEL_MAX_OUTPUT_TOKENS: dict[str, int] = {
    DEFAULT_PRIMARY_MODEL: 262_144,
    CANDIDATE_DEEP_MODEL: 262_144,
}

# Proven API base URL and endpoint
DEFAULT_API_BASE_URL: str = "https://api.tokenfactory.nebius.com/v1"
CHAT_COMPLETIONS_PATH: str = "/chat/completions"

# Operational bounds
DEFAULT_TIMEOUT_SECONDS: float = 90.0
MIN_TIMEOUT_SECONDS: float = 0.5
MAX_TIMEOUT_SECONDS: float = 300.0

DEFAULT_MAX_TOKENS: int = 32768
MIN_MAX_TOKENS: int = 1
MAX_MAX_TOKENS: int = 262_144

DEFAULT_TEMPERATURE: float = 0.0
MIN_TEMPERATURE: float = 0.0
MAX_TEMPERATURE: float = 2.0

# Payload and response bounds
MAX_PROMPT_CHARACTERS: int = 500_000
MAX_RESPONSE_CHARACTERS: int = 500_000
