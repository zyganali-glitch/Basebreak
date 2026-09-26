"""Nebius Token Factory Sandbox constants and endpoints.

Authority:
- Discovered and verified live in P-01.03 (docs/P01_03_LIVE_SANDBOX_DISCOVERY.md)
- OpenAPI spec: Contree API v1.0.0 (https://eu-north.nebius.computer/static/api.yaml)
- Operational ceilings frozen in P-04.03 (src/basebreak/security/sandbox_policy.py)
"""

from __future__ import annotations

# Proven API base URL and paths
DEFAULT_SANDBOX_API_BASE_URL: str = "https://api.tokenfactory.nebius.com/sandboxes/v1"
INSTANCES_PATH: str = "/instances"
OPERATIONS_PATH: str = "/operations"
WHOAMI_PATH: str = "/whoami"

# Proven pre-warmed container images
DEFAULT_SANDBOX_IMAGE: str = "tag:astral/uv:python3.11-alpine"
BUSYBOX_SANDBOX_IMAGE: str = "tag:busybox:latest"

# Operational bounds (strictly compliant with P-04.03 ceilings)
DEFAULT_SANDBOX_TIMEOUT_SECONDS: int = 180
MIN_SANDBOX_TIMEOUT_SECONDS: int = 1
MAX_SANDBOX_TIMEOUT_SECONDS: int = 600  # Strict operational upper bound (<= 3600)

MAX_COMMAND_LENGTH_BYTES: int = 16_384  # 16 KB command string upper limit
DEFAULT_POLL_INTERVAL_SECONDS: float = 0.5
MAX_POLL_INTERVAL_SECONDS: float = 5.0
