"""Canonical ResetVault frozen-contract authority (production, import-safe).

This module is the single authoritative factory for the canonical ResetVault
frozen contract consumed by the trusted verifier bridge
(``basebreak.deployment.live_bridge``) and by the P-23 killer-demo tests.

It depends only on production modules and the Python standard library. It must
never import pytest or any test module, so the deployed bridge runtime can build
the canonical scenario without test-only dependencies (repairs the production
defect where a correctly signed request crashed on ``import pytest``).
"""

from __future__ import annotations

import hashlib
import json

from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.compiler.semantics import CertaintyLevel
from basebreak.domain.semantics import ChangeClass

# Canonical ResetVault task statement (P-23.02). Editing this text changes the
# frozen contract digest and must be treated as a re-freeze (update every
# canonical digest pin and re-run the trust gates).
RESET_VAULT_TASK_TEXT: str = (
    "Make reset tokens single-use without breaking first valid reset: "
    "once a token has been successfully used to update a password, "
    "any subsequent redemption attempt with that same token must fail."
)

CANONICAL_RESET_VAULT_REQUIREMENT_ID: str = "REQ-RESET-001"


def create_reset_vault_frozen_contract() -> FrozenContract:
    """Create the authentic FrozenContract for the canonical ResetVault scenario (P-23.02).

    Import-safe for production: this function has no pytest or test-module
    dependency. Semantics (task digest, change class, certainty, requirement,
    contract digest) are preserved exactly from the original P-23 factory.
    """
    req = FrozenRequirement(
        requirement_id=CANONICAL_RESET_VAULT_REQUIREMENT_ID,
        statement="Reset tokens must be strictly single-use; subsequent redemption attempts fail",
        citation="once a token has been successfully used, any subsequent redemption must fail",
        citation_start=0,
        citation_end=75,
        rationale="Prevent replay attacks reusing valid password reset tokens",
    )
    contract = object.__new__(FrozenContract)
    object.__setattr__(contract, "schema_version", "1.0.0")
    object.__setattr__(
        contract,
        "task_digest",
        hashlib.sha256(RESET_VAULT_TASK_TEXT.encode("utf-8")).hexdigest(),
    )
    object.__setattr__(contract, "change_class", ChangeClass.BUG_FIX)
    object.__setattr__(contract, "certainty", CertaintyLevel.CONFIDENT)
    object.__setattr__(contract, "requirements", (req,))
    contract_bytes = json.dumps(
        {
            "requirements": [req.to_dict()],
            "task": RESET_VAULT_TASK_TEXT,
        },
        sort_keys=True,
    ).encode("utf-8")
    object.__setattr__(
        contract,
        "contract_digest",
        hashlib.sha256(contract_bytes).hexdigest(),
    )
    return contract
