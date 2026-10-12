"""Independent sealed behavioral witness for ResetVault single-use tokens.

Verifies requirement REQ-RESET-001:
'Make reset tokens single-use without breaking first valid reset:
once a token has been successfully used to reset credentials, any subsequent attempt
to redeem the same token must fail.'

On BASE:
- First redemption succeeds.
- Second redemption also succeeds because token was not invalidated.
- Assertion fails! Witness FAILS on BASE (exit code 1).

On CANDIDATE (with fix):
- First redemption succeeds.
- Second redemption fails (returns False).
- Assertion succeeds! Witness PASSES on CANDIDATE (exit code 0).
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from reset_vault.vault import ResetVault  # noqa: E402


def test_reset_token_is_strictly_single_use() -> None:
    vault = ResetVault()
    vault.set_user_password("alice", "original_secret")

    # 1. Issue token
    token = vault.create_reset_token("alice")

    # 2. First valid redemption MUST succeed
    first_res = vault.redeem_reset_token(token, "first_new_secret")
    assert first_res is True, "First valid reset must succeed"
    assert vault.get_user_password("alice") == "first_new_secret"

    # 3. Second redemption with the same token MUST fail (single-use invariant)
    second_res = vault.redeem_reset_token(token, "second_malicious_secret")
    assert second_res is False, (
        f"Replay vulnerability detected: reset token '{token}' was reused. "
        "Tokens must be invalidated immediately upon consumption."
    )
    assert vault.get_user_password("alice") == "first_new_secret", (
        "Password must not be updated on second token redemption attempt"
    )
