"""Tests for isolated demo target fixture and identity separation.

Validates that:
1. The controlled BUG_FIX demonstration target exists completely outside
   production Basebreak implementation surfaces.
2. Basebreak production package (src/basebreak) contains zero planted defects
   and no premature CLI implementation.
3. The demo target in tests/fixtures/demo_target exhibits the expected BASE defect
   (format_quiet_output returns verbose output when quiet=True).
4. The candidate patch fixes the defect cleanly and does not collide with any
   canonical Basebreak protected surfaces.
5. Exact target repository identity (locator, commit, tree, patch) is isolated
   from Basebreak implementation identity.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

from basebreak.security.protected_surfaces import (
    get_canonical_basebreak_protected_manifest,
    validate_diff,
)
from basebreak.security.secret_policy import validate_no_secrets

DEMO_FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "demo_target"
DEMO_CLI_PATH = DEMO_FIXTURE_DIR / "src" / "demo_target" / "cli.py"


def _load_demo_cli_module() -> object:
    spec = importlib.util.spec_from_file_location("demo_target.cli", DEMO_CLI_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestDemoTargetIsolation:
    """Verifies isolation of demonstration target from production surfaces."""

    def test_production_basebreak_contains_no_cli_or_planted_defect(self) -> None:
        """Basebreak production source (src/basebreak) must not contain cli.py or defect."""
        repo_root = Path(__file__).resolve().parent.parent.parent
        prod_cli = repo_root / "src" / "basebreak" / "cli.py"
        assert not prod_cli.exists(), "src/basebreak/cli.py must NOT exist in production source!"

        # Ensure no format_quiet_output definition in any production file
        prod_src = repo_root / "src" / "basebreak"
        for py_file in prod_src.rglob("*.py"):
            text = py_file.read_text(encoding="utf-8")
            assert "def format_quiet_output" not in text, (
                f"Planted defect definition found in production file: {py_file}"
            )

    def test_demo_target_fixture_contains_intentional_defect(self) -> None:
        """The isolated demo target fixture must contain the controlled defect."""
        assert DEMO_CLI_PATH.exists(), f"Demo CLI fixture must exist at {DEMO_CLI_PATH}"
        demo_mod: object = _load_demo_cli_module()
        format_func = getattr(demo_mod, "format_quiet_output")

        # Verbose/quiet=False works normally
        assert format_func("test output", quiet=False) == "test output"

        # Under BASE: quiet=True intentionally produces "verbose: test output" (DEFECT)
        base_result = format_func("test output", quiet=True)
        assert base_result == "verbose: test output", (
            f"Expected planted defect 'verbose: test output', got {base_result!r}"
        )

    def test_candidate_patch_is_secret_safe_and_protects_canonical_surfaces(self) -> None:
        """Candidate patch modifies demo target only and collides with zero protected surfaces."""
        patch_text = (
            "diff --git a/src/demo_target/cli.py b/src/demo_target/cli.py\n"
            "index 878b16f..f2e0928 100644\n"
            "--- a/src/demo_target/cli.py\n"
            "+++ b/src/demo_target/cli.py\n"
            "@@ -13,5 +13,5 @@ def format_quiet_output(output: str, quiet: bool = False) -> str:\n"
            '     When quiet is True, stdout must be empty ("").\n'
            '     """\n'
            "     if quiet:\n"
            '-        return "verbose: " + output\n'
            '+        return ""\n'
            "     return output\n"
        )
        # Secret safety check
        validate_no_secrets(patch_text, path="demo_target_candidate_patch")

        # Protected surfaces check
        manifest = get_canonical_basebreak_protected_manifest()
        validate_diff(patch_text, manifest)

        # Patch digest verification
        patch_digest = hashlib.sha256(patch_text.encode("utf-8")).hexdigest()
        assert len(patch_digest) == 64

    def test_fixed_code_satisfies_quiet_requirement(self) -> None:
        """Applying the candidate fix produces empty string on quiet=True."""
        base_code = DEMO_CLI_PATH.read_text(encoding="utf-8")
        fixed_code = base_code.replace('"verbose: " + output', '""')

        # Execute fixed code in a clean namespace
        ns: dict[str, object] = {}
        exec(fixed_code, ns)
        fixed_func = ns["format_quiet_output"]
        assert callable(fixed_func)

        assert fixed_func("test output", quiet=False) == "test output"
        assert fixed_func("test output", quiet=True) == ""
