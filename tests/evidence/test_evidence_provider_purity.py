"""Provider purity verification tests for basebreak.evidence.

Verifies that src/basebreak/evidence remains strictly provider-neutral and free of:
- Nebius SDK/domain types;
- NVIDIA SDK/domain types;
- Tavily SDK/domain types;
- provider-specific sandbox fields;
- model IDs/endpoints/regions;
- checkpoint/clone/branch/snapshot assumptions.
"""

from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

ALLOWED_STDLIB_MODULES = frozenset(
    {
        "__future__",
        "ast",
        "collections",
        "collections.abc",
        "dataclasses",
        "enum",
        "hashlib",
        "json",
        "math",
        "pathlib",
        "re",
        "sys",
        "typing",
    }
)

FORBIDDEN_IMPORT_PREFIXES = (
    "nebius",
    "nvidia",
    "tavily",
    "openai",
    "anthropic",
    "langchain",
    "e2b",
    "daytona",
    "boto3",
    "botocore",
    "azure",
)

FORBIDDEN_STRING_FRAGMENTS = (
    "api.studio.nebius.ai",
    "token_factory",
    "tokenfactory",
    "nemotron",
    "tavily.com",
    "integrate.api.nvidia.com",
    "eu-north1",
    "eu-west1",
    "us-central1",
    "nvidia/llama-3.1-nemotron",
)

FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "checkpoint_id",
        "snapshot_id",
        "branch_name",
        "git_branch",
        "clone_depth",
        "fork_url",
    }
)


def _get_evidence_python_files() -> list[Path]:
    evidence_dir = Path(__file__).resolve().parent.parent.parent / "src" / "basebreak" / "evidence"
    assert evidence_dir.is_dir(), f"Evidence directory not found at {evidence_dir}"
    return list(evidence_dir.glob("*.py"))


class TestEvidenceProviderPurityAST:
    def test_evidence_files_exist(self) -> None:
        files = _get_evidence_python_files()
        assert len(files) >= 2, f"Expected at least 2 evidence files, found {len(files)}"

    def test_imports_strictly_stdlib_and_internal(self) -> None:
        files = _get_evidence_python_files()
        for filepath in files:
            tree = ast.parse(filepath.read_text(encoding="utf-8"), filename=str(filepath))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top_module = alias.name.split(".")[0]
                        for forbidden in FORBIDDEN_IMPORT_PREFIXES:
                            assert not alias.name.startswith(forbidden), (
                                f"{filepath.name} imports forbidden module: {alias.name}"
                            )
                        is_allowed = (
                            alias.name in ALLOWED_STDLIB_MODULES
                            or top_module in ALLOWED_STDLIB_MODULES
                            or alias.name.startswith("basebreak.")
                        )
                        assert is_allowed, (
                            f"{filepath.name} imports non-allowlisted module: {alias.name}"
                        )

                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    top_module = module.split(".")[0]
                    for forbidden in FORBIDDEN_IMPORT_PREFIXES:
                        assert not module.startswith(forbidden), (
                            f"{filepath.name} imports forbidden module from: {module}"
                        )
                    is_allowed = (
                        module in ALLOWED_STDLIB_MODULES
                        or top_module in ALLOWED_STDLIB_MODULES
                        or module.startswith("basebreak.")
                    )
                    assert is_allowed, (
                        f"{filepath.name} imports from non-allowlisted module: {module}"
                    )

    def test_no_provider_string_literals_or_endpoints(self) -> None:
        files = _get_evidence_python_files()
        for filepath in files:
            tree = ast.parse(filepath.read_text(encoding="utf-8"), filename=str(filepath))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    lower_val = node.value.lower()
                    for fragment in FORBIDDEN_STRING_FRAGMENTS:
                        assert fragment not in lower_val, (
                            f"{filepath.name} contains forbidden provider fragment "
                            f"{fragment!r} in string literal: {node.value!r}"
                        )

    def test_no_provider_sandbox_assumptions_or_fields(self) -> None:
        files = _get_evidence_python_files()
        for filepath in files:
            tree = ast.parse(filepath.read_text(encoding="utf-8"), filename=str(filepath))
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    for item in node.body:
                        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                            assert item.target.id not in FORBIDDEN_FIELD_NAMES, (
                                f"{filepath.name} defines forbidden field {item.target.id} "
                                f"in class {node.name}"
                            )


class TestEvidenceProviderPurityRuntime:
    def test_runtime_sys_modules_purity(self) -> None:
        mod = importlib.import_module("basebreak.evidence.artifact")
        for attr_name, attr_val in vars(mod).items():
            if hasattr(attr_val, "__module__") and attr_val.__module__:
                for forbidden in FORBIDDEN_IMPORT_PREFIXES:
                    assert not attr_val.__module__.startswith(forbidden), (
                        f"Module artifact attribute {attr_name} "
                        f"has forbidden module {attr_val.__module__}"
                    )

        loaded_modules = set(sys.modules.keys())
        for forbidden in FORBIDDEN_IMPORT_PREFIXES:
            matching = [
                m for m in loaded_modules if m == forbidden or m.startswith(f"{forbidden}.")
            ]
            assert not matching, f"Forbidden provider module loaded: {matching}"
