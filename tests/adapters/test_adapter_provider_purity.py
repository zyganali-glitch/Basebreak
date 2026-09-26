"""Provider-purity tests verifying domain/evidence/security isolation from adapters.

Authority:
- Rule 19: provider-neutral domain/security/evidence modules remain free of
  Nebius / Token Factory client imports.
- Section 4: Provider-specific facts MAY live in P-05 adapter code. They MUST NOT
  leak backward into domain/, evidence/, security/.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent.parent / "src" / "basebreak"


def _get_python_files(subpkg: str) -> list[Path]:
    pkg_dir = SRC_DIR / subpkg
    assert pkg_dir.exists(), f"Directory not found: {pkg_dir}"
    return list(pkg_dir.glob("**/*.py"))


def _extract_imported_modules(py_file: Path) -> set[str]:
    content = py_file.read_text(encoding="utf-8")
    tree = ast.parse(content, filename=str(py_file))
    imported: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module)
    return imported


class TestProviderPurity:
    """Verifies that domain, evidence, and security packages do not import adapters."""

    def test_domain_has_zero_adapter_imports(self) -> None:
        files = _get_python_files("domain")
        for f in files:
            imported = _extract_imported_modules(f)
            for mod in imported:
                assert not mod.startswith("basebreak.adapters"), (
                    f"Domain file '{f.name}' violates provider purity by importing '{mod}'"
                )
                assert not mod.startswith("adapters"), (
                    f"Domain file '{f.name}' violates provider purity by importing '{mod}'"
                )

    def test_evidence_has_zero_adapter_imports(self) -> None:
        files = _get_python_files("evidence")
        for f in files:
            imported = _extract_imported_modules(f)
            for mod in imported:
                assert not mod.startswith("basebreak.adapters"), (
                    f"Evidence file '{f.name}' violates provider purity by importing '{mod}'"
                )
                assert not mod.startswith("adapters"), (
                    f"Evidence file '{f.name}' violates provider purity by importing '{mod}'"
                )

    def test_security_has_zero_adapter_imports(self) -> None:
        files = _get_python_files("security")
        for f in files:
            imported = _extract_imported_modules(f)
            for mod in imported:
                assert not mod.startswith("basebreak.adapters"), (
                    f"Security file '{f.name}' violates provider purity by importing '{mod}'"
                )
                assert not mod.startswith("adapters"), (
                    f"Security file '{f.name}' violates provider purity by importing '{mod}'"
                )
