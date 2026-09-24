"""Focused acceptance and closure tests for Master Plan task P-04.04.

Validates the thirteen required Master Plan acceptance criteria:
A. exact protected-file mutation rejection
B. protected-directory descendant rejection
C. safe unprotected path acceptance
D. ../ traversal attempt rejection
E. absolute path rejection
F. Windows separator / mixed-separator bypass attempt
G. case-normalization bypass attempt
H. rename/move onto a protected path
I. rename/move away from a protected path
J. symlink target traversal / root escape
K. symlink interaction with protected paths where deterministically knowable
L. normalization stability / determinism
M. no provider-specific dependency or assumption
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from basebreak.security.protected_surfaces import (
    FileChange,
    FileChangeKind,
    PathTraversalError,
    ProtectedSurfaceManifest,
    ProtectedSurfaceViolation,
    ProtectedSurfaceViolationKind,
    check_change,
    check_protected_surfaces,
    get_canonical_basebreak_protected_manifest,
    is_path_protected,
    match_protected_surface,
    normalize_repo_path,
    validate_diff,
    validate_path,
    validate_protected_surfaces,
)


@pytest.fixture
def canonical_manifest() -> ProtectedSurfaceManifest:
    """Fixture providing the canonical Basebreak protected surface manifest."""
    return get_canonical_basebreak_protected_manifest()


@pytest.fixture
def test_manifest() -> ProtectedSurfaceManifest:
    """Fixture providing a focused test manifest with known exact and prefix surfaces."""
    return ProtectedSurfaceManifest(
        exact_files=frozenset({"AGENTS.md", "plans/BASEBREAK_MASTER_EXECUTION_PLAN.md"}),
        directory_prefixes=frozenset({"docs", "src/basebreak/security"}),
        description="Focused P-04.04 verification manifest",
    )


class TestCriterionAExactProtectedFileMutationRejection:
    """Criterion A: Exact protected-file mutation rejection."""

    @pytest.mark.parametrize(
        "change_kind",
        [FileChangeKind.MODIFY, FileChangeKind.ADD, FileChangeKind.DELETE],
    )
    def test_rejects_exact_protected_file_all_change_kinds(
        self, test_manifest: ProtectedSurfaceManifest, change_kind: FileChangeKind
    ) -> None:
        change = FileChange(path="AGENTS.md", kind=change_kind)
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.EXACT_MATCH
        assert findings[0].path == "AGENTS.md"
        assert findings[0].protected_pattern == "AGENTS.md"

        with pytest.raises(ProtectedSurfaceViolation, match="EXACT_MATCH"):
            validate_protected_surfaces([change], test_manifest)

    def test_rejects_nested_exact_protected_file(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.modify("plans/BASEBREAK_MASTER_EXECUTION_PLAN.md")
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.EXACT_MATCH
        assert findings[0].protected_pattern == "plans/BASEBREAK_MASTER_EXECUTION_PLAN.md"

    def test_exact_path_helpers_and_diff(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        assert is_path_protected("AGENTS.md", test_manifest) is True
        match = match_protected_surface("AGENTS.md", test_manifest)
        assert match is not None
        assert match.protected_pattern == "AGENTS.md"

        with pytest.raises(ProtectedSurfaceViolation):
            validate_path("AGENTS.md", test_manifest)

        diff = (
            "diff --git a/AGENTS.md b/AGENTS.md\n"
            "--- a/AGENTS.md\n"
            "+++ b/AGENTS.md\n"
            "@@ -1 +1 @@\n"
            "-a\n"
            "+b\n"
        )
        with pytest.raises(ProtectedSurfaceViolation):
            validate_diff(diff, test_manifest)


class TestCriterionBProtectedDirectoryDescendantRejection:
    """Criterion B: Protected-directory descendant rejection."""

    @pytest.mark.parametrize(
        "descendant_path",
        [
            "docs/SECURITY_BOUNDARY.md",
            "docs/DONOR_MANIFEST.md",
            "docs/sub/nested/file.txt",
            "src/basebreak/security/secret_policy.py",
            "src/basebreak/security/deeply/nested/helper.py",
        ],
    )
    def test_rejects_protected_directory_descendants(
        self, test_manifest: ProtectedSurfaceManifest, descendant_path: str
    ) -> None:
        change = FileChange.modify(descendant_path)
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.PREFIX_MATCH
        assert findings[0].path == descendant_path

        with pytest.raises(ProtectedSurfaceViolation, match="PREFIX_MATCH"):
            validate_protected_surfaces([change], test_manifest)


class TestCriterionCSafeUnprotectedPathAcceptance:
    """Criterion C: Safe unprotected path acceptance."""

    @pytest.mark.parametrize(
        "safe_path",
        [
            "src/basebreak/domain/source.py",
            "tests/domain/test_source.py",
            "src/app/main.py",
            "README.md",
            "pyproject.toml",
            "scripts/build.sh",
        ],
    )
    def test_accepts_safe_unprotected_paths(
        self, test_manifest: ProtectedSurfaceManifest, safe_path: str
    ) -> None:
        change = FileChange.modify(safe_path)
        findings = check_change(change, test_manifest)
        assert len(findings) == 0

        # Additional API coverage
        assert is_path_protected(safe_path, test_manifest) is False
        assert validate_path(safe_path, test_manifest) == safe_path
        assert check_protected_surfaces([safe_path], test_manifest).is_valid

        # validate_protected_surfaces passes without raising
        report = validate_protected_surfaces([change], test_manifest)
        assert report.is_valid
        assert len(report.violations) == 0


class TestCriterionDTraversalAttemptRejection:
    """Criterion D: ../ traversal attempt rejection."""

    @pytest.mark.parametrize(
        "traversal_path",
        [
            "../outside.txt",
            "../../etc/passwd",
            "../../../shadow",
            "foo/../../outside.py",
            "a/b/c/../../../../escape",
            "..",
            "sub/../..",
        ],
    )
    def test_rejects_path_traversal_above_root(
        self, test_manifest: ProtectedSurfaceManifest, traversal_path: str
    ) -> None:
        with pytest.raises(PathTraversalError, match="traverses above repository root"):
            normalize_repo_path(traversal_path)

        # In change checking, recorded as PATH_TRAVERSAL finding
        change = FileChange.modify(traversal_path)
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.PATH_TRAVERSAL

        with pytest.raises(ProtectedSurfaceViolation, match="PATH_TRAVERSAL"):
            validate_protected_surfaces([change], test_manifest)

    def test_internal_traversal_reaching_protected_surface_is_rejected(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        # Resolves logically to AGENTS.md within repo root
        change = FileChange.modify("unprotected/../AGENTS.md")
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.EXACT_MATCH
        assert findings[0].path == "AGENTS.md"


class TestCriterionEAbsolutePathRejection:
    """Criterion E: Absolute path rejection."""

    @pytest.mark.parametrize(
        "absolute_path",
        [
            "/etc/passwd",
            "/var/log/syslog",
            "//server/share/file.txt",
            "\\Windows\\System32\\cmd.exe",
            "C:/Windows/System32",
            "C:\\Windows\\System32",
            "d:untrusted.py",
            "~/.ssh/id_rsa",
            "~/config",
        ],
    )
    def test_rejects_absolute_drive_and_home_paths(
        self, test_manifest: ProtectedSurfaceManifest, absolute_path: str
    ) -> None:
        with pytest.raises(PathTraversalError):
            normalize_repo_path(absolute_path)

        change = FileChange.modify(absolute_path)
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.PATH_TRAVERSAL


class TestCriterionFWindowsSeparatorBypassAttempt:
    """Criterion F: Windows separator / mixed-separator bypass attempt."""

    def test_rejects_windows_separator_exact_file_bypass(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        # Attacker attempts to bypass POSIX path match by using backslashes
        change = FileChange.modify("plans\\BASEBREAK_MASTER_EXECUTION_PLAN.md")
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.EXACT_MATCH
        assert findings[0].path == "plans/BASEBREAK_MASTER_EXECUTION_PLAN.md"

    def test_rejects_windows_separator_prefix_bypass(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.modify("docs\\SECURITY_BOUNDARY.md")
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.PREFIX_MATCH
        assert findings[0].path == "docs/SECURITY_BOUNDARY.md"

    def test_rejects_mixed_separator_traversal_bypass(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.modify("unprotected\\../docs/SECURITY_BOUNDARY.md")
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.PREFIX_MATCH


class TestCriterionGCaseNormalizationBypassAttempt:
    """Criterion G: Case-normalization bypass attempt."""

    @pytest.mark.parametrize(
        "case_variant",
        [
            "agents.md",
            "Agents.md",
            "AGENTS.MD",
            "aGeNtS.mD",
        ],
    )
    def test_rejects_case_variant_exact_protected_file(
        self, test_manifest: ProtectedSurfaceManifest, case_variant: str
    ) -> None:
        change = FileChange.modify(case_variant)
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind in (
            ProtectedSurfaceViolationKind.EXACT_MATCH,
            ProtectedSurfaceViolationKind.CASE_FOLD_MATCH,
        )
        assert findings[0].protected_pattern == "AGENTS.md"

        with pytest.raises(ProtectedSurfaceViolation):
            validate_protected_surfaces([change], test_manifest)

    @pytest.mark.parametrize(
        "case_variant_prefix",
        [
            "DOCS/SECURITY_BOUNDARY.md",
            "Docs/security_boundary.md",
            "dOcS/file.txt",
            "SRC/BASEBREAK/SECURITY/secret_policy.py",
        ],
    )
    def test_rejects_case_variant_directory_prefix(
        self, test_manifest: ProtectedSurfaceManifest, case_variant_prefix: str
    ) -> None:
        change = FileChange.modify(case_variant_prefix)
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind in (
            ProtectedSurfaceViolationKind.PREFIX_MATCH,
            ProtectedSurfaceViolationKind.CASE_FOLD_MATCH,
        )


class TestCriterionHRenameOntoProtectedPath:
    """Criterion H: Rename/move onto a protected path."""

    def test_rejects_rename_onto_exact_protected_file(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.rename("unprotected/hack.md", "AGENTS.md")
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == (
            ProtectedSurfaceViolationKind.RENAME_DESTINATION_PROTECTED
        )
        assert findings[0].path == "AGENTS.md"

        with pytest.raises(ProtectedSurfaceViolation, match="RENAME_DESTINATION_PROTECTED"):
            validate_protected_surfaces([change], test_manifest)

    def test_rejects_rename_onto_protected_directory(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.rename("unprotected/hack.md", "docs/new_spec.md")
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == (
            ProtectedSurfaceViolationKind.RENAME_DESTINATION_PROTECTED
        )


class TestCriterionIRenameAwayFromProtectedPath:
    """Criterion I: Rename/move away from a protected path."""

    def test_rejects_rename_away_from_exact_protected_file(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.rename("AGENTS.md", "unprotected/agents_backup.md")
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.RENAME_SOURCE_PROTECTED
        assert findings[0].old_path == "AGENTS.md"

        with pytest.raises(ProtectedSurfaceViolation, match="RENAME_SOURCE_PROTECTED"):
            validate_protected_surfaces([change], test_manifest)

    def test_rejects_rename_away_from_protected_directory(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.rename("docs/SECURITY_BOUNDARY.md", "unprotected/moved.md")
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.RENAME_SOURCE_PROTECTED
        assert findings[0].old_path == "docs/SECURITY_BOUNDARY.md"


class TestCriterionJSymlinkTargetTraversal:
    """Criterion J: Symlink target traversal / root escape."""

    @pytest.mark.parametrize(
        "target",
        [
            "../../etc/passwd",
            "/etc/shadow",
            "C:\\Windows\\System32",
            "~/.ssh/authorized_keys",
        ],
    )
    def test_rejects_symlink_target_escaping_root(
        self, test_manifest: ProtectedSurfaceManifest, target: str
    ) -> None:
        change = FileChange.symlink("links/evil", target)
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.SYMLINK_TARGET_TRAVERSAL

        with pytest.raises(ProtectedSurfaceViolation, match="SYMLINK_TARGET_TRAVERSAL"):
            validate_protected_surfaces([change], test_manifest)

    def test_rejects_relative_symlink_traversing_out_from_subdirectory(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        # Symlink at sub/link pointing ../../outside (directory is "sub", so 2 x ".." escapes root)
        change = FileChange.symlink("sub/link", "../../outside")
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.SYMLINK_TARGET_TRAVERSAL


class TestCriterionKSymlinkInteractionWithProtectedPaths:
    """Criterion K: Symlink interaction with protected paths where deterministically knowable."""

    def test_rejects_symlink_targeting_exact_protected_file(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.symlink("links/agents_alias", "../AGENTS.md")
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.SYMLINK_TARGET_PROTECTED
        assert findings[0].protected_pattern == "AGENTS.md"

        with pytest.raises(ProtectedSurfaceViolation, match="SYMLINK_TARGET_PROTECTED"):
            validate_protected_surfaces([change], test_manifest)

    def test_rejects_symlink_targeting_protected_directory(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.symlink("my_docs", "docs/SECURITY_BOUNDARY.md")
        findings = check_change(change, test_manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.SYMLINK_TARGET_PROTECTED
        assert findings[0].protected_pattern == "docs"

    def test_rejects_symlink_created_at_protected_location(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.symlink("AGENTS.md", "safe.txt")
        findings = check_change(change, test_manifest)
        assert any(
            f.violation_kind == ProtectedSurfaceViolationKind.EXACT_MATCH for f in findings
        )

    def test_accepts_safe_symlink_targeting_unprotected_file(
        self, test_manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.symlink("links/safe_alias", "../src/app/main.py")
        findings = check_change(change, test_manifest)
        assert len(findings) == 0


class TestCriterionLNormalizationStability:
    """Criterion L: Normalization stability / determinism."""

    @pytest.mark.parametrize(
        "test_path",
        [
            "src/basebreak/security/protected_surfaces.py",
            "docs/SECURITY_BOUNDARY.md",
            "./a/b/./c/d.py",
            "foo//bar///baz.py",
            "sub/nested/../file.txt",
            "windows\\path\\to\\file.txt",
        ],
    )
    def test_normalization_idempotent(self, test_path: str) -> None:
        norm1 = normalize_repo_path(test_path)
        norm2 = normalize_repo_path(norm1)
        norm3 = normalize_repo_path(norm2)
        assert norm1 == norm2 == norm3

    def test_normalization_consistent_across_repeated_evaluations(self) -> None:
        path = "src/../src/basebreak/./security\\protected_surfaces.py"
        expected = "src/basebreak/security/protected_surfaces.py"
        for _ in range(50):
            assert normalize_repo_path(path) == expected


class TestCriterionMProviderPurity:
    """Criterion M: No provider-specific dependency or assumption."""

    def test_zero_provider_imports_in_protected_surfaces(self) -> None:
        module_path = Path("src/basebreak/security/protected_surfaces.py")
        assert module_path.exists()

        tree = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
        forbidden_prefixes = (
            "nebius",
            "nvidia",
            "openai",
            "anthropic",
            "tavily",
            "boto3",
            "azure",
            "google",
            "e2b",
            "daytona",
        )

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for fb in forbidden_prefixes:
                        assert not alias.name.startswith(fb), (
                            f"Forbidden provider import: {alias.name}"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    for fb in forbidden_prefixes:
                        assert not node.module.startswith(fb), (
                            f"Forbidden provider import: {node.module}"
                        )

    def test_no_host_os_realpath_or_resolve_calls(self) -> None:
        # Policy primitive must not call os.path.realpath() or Path.resolve() on untrusted paths
        module_path = Path("src/basebreak/security/protected_surfaces.py")
        content = module_path.read_text(encoding="utf-8")
        assert "realpath" not in content
        assert "Path.resolve" not in content
