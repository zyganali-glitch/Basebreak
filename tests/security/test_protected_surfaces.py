"""Unit and boundary tests for protected surfaces, path normalization, and diff checks.

Verifies:
- Repository path normalization rules and fail-closed security properties;
- ProtectedSurfaceManifest immutability, serialization, and prefix normalization;
- Exact, prefix, and case-folded protected surface matching;
- Candidate FileChange records, rename validation, and symlink security;
- Diff parsing and candidate patch validation;
- Canonical Basebreak governance manifest correctness.
"""

from __future__ import annotations

import pytest

from basebreak.security.protected_surfaces import (
    FileChange,
    FileChangeKind,
    InvalidPathError,
    PathTraversalError,
    ProtectedSurfaceManifest,
    ProtectedSurfaceViolation,
    ProtectedSurfaceViolationKind,
    check_change,
    get_canonical_basebreak_protected_manifest,
    is_path_protected,
    match_protected_surface,
    normalize_repo_path,
    parse_unified_diff_changes,
    validate_diff,
    validate_path,
    validate_protected_surfaces,
)


class TestPathNormalization:
    """Test deterministic repository path normalization and fail-closed rules."""

    def test_normalize_valid_relative_paths(self) -> None:
        assert normalize_repo_path("foo/bar.py") == "foo/bar.py"
        assert normalize_repo_path("src/basebreak/security/policy.py") == (
            "src/basebreak/security/policy.py"
        )
        assert normalize_repo_path("single_file.txt") == "single_file.txt"

    def test_normalize_collapses_current_directory_segments(self) -> None:
        assert normalize_repo_path("./foo/bar.py") == "foo/bar.py"
        assert normalize_repo_path("foo/./bar.py") == "foo/bar.py"
        assert normalize_repo_path("foo/bar/.") == "foo/bar"
        assert normalize_repo_path("./././foo.py") == "foo.py"

    def test_normalize_collapses_repeated_separators(self) -> None:
        assert normalize_repo_path("foo//bar.py") == "foo/bar.py"
        assert normalize_repo_path("foo///bar///baz.py") == "foo/bar/baz.py"
        assert normalize_repo_path("foo/bar/") == "foo/bar"

    def test_normalize_resolves_safe_parent_segments(self) -> None:
        assert normalize_repo_path("foo/../bar.py") == "bar.py"
        assert normalize_repo_path("a/b/c/../../d.py") == "a/d.py"
        assert normalize_repo_path("sub/nested/../file.txt") == "sub/file.txt"

    def test_normalize_unifies_windows_separators(self) -> None:
        assert normalize_repo_path("foo\\bar.py") == "foo/bar.py"
        assert normalize_repo_path("docs\\SECURITY_BOUNDARY.md") == "docs/SECURITY_BOUNDARY.md"
        assert normalize_repo_path("src\\basebreak/security\\file.py") == (
            "src/basebreak/security/file.py"
        )

    def test_normalize_unicode_nfc(self) -> None:
        # Combining character sequence normalized to NFC precomposed form
        decomposed = "cafe\u0301.txt"  # e + combining acute accent
        precomposed = "caf\u00e9.txt"  # e-acute
        assert normalize_repo_path(decomposed) == precomposed

    def test_reject_empty_or_whitespace_path(self) -> None:
        with pytest.raises(InvalidPathError, match="must not be empty"):
            normalize_repo_path("")
        with pytest.raises(InvalidPathError, match="whitespace"):
            normalize_repo_path("  ")
        with pytest.raises(InvalidPathError, match="whitespace"):
            normalize_repo_path(" foo.py")
        with pytest.raises(InvalidPathError, match="whitespace"):
            normalize_repo_path("foo.py ")
        with pytest.raises(InvalidPathError, match="whitespace"):
            normalize_repo_path("foo\nbar.py")

    def test_reject_null_bytes(self) -> None:
        with pytest.raises(InvalidPathError, match="null byte"):
            normalize_repo_path("foo\0bar.py")
        with pytest.raises(InvalidPathError, match="null byte"):
            normalize_repo_path("\0")

    def test_reject_non_string_type(self) -> None:
        with pytest.raises(TypeError, match="must be a string"):
            normalize_repo_path(None)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="must be a string"):
            normalize_repo_path(123)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="must be a string"):
            normalize_repo_path(["path.py"])  # type: ignore[arg-type]

    def test_reject_absolute_paths(self) -> None:
        with pytest.raises(PathTraversalError, match="Absolute path starting with slash"):
            normalize_repo_path("/etc/passwd")
        with pytest.raises(PathTraversalError, match="Absolute path starting with slash"):
            normalize_repo_path("/foo/bar")
        with pytest.raises(PathTraversalError, match="Absolute path starting with slash"):
            normalize_repo_path("\\Windows\\System32")
        with pytest.raises(PathTraversalError, match="Absolute path starting with slash"):
            normalize_repo_path("//server/share")

    def test_reject_windows_drive_letters(self) -> None:
        with pytest.raises(PathTraversalError, match="Absolute path with drive letter"):
            normalize_repo_path("C:/Windows/System32")
        with pytest.raises(PathTraversalError, match="Absolute path with drive letter"):
            normalize_repo_path("C:\\Windows\\System32")
        with pytest.raises(PathTraversalError, match="Absolute path with drive letter"):
            normalize_repo_path("d:file.txt")

    def test_reject_home_directory(self) -> None:
        with pytest.raises(PathTraversalError, match="Home directory path"):
            normalize_repo_path("~/.ssh/id_rsa")
        with pytest.raises(PathTraversalError, match="Home directory path"):
            normalize_repo_path("~/repo")

    def test_reject_traversal_above_root(self) -> None:
        with pytest.raises(PathTraversalError, match="traverses above repository root"):
            normalize_repo_path("../outside.txt")
        with pytest.raises(PathTraversalError, match="traverses above repository root"):
            normalize_repo_path("../../etc/shadow")
        with pytest.raises(PathTraversalError, match="traverses above repository root"):
            normalize_repo_path("foo/../../escape.py")
        with pytest.raises(PathTraversalError, match="traverses above repository root"):
            normalize_repo_path("a/b/c/../../../../escape.py")
        with pytest.raises(PathTraversalError, match="traverses above repository root"):
            normalize_repo_path("..")

    def test_reject_empty_root_resolution(self) -> None:
        with pytest.raises(InvalidPathError, match="resolves to empty repository root"):
            normalize_repo_path(".")
        with pytest.raises(InvalidPathError, match="resolves to empty repository root"):
            normalize_repo_path("./.")
        with pytest.raises(InvalidPathError, match="resolves to empty repository root"):
            normalize_repo_path("foo/..")


class TestProtectedSurfaceManifest:
    """Test ProtectedSurfaceManifest creation, immutability, and serialization."""

    def test_manifest_creation_and_immutability(self) -> None:
        manifest = ProtectedSurfaceManifest(
            exact_files=frozenset({"AGENTS.md", "README.md"}),
            directory_prefixes=frozenset({"docs", "plans"}),
            description="Test manifest",
        )
        assert "AGENTS.md" in manifest.exact_files
        assert "docs" in manifest.directory_prefixes
        assert manifest.description == "Test manifest"

        # Immutability verification
        with pytest.raises(Exception):
            manifest.exact_files = frozenset()  # type: ignore[misc]

    def test_manifest_normalizes_entries_at_creation(self) -> None:
        manifest = ProtectedSurfaceManifest(
            exact_files=frozenset({"./AGENTS.md", "plans//PLAN.md", "docs\\FILE.md"}),
            directory_prefixes=frozenset({"docs/", "src/basebreak/security/"}),
        )
        assert "AGENTS.md" in manifest.exact_files
        assert "plans/PLAN.md" in manifest.exact_files
        assert "docs/FILE.md" in manifest.exact_files
        assert "docs" in manifest.directory_prefixes
        assert "src/basebreak/security" in manifest.directory_prefixes

    def test_manifest_rejects_empty_directory_prefix(self) -> None:
        with pytest.raises(InvalidPathError, match="must not be empty or root slash"):
            ProtectedSurfaceManifest(
                exact_files=frozenset(),
                directory_prefixes=frozenset({""}),
            )
        with pytest.raises(InvalidPathError, match="must not be empty or root slash"):
            ProtectedSurfaceManifest(
                exact_files=frozenset(),
                directory_prefixes=frozenset({"/"}),
            )

    def test_manifest_serialization_roundtrip(self) -> None:
        original = ProtectedSurfaceManifest(
            exact_files=frozenset({"AGENTS.md", "plans/BASEBREAK_MASTER_EXECUTION_PLAN.md"}),
            directory_prefixes=frozenset({"docs", "src/basebreak/domain"}),
            description="Roundtrip manifest",
        )
        data = original.to_dict()
        assert data["exact_files"] == ["AGENTS.md", "plans/BASEBREAK_MASTER_EXECUTION_PLAN.md"]
        assert data["directory_prefixes"] == ["docs", "src/basebreak/domain"]
        assert data["description"] == "Roundtrip manifest"

        restored = ProtectedSurfaceManifest.from_dict(data)
        assert restored == original


class TestProtectedSurfaceMatching:
    """Test exact, prefix, and case-folded matching against protected surfaces."""

    @pytest.fixture
    def manifest(self) -> ProtectedSurfaceManifest:
        return ProtectedSurfaceManifest(
            exact_files=frozenset({"AGENTS.md", "config/rules.json"}),
            directory_prefixes=frozenset({"docs", "src/basebreak/security"}),
            description="Test surface manifest",
        )

    def test_exact_match_case_sensitive(self, manifest: ProtectedSurfaceManifest) -> None:
        match = match_protected_surface("AGENTS.md", manifest)
        assert match is not None
        assert match.matched_path == "AGENTS.md"
        assert match.protected_pattern == "AGENTS.md"
        assert not match.is_prefix
        assert not match.is_case_folded

    def test_prefix_match_case_sensitive(self, manifest: ProtectedSurfaceManifest) -> None:
        match = match_protected_surface("docs/SECURITY_BOUNDARY.md", manifest)
        assert match is not None
        assert match.matched_path == "docs/SECURITY_BOUNDARY.md"
        assert match.protected_pattern == "docs"
        assert match.is_prefix
        assert not match.is_case_folded

        # Nested directory descendant
        match_nested = match_protected_surface("src/basebreak/security/deep/policy.py", manifest)
        assert match_nested is not None
        assert match_nested.protected_pattern == "src/basebreak/security"
        assert match_nested.is_prefix

    def test_prefix_boundary_does_not_overmatch_sibling_directory(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        # "docs_fake" is not a child of "docs"
        match = match_protected_surface("docs_fake/file.txt", manifest)
        assert match is None

    def test_case_folded_exact_match(self, manifest: ProtectedSurfaceManifest) -> None:
        match_lower = match_protected_surface("agents.md", manifest)
        assert match_lower is not None
        assert match_lower.protected_pattern == "AGENTS.md"
        assert not match_lower.is_prefix
        assert match_lower.is_case_folded

        match_mixed = match_protected_surface("AgEnTs.Md", manifest)
        assert match_mixed is not None
        assert match_mixed.is_case_folded

    def test_case_folded_prefix_match(self, manifest: ProtectedSurfaceManifest) -> None:
        match_upper = match_protected_surface("DOCS/SECURITY_BOUNDARY.md", manifest)
        assert match_upper is not None
        assert match_upper.protected_pattern == "docs"
        assert match_upper.is_prefix
        assert match_upper.is_case_folded

        match_mixed = match_protected_surface("Src/Basebreak/Security/policy.py", manifest)
        assert match_mixed is not None
        assert match_mixed.is_case_folded

    def test_unprotected_paths_return_none(self, manifest: ProtectedSurfaceManifest) -> None:
        assert match_protected_surface("src/app/main.py", manifest) is None
        assert match_protected_surface("tests/test_feature.py", manifest) is None
        assert match_protected_surface("README.md", manifest) is None

    def test_is_path_protected_helper(self, manifest: ProtectedSurfaceManifest) -> None:
        assert is_path_protected("AGENTS.md", manifest) is True
        assert is_path_protected("agents.md", manifest) is True
        assert is_path_protected("docs/any.txt", manifest) is True
        assert is_path_protected("src/app/main.py", manifest) is False
        assert is_path_protected("/absolute/invalid", manifest) is False

    def test_validate_path_accepts_safe_path(self, manifest: ProtectedSurfaceManifest) -> None:
        assert validate_path("src/app/main.py", manifest) == "src/app/main.py"
        assert validate_path("./src/app/main.py", manifest) == "src/app/main.py"

    def test_validate_path_rejects_protected(self, manifest: ProtectedSurfaceManifest) -> None:
        with pytest.raises(ProtectedSurfaceViolation, match="touches protected surface"):
            validate_path("AGENTS.md", manifest)
        with pytest.raises(ProtectedSurfaceViolation, match="touches protected surface"):
            validate_path("docs/file.txt", manifest)


class TestFileChangeContract:
    """Test FileChange representation and validation."""

    def test_file_change_factories(self) -> None:
        add_c = FileChange.add("foo.py")
        assert add_c.kind == FileChangeKind.ADD
        assert add_c.path == "foo.py"

        mod_c = FileChange.modify("bar.py")
        assert mod_c.kind == FileChangeKind.MODIFY

        del_c = FileChange.delete("baz.py")
        assert del_c.kind == FileChangeKind.DELETE

        ren_c = FileChange.rename("old.py", "new.py")
        assert ren_c.kind == FileChangeKind.RENAME
        assert ren_c.old_path == "old.py"
        assert ren_c.path == "new.py"

        sym_c = FileChange.symlink("link", "target.txt")
        assert sym_c.kind == FileChangeKind.SYMLINK
        assert sym_c.path == "link"
        assert sym_c.symlink_target == "target.txt"

    def test_file_change_validation_invariants(self) -> None:
        with pytest.raises(ValueError, match="RENAME change must specify a non-empty old_path"):
            FileChange(path="new.py", kind=FileChangeKind.RENAME, old_path=None)

        with pytest.raises(ValueError, match="old_path is forbidden for change kind MODIFY"):
            FileChange(path="file.py", kind=FileChangeKind.MODIFY, old_path="old.py")

        with pytest.raises(
            ValueError, match="SYMLINK change must specify a non-empty symlink_target"
        ):
            FileChange(path="link", kind=FileChangeKind.SYMLINK, symlink_target=None)

        with pytest.raises(ValueError, match="symlink_target is forbidden for change kind ADD"):
            FileChange(path="file.py", kind=FileChangeKind.ADD, symlink_target="target")

    def test_file_change_serialization(self) -> None:
        c = FileChange.rename("a.py", "b.py")
        data = c.to_dict()
        assert data == {
            "path": "b.py",
            "kind": "RENAME",
            "old_path": "a.py",
            "symlink_target": None,
        }


class TestRenameAndSymlinkSecurity:
    """Test rename and symlink boundary verification."""

    @pytest.fixture
    def manifest(self) -> ProtectedSurfaceManifest:
        return ProtectedSurfaceManifest(
            exact_files=frozenset({"AGENTS.md"}),
            directory_prefixes=frozenset({"docs"}),
            description="Rename/symlink test manifest",
        )

    def test_rename_moving_protected_file_out_is_rejected(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.rename("AGENTS.md", "unprotected/agents.md")
        findings = check_change(change, manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.RENAME_SOURCE_PROTECTED
        assert findings[0].old_path == "AGENTS.md"

    def test_rename_moving_unprotected_onto_protected_is_rejected(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.rename("unprotected/hack.md", "AGENTS.md")
        findings = check_change(change, manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == (
            ProtectedSurfaceViolationKind.RENAME_DESTINATION_PROTECTED
        )
        assert findings[0].path == "AGENTS.md"

    def test_rename_moving_into_protected_directory_is_rejected(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.rename("safe.txt", "docs/new_file.txt")
        findings = check_change(change, manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == (
            ProtectedSurfaceViolationKind.RENAME_DESTINATION_PROTECTED
        )

    def test_rename_safe_files_is_accepted(self, manifest: ProtectedSurfaceManifest) -> None:
        change = FileChange.rename("src/old.py", "src/new.py")
        findings = check_change(change, manifest)
        assert len(findings) == 0

    def test_symlink_target_escaping_root_is_rejected(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        # Symlink in subfolder trying to traverse above repo root
        change = FileChange.symlink("links/escape", "../../etc/shadow")
        findings = check_change(change, manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.SYMLINK_TARGET_TRAVERSAL

    def test_symlink_target_absolute_is_rejected(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.symlink("links/abs", "/etc/passwd")
        findings = check_change(change, manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.SYMLINK_TARGET_TRAVERSAL

    def test_symlink_target_windows_drive_is_rejected(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        change = FileChange.symlink("links/win", "C:\\Windows\\System32")
        findings = check_change(change, manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.SYMLINK_TARGET_TRAVERSAL

    def test_symlink_target_resolving_to_protected_file_is_rejected(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        # Symlink at links/agents pointing to ../AGENTS.md -> resolves logically to AGENTS.md
        change = FileChange.symlink("links/agents", "../AGENTS.md")
        findings = check_change(change, manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.SYMLINK_TARGET_PROTECTED
        assert findings[0].protected_pattern == "AGENTS.md"

    def test_symlink_target_resolving_into_protected_directory_is_rejected(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        # Symlink in root pointing to docs/SECURITY_BOUNDARY.md
        change = FileChange.symlink("link_docs", "docs/SECURITY_BOUNDARY.md")
        findings = check_change(change, manifest)
        assert len(findings) == 1
        assert findings[0].violation_kind == ProtectedSurfaceViolationKind.SYMLINK_TARGET_PROTECTED
        assert findings[0].protected_pattern == "docs"

    def test_symlink_placed_at_protected_location_is_rejected(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        # Attacker tries to replace AGENTS.md with a symlink to safe.txt
        change = FileChange.symlink("AGENTS.md", "safe.txt")
        findings = check_change(change, manifest)
        assert any(
            f.violation_kind == ProtectedSurfaceViolationKind.EXACT_MATCH for f in findings
        )

    def test_symlink_safe_relative_target_is_accepted(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        # Symlink at links/my_link pointing to ../src/safe.py -> resolves to src/safe.py
        change = FileChange.symlink("links/my_link", "../src/safe.py")
        findings = check_change(change, manifest)
        assert len(findings) == 0


class TestBatchAndDiffValidation:
    """Test batch change validation and unified diff parsing."""

    @pytest.fixture
    def manifest(self) -> ProtectedSurfaceManifest:
        return get_canonical_basebreak_protected_manifest()

    def test_validate_protected_surfaces_passes_clean_batch(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        changes: list[FileChange | str] = [
            "src/app/main.py",
            FileChange.add("tests/test_feature.py"),
            FileChange.modify("README.md"),
        ]
        report = validate_protected_surfaces(changes, manifest)
        assert report.is_valid
        assert len(report.violations) == 0
        assert report.checked_changes == 3

    def test_validate_protected_surfaces_fails_on_violation(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        changes: list[FileChange | str] = [
            "src/app/main.py",
            "AGENTS.md",
        ]
        with pytest.raises(ProtectedSurfaceViolation, match="EXACT_MATCH"):
            validate_protected_surfaces(changes, manifest)

    def test_parse_unified_diff_git_headers(self) -> None:
        diff_text = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,3 +1,3 @@
-old
+new
"""
        changes = parse_unified_diff_changes(diff_text)
        assert len(changes) == 1
        assert changes[0].path == "src/app.py"
        assert changes[0].kind == FileChangeKind.MODIFY

    def test_parse_unified_diff_add_and_delete(self) -> None:
        diff_text = """diff --git a/new_file.py b/new_file.py
--- /dev/null
+++ b/new_file.py
@@ -0,0 +1 @@
+content
diff --git a/del_file.py b/del_file.py
--- a/del_file.py
+++ /dev/null
@@ -1 +0,0 @@
-content
"""
        changes = parse_unified_diff_changes(diff_text)
        assert len(changes) == 2
        assert changes[0].path == "new_file.py"
        assert changes[0].kind == FileChangeKind.ADD
        assert changes[1].path == "del_file.py"
        assert changes[1].kind == FileChangeKind.DELETE

    def test_parse_unified_diff_rename(self) -> None:
        diff_text = """diff --git a/old_name.py b/new_name.py
similarity index 100%
rename from old_name.py
rename to new_name.py
"""
        changes = parse_unified_diff_changes(diff_text)
        assert len(changes) == 1
        assert changes[0].kind == FileChangeKind.RENAME
        assert changes[0].old_path == "old_name.py"
        assert changes[0].path == "new_name.py"

    def test_parse_unified_diff_symlink_mode_120000(self) -> None:
        diff_text = """diff --git a/link b/link
new file mode 120000
--- /dev/null
+++ b/link
@@ -0,0 +1 @@
+../target.txt
"""
        changes = parse_unified_diff_changes(diff_text)
        assert len(changes) == 1
        assert changes[0].kind == FileChangeKind.SYMLINK
        assert changes[0].path == "link"
        assert changes[0].symlink_target == "../target.txt"

    def test_validate_diff_rejects_malicious_diff_touching_agents_md(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        diff_text = """diff --git a/AGENTS.md b/AGENTS.md
--- a/AGENTS.md
+++ b/AGENTS.md
@@ -1,3 +1,3 @@
-Authority
+Hacked
"""
        with pytest.raises(ProtectedSurfaceViolation, match="AGENTS.md"):
            validate_diff(diff_text, manifest)

    def test_validate_diff_accepts_unprotected_patch(
        self, manifest: ProtectedSurfaceManifest
    ) -> None:
        diff_text = """diff --git a/src/app/feature.py b/src/app/feature.py
--- a/src/app/feature.py
+++ b/src/app/feature.py
@@ -1 +1 @@
-pass
+return True
"""
        report = validate_diff(diff_text, manifest)
        assert report.is_valid
        assert len(report.violations) == 0


class TestCanonicalBasebreakManifest:
    """Verify the canonical manifest derived from committed governance authority."""

    def test_canonical_manifest_surfaces_and_reasons(self) -> None:
        manifest = get_canonical_basebreak_protected_manifest()

        # Exact files
        assert "AGENTS.md" in manifest.exact_files
        assert "plans/BASEBREAK_MASTER_EXECUTION_PLAN.md" in manifest.exact_files
        assert "docs/SECURITY_BOUNDARY.md" in manifest.exact_files
        assert "docs/DONOR_MANIFEST.md" in manifest.exact_files
        assert "docs/OPERATOR_REQUIREMENTS.md" in manifest.exact_files
        assert "docs/COMPETITION_FEEDBACK_LOG.md" in manifest.exact_files

        # Directory prefixes
        assert "src/basebreak/domain" in manifest.directory_prefixes
        assert "src/basebreak/evidence" in manifest.directory_prefixes
        assert "src/basebreak/security" in manifest.directory_prefixes

        # No speculative future witness paths (e.g. sealed witness assets from P-08/P-09)
        for f in manifest.exact_files:
            assert "witness" not in f.lower()
        for p in manifest.directory_prefixes:
            assert "witness" not in p.lower()
