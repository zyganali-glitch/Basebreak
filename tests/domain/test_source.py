"""Focused tests for repository/source identity and immutable revision contracts."""

from dataclasses import FrozenInstanceError

import pytest

from basebreak.domain.source import CommitRevision, RequestedRef, SourceIdentity

# Canonical 40-char SHA-1 and 64-char SHA-256 test fixtures
VALID_SHA1 = "b15d4b5ac2123360cd937ee2ffc44a04854475e0"
VALID_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestCommitRevision:
    """Tests for CommitRevision immutable contract."""

    def test_valid_sha1_accepted(self) -> None:
        rev = CommitRevision(VALID_SHA1)
        assert rev.commit_id == VALID_SHA1
        assert str(rev) == VALID_SHA1

    def test_valid_sha256_accepted(self) -> None:
        rev = CommitRevision(VALID_SHA256)
        assert rev.commit_id == VALID_SHA256
        assert str(rev) == VALID_SHA256

    @pytest.mark.parametrize(
        "invalid_rev",
        [
            "",
            "   ",
            "main",
            "master",
            "HEAD",
            "refs/heads/main",
            "v1.0.0",
            "develop",
            # 39 chars (too short)
            "b15d4b5ac2123360cd937ee2ffc44a04854475e",
            # 41 chars (too long for sha1)
            "b15d4b5ac2123360cd937ee2ffc44a04854475e00",
            # 63 chars
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
            # 65 chars
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550",
            # uppercase hex
            VALID_SHA1.upper(),
            # non-hex chars within 40 chars
            "z" * 40,
            "g" * 40,
            # whitespace padding
            f" {VALID_SHA1}",
            f"{VALID_SHA1} ",
        ],
    )
    def test_malformed_immutable_revision_rejected(self, invalid_rev: str) -> None:
        with pytest.raises(ValueError):
            CommitRevision(invalid_rev)

    def test_mutable_branch_name_cannot_satisfy_resolved_revision(self) -> None:
        with pytest.raises(ValueError, match="hexadecimal"):
            CommitRevision("main")
        with pytest.raises(ValueError, match="hexadecimal"):
            CommitRevision("HEAD")

    def test_type_error_for_non_string(self) -> None:
        with pytest.raises(TypeError):
            CommitRevision(12345)  # type: ignore[arg-type]

    def test_frozen_immutability(self) -> None:
        rev = CommitRevision(VALID_SHA1)
        with pytest.raises(FrozenInstanceError):
            rev.commit_id = VALID_SHA256  # type: ignore[misc]


class TestRequestedRef:
    """Tests for RequestedRef audit-only reference."""

    def test_valid_requested_ref(self) -> None:
        ref = RequestedRef("main")
        assert ref.name == "main"
        assert str(ref) == "main"

    @pytest.mark.parametrize("invalid_ref", ["", "   ", " main", "main "])
    def test_invalid_requested_ref_rejected(self, invalid_ref: str) -> None:
        with pytest.raises(ValueError):
            RequestedRef(invalid_ref)

    def test_frozen_immutability(self) -> None:
        ref = RequestedRef("feature-branch")
        with pytest.raises(FrozenInstanceError):
            ref.name = "main"  # type: ignore[misc]


class TestSourceIdentity:
    """Tests for SourceIdentity contract."""

    def test_valid_source_identity_minimal(self) -> None:
        rev = CommitRevision(VALID_SHA1)
        src = SourceIdentity(
            locator="https://github.com/zyganali-glitch/Basebreak",
            revision=rev,
        )
        assert src.locator == "https://github.com/zyganali-glitch/Basebreak"
        assert src.revision == rev
        assert src.resolved_commit_id == VALID_SHA1
        assert src.subpath is None
        assert src.requested_ref is None

    def test_valid_source_identity_full(self) -> None:
        rev = CommitRevision(VALID_SHA256)
        req = RequestedRef("main")
        src = SourceIdentity(
            locator="git@github.com:zyganali-glitch/Basebreak.git",
            revision=rev,
            subpath="packages/core",
            requested_ref=req,
        )
        assert src.subpath == "packages/core"
        assert src.requested_ref == req
        assert src.resolved_commit_id == VALID_SHA256

    def test_canonical_repo_slug_locator_accepted(self) -> None:
        rev = CommitRevision(VALID_SHA1)
        src = SourceIdentity(
            locator="zyganali-glitch/Basebreak",
            revision=rev,
        )
        assert src.locator == "zyganali-glitch/Basebreak"

    @pytest.mark.parametrize(
        "credential_locator",
        [
            "https://user:password@github.com/org/repo.git",
            "https://token123@github.com/org/repo.git",
            "http://admin:secret@gitlab.com/org/repo.git",
            "user:password@github.com:org/repo.git",
        ],
    )
    def test_source_locator_with_embedded_credentials_rejected(
        self, credential_locator: str
    ) -> None:
        rev = CommitRevision(VALID_SHA1)
        with pytest.raises(ValueError, match="embedded credentials"):
            SourceIdentity(locator=credential_locator, revision=rev)

    @pytest.mark.parametrize(
        "workspace_path",
        [
            "./repo",
            ".\\repo",
            "../other/repo",
            "..\\other\\repo",
            "/home/user/repo",
            "\\var\\repo",
            "~/workspace",
            "C:\\Users\\MEHMET\\workspace",
            "D:/projects/basebreak",
            "repo/../../escape",
        ],
    )
    def test_mutable_workspace_path_rejected_as_locator(self, workspace_path: str) -> None:
        rev = CommitRevision(VALID_SHA1)
        with pytest.raises(ValueError, match="workspace path|drive path|path traversal"):
            SourceIdentity(locator=workspace_path, revision=rev)

    @pytest.mark.parametrize("empty_locator", ["", "   ", " https://github.com/repo "])
    def test_empty_or_whitespace_locator_rejected(self, empty_locator: str) -> None:
        rev = CommitRevision(VALID_SHA1)
        with pytest.raises(ValueError):
            SourceIdentity(locator=empty_locator, revision=rev)

    @pytest.mark.parametrize(
        "invalid_subpath",
        [
            "",
            "   ",
            "/packages/core",
            "\\packages\\core",
            "../outside",
            "packages/../../escape",
        ],
    )
    def test_invalid_subpath_rejected(self, invalid_subpath: str) -> None:
        rev = CommitRevision(VALID_SHA1)
        with pytest.raises(ValueError):
            SourceIdentity(
                locator="https://github.com/org/repo",
                revision=rev,
                subpath=invalid_subpath,
            )

    def test_frozen_immutability(self) -> None:
        rev = CommitRevision(VALID_SHA1)
        src = SourceIdentity(
            locator="https://github.com/zyganali-glitch/Basebreak",
            revision=rev,
        )
        with pytest.raises(FrozenInstanceError):
            src.locator = "https://github.com/other/repo"  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            src.revision = CommitRevision(VALID_SHA256)  # type: ignore[misc]

    def test_materially_different_sources_are_not_equal(self) -> None:
        rev1 = CommitRevision(VALID_SHA1)
        rev2 = CommitRevision(VALID_SHA256)
        src1 = SourceIdentity(locator="org/repo-a", revision=rev1)
        src2 = SourceIdentity(locator="org/repo-b", revision=rev1)
        src3 = SourceIdentity(locator="org/repo-a", revision=rev2)

        assert src1 != src2
        assert src1 != src3
        assert hash(src1) != hash(src2)
        assert hash(src1) != hash(src3)
