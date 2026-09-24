"""Comprehensive tests for deterministic secret redaction engine and persistence rules (P-04.02)."""

from __future__ import annotations

import pytest

from basebreak.domain.execution import ExecutionCommand
from basebreak.security.secret_policy import (
    REDACTION_MARKER,
    SecretFinding,
    SecretPersistenceError,
    contains_secret,
    find_secret_findings,
    is_sensitive_key,
    redact_for_display,
    redact_log_text,
    redact_text,
    validate_execution_command_for_persistence,
    validate_no_secrets,
)


class TestRecognizedSecretCategories:
    """Validate deterministic detection and redaction across all required categories."""

    def test_auth_bearer_token(self) -> None:
        token = "synthetic_bearer_jwt_token_12345"
        text = f"Authorization: Bearer {token}"
        redacted, modified = redact_text(text)
        assert modified
        assert "Bearer [REDACTED]" in redacted
        assert token not in redacted
        assert contains_secret(text)
        assert not contains_secret(redacted)

    def test_auth_bearer_case_insensitive(self) -> None:
        token = "synthetic_bearer_jwt_token_12345"
        text = f"authorization: bearer {token}"
        redacted, modified = redact_text(text)
        assert modified
        assert "[REDACTED]" in redacted
        assert token not in redacted

    def test_auth_basic_credential(self) -> None:
        cred = "dXNlcjpwYXNzd29yZDEyMzQ="
        text = f"Authorization: Basic {cred}"
        redacted, modified = redact_text(text)
        assert modified
        assert "Basic [REDACTED]" in redacted
        assert cred not in redacted
        assert contains_secret(text)
        assert not contains_secret(redacted)

    def test_key_value_assignments_various_keys(self) -> None:
        test_keys = [
            "api_key",
            "api-key",
            "apikey",
            "token",
            "secret",
            "password",
            "passwd",
            "credential",
            "credentials",
            "authorization",
            "auth",
            "private_key",
            "access_key",
            "client_secret",
            "auth_token",
            "secret_key",
        ]
        synthetic_secret = "synthetic_secret_value_xyz"
        for key in test_keys:
            raw = f"{key} = '{synthetic_secret}'"
            redacted, modified = redact_text(raw)
            assert modified, f"Failed to redact key: {key}"
            assert "[REDACTED]" in redacted
            assert synthetic_secret not in redacted
            assert contains_secret(raw)
            assert not contains_secret(redacted)

    def test_token_prefix_forms(self) -> None:
        prefix_cases = [
            ("sk-synthetic1234567890abcdef", "sk-"),
            ("ghp_synthetictokentest123456789012345", "ghp_"),
            ("gho_synthetictokentest123456789012345", "gho_"),
            ("ghu_synthetictokentest123456789012345", "ghu_"),
            ("ghs_synthetictokentest123456789012345", "ghs_"),
            ("ghr_synthetictokentest123456789012345", "ghr_"),
            ("glpat-synthetictoken123456789012", "glpat-"),
        ]
        for token, prefix in prefix_cases:
            text = f"Using credentials: {token} for access"
            redacted, modified = redact_text(text)
            assert modified, f"Failed to redact prefix: {prefix}"
            assert "[REDACTED]" in redacted
            assert token not in redacted
            assert contains_secret(text)
            assert not contains_secret(redacted)

    def test_pem_private_key_block(self) -> None:
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0synthetic1234567890abcdef\n"
            "MIIEowIBAAKCAQEA0synthetic1234567890abcdef\n"
            "-----END RSA PRIVATE KEY-----"
        )
        text = f"Loading certificate:\n{pem}\nKey loaded."
        redacted, modified = redact_text(text)
        assert modified
        assert "[REDACTED]" in redacted
        assert "MIIEowIBAAKCAQEA0synthetic1234567890abcdef" not in redacted
        assert "-----BEGIN RSA PRIVATE KEY-----" not in redacted
        assert contains_secret(text)
        assert not contains_secret(redacted)

    def test_pem_generic_private_key_block(self) -> None:
        pem = "-----BEGIN PRIVATE KEY-----\nMIIEowIBAAKCAQEA0synthetic\n-----END PRIVATE KEY-----"
        text = f"Header\n{pem}\nFooter"
        redacted, modified = redact_text(text)
        assert modified
        assert "[REDACTED]" in redacted
        assert "MIIEowIBAAKCAQEA0synthetic" not in redacted
        assert contains_secret(text)
        assert not contains_secret(redacted)

    def test_url_credentials(self) -> None:
        raw_url = "https://user:synthetic_password@example.com/api/v1"
        redacted, modified = redact_text(raw_url)
        assert modified
        assert redacted == "https://[REDACTED]@example.com/api/v1"
        assert "synthetic_password" not in redacted
        assert contains_secret(raw_url)
        assert not contains_secret(redacted)

    def test_url_credentials_password_only(self) -> None:
        raw_url = "https://:synthetic_password@api.example.com"
        redacted, modified = redact_text(raw_url)
        assert modified
        assert redacted == "https://[REDACTED]@api.example.com"
        assert "synthetic_password" not in redacted


class TestKeyAwarePolicy:
    """Validate that sensitive keys treat short values as secrets.

    Ensures zero near-miss false positives on benign prose.
    """

    def test_sensitive_key_with_short_value_in_text(self) -> None:
        cases = [
            ("API_KEY=abc", "API_KEY=[REDACTED]"),
            ("api_key: 'x'", "api_key: '[REDACTED]'"),
            ('password="1"', 'password="[REDACTED]"'),
            ("secret=123", "secret=[REDACTED]"),
            ("token: 99", "token: [REDACTED]"),
        ]
        for raw, expected in cases:
            redacted, modified = redact_text(raw)
            assert modified, f"Failed on {raw}"
            assert redacted == expected
            assert contains_secret(raw)

    def test_sensitive_env_key_with_short_value_in_command(self) -> None:
        cmd = ExecutionCommand(
            argv=("test", "run"),
            env=(("API_KEY", "abc"),),
        )
        with pytest.raises(SecretPersistenceError) as exc_info:
            validate_execution_command_for_persistence(cmd)
        err = exc_info.value
        assert err.rule_id == "SENSITIVE_ENV_KEY"
        assert "API_KEY" in err.path
        assert "abc" not in str(err)
        assert "abc" not in repr(err)

    def test_is_sensitive_key_matching(self) -> None:
        assert is_sensitive_key("API_KEY")
        assert is_sensitive_key("api-key")
        assert is_sensitive_key("NEBIUS_API_KEY")
        assert is_sensitive_key("NVIDIA_API_KEY")
        assert is_sensitive_key("TAVILY_API_KEY")
        assert is_sensitive_key("GITHUB_TOKEN")
        assert is_sensitive_key("AWS_SECRET_ACCESS_KEY")
        assert is_sensitive_key("CLIENT_SECRET")
        assert is_sensitive_key("DB_PASSWORD")
        assert is_sensitive_key("TOKEN")
        assert is_sensitive_key("SECRET")
        assert is_sensitive_key("PASSWORD")

    def test_is_sensitive_key_near_misses(self) -> None:
        assert not is_sensitive_key("TOKEN_BUDGET")
        assert not is_sensitive_key("SECRETARY")
        assert not is_sensitive_key("AUTHOR")
        assert not is_sensitive_key("SORT_KEY")
        assert not is_sensitive_key("CACHE_KEY")
        assert not is_sensitive_key("PATH")
        assert not is_sensitive_key("USER")
        assert not is_sensitive_key("HOME")
        assert not is_sensitive_key("PYTHONPATH")
        assert not is_sensitive_key("LANG")

    def test_prose_near_misses_are_not_flagged(self) -> None:
        benign_prose = [
            "The token budget for this model inference is 4096 tokens.",
            "The executive secretary scheduled the meeting for Tuesday.",
            "Running the complete authentication test suite against localhost.",
            'author = "Jane Doe"',
            "harmless_filename: test_token.py",
            "git commit -m 'fix token parser edge cases'",
            "authorized = True",
            "authority_level = 5",
            "secret_notes.txt",
        ]
        for prose in benign_prose:
            redacted, modified = redact_text(prose)
            assert not modified, f"False positive on: {prose!r} -> {redacted!r}"
            assert redacted == prose
            assert not contains_secret(prose)


class TestFalsePositiveControl:
    """Ensure hashes, digests, clean URLs, and harmless identifiers are never redacted."""

    def test_sha1_and_sha256_digests_not_redacted(self) -> None:
        sha1 = "0123456789abcdef0123456789abcdef01234567"
        sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        text = f"commit {sha1} with digest {sha256}"
        redacted, modified = redact_text(text)
        assert not modified
        assert redacted == text
        assert not contains_secret(text)

    def test_clean_urls_not_redacted(self) -> None:
        urls = [
            "https://github.com/zyganali-glitch/Basebreak",
            "https://api.nebius.ai/v1/models",
            "http://localhost:8080/metrics",
            "https://example.com/path/to/resource?param=value",
            "git+ssh://git@github.com/repo/name.git",
        ]
        for url in urls:
            redacted, modified = redact_text(url)
            assert not modified, f"False positive on clean URL: {url}"
            assert redacted == url
            assert not contains_secret(url)

    def test_run_and_evidence_ids_not_redacted(self) -> None:
        ident = "run-2026-09-24-exec-001 ev-uuid-123456789"
        redacted, modified = redact_text(ident)
        assert not modified
        assert redacted == ident


class TestNonLeakingErrorsAndMetadata:
    """Verify that exceptions and metadata never echo raw synthetic secret values."""

    def test_exception_never_echoes_raw_secret(self) -> None:
        secret = "super_synthetic_secret_never_echo_9999"
        try:
            validate_no_secrets(f"api_key={secret}", path="test.config")
            pytest.fail("Should have raised SecretPersistenceError")
        except SecretPersistenceError as exc:
            # 1. str(exc) does not contain secret
            assert secret not in str(exc)
            # 2. repr(exc) does not contain secret
            assert secret not in repr(exc)
            # 3. attributes do not contain secret
            assert secret not in exc.rule_id
            assert secret not in exc.path
            assert secret not in exc.category
            # 4. safe metadata is present
            assert "test.config" in exc.path
            assert "SECRET_PERSISTENCE_FORBIDDEN" in exc.category

    def test_findings_metadata_never_contains_raw_secret(self) -> None:
        secret = "secret_raw_text_value_abc123"
        text = f"export API_KEY={secret}"
        findings = find_secret_findings(text)
        assert len(findings) == 1
        finding = findings[0]
        assert isinstance(finding, SecretFinding)
        assert secret not in finding.rule_id
        assert secret not in str(finding)
        assert secret not in repr(finding)
        # Verify indices point to secret in text
        matched_slice = text[finding.start : finding.end]
        assert secret in matched_slice


class TestDeterminismAndIdempotence:
    """Verify mathematical properties: determinism, idempotence, and stability."""

    def test_redact_idempotence(self) -> None:
        samples = [
            "Authorization: Bearer synthetic_jwt_token_12345",
            "Basic dXNlcjpwYXNzd29yZDEyMzQ=",
            'api_key = "synthetic_key_value"',
            "NEBIUS_API_KEY=synthetic_nebius_123",
            "sk-synthetic1234567890abcdef",
            "https://user:password123@example.com/path",
            "Already clean text line without secrets.",
            "[REDACTED]",
            "api_key=[REDACTED]",
            'token = "[REDACTED]"',
            "Bearer [REDACTED]",
        ]
        for s in samples:
            first_pass, _ = redact_text(s)
            second_pass, second_modified = redact_text(first_pass)
            assert first_pass == second_pass, f"Idempotence failed on: {s!r}"
            assert not second_modified, f"Second pass reported modified on: {s!r}"

    def test_redact_determinism(self) -> None:
        raw = "Config: api_key='synthetic_key' and Bearer synthetic_token_12345"
        r1, m1 = redact_text(raw)
        r2, m2 = redact_text(raw)
        assert r1 == r2
        assert m1 == m2


class TestSafeLogAndDisplayBoundaries:
    """Verify non-authoritative log and display redaction helpers."""

    def test_redact_log_text_helper(self) -> None:
        raw = "Log event: failed login with password=synthetic_pw"
        clean = redact_log_text(raw)
        assert "password=[REDACTED]" in clean
        assert "synthetic_pw" not in clean
        # Non-string raises TypeError
        with pytest.raises(TypeError, match="text must be a str"):
            redact_log_text(123)  # type: ignore[arg-type]

    def test_redact_for_display_nested_structure(self) -> None:
        nested = {
            "name": "run-001",
            "env": {
                "PATH": "/usr/bin",
                "API_KEY": "synthetic_secret_key",
                "NESTED": ["sk-synthetic1234567890abcdef", "safe_item"],
            },
            "command": ("curl", "-H", "Authorization: Bearer synthetic_bearer_token"),
        }
        displayed = redact_for_display(nested)
        assert displayed["name"] == "run-001"
        assert displayed["env"]["PATH"] == "/usr/bin"
        assert displayed["env"]["API_KEY"] == REDACTION_MARKER
        assert displayed["env"]["NESTED"][0] == REDACTION_MARKER
        assert displayed["env"]["NESTED"][1] == "safe_item"
        assert "Bearer [REDACTED]" in displayed["command"][2]
        assert "synthetic" not in str(displayed)


class TestAdversarialSelfChecks:
    """Adversarial boundary stress tests."""

    def test_mixed_case_key_names(self) -> None:
        cases = [
            ("ApI_kEy = 'synthetic1'", "ApI_kEy = '[REDACTED]'"),
            ("PassWord: 'synthetic2'", "PassWord: '[REDACTED]'"),
            ("TOKEN=synthetic3", "TOKEN=[REDACTED]"),
            ("cLiEnT_sEcReT='synthetic4'", "cLiEnT_sEcReT='[REDACTED]'"),
        ]
        for raw, expected in cases:
            redacted, modified = redact_text(raw)
            assert modified, f"Failed on {raw}"
            assert redacted == expected

    def test_quoted_values_variations(self) -> None:
        cases = [
            ('api_key="double_quoted"', 'api_key="[REDACTED]"'),
            ("api_key='single_quoted'", "api_key='[REDACTED]'"),
            ("api_key=unquoted_val", "api_key=[REDACTED]"),
        ]
        for raw, expected in cases:
            redacted, modified = redact_text(raw)
            assert modified
            assert redacted == expected

    def test_separator_variations(self) -> None:
        cases = [
            ("api_key=val", "api_key=[REDACTED]"),
            ("api_key:val", "api_key:[REDACTED]"),
            ("api_key = val", "api_key = [REDACTED]"),
            ("api_key  :  val", "api_key  :  [REDACTED]"),
        ]
        for raw, expected in cases:
            redacted, modified = redact_text(raw)
            assert modified
            assert redacted == expected

    def test_secret_at_boundaries(self) -> None:
        # At start
        s1 = "api_key=secret_start rest of line"
        r1, _ = redact_text(s1)
        assert r1.startswith("api_key=[REDACTED]")

        # At end
        s2 = "prefix text api_key=secret_end"
        r2, _ = redact_text(s2)
        assert r2.endswith("api_key=[REDACTED]")

        # Entire string
        s3 = "api_key=secret_alone"
        r3, _ = redact_text(s3)
        assert r3 == "api_key=[REDACTED]"

    def test_multiple_secrets_in_single_string(self) -> None:
        raw = (
            "Connecting with api_key=key1, token=sk-synthetic1234567890abcdef, "
            "and Authorization: Bearer synthetic_jwt_token_12345"
        )
        redacted, modified = redact_text(raw)
        assert modified
        assert "key1" not in redacted
        assert "sk-synthetic1234567890abcdef" not in redacted
        assert "synthetic_jwt_token_12345" not in redacted
        assert "api_key=[REDACTED]" in redacted
        assert "token=[REDACTED]" in redacted
        assert "Bearer [REDACTED]" in redacted

    def test_already_redacted_marker_not_corrupted(self) -> None:
        markers = [
            "[REDACTED]",
            "Bearer [REDACTED]",
            "Basic [REDACTED]",
            "api_key=[REDACTED]",
            'api_key="[REDACTED]"',
            "password: [REDACTED]",
        ]
        for m in markers:
            redacted, modified = redact_text(m)
            assert not modified, f"Corrupted marker: {m!r} -> {redacted!r}"
            assert redacted == m

    def test_command_argv_with_flag_secrets(self) -> None:
        cmd = ExecutionCommand(argv=("tool", "--api-key=synthetic_secret_123", "--verbose"))
        with pytest.raises(SecretPersistenceError) as exc_info:
            validate_execution_command_for_persistence(cmd)
        err = exc_info.value
        assert "command.argv[1]" in err.path
        assert "synthetic_secret_123" not in str(err)
        assert "synthetic_secret_123" not in repr(err)


class TestPropertyInvariants:
    """Property tests across systematically generated synthetic inputs."""

    @pytest.mark.parametrize(
        "secret",
        [
            "synthetic_token_alpha",
            "synthetic_key_123456",
            "sk-synthetic1234567890abcdef",
            "dXNlcjpwYXNzd29yZDEyMzQ=",
        ],
    )
    @pytest.mark.parametrize("separator", ["=", ":", " = ", " : "])
    @pytest.mark.parametrize("key", ["api_key", "password", "token", "secret"])
    def test_property_non_leakage_and_idempotence(
        self, secret: str, separator: str, key: str
    ) -> None:
        raw = f"setting {key}{separator}{secret} in config"
        redacted_1, mod_1 = redact_text(raw)
        assert mod_1
        assert secret not in redacted_1

        redacted_2, mod_2 = redact_text(redacted_1)
        assert not mod_2
        assert redacted_1 == redacted_2

    @pytest.mark.parametrize(
        "benign",
        [
            "All 460 tests passed in 1.56s",
            "commit 0123456789abcdef0123456789abcdef01234567",
            "https://github.com/zyganali-glitch/Basebreak/blob/main/README.md",
            "token budget 8192",
            "secretary of defense",
            "test_authentication_flow()",
            "USER=alice",
            "PATH=/usr/local/bin:/usr/bin",
        ],
    )
    def test_property_stable_benign_inputs(self, benign: str) -> None:
        redacted, mod = redact_text(benign)
        assert not mod
        assert redacted == benign
        assert not contains_secret(benign)
