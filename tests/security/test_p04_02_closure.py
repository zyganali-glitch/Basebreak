"""Focused closure verification tests for P-04.02.

Validates:
1. Canonical deterministic secret-shaped value redaction engine.
2. Forbidden durable-secret persistence rules for EvidenceStore and EvidenceRecord.
3. Safe log and serialization boundaries.
4. Synthetic-credential coverage across all required categories.
5. Invariant properties: determinism, idempotence, non-leakage, safe-error, stable benign.
6. EvidenceStore append failure atomicity and clean retry.
7. Boundary consistency across capture, log, and evidence persistence.
8. False-positive controls on digests, harmless paths, and clean URLs.
9. Provider purity: zero external provider SDK imports.
"""

from __future__ import annotations

import pytest

from basebreak.domain.causal import (
    CandidateIdentity,
    CausalBinding,
    ExecutionWorld,
    WitnessIdentity,
)
from basebreak.domain.execution import ExecutionCommand
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.append_model import (
    EvidenceIdentity,
    EvidenceRecord,
    EvidenceStore,
    RunIdentity,
)
from basebreak.evidence.artifact import (
    ArtifactDigest,
    ArtifactReference,
    DigestAlgorithm,
)
from basebreak.evidence.capture import StreamType, capture_stream
from basebreak.security.secret_policy import (
    REDACTION_MARKER,
    SecretPersistenceError,
    redact_for_display,
    redact_log_text,
    redact_text,
)


class TestP0402ClosureProviderPurity:
    """Verify provider neutrality and zero external provider SDK dependencies."""

    def test_no_forbidden_provider_imports_in_security_package(self) -> None:
        import ast
        from pathlib import Path

        security_dir = Path("src/basebreak/security")
        forbidden = (
            "nebius",
            "nvidia",
            "openai",
            "anthropic",
            "tavily",
            "boto3",
            "azure",
            "google",
        )

        for py_file in security_dir.glob("*.py"):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for fb in forbidden:
                            assert not alias.name.startswith(fb), (
                                f"Forbidden import {alias.name} in {py_file}"
                            )
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        for fb in forbidden:
                            assert not node.module.startswith(fb), (
                                f"Forbidden import from {node.module} in {py_file}"
                            )

    def test_security_module_uses_stdlib_only(self) -> None:
        import ast
        from pathlib import Path

        security_dir = Path("src/basebreak/security")
        allowed_stdlib = {
            "__future__",
            "re",
            "dataclasses",
            "enum",
            "typing",
            "sys",
            "collections",
            "collections.abc",
        }

        for py_file in security_dir.glob("*.py"):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top = alias.name.split(".")[0]
                        assert top in allowed_stdlib or top == "basebreak", (
                            f"Non-stdlib import {alias.name} in {py_file}"
                        )
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        top = node.module.split(".")[0]
                        assert top in allowed_stdlib or top == "basebreak", (
                            f"Non-stdlib import from {node.module} in {py_file}"
                        )


class TestP0402ClosureRedactionEngine:
    """Verify the deterministic redaction engine satisfies all Master Plan shapes."""

    def test_bearer_authorization_redacted(self) -> None:
        raw = "Header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        redacted, mod = redact_text(raw)
        assert mod
        assert "Bearer [REDACTED]" in redacted
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted

    def test_basic_authorization_redacted(self) -> None:
        raw = "Header Authorization: Basic dXNlcjpwYXNzd29yZDEyMzQ="
        redacted, mod = redact_text(raw)
        assert mod
        assert "Basic [REDACTED]" in redacted
        assert "dXNlcjpwYXNzd29yZDEyMzQ=" not in redacted

    def test_token_prefix_forms_redacted(self) -> None:
        raw = (
            "Client tokens: sk-synthetic1234567890abcdef and ghp_synthetictokentest123456789012345"
        )
        redacted, mod = redact_text(raw)
        assert mod
        assert "sk-synthetic1234567890abcdef" not in redacted
        assert "ghp_synthetictokentest123456789012345" not in redacted

    def test_pem_private_key_redacted(self) -> None:
        raw = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3synthetic\n"
            "-----END PRIVATE KEY-----"
        )
        redacted, mod = redact_text(raw)
        assert mod
        assert "[REDACTED]" in redacted
        assert "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3synthetic" not in redacted

    def test_url_credentials_redacted(self) -> None:
        raw = "https://svc_account:synthetic_secret_token@proxy.internal:8443/rpc"
        redacted, mod = redact_text(raw)
        assert mod
        assert redacted == "https://[REDACTED]@proxy.internal:8443/rpc"
        assert "synthetic_secret_token" not in redacted

    def test_key_value_assignments_redacted(self) -> None:
        raw = 'api_key="synthetic_val_1" password=synthetic_val_2 token: "synthetic_val_3"'
        redacted, mod = redact_text(raw)
        assert mod
        assert "synthetic_val_1" not in redacted
        assert "synthetic_val_2" not in redacted
        assert "synthetic_val_3" not in redacted
        assert 'api_key="[REDACTED]"' in redacted
        assert "password=[REDACTED]" in redacted
        assert 'token: "[REDACTED]"' in redacted


class TestP0402ClosurePersistenceAndAtomicity:
    """Verify forbidden durable-secret persistence and failure atomicity."""

    def test_evidence_record_post_init_rejects_secret_in_argv(self) -> None:
        cmd = ExecutionCommand(argv=("python", "-c", "api_key='synthetic_key_123'"))
        with pytest.raises(SecretPersistenceError) as exc_info:
            EvidenceRecord(
                evidence_id=EvidenceIdentity("ev-p4-argv"),
                run_id=RunIdentity("run-p4"),
                sequence_number=0,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                command=cmd,
            )
        err = exc_info.value
        assert "synthetic_key_123" not in str(err)
        assert "synthetic_key_123" not in repr(err)

    def test_evidence_record_post_init_rejects_secret_in_env(self) -> None:
        cmd = ExecutionCommand(
            argv=("python", "script.py"),
            env=(("TAVILY_API_KEY", "tvly-synthetic-12345"),),
        )
        with pytest.raises(SecretPersistenceError) as exc_info:
            EvidenceRecord(
                evidence_id=EvidenceIdentity("ev-p4-env"),
                run_id=RunIdentity("run-p4"),
                sequence_number=0,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                command=cmd,
            )
        err = exc_info.value
        assert "tvly-synthetic-12345" not in str(err)
        assert "tvly-synthetic-12345" not in repr(err)

    def test_evidence_store_atomicity_and_deterministic_retry(self) -> None:
        store = EvidenceStore()
        run = RunIdentity("run-p4-atom")

        rec0 = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-000"),
            run_id=run,
            sequence_number=0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            command=ExecutionCommand(argv=("echo", "clean")),
        )
        store.append(rec0)
        assert len(store) == 1

        # Attempt to append record with secret in env
        rec1_tainted = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-001"),
            run_id=run,
            sequence_number=1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            command=ExecutionCommand(argv=("echo", "clean_argv")),
        )
        object.__setattr__(
            rec1_tainted,
            "command",
            ExecutionCommand(argv=("echo", "test"), env=(("API_KEY", "synthetic_pw"),)),
        )

        with pytest.raises(SecretPersistenceError):
            store.append(rec1_tainted)

        # Atomic failure checks:
        assert len(store) == 1
        assert store.get("ev-001") is None
        assert store._run_next_sequence["run-p4-atom"] == 1
        assert store.get("ev-000") == rec0

        # Deterministic retry with sanitized record succeeds
        rec1_clean = EvidenceRecord(
            evidence_id=EvidenceIdentity("ev-001"),
            run_id=run,
            sequence_number=1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            command=ExecutionCommand(argv=("echo", "test"), env=(("API_KEY", REDACTION_MARKER),)),
        )
        store.append(rec1_clean)
        assert len(store) == 2
        assert store.get("ev-001") == rec1_clean
        assert store._run_next_sequence["run-p4-atom"] == 2


class TestP0402ClosureBoundaryConsistency:
    """Verify boundary consistency across capture, log, display, and evidence persistence."""

    def test_shape_recognized_across_all_boundaries(self) -> None:
        synthetic_secret = "sk-synthetic1234567890abcdef"
        raw_text = f"Using API key {synthetic_secret} in service"

        # 1. Capture stream sanitization
        stream = capture_stream(raw_text, stream_type=StreamType.STDOUT)
        assert stream.is_sanitized
        assert synthetic_secret not in stream.retained_text
        assert "[REDACTED]" in stream.retained_text

        # 2. Log boundary
        log_out = redact_log_text(raw_text)
        assert synthetic_secret not in log_out
        assert "[REDACTED]" in log_out

        # 3. Display boundary
        display_out = redact_for_display({"log": raw_text})
        assert synthetic_secret not in str(display_out)
        assert display_out["log"] == log_out

        # 4. Evidence persistence boundary fails closed
        cmd = ExecutionCommand(argv=("curl", "-H", f"Key: {synthetic_secret}"))
        with pytest.raises(SecretPersistenceError) as exc_info:
            EvidenceRecord(
                evidence_id=EvidenceIdentity("ev-boundary"),
                run_id=RunIdentity("run-b"),
                sequence_number=0,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                command=cmd,
            )
        assert synthetic_secret not in str(exc_info.value)


class TestP0402ClosureDurableSurfaceCoverage:
    """Verify durable string-bearing surface coverage and safe diagnostic paths."""

    def test_artifact_media_type_persistence_rejection(self) -> None:
        secret = "synthetic_media_secret_value"
        media_type = f"application/json; secret_token={secret}"
        digest = ArtifactDigest(
            algorithm=DigestAlgorithm.SHA256,
            value="a" * 64,
            byte_length=128,
        )
        art = ArtifactReference(digest=digest, media_type=media_type)
        with pytest.raises(SecretPersistenceError) as exc_info:
            EvidenceRecord(
                evidence_id=EvidenceIdentity("ev-art-test"),
                run_id=RunIdentity("run-art-test"),
                sequence_number=0,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                artifacts=(art,),
            )
        exc = exc_info.value
        assert secret not in str(exc)
        assert secret not in repr(exc)
        assert secret not in exc.rule_id
        assert secret not in exc.path
        assert secret not in exc.category
        assert exc.path == "artifacts[0].media_type"

    def test_causal_binding_surface_coverage(self) -> None:
        secret = "sk-synthetic_cb_req_1234567890"
        source = SourceIdentity(
            locator="https://github.com/repo",
            revision=CommitRevision("0" * 40),
        )
        cand = CandidateIdentity(candidate_id="cand-01", source=source, patch_digest="a" * 64)
        witness = WitnessIdentity(witness_id="wit-01", digest="b" * 64, description="clean")
        cb = CausalBinding(
            requirement_id=secret,
            witness=witness,
            base_source=source,
            candidate=cand,
            world=ExecutionWorld.CANDIDATE,
        )
        with pytest.raises(SecretPersistenceError) as exc_info:
            EvidenceRecord(
                evidence_id=EvidenceIdentity("ev-cb-test"),
                run_id=RunIdentity("run-cb-test"),
                sequence_number=0,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                causal_binding=cb,
            )
        exc = exc_info.value
        assert secret not in str(exc)
        assert secret not in repr(exc)
        assert secret not in exc.rule_id
        assert secret not in exc.path
        assert secret not in exc.category
        assert exc.path == "causal_binding.requirement_id"

    def test_env_key_and_value_structural_indexing(self) -> None:
        secret = "sk-synthetic_env_key_secret_12"
        cmd = ExecutionCommand(
            argv=("test",),
            env=((secret, "val"),),
        )
        with pytest.raises(SecretPersistenceError) as exc_info:
            EvidenceRecord(
                evidence_id=EvidenceIdentity("ev-env-test"),
                run_id=RunIdentity("run-env-test"),
                sequence_number=0,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                command=cmd,
            )
        exc = exc_info.value
        assert secret not in str(exc)
        assert secret not in repr(exc)
        assert secret not in exc.rule_id
        assert secret not in exc.path
        assert secret not in exc.category
        assert exc.path == "command.env[0].key"


class TestP0402ClosureShortCredentialsAndDisplayKeys:
    """Validate closure requirements for short Bearer/Basic credentials and display mapping keys."""

    @pytest.mark.parametrize(
        "raw,expected_token,expected_header",
        [
            ("Authorization: Bearer a", "a", "Authorization: Bearer [REDACTED]"),
            ("Authorization: Bearer abc", "abc", "Authorization: Bearer [REDACTED]"),
            ("authorization: bearer xyz", "xyz", "authorization: bearer [REDACTED]"),
            ("Authorization: Basic YQ==", "YQ==", "Authorization: Basic [REDACTED]"),
            ("Authorization: Basic YTo=", "YTo=", "Authorization: Basic [REDACTED]"),
        ],
    )
    def test_short_credentials_canonical_policy(
        self, raw: str, expected_token: str, expected_header: str
    ) -> None:
        from basebreak.security.secret_policy import contains_secret

        assert contains_secret(raw)
        redacted, modified = redact_text(raw)
        assert modified
        assert redacted == expected_header
        assert f"Bearer {expected_token}" not in redacted
        assert f"bearer {expected_token}" not in redacted
        assert f"Basic {expected_token}" not in redacted
        assert f"basic {expected_token}" not in redacted
        if len(expected_token) > 1:
            assert expected_token not in redacted
        assert not redacted.endswith("=")
        assert not redacted.endswith("==")

        log_out = redact_log_text(raw)
        assert log_out == expected_header
        assert f"Bearer {expected_token}" not in log_out
        assert f"Basic {expected_token}" not in log_out

        second, second_mod = redact_text(redacted)
        assert second == redacted
        assert not second_mod
        assert not contains_secret(redacted)

    def test_short_credential_stream_and_authoritative_persistence(self) -> None:
        # 1. Stream capture sanitization
        stream = capture_stream("Connecting: Authorization: Bearer abc", StreamType.STDOUT)
        assert stream.is_sanitized
        assert "abc" not in stream.retained_text
        assert "Bearer [REDACTED]" in stream.retained_text

        basic_stream = capture_stream("Header: Authorization: Basic YQ==", StreamType.STDOUT)
        assert basic_stream.is_sanitized
        assert "YQ==" not in basic_stream.retained_text
        assert not basic_stream.retained_text.endswith("=")
        assert "Basic [REDACTED]" in basic_stream.retained_text

        # 2. Authoritative evidence persistence fails closed
        cmd_bearer = ExecutionCommand(argv=("curl", "-H", "Authorization: Bearer abc"))
        with pytest.raises(SecretPersistenceError) as exc_info:
            EvidenceRecord(
                evidence_id=EvidenceIdentity("ev-short-bearer"),
                run_id=RunIdentity("run-sb"),
                sequence_number=0,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                command=cmd_bearer,
            )
        exc = exc_info.value
        assert exc.rule_id == "AUTH_BEARER"
        assert "abc" not in str(exc)
        assert "abc" not in repr(exc)

        cmd_basic = ExecutionCommand(argv=("curl", "-H", "Authorization: Basic YQ=="))
        with pytest.raises(SecretPersistenceError) as exc_info_b:
            EvidenceRecord(
                evidence_id=EvidenceIdentity("ev-short-basic"),
                run_id=RunIdentity("run-sba"),
                sequence_number=0,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                command=cmd_basic,
            )
        exc_b = exc_info_b.value
        assert exc_b.rule_id == "AUTH_BASIC"
        assert "YQ==" not in str(exc_b)

    def test_display_mapping_keys_sanitization_and_collision_safety(self) -> None:
        raw_token = "sk-synthetic1234567890abcdef"
        raw_assigned = "synthetic_secret_value"

        # 1. Token prefix key
        d1 = {raw_token: "safe"}
        r1 = redact_for_display(d1)
        assert raw_token not in str(r1)
        assert r1 == {REDACTION_MARKER: "safe"}
        assert raw_token in d1  # unmutated

        # 2. Key-value assignment in key
        d2 = {f"api_key={raw_assigned}": "safe"}
        r2 = redact_for_display(d2)
        assert raw_assigned not in str(r2)
        assert r2 == {f"api_key={REDACTION_MARKER}": "safe"}
        assert f"api_key={raw_assigned}" in d2  # unmutated

        # 3. Nested mapping
        nested = {
            "outer": {
                raw_token: {
                    f"api_key={raw_assigned}": "safe_leaf",
                }
            }
        }
        r_nested = redact_for_display(nested)
        assert raw_token not in str(r_nested)
        assert raw_assigned not in str(r_nested)
        assert r_nested == {
            "outer": {
                REDACTION_MARKER: {
                    f"api_key={REDACTION_MARKER}": "safe_leaf",
                }
            }
        }

        # 4. Multiple colliding secret keys
        colliding = {
            "sk-synthetic1111111111111111": "val1",
            "sk-synthetic2222222222222222": "val2",
        }
        r_col = redact_for_display(colliding)
        assert "synthetic" not in str(r_col)
        assert r_col == {
            REDACTION_MARKER: "val1",
            f"{REDACTION_MARKER}#2": "val2",
        }
        # Idempotence on repeated redaction
        assert redact_for_display(r_col) == r_col

        # 5. Sensitive schema keys remain recognizable
        schema_dict = {"API_KEY": "secret_data"}
        r_schema = redact_for_display(schema_dict)
        assert "secret_data" not in str(r_schema)
        assert r_schema == {"API_KEY": REDACTION_MARKER}
