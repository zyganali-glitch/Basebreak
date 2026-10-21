"""P-27.06 surgical code-patch secret false-positive repair: adversarial tests.

Root cause repaired here: the generic KEY_VALUE_ASSIGNMENT secret rule matched
ordinary Python expressions such as ``token = secrets.token_hex(16)``,
``token = new_token`` and ``token = None`` inside model-generated candidate
patches, rejecting benign source code at the candidate-patch persistence
boundary (reported seventh live run failure:
``SECRET_PERSISTENCE_FORBIDDEN`` / ``KEY_VALUE_ASSIGNMENT`` at
``candidate_patch_text``).

Repair under test: ``validate_no_secrets_in_source_patch`` — a context-aware
source-code patch boundary used by CandidateDeltaSubtractor, the
candidate/counterfactual materializer, and the patch-subset (minimizer)
validator. The generic ``validate_no_secrets`` boundary for logs, JSON
evidence, receipts, environment variables and provider responses is unchanged.

Adversarial matrix:
- Benign Python runtime assignments are accepted.
- A valid ResetVault single-use-token patch is not rejected merely for ordinary
  token/password variable references.
- Real hardcoded credentials remain rejected.
- Secrets in added code, string literals, diff context or removed lines are not
  silently allowed into persistent evidence.
- Malformed or ambiguous patch/security input fails closed.
- Protected-surface mutations remain rejected.
- Candidate patch digest and tree identity remain unchanged by validation.
- The subtraction, patch-subset and materialization chain reaches the next
  legitimate boundary under offline execution.
- No Builder self-certification or mock-to-live promotion.

All evidence provenance here is LOCAL_EXECUTION / FIXTURE (synthetic nonsecret
patch with the same false-positive shape; the seventh-run candidate bytes were
not independently available for local reproduction).
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from basebreak.adapters.nebius.materialization import MaterializedSourceRecord
from basebreak.causal.materializer import (
    CausalRepositoryMaterializer,
    CounterfactualMaterializationError,
)
from basebreak.causal.minimizer import create_tested_patch_subset_from_hunks
from basebreak.causal.subtraction import (
    CandidateDeltaSubtractor,
    CounterfactualDeltaPlan,
    ProtectedSurfaceSubtractionError,
    SecretPolicySubtractionError,
    SubtractionRequest,
    SubtractionStrategyType,
    parse_candidate_patch,
)
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.security.secret_policy import (
    SecretPersistenceError,
    validate_no_secrets,
    validate_no_secrets_in_source_patch,
)

SOURCE_COMMIT = "80b43b84014fa61b941c7ebcd87836a56dcd7c92"
SOURCE_LOCATOR = "https://github.com/zyganali-glitch/Basebreak.git"
CANDIDATE_TREE = "1ec63ce19c2d53dd46e29ba5c1ad79a2b75f29a3"
FROZEN_CONTRACT_DIGEST = "93eeeb2cc7eb02a988da3c8a8543ad40b4816608c1452d048ff62ee93702f812"
SEALED_WITNESS_DIGEST = "0" * 64

# Synthetic nonsecret model-style patch for the ResetVault single-use-token fix
# (same KEY_VALUE_ASSIGNMENT false-positive shape as the reported seventh live
# run: ordinary token/password variable references in context and added lines).
BENIGN_RESET_VAULT_PATCH = (
    "diff --git a/tests/fixtures/reset_vault/src/reset_vault/vault.py "
    "b/tests/fixtures/reset_vault/src/reset_vault/vault.py\n"
    "--- a/tests/fixtures/reset_vault/src/reset_vault/vault.py\n"
    "+++ b/tests/fixtures/reset_vault/src/reset_vault/vault.py\n"
    "@@ -33,14 +33,14 @@ class ResetVault:\n"
    "         return self._passwords.get(user_id)\n"
    " \n"
    "     def create_reset_token(self, user_id: str, ttl_seconds: float = 3600.0) -> str:\n"
    '         """Issue a new password reset token."""\n'
    "         token = secrets.token_hex(16)\n"
    "         self._tokens[token] = {\n"
    '             "user_id": user_id,\n'
    '             "expires_at": time.time() + ttl_seconds,\n'
    '             "created_at": time.time(),\n'
    "         }\n"
    "         return token\n"
    " \n"
    "     def redeem_reset_token(self, token: str, new_password: str) -> bool:\n"
    '         """Redeem reset token and update password.\n'
    "@@ -60,5 +62,7 @@ class ResetVault:\n"
    " \n"
    '         user_id = record["user_id"]\n'
    "         self._passwords[user_id] = new_password\n"
    "+        # Invalidate the reset token upon redemption (single-use invariant)\n"
    "+        del self._tokens[token]\n"
    " \n"
    "         return True\n"
)

# Minimal benign single-hunk patch exercising the documented false-positive shapes.
BENIGN_RUNTIME_ASSIGNMENT_PATCH = (
    "diff --git a/src/demo_service.py b/src/demo_service.py\n"
    "--- a/src/demo_service.py\n"
    "+++ b/src/demo_service.py\n"
    "@@ -2,4 +2,7 @@ import secrets\n"
    " def issue():\n"
    "     token = None\n"
    "+    token = secrets.token_hex(16)\n"
    "+    token = new_token\n"
    "+    password = derive_password(user)\n"
    "     return token\n"
)


def _patch_digest(patch_text: str) -> str:
    return hashlib.sha256(patch_text.encode("utf-8")).hexdigest()


def _source_identity() -> SourceIdentity:
    return SourceIdentity(
        locator=SOURCE_LOCATOR,
        revision=CommitRevision(SOURCE_COMMIT),
    )


def _plan_subtraction(
    patch_text: str,
    *,
    strategy: SubtractionStrategyType = SubtractionStrategyType.FULL_PATCH_REVERT,
    target_files: tuple[str, ...] = (),
    target_hunk_ids: tuple[str, ...] = (),
) -> CounterfactualDeltaPlan:
    return CandidateDeltaSubtractor.plan_subtraction(
        candidate_id="cand-p27-06-repair-001",
        candidate_patch_text=patch_text,
        candidate_patch_digest=_patch_digest(patch_text),
        candidate_tree_digest=CANDIDATE_TREE,
        source_commit_id=SOURCE_COMMIT,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        sealed_witness_digest=SEALED_WITNESS_DIGEST,
        request=SubtractionRequest(
            strategy_type=strategy,
            target_files=target_files,
            target_hunk_ids=target_hunk_ids,
            description="P-27.06 source-patch secret repair adversarial test",
        ),
        source_identity=_source_identity(),
    )


def _python_patch(added_line: str, context_line: str | None = None) -> str:
    lines = [
        "diff --git a/src/module.py b/src/module.py\n",
        "--- a/src/module.py\n",
        "+++ b/src/module.py\n",
        "@@ -1,2 +1,2 @@\n",
    ]
    if context_line is not None:
        lines.append(f" {context_line}\n")
        lines_header_old = 2
    else:
        lines_header_old = 1
    lines.append(f"+{added_line}\n")
    if context_line is not None:
        lines.append(" pass\n")
        header = f"@@ -1,{lines_header_old + 1} +1,{lines_header_old + 1} @@\n"
    else:
        header = f"@@ -1,{lines_header_old} +1,{lines_header_old} @@\n"
    lines[3] = header
    return "".join(lines)


# ==============================================================================
# 1. Benign Python runtime assignments are accepted
# ==============================================================================


class TestBenignPythonAssignmentsAccepted:
    def test_reset_vault_shaped_patch_passes_validator(self) -> None:
        validate_no_secrets_in_source_patch(BENIGN_RESET_VAULT_PATCH, path="candidate_patch_text")

    def test_runtime_assignment_shapes_pass_validator(self) -> None:
        validate_no_secrets_in_source_patch(
            BENIGN_RUNTIME_ASSIGNMENT_PATCH, path="candidate_patch_text"
        )

    @pytest.mark.parametrize(
        "added_line",
        [
            "token = secrets.token_hex(16)",
            "token = new_token",
            "token = None",
            "token = uuid.uuid4().hex",
            "password = derive_password(user)",
            "api_key = rotate_api_key(previous_key)",
            "token: str",
            "auth_token = request.headers.get_token()",
            "secret = hmac.digest(seed, nonce)",
        ],
    )
    def test_individual_benign_added_lines_pass(self, added_line: str) -> None:
        validate_no_secrets_in_source_patch(_python_patch(added_line))

    def test_benign_keyword_argument_and_dict_entry_pass(self) -> None:
        validate_no_secrets_in_source_patch(_python_patch("issue_reset(password=new_password)"))
        validate_no_secrets_in_source_patch(_python_patch('cfg = {"password": new_password}'))


# ==============================================================================
# 2. Valid ResetVault patch passes the subtraction chain
# ==============================================================================


class TestResetVaultPatchPassesSubtractionChain:
    def test_full_patch_revert_plan_is_created(self) -> None:
        plan = _plan_subtraction(BENIGN_RESET_VAULT_PATCH)
        assert plan.target_candidate_patch_digest == _patch_digest(BENIGN_RESET_VAULT_PATCH)
        assert plan.candidate_tree_digest == CANDIDATE_TREE
        assert plan.subtracted_delta_text == BENIGN_RESET_VAULT_PATCH
        assert plan.counterfactual_patch_text == ""

    def test_file_level_revert_residual_patch_passes(self) -> None:
        plan = _plan_subtraction(
            BENIGN_RESET_VAULT_PATCH,
            strategy=SubtractionStrategyType.FILE_LEVEL_REVERT,
            target_files=("tests/fixtures/reset_vault/src/reset_vault/vault.py",),
        )
        assert plan.counterfactual_patch_text == ""
        # The residual counterfactual patch and reverse delta both pass the
        # source-patch secret boundary (materializer Step D inputs).
        validate_no_secrets_in_source_patch(
            plan.counterfactual_patch_text, path="counterfactual_patch_text"
        )
        validate_no_secrets_in_source_patch(plan.reverse_delta_text, path="reverse_delta_text")

    def test_hunk_level_revert_residual_patch_passes(self) -> None:
        parsed = parse_candidate_patch(BENIGN_RESET_VAULT_PATCH)
        hunk_ids = sorted(h.hunk_id for f in parsed.files for h in f.hunks)
        plan = _plan_subtraction(
            BENIGN_RESET_VAULT_PATCH,
            strategy=SubtractionStrategyType.HUNK_LEVEL_REVERT,
            target_hunk_ids=(hunk_ids[0],),
        )
        assert plan.subtracted_hunk_ids == (hunk_ids[0],)
        assert plan.counterfactual_patch_text.strip()
        validate_no_secrets_in_source_patch(
            plan.counterfactual_patch_text, path="counterfactual_patch_text"
        )


# ==============================================================================
# 3. Real hardcoded credentials remain rejected
# ==============================================================================


class TestHardcodedCredentialsRemainRejected:
    @pytest.mark.parametrize(
        "added_line",
        [
            'api_key = "ghp_123456789012345678901234567890123456"',
            'token = "sk-abcdefghijklmnopqrstuvwx"',
            'password = "hunter2"',
            'NEBIUS_API_KEY = "nb_live_123456789012345678901234567890"',
            'token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"',
            'client_secret = "s3cr3t-valu3-with-padding"',
            "api_key = 'synthetic_secret_value_xyz'",
        ],
    )
    def test_hardcoded_literal_credentials_rejected(self, added_line: str) -> None:
        with pytest.raises(SecretPersistenceError, match="KEY_VALUE_ASSIGNMENT|TOKEN_PREFIX"):
            validate_no_secrets_in_source_patch(_python_patch(added_line))

    def test_authorization_header_in_python_code_rejected(self) -> None:
        with pytest.raises(SecretPersistenceError):
            validate_no_secrets_in_source_patch(
                _python_patch('headers = {"Authorization": "Bearer abc12345678"}')
            )

    def test_pem_private_key_in_python_code_rejected(self) -> None:
        pem_line = (
            'private_key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEow\\n'
            '-----END RSA PRIVATE KEY-----"'
        )
        with pytest.raises(SecretPersistenceError):
            validate_no_secrets_in_source_patch(_python_patch(pem_line))

    def test_credential_url_in_python_code_rejected(self) -> None:
        with pytest.raises(SecretPersistenceError):
            validate_no_secrets_in_source_patch(
                _python_patch('endpoint = "https://user:pass@example.com/v1"')
            )

    def test_recognized_token_prefix_rejected_even_without_sensitive_key(self) -> None:
        with pytest.raises(SecretPersistenceError, match="TOKEN_PREFIX"):
            validate_no_secrets_in_source_patch(
                _python_patch('value = "sk-abcdefghijklmnopqrstuvwx"')
            )

    def test_secret_patch_rejected_by_subtraction_chain(self) -> None:
        secret_patch = (
            "diff --git a/src/keys.py b/src/keys.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/src/keys.py\n"
            "+++ b/src/keys.py\n"
            "@@ -1,2 +1,3 @@\n"
            " def key(): pass\n"
            '+NEBIUS_API_KEY = "nb_live_123456789012345678901234567890"\n'
            " def key(): pass\n"
        )
        with pytest.raises(SecretPolicySubtractionError, match="secret"):
            _plan_subtraction(secret_patch)


# ==============================================================================
# 4. Secrets in added code, string literals, context or removed lines
# ==============================================================================


class TestSecretLocationsRemainRejected:
    def test_secret_in_context_line_rejected(self) -> None:
        patch = _python_patch(
            "value = compute()",
            context_line='password = "hunter2"',
        )
        with pytest.raises(SecretPersistenceError):
            validate_no_secrets_in_source_patch(patch)

    def test_secret_in_removed_line_rejected(self) -> None:
        patch = (
            "diff --git a/src/module.py b/src/module.py\n"
            "--- a/src/module.py\n"
            "+++ b/src/module.py\n"
            "@@ -1,2 +1,1 @@\n"
            '-password = "hunter2"\n'
            "+value = compute()\n"
        )
        with pytest.raises(SecretPersistenceError):
            validate_no_secrets_in_source_patch(patch)

    def test_secret_in_added_code_rejected(self) -> None:
        with pytest.raises(SecretPersistenceError):
            validate_no_secrets_in_source_patch(_python_patch('token = "abc123secret"'))

    def test_string_literal_inside_call_fails_closed(self) -> None:
        # Embedded string literals inside the bound expression are never exempt.
        with pytest.raises(SecretPersistenceError):
            validate_no_secrets_in_source_patch(
                _python_patch('token = record.get("issued_token", token)')
            )

    def test_generic_boundary_still_rejects_benign_patch_text(self) -> None:
        # Negative control: the generic (non-code) boundary is NOT weakened.
        with pytest.raises(SecretPersistenceError, match="KEY_VALUE_ASSIGNMENT"):
            validate_no_secrets(BENIGN_RESET_VAULT_PATCH, path="candidate_patch_text")


# ==============================================================================
# 5. Malformed or ambiguous input fails closed
# ==============================================================================


class TestMalformedOrAmbiguousInputFailsClosed:
    def test_headerless_patch_text_fails_closed(self) -> None:
        with pytest.raises(SecretPersistenceError):
            validate_no_secrets_in_source_patch("token = new_token\n")

    def test_non_python_env_file_fails_closed(self) -> None:
        patch = (
            "diff --git a/.env b/.env\n"
            "--- a/.env\n"
            "+++ b/.env\n"
            "@@ -1,1 +1,1 @@\n"
            "-OLD=1\n"
            "+API_TOKEN=abc123def456\n"
        )
        with pytest.raises(SecretPersistenceError):
            validate_no_secrets_in_source_patch(patch)

    def test_non_python_json_file_fails_closed(self) -> None:
        patch = (
            "diff --git a/config.json b/config.json\n"
            "--- a/config.json\n"
            "+++ b/config.json\n"
            "@@ -1,2 +1,2 @@\n"
            " {\n"
            '+  "api_key": "nb_live_123456789012345678901234567890"\n'
            " }\n"
        )
        with pytest.raises(SecretPersistenceError):
            validate_no_secrets_in_source_patch(patch)

    def test_multi_statement_line_fails_closed(self) -> None:
        with pytest.raises(SecretPersistenceError):
            validate_no_secrets_in_source_patch(_python_patch('token = a; password = "hunter2"'))

    def test_comment_line_fails_closed(self) -> None:
        with pytest.raises(SecretPersistenceError):
            validate_no_secrets_in_source_patch(_python_patch("# token = abc123def456"))

    def test_non_string_input_raises_type_error(self) -> None:
        with pytest.raises(TypeError):
            validate_no_secrets_in_source_patch(b"diff --git a/x.py b/x.py")  # type: ignore[arg-type]


# ==============================================================================
# 6. Protected-surface mutations remain rejected
# ==============================================================================


class TestProtectedSurfacesRemainRejected:
    def test_verifier_surface_patch_rejected_by_subtraction(self) -> None:
        protected_patch = (
            "diff --git a/src/basebreak/verifier/witness_store.py "
            "b/src/basebreak/verifier/witness_store.py\n"
            "--- a/src/basebreak/verifier/witness_store.py\n"
            "+++ b/src/basebreak/verifier/witness_store.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+tamper\n"
        )
        with pytest.raises(ProtectedSurfaceSubtractionError, match="protected surface"):
            _plan_subtraction(protected_patch)


# ==============================================================================
# 7. Digest and tree identity preservation
# ==============================================================================


class TestDigestAndTreeIdentityPreserved:
    def test_patch_bytes_and_digests_unchanged_by_validation(self) -> None:
        original = BENIGN_RESET_VAULT_PATCH
        validate_no_secrets_in_source_patch(original, path="candidate_patch_text")
        assert original == BENIGN_RESET_VAULT_PATCH
        assert _patch_digest(original) == _patch_digest(BENIGN_RESET_VAULT_PATCH)

        plan = _plan_subtraction(original)
        assert plan.target_candidate_patch_digest == _patch_digest(BENIGN_RESET_VAULT_PATCH)
        assert plan.candidate_tree_digest == CANDIDATE_TREE
        assert plan.source_commit_id == SOURCE_COMMIT
        assert plan.subtracted_delta_text == BENIGN_RESET_VAULT_PATCH

    def test_no_self_certification_or_authority_granted(self) -> None:
        plan = _plan_subtraction(BENIGN_RESET_VAULT_PATCH)
        assert plan.is_authoritative is False
        assert plan.is_causally_verified is False
        assert plan.grants_pass is False


# ==============================================================================
# 8. Offline chain: subtraction -> patch-subset -> materialization
# ==============================================================================


class _MockCommandResult:
    def __init__(self, stdout: str) -> None:
        self.exit_code = 0
        self.stdout = stdout
        self.stderr = ""
        self.duration_seconds = 0.1
        self.operation_id = "op-mock-001"
        self.result_image_uuid = None


class _MockSourceMaterializer:
    def materialize_repository(
        self,
        *,
        source_identity: SourceIdentity,
        sandbox: Any,
        workspace_path: str,
        disposable: bool = False,
        timeout_seconds: int = 120,
        **kwargs: Any,
    ) -> MaterializedSourceRecord:
        return MaterializedSourceRecord(
            source_identity=source_identity,
            resolved_commit_sha=SOURCE_COMMIT,
            resolved_tree_sha="a" * 40,
            workspace_path=workspace_path,
            sandbox_identity=SandboxIdentity(sandbox_id="sbx-mock-base-001"),
            operation_id="op-mock-base-001",
            duration_seconds=0.1,
        )


class _MockSandboxAdapter:
    def __init__(self, stdout: str) -> None:
        self._stdout = stdout

    def execute_command(self, sandbox: Any, command: Any, **kwargs: Any) -> _MockCommandResult:
        return _MockCommandResult(self._stdout)


class TestOfflineChainReachesNextBoundary:
    def test_patch_subset_validator_accepts_benign_patch(self) -> None:
        parsed = parse_candidate_patch(BENIGN_RESET_VAULT_PATCH)
        hunk_ids = sorted(h.hunk_id for f in parsed.files for h in f.hunks)
        subset = create_tested_patch_subset_from_hunks(parsed, retained_hunk_ids=hunk_ids)
        assert subset.retained_hunk_ids == tuple(hunk_ids)
        assert subset.is_authoritative is False
        assert subset.grants_pass is False

    def test_patch_subset_validator_still_rejects_secret_patch(self) -> None:
        secret_patch = (
            "diff --git a/src/config.py b/src/config.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/src/config.py\n"
            "+++ b/src/config.py\n"
            "@@ -1,2 +1,3 @@\n"
            " config\n"
            "+api_key = 'synthetic_secret_value_xyz'\n"
            " config\n"
        )
        parsed = parse_candidate_patch(secret_patch)
        h0 = parsed.files[0].hunks[0].hunk_id
        with pytest.raises(SecretPersistenceError):
            create_tested_patch_subset_from_hunks(parsed, retained_hunk_ids=(h0,))

    def test_candidate_world_materialization_reaches_patch_application(self) -> None:
        stdout = (
            f"BASEBREAK_RESOLVED_COMMIT={SOURCE_COMMIT}\nBASEBREAK_RESOLVED_TREE={CANDIDATE_TREE}\n"
        )
        materializer = CausalRepositoryMaterializer(
            adapter=_MockSandboxAdapter(stdout),
            source_materializer=_MockSourceMaterializer(),
        )
        record = materializer.materialize_repository(
            source_identity=_source_identity(),
            sandbox=SandboxIdentity(sandbox_id="sbx-mock-cand-001"),
            world=ExecutionWorld.CANDIDATE,
            candidate_patch_text=BENIGN_RESET_VAULT_PATCH,
            expected_tree_sha=CANDIDATE_TREE,
        )
        assert isinstance(record, MaterializedSourceRecord)
        assert record.resolved_tree_sha == CANDIDATE_TREE
        assert record.is_verified is True

    def test_candidate_world_materialization_still_rejects_secret_patch(self) -> None:
        secret_patch = (
            "diff --git a/src/keys.py b/src/keys.py\n"
            "--- a/src/keys.py\n"
            "+++ b/src/keys.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def key(): pass\n"
            '+NEBIUS_API_KEY = "nb_live_123456789012345678901234567890"\n'
        )
        materializer = CausalRepositoryMaterializer(
            adapter=_MockSandboxAdapter(""),
            source_materializer=_MockSourceMaterializer(),
        )
        with pytest.raises(SecretPersistenceError):
            materializer.materialize_repository(
                source_identity=_source_identity(),
                sandbox=SandboxIdentity(sandbox_id="sbx-mock-cand-002"),
                world=ExecutionWorld.CANDIDATE,
                candidate_patch_text=secret_patch,
            )

    def test_counterfactual_world_materialization_reaches_delta_application(self) -> None:
        plan = _plan_subtraction(BENIGN_RESET_VAULT_PATCH)
        stdout = (
            f"STAGED_CANDIDATE_TREE={CANDIDATE_TREE}\n"
            f"BASEBREAK_RESOLVED_COMMIT={SOURCE_COMMIT}\n"
            f"BASEBREAK_RESOLVED_TREE={'b' * 40}\n"
        )
        materializer = CausalRepositoryMaterializer(
            adapter=_MockSandboxAdapter(stdout),
            source_materializer=_MockSourceMaterializer(),
        )
        record = materializer.materialize_repository(
            source_identity=_source_identity(),
            sandbox=SandboxIdentity(sandbox_id="sbx-mock-cf-001"),
            world=ExecutionWorld.COUNTERFACTUAL,
            counterfactual_plan=plan,
            candidate_patch_text=BENIGN_RESET_VAULT_PATCH,
        )
        assert isinstance(record, MaterializedSourceRecord)
        assert record.resolved_tree_sha == "b" * 40

    def test_counterfactual_world_materialization_rejects_secret_reverse_delta(
        self,
    ) -> None:
        plan = _plan_subtraction(BENIGN_RESET_VAULT_PATCH)
        # Tamper the plan's bound reverse delta into a hardcoded credential while
        # keeping a valid digest, then confirm the materializer secret boundary
        # rejects it before any patch application.

        secret_reverse = (
            "diff --git a/src/keys.py b/src/keys.py\n"
            "--- a/src/keys.py\n"
            "+++ b/src/keys.py\n"
            "@@ -1,1 +1,1 @@\n"
            '-old\n+NEBIUS_API_KEY = "nb_live_123456789012345678901234567890"\n'
        )
        object.__setattr__(plan, "reverse_delta_text", secret_reverse)
        object.__setattr__(
            plan,
            "reverse_delta_digest",
            hashlib.sha256(secret_reverse.encode("utf-8")).hexdigest(),
        )
        materializer = CausalRepositoryMaterializer(
            adapter=_MockSandboxAdapter(""),
            source_materializer=_MockSourceMaterializer(),
        )
        with pytest.raises(CounterfactualMaterializationError, match="secret"):
            materializer.materialize_repository(
                source_identity=_source_identity(),
                sandbox=SandboxIdentity(sandbox_id="sbx-mock-cf-002"),
                world=ExecutionWorld.COUNTERFACTUAL,
                counterfactual_plan=plan,
                candidate_patch_text=BENIGN_RESET_VAULT_PATCH,
            )
