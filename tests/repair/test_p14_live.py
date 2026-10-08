"""P-14 Live Demonstration: End-to-End Sealed Repair Loop in Nebius Token Factory.

Demonstrates the sealed repair loop on real Nebius Token Factory Sandboxes:
1. Candidate 0 fails verification on demo target (intentional bug).
2. Verifier emits bounded safe feedback (zero witness code disclosed).
3. Real AI Builder (Nemotron) produces repaired candidate with new git patch and tree hash.
4. Verifier creates fresh disposable sandbox and reproduces verification.
5. Repaired candidate passes verification -> VERIFIED_AFTER_REPAIR.
6. Emits cryptographic RepairLoopReceipt with provenance LIVE_NEBIUS.
7. Verifies sandbox non-reuse, candidate non-inheritance, and receipt integrity.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

import dotenv
import pytest

from basebreak.adapters.nebius.client import (
    ChatMessage,
    ModelClientConfig,
    NebiusModelClient,
)
from basebreak.adapters.nebius.materialization import NebiusSourceMaterializer
from basebreak.adapters.nebius.models import DEFAULT_PRIMARY_MODEL
from basebreak.adapters.nebius.sandbox import (
    NebiusSandboxAdapter,
    SandboxClientConfig,
)
from basebreak.builder.capture import CandidateSnapshot
from basebreak.causal.materializer import CausalRepositoryMaterializer
from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.compiler.semantics import CertaintyLevel
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.repair.context import BuilderRepairContextEnvelope
from basebreak.repair.engine import (
    RepairLoopBudget,
    RepairLoopCounters,
    RepairLoopReceipt,
    RepairLoopStatus,
    run_sealed_repair_loop,
    verify_repair_loop_receipt_integrity,
)
from basebreak.security.protected_surfaces import (
    get_canonical_basebreak_protected_manifest,
    validate_diff,
)
from basebreak.security.secret_policy import validate_no_secrets
from basebreak.verifier.sandbox import VerifierSandboxManager
from basebreak.verifier.witness_lock import create_witness_lock
from basebreak.verifier.witness_store import (
    TrustedWitnessVault,
    WitnessArtifact,
)

DEMO_TARGET_LOCATOR = "https://github.com/zyganali-glitch/basebreak-demo-target.git"
DEMO_TARGET_BASE_COMMIT = "40ff923a134a21d8e357deb7a7988571cd396b56"
DEMO_TARGET_BASE_TREE = "f81f6faa0c7572f9941570bbce376fadc10f39a3"

# Candidate 0 (Buggy Candidate): Returns "QUIET: " instead of ""
BUGGY_PATCH_TEXT = (
    "diff --git a/src/demo_target/cli.py b/src/demo_target/cli.py\n"
    "index 878b16f..1111111 100644\n"
    "--- a/src/demo_target/cli.py\n"
    "+++ b/src/demo_target/cli.py\n"
    "@@ -13,5 +13,5 @@ def format_quiet_output(output: str, quiet: bool = False) -> str:\n"
    '     When quiet is True, stdout must be empty ("").\n'
    '     """\n'
    "     if quiet:\n"
    '-        return "verbose: " + output\n'
    '+        return "QUIET: " + output\n'
    "     return output\n"
)
BUGGY_PATCH_DIGEST = hashlib.sha256(BUGGY_PATCH_TEXT.encode("utf-8")).hexdigest()

EXPECTED_CORRECT_TREE_DIGEST = "31f7ab50a5e0da6da9160ce47bdc5daf71072216"


def _make_bug_fix_contract(req_id: str = "REQ-P14-REPAIR-01") -> FrozenContract:
    req = FrozenRequirement(
        requirement_id=req_id,
        statement="When user specifies --quiet flag, stdout must be empty.",
        citation="cli.py format_quiet_output docstring",
        citation_start=0,
        citation_end=60,
    )
    contract = object.__new__(FrozenContract)
    object.__setattr__(contract, "schema_version", "1.0.0")
    object.__setattr__(contract, "task_digest", "b" * 64)
    object.__setattr__(contract, "change_class", ChangeClass.BUG_FIX)
    object.__setattr__(contract, "certainty", CertaintyLevel.CONFIDENT)
    object.__setattr__(contract, "requirements", (req,))
    raw = f"contract-{ChangeClass.BUG_FIX.value}-{req_id}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    object.__setattr__(contract, "contract_digest", digest)
    return contract


@pytest.mark.live
def test_p14_live_sealed_repair_loop() -> None:
    """Execute end-to-end sealed repair loop demonstration in Nebius Token Factory Sandboxes."""
    env_file = Path(".env")
    if env_file.is_file():
        try:
            dotenv.load_dotenv(dotenv_path=env_file)
        except Exception:
            pass

    api_key = os.environ.get("NEBIUS_API_KEY")
    if not api_key:
        pytest.skip("NEBIUS_API_KEY not configured for live test")

    project_id = os.environ.get("NEBIUS_PROJECT_ID", "aiproject-e00mae0nmzkxjswr1k")
    if not project_id:
        pytest.skip("NEBIUS_PROJECT_ID not configured for live test")

    # Record clean implementation commit SHA before test
    impl_sha_proc = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    )
    impl_sha = impl_sha_proc.stdout.strip()
    assert len(impl_sha) == 40, f"Expected 40-char SHA, got {impl_sha!r}"

    adapter = NebiusSandboxAdapter(
        config=SandboxClientConfig(
            api_key=api_key,
            project_id=project_id,
            poll_interval_seconds=1.0,
            default_timeout_seconds=180,
        )
    )
    source_materializer = NebiusSourceMaterializer(adapter=adapter)
    materializer = CausalRepositoryMaterializer(
        adapter=adapter, source_materializer=source_materializer
    )

    source_id = SourceIdentity(
        locator=DEMO_TARGET_LOCATOR,
        revision=CommitRevision(DEMO_TARGET_BASE_COMMIT),
    )
    contract = _make_bug_fix_contract()

    # Create Sealed Witness in Vault & Lock
    vault = TrustedWitnessVault(b"test-live-vault-secret-32-bytes!!")
    witness_test_code = (
        "import sys\n"
        "sys.path.insert(0, '/verifier_workspace/src')\n"
        "from demo_target.cli import format_quiet_output\n"
        "\n"
        "# Defect verification check: quiet=True must return empty string\n"
        "res_quiet = format_quiet_output('payload_string', quiet=True)\n"
        "assert res_quiet == '', f'Defect: got {res_quiet!r}'\n"
        "\n"
        "# Preservation check: quiet=False must return original string\n"
        "res_normal = format_quiet_output('payload_string', quiet=False)\n"
        "assert res_normal == 'payload_string', f'Preservation: got {res_normal!r}'\n"
        "print('WITNESS_PASS: format_quiet_output satisfies quiet specification')\n"
    )
    witness_artifact = WitnessArtifact.from_text("tests/test_witness_repair.py", witness_test_code)
    sealed_record = vault.seal_witness(
        witness_id="wit-repair-live-01",
        requirement_id=contract.requirements[0].requirement_id,
        frozen_contract_digest=contract.contract_digest,
        source_commit_id=DEMO_TARGET_BASE_COMMIT,
        artifacts=[witness_artifact],
    )
    witness_lock = create_witness_lock(record=sealed_record, vault=vault)

    # Clone clean base repository locally once to serve as reference
    with tempfile.TemporaryDirectory() as td_base:
        base_repo_dir = Path(td_base) / "base_repo"
        subprocess.run(
            [
                "git",
                "clone",
                "--config",
                "core.autocrlf=input",
                DEMO_TARGET_LOCATOR,
                str(base_repo_dir),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "checkout", DEMO_TARGET_BASE_COMMIT],
            cwd=base_repo_dir,
            check=True,
            capture_output=True,
        )
        base_tree_check = subprocess.run(
            ["git", "write-tree"],
            cwd=base_repo_dir,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        assert base_tree_check == DEMO_TARGET_BASE_TREE
        base_cli_py = (base_repo_dir / "src" / "demo_target" / "cli.py").read_text(encoding="utf-8")

        # -------------------------------------------------------------------------
        # STEP 1: Verify Initial Candidate (Candidate 0) FAILS in real Nebius sandbox
        # -------------------------------------------------------------------------
        sbx_c0 = adapter.create_sandbox(disposable=False)
        sbx_c0_id = sbx_c0.sandbox_identity.sandbox_id
        c0_exit_code: int = -1
        c0_tree_sha: str = ""
        try:
            # Materialize base
            source_materializer.materialize_repository(
                source_identity=source_id,
                sandbox=sbx_c0,
                workspace_path="/verifier_workspace",
                disposable=False,
                timeout_seconds=120,
            )
            # Apply buggy patch
            b64_patch0 = base64.b64encode(BUGGY_PATCH_TEXT.encode("utf-8")).decode("ascii")
            apply_cmd0 = (
                "set -e\n"
                "cd /verifier_workspace\n"
                f'printf "%s" "{b64_patch0}" | base64 -d > /tmp/cand0.patch\n'
                "git apply --binary --whitespace=nowarn /tmp/cand0.patch\n"
                "rm -f /tmp/cand0.patch\n"
                "git add -A\n"
                "git write-tree\n"
            )
            res_apply0 = adapter.execute_command(
                sbx_c0,
                apply_cmd0,
                working_dir="/verifier_workspace",
                timeout_seconds=60,
                disposable=False,
            )
            assert res_apply0.exit_code == 0, f"Buggy patch apply failed: {res_apply0.stderr}"
            c0_tree_sha = res_apply0.stdout.strip().splitlines()[-1]

            # Deploy witness
            b64_wit = base64.b64encode(witness_test_code.encode("utf-8")).decode("ascii")
            deploy_cmd = (
                "set -e\n"
                "mkdir -p /verifier_workspace/tests\n"
                f'printf "%s" "{b64_wit}" | '
                "base64 -d > /verifier_workspace/tests/test_witness_repair.py\n"
            )
            res_deploy = adapter.execute_command(
                sbx_c0,
                deploy_cmd,
                working_dir="/verifier_workspace",
                timeout_seconds=30,
                disposable=False,
            )
            assert res_deploy.exit_code == 0

            # Execute witness against Candidate 0 -> MUST FAIL
            res_test0 = adapter.execute_command(
                sbx_c0,
                "python3 tests/test_witness_repair.py",
                working_dir="/verifier_workspace",
                timeout_seconds=60,
                disposable=True,
            )
            c0_exit_code = res_test0.exit_code or 1
            assert c0_exit_code != 0, f"Candidate 0 expected non-zero exit, got {c0_exit_code}"
            assert "AssertionError" in (res_test0.stderr or res_test0.stdout)
        finally:
            adapter.teardown_sandbox(sbx_c0)

        # -------------------------------------------------------------------------
        # STEP 2: Configure Initial Candidate Snapshot (Candidate 0)
        # -------------------------------------------------------------------------
        initial_candidate = CandidateSnapshot(
            candidate_id="cand-live-buggy-c0",
            source_identity=source_id,
            candidate_tree_digest=c0_tree_sha,
            patch_digest=BUGGY_PATCH_DIGEST,
            patch_text=BUGGY_PATCH_TEXT,
            files_added=(),
            files_modified=("src/demo_target/cli.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=contract.contract_digest,
            context_digest="0" * 64,
            sandbox_identity=SandboxIdentity(sbx_c0_id),
            provenance=EvidenceProvenance.LIVE_NEBIUS,
            is_authoritative=False,
        )

        # -------------------------------------------------------------------------
        # STEP 3: Define Real AI Builder Repair Function (Nebius Nemotron)
        # -------------------------------------------------------------------------
        model_cfg = ModelClientConfig(
            api_key=api_key,
            model=DEFAULT_PRIMARY_MODEL,
            max_tokens=4096,
            temperature=0.0,
            timeout_seconds=60.0,
        )
        model_client = NebiusModelClient(config=model_cfg)
        builder_invocations: list[str] = []
        model_executions: list[dict[str, Any]] = []
        repair_counters = RepairLoopCounters()

        def builder_repair_fn(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
            builder_invocations.append(ctx.repair_context_id)

            # --- MECHANICAL WITNESS-SECRECY PROOF ---
            ctx_repr = repr(ctx)
            assert "witness_test_code" not in ctx_repr
            assert "test_witness_repair.py" not in ctx_repr
            assert "wit-repair-live-01" not in ctx_repr
            assert "test-live-vault-secret" not in ctx_repr
            assert "WITNESS_PASS" not in ctx_repr
            assert "res_quiet" not in ctx_repr
            assert "res_normal" not in ctx_repr
            assert sbx_c0_id not in ctx_repr

            assert ctx.repair_feedback is not None
            assert "witness_test_code" not in ctx.repair_feedback.observed_behavior
            assert "test_witness_repair.py" not in ctx.repair_feedback.permitted_patch_region

            # --- CONSTRUCT BOUNDED PROMPT (Allowed context only) ---
            system_msg = (
                "You are an automated software repair engine. "
                "Output ONLY the python code block requested without conversational explanation."
            )
            user_prompt = (
                f"Requirement: {contract.requirements[0].statement}\n"
                f"Permitted edit scope: {', '.join(ctx.permitted_paths)}\n\n"
                "Base source code of src/demo_target/cli.py:\n"
                "```python\n"
                f"{base_cli_py}\n"
                "```\n\n"
                "Current buggy patch (Candidate 0):\n"
                "```diff\n"
                f"{ctx.parent_patch_text}\n"
                "```\n\n"
                "Verifier Failure Feedback:\n"
                f"- Failed Condition: {ctx.repair_feedback.failed_condition.value}\n"
                f"- Observed Behavior: {ctx.repair_feedback.observed_behavior}\n"
                f"- Expected Behavior: {ctx.repair_feedback.expected_behavior}\n\n"
                f"Repair Round: {ctx.repair_round} of {ctx.max_repair_rounds}\n\n"
                "Provide the complete repaired source code of src/demo_target/cli.py.\n"
                "Enclose the complete python code in ```python and ``` code blocks.\n"
                "Do NOT include any other text.\n"
            )

            # Strict secrecy checks on outgoing prompt string
            assert "witness_test_code" not in user_prompt
            assert "test_witness_repair.py" not in user_prompt
            assert "wit-repair-live-01" not in user_prompt
            assert "test-live-vault-secret" not in user_prompt
            assert "WITNESS_PASS" not in user_prompt
            assert "res_quiet" not in user_prompt
            assert "res_normal" not in user_prompt
            assert sbx_c0_id not in user_prompt
            assert api_key not in user_prompt

            # --- REAL MODEL INFERENCE ---
            model_res = model_client.complete(
                [
                    ChatMessage(role="system", content=system_msg),
                    ChatMessage(role="user", content=user_prompt),
                ]
            )

            assert model_res.configured_model == DEFAULT_PRIMARY_MODEL
            assert model_res.content and len(model_res.content) > 0
            if model_res.usage:
                repair_counters.tokens_used += model_res.usage.total_tokens

            model_exec_fact = {
                "configured_model": model_res.configured_model,
                "returned_model": model_res.returned_model,
                "request_id": model_res.request_id,
                "finish_reason": model_res.finish_reason,
                "prompt_tokens": model_res.usage.prompt_tokens if model_res.usage else None,
                "completion_tokens": model_res.usage.completion_tokens if model_res.usage else None,
                "total_tokens": model_res.usage.total_tokens if model_res.usage else None,
                "duration_seconds": round(model_res.duration_seconds, 4),
            }
            model_executions.append(model_exec_fact)

            # --- PARSE AND VALIDATE MODEL OUTPUT ---
            code_match = re.search(r"```python\s*\n(.*?)\n```", model_res.content, re.DOTALL)
            if code_match:
                repaired_code = code_match.group(1).strip() + "\n"
            else:
                repaired_code = model_res.content.strip() + "\n"

            validate_no_secrets(repaired_code)

            # --- MATERIALIZE REPAIRED CANDIDATE IN CLEAN LOCAL WORKSPACE ---
            with tempfile.TemporaryDirectory() as td_builder:
                builder_work = Path(td_builder) / "builder_candidate"
                subprocess.run(
                    [
                        "git",
                        "clone",
                        "--config",
                        "core.autocrlf=input",
                        str(base_repo_dir),
                        str(builder_work),
                    ],
                    check=True,
                    capture_output=True,
                )
                cli_target = builder_work / "src" / "demo_target" / "cli.py"
                cli_target.write_text(repaired_code, encoding="utf-8")

                subprocess.run(
                    ["git", "add", "-A"], cwd=builder_work, check=True, capture_output=True
                )
                diff_proc = subprocess.run(
                    ["git", "diff", "--cached"],
                    cwd=builder_work,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                repaired_patch_text = diff_proc.stdout
                assert repaired_patch_text.strip(), "Model produced empty diff against base"

                tree_proc = subprocess.run(
                    ["git", "write-tree"],
                    cwd=builder_work,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                repaired_tree_digest = tree_proc.stdout.strip()

            # --- MECHANICAL CHECKS ON CANDIDATE ---
            repaired_patch_digest = hashlib.sha256(repaired_patch_text.encode("utf-8")).hexdigest()

            # Anti-stagnation & novelty checks
            assert repaired_patch_digest != ctx.parent_patch_digest, (
                "Repaired patch identical to parent"
            )
            assert repaired_tree_digest != ctx.parent_candidate_tree_digest, (
                "Repaired tree identical to parent"
            )
            assert repaired_patch_digest != BUGGY_PATCH_DIGEST
            assert repaired_tree_digest != c0_tree_sha

            # Protected surface & secret validation
            manifest = get_canonical_basebreak_protected_manifest()
            validate_diff(repaired_patch_text, manifest)
            validate_no_secrets(repaired_patch_text)

            cand_id = f"cand-live-repaired-r{ctx.repair_round}-{uuid.uuid4().hex[:8]}"
            return CandidateSnapshot(
                candidate_id=cand_id,
                source_identity=source_id,
                candidate_tree_digest=repaired_tree_digest,
                patch_digest=repaired_patch_digest,
                patch_text=repaired_patch_text,
                files_added=(),
                files_modified=("src/demo_target/cli.py",),
                files_deleted=(),
                builder_authored_tests=(),
                frozen_contract_digest=contract.contract_digest,
                context_digest=ctx.repair_context_digest,
                sandbox_identity=None,  # Clean fresh context
                provenance=EvidenceProvenance.LIVE_NEBIUS,
                is_authoritative=False,
            )

        # -------------------------------------------------------------------------
        # STEP 4: Run Sealed Repair Loop Orchestration in Live Nebius
        # -------------------------------------------------------------------------
        manager = VerifierSandboxManager(
            known_builder_sandbox_ids=(sbx_c0_id,)  # Forbid reuse of Candidate 0 sandbox
        )

        receipt: RepairLoopReceipt = run_sealed_repair_loop(
            initial_candidate=initial_candidate,
            frozen_contract=contract,
            source_identity=source_id,
            sealed_record=sealed_record,
            witness_lock=witness_lock,
            builder_repair_fn=builder_repair_fn,
            sandbox_manager=manager,
            sandbox_adapter=adapter,
            materializer=materializer,
            execution_command="python3 tests/test_witness_repair.py",
            budget=RepairLoopBudget(max_repair_rounds=2),
            originating_receipt_digest=hashlib.sha256(b"rcpt-initial-fail-candidate-0").hexdigest(),
            prior_sandbox_ids=[sbx_c0_id],
            provenance=EvidenceProvenance.LIVE_NEBIUS,
            counters=repair_counters,
        )

        # -------------------------------------------------------------------------
        # STEP 5: Verify Repair Loop Receipt & Anti-Tampering Facts
        # -------------------------------------------------------------------------
        assert receipt.status == RepairLoopStatus.VERIFIED_AFTER_REPAIR
        assert receipt.preliminary_verdict == PreliminaryVerdict.VERIFIED
        assert receipt.is_causally_verified is True
        assert receipt.grants_pass is True
        assert receipt.is_authoritative is False  # Zero verdict authority invariant
        assert receipt.provenance == EvidenceProvenance.LIVE_NEBIUS
        assert receipt.total_rounds == 1
        assert len(receipt.lineage_digests) == 1
        assert len(receipt.feedback_digests) == 1
        assert len(receipt.reproduction_receipt_digests) == 1
        assert receipt.final_candidate_id is not None
        assert receipt.final_candidate_id.startswith("cand-live-repaired-r1-")
        assert receipt.final_patch_digest is not None
        assert len(receipt.final_patch_digest) == 64
        assert receipt.final_tree_digest is not None
        assert len(receipt.final_tree_digest) == 40
        assert receipt.final_patch_digest != BUGGY_PATCH_DIGEST
        assert receipt.final_tree_digest != c0_tree_sha
        assert receipt.final_tree_digest == EXPECTED_CORRECT_TREE_DIGEST

        # Anti-Tampering Check
        assert verify_repair_loop_receipt_integrity(receipt) is True
        assert len(builder_invocations) == 1
        assert len(model_executions) == 1
        assert receipt.counters["tokens_used"] > 0
        assert receipt.counters["builder_attempts_used"] == 1
        assert receipt.counters["verifier_executions_used"] == 1
        assert receipt.counters["sandbox_executions_used"] == 1

        # Print comprehensive deterministic facts for judge-facing proof report
        print("\n=======================================================")
        print("P-14 SEALED REPAIR LOOP LIVE_NEBIUS CLOSURE PROOF FACTS")
        print("=======================================================")
        print(f"Basebreak Implementation SHA: {impl_sha}")
        print(f"Repair Receipt ID: {receipt.repair_receipt_id}")
        print(f"Receipt Digest: {receipt.receipt_digest}")
        print(f"Candidate 0 ID: {receipt.initial_candidate_id}")
        print(f"Candidate 0 Patch Digest: {receipt.initial_patch_digest}")
        print(f"Candidate 0 Tree Digest: {receipt.initial_tree_digest}")
        print(f"Candidate 0 Sandbox ID: {sbx_c0_id} (Exit Code: {c0_exit_code})")
        print(f"Model Invocations: {len(model_executions)}")
        print(f"Model Execution Metadata: {model_executions[0]}")
        print(f"Candidate 1 ID: {receipt.final_candidate_id}")
        print(f"Candidate 1 Patch Digest: {receipt.final_patch_digest}")
        print(f"Candidate 1 Tree Digest: {receipt.final_tree_digest}")
        print(f"Lineage Digest: {receipt.lineage_digests[0]}")
        print(f"Feedback Digest: {receipt.feedback_digests[0]}")
        print(f"Reproduction Receipt Digest: {receipt.reproduction_receipt_digests[0]}")
        print(f"Total Rounds: {receipt.total_rounds}")
        print(f"Status: {receipt.status.value}")
        print(f"Preliminary Verdict: {receipt.preliminary_verdict.value}")
        print(f"Causally Verified: {receipt.is_causally_verified}")
        print(f"Grants Pass: {receipt.grants_pass}")
        print(f"Provenance: {receipt.provenance.value}")
        print(f"Counters: {receipt.counters}")
        print("=======================================================\n")
