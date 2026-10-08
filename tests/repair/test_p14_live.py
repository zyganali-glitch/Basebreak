"""P-14 Live Demonstration: End-to-End Sealed Repair Loop in Nebius Token Factory.

Demonstrates the sealed repair loop on real Nebius Token Factory Sandboxes:
1. Candidate 0 fails verification on demo target (intentional bug).
2. Verifier emits bounded safe feedback (zero witness code disclosed).
3. Builder produces repaired candidate with new git patch and tree hash.
4. Verifier creates fresh disposable sandbox and reproduces verification.
5. Repaired candidate passes verification -> VERIFIED_AFTER_REPAIR.
6. Emits cryptographic RepairLoopReceipt with provenance LIVE_NEBIUS.
7. Verifies sandbox non-reuse, candidate non-inheritance, and receipt integrity.
"""

from __future__ import annotations

import base64
import hashlib
import os

import pytest

from basebreak.adapters.nebius.materialization import NebiusSourceMaterializer
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
    RepairLoopReceipt,
    RepairLoopStatus,
    run_sealed_repair_loop,
    verify_repair_loop_receipt_integrity,
)
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

# Candidate 1 (Repaired Candidate): Returns "" when quiet=True
REPAIRED_PATCH_TEXT = (
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
REPAIRED_PATCH_DIGEST = hashlib.sha256(REPAIRED_PATCH_TEXT.encode("utf-8")).hexdigest()
REPAIRED_TREE_DIGEST = "31f7ab50a5e0da6da9160ce47bdc5daf71072216"


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
    api_key = os.environ.get("NEBIUS_API_KEY")
    if not api_key:
        pytest.skip("NEBIUS_API_KEY not configured for live test")

    project_id = os.environ.get("NEBIUS_PROJECT_ID", "aiproject-e00mae0nmzkxjswr1k")
    if not project_id:
        pytest.skip("NEBIUS_PROJECT_ID not configured for live test")

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

    # -------------------------------------------------------------------------
    # STEP 1: Verify Initial Candidate (Candidate 0) FAILS in real Nebius sandbox
    # -------------------------------------------------------------------------
    # First, let's materialize Candidate 0 and execute the witness to confirm it FAILS.
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
    # STEP 3: Define Builder Repair Function
    # -------------------------------------------------------------------------
    # Builder receives only permitted feedback envelope in fresh context
    builder_invocations: list[str] = []

    def builder_repair_fn(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        builder_invocations.append(ctx.repair_context_id)
        # Verify Builder receives safe sanitized feedback without hidden witness disclosure
        assert ctx.repair_feedback is not None
        assert "witness_test_code" not in ctx.repair_feedback.observed_behavior
        assert "test_witness_repair.py" not in ctx.repair_feedback.permitted_patch_region

        # Builder emits Candidate 1 with repaired patch and new identity
        return CandidateSnapshot(
            candidate_id="cand-live-repaired-c1",
            source_identity=source_id,
            candidate_tree_digest=REPAIRED_TREE_DIGEST,
            patch_digest=REPAIRED_PATCH_DIGEST,
            patch_text=REPAIRED_PATCH_TEXT,
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
    assert receipt.final_candidate_id == "cand-live-repaired-c1"
    assert receipt.final_patch_digest == REPAIRED_PATCH_DIGEST
    assert receipt.final_tree_digest == REPAIRED_TREE_DIGEST

    # Anti-Tampering Check
    assert verify_repair_loop_receipt_integrity(receipt) is True
    assert len(builder_invocations) == 1

    # Print comprehensive deterministic facts for judge-facing proof report
    print("\n=======================================================")
    print("P-14 SEALED REPAIR LOOP LIVE_NEBIUS CLOSURE PROOF FACTS")
    print("=======================================================")
    print(f"Repair Receipt ID: {receipt.repair_receipt_id}")
    print(f"Receipt Digest: {receipt.receipt_digest}")
    print(f"Candidate 0 ID: {receipt.initial_candidate_id}")
    print(f"Candidate 0 Patch Digest: {receipt.initial_patch_digest}")
    print(f"Candidate 0 Tree Digest: {receipt.initial_tree_digest}")
    print(f"Candidate 0 Sandbox ID: {sbx_c0_id} (Exit Code: {c0_exit_code})")
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
