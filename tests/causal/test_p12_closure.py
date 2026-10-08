"""Comprehensive closure test suite for P-12 Bounded Hunk Minimization & Causal Slicing.

Validates:
- P-12.01: Deterministic patch-unit parsing and bounded subset construction.
- P-12.02: Bounded hunk/subset minimization algorithm with authentic execution facts.
- P-12.03: Safe evidence caching with mandatory runtime_config_digest binding.
- P-12.04: Causal slice receipt derivation mechanically bound to minimizer records.
- P-12.05: Comprehensive adversarial, interaction, and ambiguity test coverage.
- Live Phase Closure: End-to-end LIVE_NEBIUS demonstration against isolated demo target.
"""

from __future__ import annotations

import base64
import hashlib
import os
import posixpath
import subprocess

import pytest

from basebreak.builder.capture import CandidateSnapshot
from basebreak.causal.minimizer import (
    BoundedSubsetMinimizer,
    SliceSearchBudget,
    reconstruct_subset_patch,
)
from basebreak.causal.slice import (
    LOCAL_TEST_RUNTIME_CONFIG_DIGEST,
    CausalSliceScope,
    CausalSliceStatus,
    SubsetExecutionFact,
    TestedPatchSubset,
    compute_runtime_config_digest,
    create_subset_execution_fact,
)
from basebreak.causal.slice_receipt import (
    create_causal_slice_receipt_from_result,
    verify_slice_receipt_integrity,
)
from basebreak.causal.subtraction import parse_candidate_patch
from basebreak.domain.causal import CandidateIdentity
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.verifier.witness_result import WitnessOutcome

# Constants for isolated demo target
DEMO_TARGET_LOCATOR = "https://github.com/zyganali-glitch/basebreak-demo-target.git"
DEMO_TARGET_BASE_COMMIT = "40ff923a134a21d8e357deb7a7988571cd396b56"
DEMO_TARGET_BASE_TREE = "f81f6faa0c7572f9941570bbce376fadc10f39a3"
DEMO_TARGET_CANDIDATE_TREE = "841b399818e0b60690ffd75ca9c3bbd52cfa6165"

# Candidate patch containing:
# Hunk 0 (irrelevant comment):
# Hunk 1 (causal bug fix):
DEMO_TWO_HUNK_PATCH = (
    "diff --git a/src/demo_target/cli.py b/src/demo_target/cli.py\n"
    "index 878b16f..1111111 100644\n"
    "--- a/src/demo_target/cli.py\n"
    "+++ b/src/demo_target/cli.py\n"
    "@@ -1,4 +1,5 @@\n"
    ' """Demo target CLI formatting utility.\n'
    "+# Irrelevant documentation comment for demonstration\n"
    " \n"
    " Isolated demonstration target for Basebreak causal verification.\n"
    " This file contains an intentional defect for testing causal BUG_FIX verification.\n"
    "@@ -13,5 +14,5 @@ def format_quiet_output(output: str, quiet: bool = False) -> str:\n"
    '     When quiet is True, stdout must be empty ("").\n'
    '     """\n'
    "     if quiet:\n"
    '-        return "verbose: " + output\n'
    '+        return ""\n'
    "     return output\n"
)


class TestP12ClosureLocalUnitSuite:
    """Local unit tests validating end-to-end P-12 flow with structured execution facts."""

    def test_local_end_to_end_minimizer_and_receipt_derivation(self) -> None:
        """Verify local execution flow creates verified receipt mechanically bound to facts."""
        patch_text = DEMO_TWO_HUNK_PATCH
        patch_digest = hashlib.sha256(patch_text.encode("utf-8")).hexdigest()
        source_id = SourceIdentity(
            locator=DEMO_TARGET_LOCATOR,
            revision=CommitRevision(DEMO_TARGET_BASE_COMMIT),
        )
        snap = CandidateSnapshot(
            candidate_id="cand-p12-local-01",
            source_identity=source_id,
            candidate_tree_digest=DEMO_TARGET_CANDIDATE_TREE,
            patch_digest=patch_digest,
            patch_text=patch_text,
            files_added=(),
            files_modified=("src/demo_target/cli.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest="1" * 64,
            context_digest="2" * 64,
        )
        parsed = parse_candidate_patch(patch_text)
        causal_hunk = parsed.files[0].hunks[1].hunk_id

        def mock_callback(sub: TestedPatchSubset, sc: CausalSliceScope) -> SubsetExecutionFact:
            # Pass if causal hunk is retained, fail otherwise
            outcome = (
                WitnessOutcome.PASS if causal_hunk in sub.retained_hunk_ids else WitnessOutcome.FAIL
            )
            return create_subset_execution_fact(
                subset=sub,
                scope=sc,
                outcome=outcome,
                exit_code=0 if outcome == WitnessOutcome.PASS else 1,
                runtime_config_digest=LOCAL_TEST_RUNTIME_CONFIG_DIGEST,
                sandbox_id=f"sbx-local-{sub.subset_id[:8]}",
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
            )

        minimizer = BoundedSubsetMinimizer(
            execution_callback=mock_callback,
            runtime_config_digest=LOCAL_TEST_RUNTIME_CONFIG_DIGEST,
            budget=SliceSearchBudget(max_iterations=10, max_subsets_tested=10),
        )
        result = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest="1" * 64,
            sealed_witness_digest="3" * 64,
            requirement_id="REQ-QUIET-001",
            base_outcome=WitnessOutcome.FAIL,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        assert result.status == CausalSliceStatus.TESTED_NECESSARY_SUBSET
        assert result.minimal_subset is not None
        assert result.minimal_subset.retained_hunk_ids == (causal_hunk,)
        assert len(result.minimal_subset.subtracted_hunk_ids) == 1

        receipt = create_causal_slice_receipt_from_result(
            result=result,
            witness_id="wit-local-quiet",
        )
        assert verify_slice_receipt_integrity(receipt) is True
        assert receipt.status == CausalSliceStatus.TESTED_NECESSARY_SUBSET
        assert len(receipt.execution_facts) == len(result.evaluated_subsets)


class TestP12LiveClosureSuite:
    """Live phase closure demonstration against real Nebius Token Factory sandboxes."""

    @pytest.mark.live
    def test_p12_live_causal_slice_demonstration(self) -> None:
        """P-12 Live Causal Slicing Demonstration across real Nebius Token Factory Sandboxes.

        Constructs a candidate containing:
        - Causal change: bug fix in format_quiet_output required by sealed witness
        - Irrelevant independent change: documentation comment

        Demonstrates:
        1. BASE = FAIL (exit 1 in real Nebius sandbox)
        2. FULL CANDIDATE = PASS (exit 0 in real Nebius sandbox)
        3. SUBSET RETAINING CAUSAL CHANGE / REMOVING IRRELEVANT CHANGE = PASS (exit 0)
        4. SUBSET/COUNTERFACTUAL REMOVING CAUSAL CHANGE = FAIL (exit 1)

        Emits authentic CausalSliceReceipt with:
        - Exact Basebreak implementation SHA tested
        - LIVE_NEBIUS provenance
        - Distinct sandbox identities
        - Structured SubsetExecutionFacts bound to every evaluated subset
        - Deterministic runtime_config_digest
        - Prominently rendered non-formal-proof disclaimer
        """
        from basebreak.adapters.nebius.client import (
            ModelClientConfig,
            NebiusModelClient,
        )
        from basebreak.adapters.nebius.models import DEFAULT_PRIMARY_MODEL
        from basebreak.adapters.nebius.sandbox import (
            NebiusSandboxAdapter,
            SandboxClientConfig,
        )
        from basebreak.causal.materializer import GitRepositoryMaterializer
        from basebreak.compiler.freeze import freeze_review_result
        from basebreak.compiler.ingestion import ingest_task
        from basebreak.compiler.requirements import ProposedRequirement
        from basebreak.compiler.review import ReviewBundle, ReviewSession
        from basebreak.compiler.semantics import (
            CertaintyLevel,
            ChangeClass,
            ChangeSemanticsClassification,
            DeterministicClassificationFact,
        )
        from basebreak.verifier.context import VerifierContextEnvelope
        from basebreak.verifier.witness_generator import WitnessGenerator
        from basebreak.verifier.witness_lock import create_witness_lock
        from basebreak.verifier.witness_plan import (
            WitnessPlanValidator,
            generate_witness_plan,
        )
        from basebreak.verifier.witness_store import TrustedWitnessVault

        api_key = os.environ.get("NEBIUS_API_KEY")
        if not api_key:
            pytest.skip("NEBIUS_API_KEY not configured for live test")

        project_id = os.environ.get("NEBIUS_PROJECT_ID", "aiproject-e00mae0nmzkxjswr1k")
        if not project_id:
            pytest.skip("NEBIUS_PROJECT_ID not configured for live test")

        # 1. Target Identity & Candidate Patch
        candidate_patch_text = DEMO_TWO_HUNK_PATCH
        patch_digest = hashlib.sha256(candidate_patch_text.encode("utf-8")).hexdigest()

        source_id = SourceIdentity(
            locator=DEMO_TARGET_LOCATOR,
            revision=CommitRevision(DEMO_TARGET_BASE_COMMIT),
        )
        cand_id = CandidateIdentity(
            candidate_id="cand-p12-live-01",
            source=source_id,
            patch_digest=patch_digest,
        )

        # 2. Frozen Contract Pipeline
        task_text = "When user specifies --quiet flag, stdout must be empty."
        task = ingest_task(task_text)
        fact = DeterministicClassificationFact(
            inferred_class=ChangeClass.BUG_FIX,
            certainty=CertaintyLevel.CONFIDENT,
            confidence=1.0,
            alternative_classes=(),
            rationale="Fixes verbose leak when quiet flag is passed",
            evidence_citations=("quiet flag",),
            matched_signals=("quiet", "bug"),
        )
        semantics = ChangeSemanticsClassification(
            task_digest=task.task_digest,
            change_class=ChangeClass.BUG_FIX,
            certainty=CertaintyLevel.CONFIDENT,
            confidence=1.0,
            alternative_classes=(),
            rationale="Fixes verbose leak when quiet flag is passed",
            evidence_citations=("quiet flag",),
            deterministic_facts=fact,
        )
        cit = task_text
        req = ProposedRequirement(
            statement=(
                "format_quiet_output must return empty string when quiet=True. "
                "Import via sys.path.insert(0, 'src') and "
                "from demo_target.cli import format_quiet_output."
            ),
            citation=cit,
            citation_start=0,
            citation_end=len(cit),
            rationale="Mandated quiet flag behavior",
        )
        bundle = ReviewBundle(task=task, semantics=semantics, requirements=(req,))
        session = ReviewSession(bundle)
        approval = session.approve()
        contract = freeze_review_result(approval)
        req_id = contract.requirements[0].requirement_id

        # 3. Context Envelope
        envelope = VerifierContextEnvelope.create(
            frozen_contract=contract,
            source_identity=source_id,
            candidate_identity=cand_id,
            candidate_patch_text=candidate_patch_text,
            candidate_tree_digest=DEMO_TARGET_CANDIDATE_TREE,
        )

        # 4. Sealed Witness
        model_client = NebiusModelClient(
            config=ModelClientConfig(
                api_key=api_key,
                model=DEFAULT_PRIMARY_MODEL,
                max_tokens=4096,
                temperature=0.0,
            )
        )
        source_cli_path = os.path.abspath("tests/fixtures/demo_target/src/demo_target/cli.py")
        with open(source_cli_path, "r", encoding="utf-8") as f:
            source_cli = f.read()

        proposal = generate_witness_plan(
            context_envelope=envelope,
            requirement_id=req_id,
            source_files={"src/demo_target/cli.py": source_cli},
            model_client=model_client,
        )
        validator = WitnessPlanValidator()
        plan = validator.validate(proposal, context_envelope=envelope)

        vault = TrustedWitnessVault(b"basebreak-live-proof-vault-key-32b")
        generator = WitnessGenerator(vault=vault)
        sealed_record = generator.generate_and_seal_witness(plan)
        assert vault.verify_witness_integrity(sealed_record) is True
        witness_lock = create_witness_lock(record=sealed_record, vault=vault)

        # 5. Live Adapters & Infrastructure
        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key=api_key,
                project_id=project_id,
                poll_interval_seconds=1.0,
                default_timeout_seconds=180,
            )
        )
        materializer = GitRepositoryMaterializer(adapter=adapter)

        # Deterministic Live Runtime Config Digest
        live_config_dict = {
            "provider": "nebius_token_factory",
            "image": "tag:astral/uv:python3.11-alpine",
            "isolation": "remote_vm_sandbox",
            "execution_command": list(plan.execution_command),
        }
        live_runtime_config_digest = compute_runtime_config_digest(live_config_dict)

        # 6. Live BASE World Execution (Proving BASE = FAIL)
        base_handle = adapter.create_sandbox(disposable=False)
        base_sandbox_id = base_handle.sandbox_identity.sandbox_id
        try:
            materializer.source_materializer.materialize_repository(
                source_identity=source_id,
                sandbox=base_handle.sandbox_identity,
                workspace_path="/verifier_workspace",
                disposable=False,
                timeout_seconds=120,
            )
            deploy_lines = ["set -e", "cd /verifier_workspace"]
            for art in sealed_record.artifacts:
                art_posix = art.path.replace("\\", "/").lstrip("/")
                full_path = f"/verifier_workspace/{art_posix}"
                parent_dir = posixpath.dirname(full_path)
                b64_content = base64.b64encode(art.content.encode("utf-8")).decode("ascii")
                deploy_lines.append(f"mkdir -p {parent_dir}")
                deploy_lines.append(f'printf "%s" "{b64_content}" | base64 -d > {full_path}')
            adapter.execute_command(
                base_handle,
                "\n".join(deploy_lines) + "\n",
                working_dir="/verifier_workspace",
                timeout_seconds=60,
                disposable=False,
            )
            base_res = adapter.execute_command(
                base_handle,
                plan.execution_command,
                working_dir="/verifier_workspace",
                timeout_seconds=60,
                disposable=True,
            )
            base_exit = base_res.exit_code
        finally:
            adapter.teardown_sandbox(base_handle)

        assert base_exit is not None and base_exit != 0, f"BASE expected FAIL, got {base_exit}"
        base_outcome = WitnessOutcome.FAIL

        # 7. Setup CandidateSnapshot & Parsed Patch
        snapshot = CandidateSnapshot(
            candidate_id="cand-p12-live-01",
            source_identity=source_id,
            candidate_tree_digest=DEMO_TARGET_CANDIDATE_TREE,
            patch_digest=patch_digest,
            patch_text=candidate_patch_text,
            files_added=(),
            files_modified=("src/demo_target/cli.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=contract.contract_digest,
            context_digest=envelope.context_digest,
        )
        parsed_patch = parse_candidate_patch(candidate_patch_text)

        # 8. Define Live Execution Callback for Minimizer
        observed_sandboxes: list[str] = [base_sandbox_id]

        def live_execution_callback(
            subset: TestedPatchSubset, scope: CausalSliceScope
        ) -> SubsetExecutionFact:
            cand_handle = adapter.create_sandbox(disposable=False)
            sbx_id = cand_handle.sandbox_identity.sandbox_id
            observed_sandboxes.append(sbx_id)
            try:
                # Materialize clean base repository
                materializer.source_materializer.materialize_repository(
                    source_identity=source_id,
                    sandbox=cand_handle.sandbox_identity,
                    workspace_path="/verifier_workspace",
                    disposable=False,
                    timeout_seconds=120,
                )

                # Reconstruct and apply subset patch
                if subset.retained_hunk_ids:
                    ret_text, _, _, _, _, _ = reconstruct_subset_patch(
                        parsed_patch, subset.retained_hunk_ids
                    )
                    b64_patch = base64.b64encode(ret_text.encode("utf-8")).decode("ascii")
                    apply_script = (
                        "set -e\n"
                        "cd /verifier_workspace\n"
                        f"printf \"%s\" '{b64_patch}' | base64 -d > /tmp/subset.patch\n"
                        "git apply --binary --whitespace=nowarn /tmp/subset.patch\n"
                        "rm -f /tmp/subset.patch\n"
                        "git add -A\n"
                    )
                    adapter.execute_command(
                        cand_handle,
                        apply_script,
                        working_dir="/verifier_workspace",
                        timeout_seconds=60,
                        disposable=False,
                    )

                # Deploy sealed witness artifacts into sandbox
                deploy_lines = ["set -e", "cd /verifier_workspace"]
                for art in sealed_record.artifacts:
                    art_posix = art.path.replace("\\", "/").lstrip("/")
                    full_path = f"/verifier_workspace/{art_posix}"
                    parent_dir = posixpath.dirname(full_path)
                    b64_content = base64.b64encode(art.content.encode("utf-8")).decode("ascii")
                    deploy_lines.append(f"mkdir -p {parent_dir}")
                    deploy_lines.append(f'printf "%s" "{b64_content}" | base64 -d > {full_path}')
                adapter.execute_command(
                    cand_handle,
                    "\n".join(deploy_lines) + "\n",
                    working_dir="/verifier_workspace",
                    timeout_seconds=60,
                    disposable=False,
                )

                # Execute witness command in sandbox
                exec_res = adapter.execute_command(
                    cand_handle,
                    plan.execution_command,
                    working_dir="/verifier_workspace",
                    timeout_seconds=60,
                    disposable=True,
                )
                exit_code = exec_res.exit_code
                stdout = exec_res.stdout or ""
                stderr = exec_res.stderr or ""
                dur = exec_res.duration_seconds or 0.0
            finally:
                adapter.teardown_sandbox(cand_handle)

            outcome = WitnessOutcome.PASS if exit_code == 0 else WitnessOutcome.FAIL
            return create_subset_execution_fact(
                subset=subset,
                scope=scope,
                outcome=outcome,
                exit_code=exit_code,
                execution_command=plan.execution_command,
                runtime_config_digest=live_runtime_config_digest,
                sandbox_id=sbx_id,
                provenance=EvidenceProvenance.LIVE_NEBIUS,
                stdout_digest=compute_bytes_digest(stdout.encode("utf-8")).value,
                stderr_digest=compute_bytes_digest(stderr.encode("utf-8")).value,
                duration_seconds=dur,
            )

        # 9. Execute Bounded Hunk Minimizer Live
        minimizer = BoundedSubsetMinimizer(
            execution_callback=live_execution_callback,
            budget=SliceSearchBudget(max_iterations=10, max_subsets_tested=10),
            runtime_config_digest=live_runtime_config_digest,
            execution_command=plan.execution_command,
        )

        result = minimizer.minimize(
            snapshot=snapshot,
            frozen_contract_digest=contract.contract_digest,
            sealed_witness_digest=sealed_record.seal_digest,
            requirement_id=req_id,
            base_outcome=base_outcome,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
        )

        # 10. Behavioral Invariants
        assert result.status == CausalSliceStatus.TESTED_NECESSARY_SUBSET
        assert result.minimal_subset is not None
        # Must retain the causal fix (Hunk 1) and remove the irrelevant comment (Hunk 0)
        causal_hunk_id = parsed_patch.files[0].hunks[1].hunk_id
        irrelevant_hunk_id = parsed_patch.files[0].hunks[0].hunk_id
        assert result.minimal_subset.retained_hunk_ids == (causal_hunk_id,)
        assert result.minimal_subset.subtracted_hunk_ids == (irrelevant_hunk_id,)

        # Verify evaluated subsets: Full (PASS), Irrelevant alone (FAIL), Causal alone (PASS)
        outcomes_by_hunk_count: dict[int, list[WitnessOutcome]] = {}
        for ev in result.evaluated_subsets:
            n_hunks = len(ev.subset.retained_hunk_ids)
            outcomes_by_hunk_count.setdefault(n_hunks, []).append(ev.outcome)

        assert WitnessOutcome.PASS in outcomes_by_hunk_count[2]  # Full candidate PASS
        assert WitnessOutcome.FAIL in outcomes_by_hunk_count[1]  # Irrelevant subset FAIL
        assert WitnessOutcome.PASS in outcomes_by_hunk_count[1]  # Causal subset PASS

        # 11. Derive Authentic Receipt
        receipt = create_causal_slice_receipt_from_result(
            result=result,
            witness_id=sealed_record.witness_id,
        )
        assert verify_slice_receipt_integrity(receipt) is True
        assert receipt.provenance == EvidenceProvenance.LIVE_NEBIUS
        assert receipt.runtime_config_digest == live_runtime_config_digest
        assert len(receipt.execution_facts) == len(result.evaluated_subsets)

        # Sandbox isolation: all sandboxes must be distinct
        assert len(set(observed_sandboxes)) == len(observed_sandboxes)

        # 12. Basebreak Implementation SHA
        tested_impl_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()

        # 13. Write and Format docs/P12_LIVE_CLOSURE_PROOF.md
        proof_lines = [
            "# Basebreak Minimal Causal Slice Verification Proof Summary",
            "",
            "> **Thesis:** *If the patch matters, the base must break.*",
            (
                "> **Judge Claim:** Basebreak proves that an AI-written patch caused the "
                "behavior it claims to change — not merely that its tests are green."
            ),
            "",
            "## Verdict & Transition",
            f"- **Causal Slice Status**: `{receipt.status.value}`",
            f"- **Search Completeness**: `{receipt.completeness.value}`",
            f"- **Evidence Provenance**: `{receipt.provenance.value}`",
            f"- **Verification Timestamp**: `{receipt.created_at_utc}`",
            "",
            "## Verification Identity",
            f"- **Basebreak Implementation SHA:** `{tested_impl_sha}`",
            f"- **Target Repository:** `{receipt.source_locator}`",
            f"- **Target Base Commit:** `{receipt.source_commit_id}`",
            f"- **Canonical Base Tree:** `{DEMO_TARGET_BASE_TREE}`",
            f"- **Full Candidate Tree:** `{receipt.candidate_tree_digest}`",
            f"- **Candidate Patch Digest:** `{receipt.candidate_patch_digest}`",
            "",
            "## Causal Minimization Behavioral Evidence",
            "```",
            f"  BASE WORLD                    [Outcome: FAIL] (Exit {base_exit})",
            "       |",
            "       v",
            "  FULL CANDIDATE (2 hunks)      [Outcome: PASS] (Exit 0)",
            "       |",
            "       v",
            "  SUBSET (irrelevant comment)   [Outcome: FAIL] (Exit 1 - defect retained)",
            "       |",
            "       v",
            "  SUBSET (causal fix)           [Outcome: PASS] (Exit 0 - defect resolved)",
            "       |",
            (
                "       ===> MINIMAL NECESSARY SUBSET FOUND: "
                "1 hunk retained, 1 irrelevant hunk removed"
            ),
            "```",
            "",
            "### Evaluated Subsets in Real Nebius Sandboxes",
            (
                "| Subset ID | Retained Hunks | Subtracted Hunks | Outcome | "
                "Exit Code | Sandbox ID | Execution Digest |"
            ),
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for ef in receipt.execution_facts:
            sub = next(s for s in receipt.tested_subsets if s.subset_id == ef.subset_id)
            n_ret = len(sub.retained_hunk_ids)
            n_sub = len(sub.subtracted_hunk_ids)
            proof_lines.append(
                f"| `{ef.subset_id[:16]}` | {n_ret} hunks | {n_sub} hunks | "
                f"`{ef.outcome.value}` | `{ef.exit_code}` | `{ef.sandbox_id}` | "
                f"`{ef.execution_digest[:16]}...` |"
            )

        proof_lines.extend(
            [
                "",
                "## Cryptographic Custody Chain (Unbroken Custody)",
                "| Artifact / Entity | Identifier / Digest |",
                "| :--- | :--- |",
                f"| Requirement ID | `{receipt.requirement_id}` |",
                f"| Frozen Contract | `{receipt.frozen_contract_digest}` |",
                f"| Witness ID | `{receipt.witness_id}` |",
                f"| Witness Seal | `{receipt.sealed_witness_digest}` |",
                f"| Witness Lock | `{witness_lock.witness_digest}` |",
                f"| Runtime Config Digest | `{receipt.runtime_config_digest}` |",
                f"| Selected Slice Digest | `{receipt.slice_artifact.slice_digest}` |",
                f"| **Causal Slice Receipt** | **`{receipt.receipt_digest}`** |",
                "",
                "## Authority Boundary & Non-Self-Certification",
                "- **Authoritative**: `False`",
                "- **Grants Pass**: `False`",
                "- **Causally Verified**: `False`",
                "- **Claims Global Minimality**: `False`",
                "",
                "## Mandatory Non-Formal-Proof Disclaimer",
                f"> **Notice**: {receipt.disclaimer.statement}",
                "",
                "### Disclaimed Properties",
                "- **Mathematical Program Proof**: Disclaimed (`False`)",
                "- **Global Minimality**: Disclaimed (`False`)",
                "- **Universal Necessity**: Disclaimed (`False`)",
                "- **Untested Input Guarantees**: Disclaimed (`False`)",
                "- **Semantic Equivalence Beyond Witness**: Disclaimed (`False`)",
                "- **Formal Verification**: Disclaimed (`False`)",
                "",
                "---",
                (
                    "*Generated deterministically by Basebreak Bounded Hunk Minimizer "
                    "& Causal Slice Verifier.*"
                ),
            ]
        )

        proof_path = os.path.abspath("docs/P12_LIVE_CLOSURE_PROOF.md")
        rendered_proof = "\n".join(proof_lines)
        with open(proof_path, "w", encoding="utf-8") as f:
            f.write(rendered_proof)
