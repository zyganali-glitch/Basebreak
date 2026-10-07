"""Causal Two-World Engine for independent behavioral verification.

P-10.01: Execute identical witness on trusted base.
P-10.02: Execute identical witness on exact candidate.
P-10.03: Bind both executions to source/sandbox/witness hashes.
P-10.04: Reconcile BUG_FIX FAIL->PASS deterministically.
P-10.05: Handle PASS->PASS, FAIL->FAIL, ERROR/TIMEOUT as non-verified states.

Core Invariants:
1. Fresh disposable sandbox per world: BASE and CANDIDATE execute in separate, freshly created
   isolated verifier sandboxes. Sandbox IDs must never collide; Builder sandboxes are never reused.
2. Identical sealed witness: The exact same sealed witness artifacts and lock digest are executed
   in both worlds without recompilation, mutation, or adaptation.
3. Cryptographic binding: Unbroken chain:
   requirement_id -> frozen_contract_digest -> witness_digest -> lock_digest ->
   BASE facts -> CANDIDATE facts (commit, tree, sandbox, result digest).
4. No empty patch: Candidate tree must differ from base tree.
5. Fail-closed teardown: All sandboxes are guaranteed to be torn down even upon failure.
6. Absolute authority: Verification is a deterministic fact, not model belief.
"""

from __future__ import annotations

import base64
import inspect
import posixpath
import shlex
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from basebreak.causal.materializer import CounterfactualMaterializationError
from basebreak.causal.receipt import (
    LocalCausalReceipt,
    WorldExecutionFact,
    create_causal_receipt,
    create_causal_triplet_receipt,
)
from basebreak.causal.reconciliation import (
    ReconciliationFact,
    reconcile_causal_transition,
    reconcile_causal_triplet,
)
from basebreak.causal.subtraction import CounterfactualDeltaPlan
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.verifier.context import VerifierContextEnvelope
from basebreak.verifier.sandbox import (
    VerifierMaterializationError,
    VerifierSandboxManager,
    VerifierSandboxSession,
    VerifierTreeDigestMismatchError,
)
from basebreak.verifier.vacuity import (
    VacuityCheckResult,
    analyze_artifact_code_vacuity,
    analyze_runtime_execution_vacuity,
)
from basebreak.verifier.witness_lock import (
    ImmutableWitnessLock,
    verify_witness_lock_chain,
)
from basebreak.verifier.witness_result import (
    NormalizedWitnessResult,
    WitnessOutcome,
    normalize_witness_execution,
)
from basebreak.verifier.witness_store import (
    SealedWitnessRecord,
    TrustedWitnessVault,
)


class CausalEngineError(Exception):
    """Base exception for causal two-world engine errors."""


class CausalBindingError(CausalEngineError):
    """Raised when cryptographic binding between contract, witness, and executions fails."""


class SandboxCollisionError(CausalEngineError):
    """Raised when BASE and CANDIDATE share the same sandbox identity."""


class EmptyCandidatePatchError(CausalEngineError):
    """Raised when candidate tree is identical to base tree under BUG_FIX."""


@dataclass(frozen=True, slots=True)
class WorldExecutionOutput:
    """Output bundle from executing a witness in a single world sandbox."""

    session: VerifierSandboxSession
    normalized_result: NormalizedWitnessResult
    vacuity_result: VacuityCheckResult
    tree_digest: str


class CausalExecutionEngine:
    """Executes identical witnesses across BASE and CANDIDATE worlds and reconciles causality."""

    def __init__(
        self,
        *,
        sandbox_manager: VerifierSandboxManager,
        sandbox_adapter: Any,
        materializer: Any,
        vault: TrustedWitnessVault,
        provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
    ) -> None:
        if not isinstance(sandbox_manager, VerifierSandboxManager):
            mgr_type = type(sandbox_manager).__name__
            raise TypeError(f"sandbox_manager must be VerifierSandboxManager, got {mgr_type}")
        if sandbox_adapter is None:
            raise TypeError("sandbox_adapter must not be None")
        if materializer is None:
            raise TypeError("materializer must not be None")
        if not isinstance(vault, TrustedWitnessVault):
            raise TypeError(f"vault must be TrustedWitnessVault, got {type(vault).__name__}")
        if not isinstance(provenance, EvidenceProvenance):
            raise TypeError(
                f"provenance must be EvidenceProvenance, got {type(provenance).__name__}"
            )

        self.sandbox_manager = sandbox_manager
        self.sandbox_adapter = sandbox_adapter

        # Automatically wrap base-only materializer to support candidate world
        from basebreak.adapters.nebius.materialization import NebiusSourceMaterializer
        from basebreak.causal.materializer import CausalRepositoryMaterializer

        if isinstance(materializer, NebiusSourceMaterializer):
            self.materializer: Any = CausalRepositoryMaterializer(
                adapter=sandbox_adapter,
                source_materializer=materializer,
            )
        else:
            self.materializer = materializer

        self.vault = vault
        self.provenance = provenance

    def _deploy_witness_artifacts(
        self,
        *,
        session: VerifierSandboxSession,
        sealed_record: SealedWitnessRecord,
    ) -> None:
        """Deploy sealed witness artifacts into the isolated sandbox workspace."""
        lines: list[str] = ["set -e"]
        clean_ws = session.workspace_path.rstrip("/")
        lines.append(f"cd {shlex.quote(clean_ws)}")

        for art in sealed_record.artifacts:
            art_posix = art.path.replace("\\", "/").lstrip("/")
            full_path = f"{clean_ws}/{art_posix}"
            parent_dir = posixpath.dirname(full_path)
            b64_content = base64.b64encode(art.content.encode("utf-8")).decode("ascii")

            lines.append(f"mkdir -p {shlex.quote(parent_dir)}")
            lines.append(
                f'printf "%s" {shlex.quote(b64_content)} | base64 -d > {shlex.quote(full_path)}'
            )

        deploy_kwargs: dict[str, Any] = {
            "working_dir": session.workspace_path,
            "timeout_seconds": 60,
        }
        try:
            sig = inspect.signature(self.sandbox_adapter.execute_command)
            if "disposable" in sig.parameters:
                deploy_kwargs["disposable"] = False
        except Exception:
            pass

        deploy_script = "\n".join(lines) + "\n"
        res = self.sandbox_adapter.execute_command(
            session.sandbox_identity,
            deploy_script,
            **deploy_kwargs,
        )
        exit_code = getattr(res, "exit_code", None)
        if exit_code is None and hasattr(res, "result"):
            exit_code = getattr(res.result, "exit_code", None)
        if exit_code != 0:
            stderr = getattr(res, "stderr", "") or ""
            raise CausalEngineError(f"Failed to deploy witness artifacts into sandbox: {stderr}")

    def _execute_command_in_sandbox(
        self,
        *,
        session: VerifierSandboxSession,
        command: Sequence[str] | str,
        timeout_seconds: int,
    ) -> tuple[int | None, TerminationStatus, str, str, float]:
        """Execute a test command inside the sandbox and extract execution facts."""
        cmd_input: Any
        if isinstance(command, (list, tuple)):
            cmd_input = " ".join(shlex.quote(arg) for arg in command)
        else:
            cmd_input = str(command)

        exec_kwargs: dict[str, Any] = {
            "working_dir": session.workspace_path,
            "timeout_seconds": timeout_seconds,
        }
        try:
            sig = inspect.signature(self.sandbox_adapter.execute_command)
            if "disposable" in sig.parameters:
                exec_kwargs["disposable"] = True
        except Exception:
            pass

        start_time = time.perf_counter()
        try:
            res = self.sandbox_adapter.execute_command(
                session.sandbox_identity,
                cmd_input,
                **exec_kwargs,
            )
            elapsed = time.perf_counter() - start_time
        except Exception as exc:
            elapsed = time.perf_counter() - start_time
            exc_str = str(exc).lower()
            if "timeout" in exc_str:
                return None, TerminationStatus.TIMED_OUT, "", str(exc), elapsed
            return None, TerminationStatus.COMPLETED, "", str(exc), elapsed

        # Extract exit code
        exit_code = getattr(res, "exit_code", None)
        if exit_code is None and hasattr(res, "result"):
            exit_code = getattr(res.result, "exit_code", None)

        # Extract stdout / stderr
        stdout = getattr(res, "stdout", "") or ""
        stderr = getattr(res, "stderr", "") or ""

        # Extract termination status
        term_status = TerminationStatus.COMPLETED
        if getattr(res, "is_timed_out", False):
            term_status = TerminationStatus.TIMED_OUT
        elif getattr(res, "is_cancelled", False):
            term_status = TerminationStatus.CANCELLED
        elif getattr(res, "is_failed_to_start", False):
            term_status = TerminationStatus.FAILED_TO_START

        duration = getattr(res, "duration_seconds", None)
        if duration is None or not isinstance(duration, (int, float)):
            duration = elapsed

        return exit_code, term_status, stdout, stderr, float(duration)

    def execute_world(
        self,
        *,
        context_envelope: VerifierContextEnvelope,
        sealed_record: SealedWitnessRecord,
        world: ExecutionWorld,
        execution_command: Sequence[str] | str,
        candidate_tree_digest: str | None = None,
        counterfactual_plan: Any | None = None,
        counterfactual_tree_digest: str | None = None,
    ) -> WorldExecutionOutput:
        """Execute the sealed witness in a freshly isolated verifier sandbox for a single world.

        Guarantees:
        1. Fresh sandbox materialized strictly from trusted source.
        2. Clean deployment of sealed witness artifacts.
        3. Deterministic execution and normalization.
        4. Static and runtime vacuity checks.
        5. Teardown guaranteed in finally block.
        """
        # 1. Create fresh isolated verifier sandbox
        session = self.sandbox_manager.create_isolated_verifier_sandbox(
            context_envelope=context_envelope,
            world=world,
            sandbox_adapter=self.sandbox_adapter,
            materializer=self.materializer,
            candidate_tree_digest=candidate_tree_digest,
            counterfactual_plan=counterfactual_plan,
            counterfactual_tree_digest=counterfactual_tree_digest,
            provenance=self.provenance,
        )

        try:
            # 2. Deploy sealed witness artifacts into workspace
            self._deploy_witness_artifacts(session=session, sealed_record=sealed_record)

            # 3. Execute witness test command
            timeout = context_envelope.execution_policy.timeout_seconds
            exit_code, term_status, stdout, stderr, duration = self._execute_command_in_sandbox(
                session=session,
                command=execution_command,
                timeout_seconds=timeout,
            )

            # 4. Normalize execution facts
            normalized_result = normalize_witness_execution(
                witness_id=sealed_record.witness_id,
                witness_digest=sealed_record.seal_digest,
                frozen_contract_digest=sealed_record.frozen_contract_digest,
                requirement_id=sealed_record.requirement_id,
                sandbox_identity=session.sandbox_identity,
                source_commit_id=session.materialized_commit_id,
                world=world,
                status=term_status,
                exit_code=exit_code,
                stdout_raw=stdout,
                stderr_raw=stderr,
                duration_seconds=duration,
                provenance=self.provenance,
                max_output_bytes=context_envelope.execution_policy.max_output_bytes,
            )

            # 5. Vacuity checks
            code_vacuity = analyze_artifact_code_vacuity(sealed_record.artifacts)
            runtime_vacuity = analyze_runtime_execution_vacuity(normalized_result, code_vacuity)

            return WorldExecutionOutput(
                session=session,
                normalized_result=normalized_result,
                vacuity_result=runtime_vacuity,
                tree_digest=session.materialized_tree_digest,
            )

        finally:
            # Guaranteed teardown of disposable verifier sandbox
            self.sandbox_manager._teardown_sandbox(self.sandbox_adapter, session.sandbox_identity)

    def execute_causal_pair(
        self,
        *,
        context_envelope: VerifierContextEnvelope,
        sealed_record: SealedWitnessRecord,
        witness_lock: ImmutableWitnessLock,
        execution_command: Sequence[str] | str,
    ) -> LocalCausalReceipt:
        """Execute sealed witness across BASE and CANDIDATE worlds and reconcile causality.

        P-10.01: Execute on trusted BASE sandbox.
        P-10.02: Execute on exact CANDIDATE sandbox.
        P-10.03: Cryptographic binding checks.
        P-10.04 & P-10.05: Deterministic reconciliation.
        P-10.06: Local causal receipt generation.
        """
        # Step A: Validate witness lock chain of custody before any execution
        self.vault.verify_witness_integrity(sealed_record)
        verify_witness_lock_chain(
            lock=witness_lock,
            frozen_contract=context_envelope.frozen_contract,
            base_record=sealed_record,
            candidate_record=sealed_record,
        )

        if witness_lock.frozen_contract_digest != context_envelope.frozen_contract.contract_digest:
            raise CausalBindingError(
                f"witness_lock frozen_contract_digest ({witness_lock.frozen_contract_digest}) "
                f"does not match context_envelope contract digest "
                f"({context_envelope.frozen_contract.contract_digest})"
            )
        if witness_lock.source_commit_id != context_envelope.source_identity.resolved_commit_id:
            raise CausalBindingError(
                f"witness_lock source_commit_id ({witness_lock.source_commit_id}) "
                f"does not match context_envelope source commit "
                f"({context_envelope.source_identity.resolved_commit_id})"
            )

        # Step B: P-10.01 — Execute identical witness on trusted BASE
        base_output = self.execute_world(
            context_envelope=context_envelope,
            sealed_record=sealed_record,
            world=ExecutionWorld.BASE,
            execution_command=execution_command,
        )

        # Step C: P-10.02 — Execute identical witness on exact CANDIDATE
        candidate_output = self.execute_world(
            context_envelope=context_envelope,
            sealed_record=sealed_record,
            world=ExecutionWorld.CANDIDATE,
            execution_command=execution_command,
            candidate_tree_digest=context_envelope.candidate_tree_digest,
        )

        # Step D: P-10.03 — Cryptographic binding and integrity checks
        integrity_failure_reason: str | None = None

        # Check 1: Witness digest equality
        if (
            base_output.normalized_result.witness_digest != sealed_record.seal_digest
            or candidate_output.normalized_result.witness_digest != sealed_record.seal_digest
            or base_output.normalized_result.witness_digest
            != candidate_output.normalized_result.witness_digest
        ):
            integrity_failure_reason = "Witness digest mismatch across BASE and CANDIDATE runs"

        # Check 2: Sandbox ID collision
        if (
            base_output.session.sandbox_identity.sandbox_id
            == candidate_output.session.sandbox_identity.sandbox_id
        ):
            integrity_failure_reason = (
                "BASE and CANDIDATE executions reused the same sandbox identity"
            )

        # Check 3: Builder sandbox collision
        base_sid = base_output.session.sandbox_identity.sandbox_id
        cand_sid = candidate_output.session.sandbox_identity.sandbox_id
        if (
            base_sid in self.sandbox_manager.known_builder_sandbox_ids
            or cand_sid in self.sandbox_manager.known_builder_sandbox_ids
        ):
            integrity_failure_reason = "Verifier execution reused a known Builder sandbox identity"

        # Check 4: Source commit match
        expected_commit = context_envelope.source_identity.resolved_commit_id
        if (
            base_output.normalized_result.source_commit_id != expected_commit
            or candidate_output.normalized_result.source_commit_id != expected_commit
        ):
            integrity_failure_reason = (
                "Execution source commit does not match authoritative context"
            )

        # Check 5: Tree digest check — candidate must differ from base under BUG_FIX
        if base_output.tree_digest.lower() == candidate_output.tree_digest.lower():
            integrity_failure_reason = (
                "Candidate tree digest is identical to base tree digest (empty patch)"
            )

        # Step E: P-10.04 & P-10.05 — Deterministic Outcome Reconciliation
        reconciliation: ReconciliationFact = reconcile_causal_transition(
            base_outcome=base_output.normalized_result.outcome,
            candidate_outcome=candidate_output.normalized_result.outcome,
            base_vacuity=base_output.vacuity_result,
            candidate_vacuity=candidate_output.vacuity_result,
            integrity_failure_reason=integrity_failure_reason,
        )

        # Step F: P-10.06 — Local Causal Receipt Generation
        base_fact = WorldExecutionFact.from_normalized_result(
            base_output.normalized_result,
            tree_digest=base_output.tree_digest,
        )
        candidate_fact = WorldExecutionFact.from_normalized_result(
            candidate_output.normalized_result,
            tree_digest=candidate_output.tree_digest,
        )

        receipt = create_causal_receipt(
            requirement_id=sealed_record.requirement_id,
            frozen_contract_digest=sealed_record.frozen_contract_digest,
            witness_id=sealed_record.witness_id,
            witness_digest=sealed_record.seal_digest,
            lock_digest=witness_lock.lock_digest,
            base_execution=base_fact,
            candidate_execution=candidate_fact,
            transition=reconciliation.transition,
            verdict=reconciliation.verdict,
            provenance=self.provenance,
            narrative=reconciliation.rationale,
        )

        return receipt

    def execute_causal_triplet(
        self,
        *,
        context_envelope: VerifierContextEnvelope,
        sealed_record: SealedWitnessRecord,
        witness_lock: ImmutableWitnessLock,
        counterfactual_plan: CounterfactualDeltaPlan,
        execution_command: Sequence[str] | str,
    ) -> LocalCausalReceipt:
        """Execute identical witness across BASE, CANDIDATE, and COUNTERFACTUAL worlds.

        P-11.03: Materialize counterfactual candidate in fresh isolated sandbox.
        P-11.04: Execute same witness against counterfactual.
        P-11.05: Reconcile FAIL->PASS->FAIL causal triplet.
        P-11.06: Detect invalid counterfactual construction and return non-verified.
        """
        # Step A: Validate witness lock chain of custody
        self.vault.verify_witness_integrity(sealed_record)
        verify_witness_lock_chain(
            lock=witness_lock,
            frozen_contract=context_envelope.frozen_contract,
            base_record=sealed_record,
            candidate_record=sealed_record,
        )

        if witness_lock.frozen_contract_digest != context_envelope.frozen_contract.contract_digest:
            raise CausalBindingError(
                f"witness_lock frozen_contract_digest ({witness_lock.frozen_contract_digest}) "
                f"does not match context_envelope contract digest "
                f"({context_envelope.frozen_contract.contract_digest})"
            )
        if witness_lock.source_commit_id != context_envelope.source_identity.resolved_commit_id:
            raise CausalBindingError(
                f"witness_lock source_commit_id ({witness_lock.source_commit_id}) "
                f"does not match context_envelope source commit "
                f"({context_envelope.source_identity.resolved_commit_id})"
            )

        # Step B: Validate counterfactual plan binding
        if not isinstance(counterfactual_plan, CounterfactualDeltaPlan):
            raise TypeError(
                f"counterfactual_plan must be CounterfactualDeltaPlan, "
                f"got {type(counterfactual_plan).__name__}"
            )
        if (
            counterfactual_plan.frozen_contract_digest
            != context_envelope.frozen_contract.contract_digest
        ):
            raise CausalBindingError(
                "counterfactual_plan frozen_contract_digest does not match context envelope"
            )
        if counterfactual_plan.sealed_witness_digest != sealed_record.seal_digest:
            raise CausalBindingError(
                "counterfactual_plan sealed_witness_digest does not match sealed record"
            )
        if (
            counterfactual_plan.source_commit_id
            != context_envelope.source_identity.resolved_commit_id
        ):
            raise CausalBindingError(
                "counterfactual_plan source_commit_id does not match context envelope"
            )
        if counterfactual_plan.source_locator != context_envelope.source_identity.locator:
            raise CausalBindingError(
                "counterfactual_plan source_locator does not match context envelope"
            )
        if counterfactual_plan.source_subpath != context_envelope.source_identity.subpath:
            raise CausalBindingError(
                "counterfactual_plan source_subpath does not match context envelope"
            )

        # Step C: P-11.04 — Execute identical witness on trusted BASE
        base_output = self.execute_world(
            context_envelope=context_envelope,
            sealed_record=sealed_record,
            world=ExecutionWorld.BASE,
            execution_command=execution_command,
        )

        # Step D: P-11.04 — Execute identical witness on exact CANDIDATE
        candidate_output = self.execute_world(
            context_envelope=context_envelope,
            sealed_record=sealed_record,
            world=ExecutionWorld.CANDIDATE,
            execution_command=execution_command,
            candidate_tree_digest=context_envelope.candidate_tree_digest,
        )

        # Step E: P-11.03 & P-11.04 — Execute identical witness on COUNTERFACTUAL in fresh sandbox
        cf_output: WorldExecutionOutput | None = None
        invalid_cf_reason: str | None = None

        try:
            cf_output = self.execute_world(
                context_envelope=context_envelope,
                sealed_record=sealed_record,
                world=ExecutionWorld.COUNTERFACTUAL,
                execution_command=execution_command,
                counterfactual_plan=counterfactual_plan,
            )
        except (
            CounterfactualMaterializationError,
            VerifierMaterializationError,
            VerifierTreeDigestMismatchError,
        ) as exc:
            invalid_cf_reason = f"Counterfactual materialization failed: {exc}"

        # Step F: Cryptographic binding and integrity checks across available worlds
        integrity_failure_reason: str | None = None

        # Check 1: Witness digest equality across all runs
        w_digests = {
            base_output.normalized_result.witness_digest,
            candidate_output.normalized_result.witness_digest,
        }
        if cf_output is not None:
            w_digests.add(cf_output.normalized_result.witness_digest)
        if w_digests != {sealed_record.seal_digest}:
            integrity_failure_reason = "Witness digest mismatch across execution runs"

        # Check 2: Sandbox ID collision
        sandbox_ids = {
            base_output.session.sandbox_identity.sandbox_id,
            candidate_output.session.sandbox_identity.sandbox_id,
        }
        if cf_output is not None:
            sandbox_ids.add(cf_output.session.sandbox_identity.sandbox_id)
            if len(sandbox_ids) != 3:
                integrity_failure_reason = "Execution runs reused the same sandbox identity"
        else:
            if len(sandbox_ids) != 2:
                integrity_failure_reason = "Execution runs reused the same sandbox identity"

        # Check 3: Builder sandbox collision
        if any(sid in self.sandbox_manager.known_builder_sandbox_ids for sid in sandbox_ids):
            integrity_failure_reason = "Execution reused a known Builder sandbox identity"

        # Check 4: Source commit match
        expected_commit = context_envelope.source_identity.resolved_commit_id
        if (
            base_output.normalized_result.source_commit_id != expected_commit
            or candidate_output.normalized_result.source_commit_id != expected_commit
            or (
                cf_output is not None
                and cf_output.normalized_result.source_commit_id != expected_commit
            )
        ):
            integrity_failure_reason = (
                "Execution source commit does not match authoritative context"
            )

        # Check 5: Candidate tree must differ from base tree under BUG_FIX
        if base_output.tree_digest.lower() == candidate_output.tree_digest.lower():
            integrity_failure_reason = (
                "Candidate tree digest is identical to base tree digest (empty patch)"
            )

        # Check 6: Counterfactual tree check: delta subtraction must not be no-op
        if cf_output is not None and invalid_cf_reason is None:
            if cf_output.tree_digest.lower() == candidate_output.tree_digest.lower():
                invalid_cf_reason = (
                    "Counterfactual tree is identical to candidate tree "
                    "(subtraction had zero effect)"
                )

        # Step G: P-11.05 & P-11.06 — Deterministic Triplet Outcome Reconciliation
        cf_outcome = (
            cf_output.normalized_result.outcome if cf_output is not None else WitnessOutcome.ERROR
        )
        cf_vacuity = cf_output.vacuity_result if cf_output is not None else None

        reconciliation: ReconciliationFact = reconcile_causal_triplet(
            base_outcome=base_output.normalized_result.outcome,
            candidate_outcome=candidate_output.normalized_result.outcome,
            counterfactual_outcome=cf_outcome,
            base_vacuity=base_output.vacuity_result,
            candidate_vacuity=candidate_output.vacuity_result,
            counterfactual_vacuity=cf_vacuity,
            integrity_failure_reason=integrity_failure_reason,
            invalid_counterfactual_reason=invalid_cf_reason,
        )

        # Step H: Causal Triplet Receipt Generation
        base_fact = WorldExecutionFact.from_normalized_result(
            base_output.normalized_result,
            tree_digest=base_output.tree_digest,
        )
        candidate_fact = WorldExecutionFact.from_normalized_result(
            candidate_output.normalized_result,
            tree_digest=candidate_output.tree_digest,
        )
        cf_fact = (
            WorldExecutionFact.from_normalized_result(
                cf_output.normalized_result,
                tree_digest=cf_output.tree_digest,
            )
            if cf_output is not None
            else None
        )

        receipt = create_causal_triplet_receipt(
            requirement_id=sealed_record.requirement_id,
            frozen_contract_digest=sealed_record.frozen_contract_digest,
            witness_id=sealed_record.witness_id,
            witness_digest=sealed_record.seal_digest,
            lock_digest=witness_lock.lock_digest,
            base_execution=base_fact,
            candidate_execution=candidate_fact,
            counterfactual_execution=cf_fact,
            counterfactual_id=counterfactual_plan.counterfactual_id,
            delta_digest=counterfactual_plan.subtracted_delta_digest,
            transition=reconciliation.transition,
            verdict=reconciliation.verdict,
            provenance=self.provenance,
            narrative=reconciliation.rationale,
        )

        return receipt
