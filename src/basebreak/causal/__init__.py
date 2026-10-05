"""Basebreak Causal Two-World Engine and Verification Primitives.

P-10: Causal Two-World Engine implementation.
"""

from __future__ import annotations

from basebreak.causal.engine import (
    CausalBindingError,
    CausalEngineError,
    CausalExecutionEngine,
    EmptyCandidatePatchError,
    SandboxCollisionError,
    WorldExecutionOutput,
)
from basebreak.causal.harness import (
    BASEBREAK_JUDGE_CLAIM,
    BASEBREAK_THESIS,
    format_judge_proof_summary,
    render_judge_proof_markdown,
    run_causal_verification_slice,
)
from basebreak.causal.materializer import (
    CausalRepositoryMaterializer,
    GitRepositoryMaterializer,
)
from basebreak.causal.receipt import (
    CAUSAL_RECEIPT_SCHEMA_VERSION,
    CausalReceiptError,
    CausalReceiptIntegrityError,
    CausalReceiptTamperingError,
    LocalCausalReceipt,
    WorldExecutionFact,
    build_canonical_receipt_payload,
    compute_receipt_digest,
    create_causal_receipt,
    verify_causal_receipt_integrity,
)
from basebreak.causal.reconciliation import (
    CausalTransition,
    ReconciliationFact,
    reconcile_causal_transition,
)

__all__ = [
    "BASEBREAK_JUDGE_CLAIM",
    "BASEBREAK_THESIS",
    "CAUSAL_RECEIPT_SCHEMA_VERSION",
    "CausalBindingError",
    "CausalEngineError",
    "CausalExecutionEngine",
    "CausalReceiptError",
    "CausalReceiptIntegrityError",
    "CausalReceiptTamperingError",
    "CausalRepositoryMaterializer",
    "CausalTransition",
    "EmptyCandidatePatchError",
    "GitRepositoryMaterializer",
    "LocalCausalReceipt",
    "ReconciliationFact",
    "SandboxCollisionError",
    "WorldExecutionFact",
    "WorldExecutionOutput",
    "build_canonical_receipt_payload",
    "compute_receipt_digest",
    "create_causal_receipt",
    "format_judge_proof_summary",
    "reconcile_causal_transition",
    "render_judge_proof_markdown",
    "run_causal_verification_slice",
    "verify_causal_receipt_integrity",
]
