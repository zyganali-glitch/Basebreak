# P-10 Causal Two-World Engine Proof

## Overview
This document records the architecture, execution proof, and verification invariants for **P-10 (Causal Two-World Engine)**.

- **Core Thesis:** *"If the patch matters, the base must break."*
- **Judge Claim:** *"Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green."*
- **Tested Base Commit SHA:** `55abf808e9fc01d5003ef32d61557800942ceed8`
- **P-09 Verified Baseline:** `4ee198177f9edcb2f0587060ca271863a09aaf93`
- **Verification Provenance:** `LOCAL_EXECUTION` (with live Token Factory readiness preserved)

---

## Architecture: Unbroken Verification Chain

The Causal Two-World Engine enforces an unbroken mechanical custody chain from task specification to judge proof:

```
Frozen Contract (contract_digest)
       |
       v
Verifier Context Envelope (envelope_digest)
       |
       v
Validated Witness Plan (plan_digest)
       |
       v
Sealed Witness Record in Vault (witness_digest)
       |
       v
Pre-Execution Witness Lock (lock_digest)
       |
       +-------------------------------+
       |                               |
       v                               v
Fresh Disposable BASE Sandbox    Fresh Disposable CANDIDATE Sandbox
(sbx-base-001, exit 1 -> FAIL)   (sbx-cand-002, exit 0 -> PASS)
       |                               |
       +---------------+---------------+
                       |
                       v
       Deterministic Reconciliation Engine
     (BASE=FAIL, CANDIDATE=PASS -> CAUSAL_BUG_FIX_VERIFIED)
                       |
                       v
             Local Causal Receipt
           (receipt_digest, tamper-evident)
                       |
                       v
         Judge Proof Summary (JSON & Markdown)
```

---

## Micro-Task Validation Summary

### P-10.01 — Execute sealed behavioral witness on trusted base
- **Implementation:** `src/basebreak/causal/engine.py` (`CausalExecutionEngine.execute_world`)
- **Invariant:** Executes in a fresh, disposable verifier sandbox session.
- **Base world behavior:** Clean base materialization strictly from trusted source commit. Under BUG_FIX, the sealed witness fails with exit code 1 (`WitnessOutcome.FAIL`).

### P-10.02 — Execute identical sealed behavioral witness on exact candidate
- **Implementation:** `src/basebreak/causal/engine.py` (`CausalExecutionEngine.execute_world`)
- **Invariant:** Executes in a fresh, disposable verifier sandbox session separate from the base sandbox.
- **Candidate world behavior:** Materialized from trusted commit plus candidate patch. The identical witness passes with exit code 0 (`WitnessOutcome.PASS`).
- **No witness adaptation:** The identical test artifact and command are executed without modification.

### P-10.03 — Prevent witness mutation, sandbox pollution, or shared state between runs
- **Distinct sandboxes:** `receipt.base_execution.sandbox_id != receipt.candidate_execution.sandbox_id`.
- **Builder sandbox rejection:** Builder sandboxes are strictly prohibited; attempted reuse triggers `BuilderSandboxReuseError`.
- **Pre-execution witness lock:** `verify_witness_lock_chain` verifies that the witness digest was locked before candidate execution started.
- **Empty patch detection:** If candidate tree matches base tree, the engine flags `EmptyCandidatePatchError` / `NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE`.
- **Teardown guarantee:** All sandboxes are torn down in `finally` blocks regardless of outcome.

### P-10.04 — Reconcile BUG_FIX FAIL->PASS deterministically
- **Implementation:** `src/basebreak/causal/reconciliation.py` (`reconcile_causal_transition`)
- **Invariant Truth:** Under `BUG_FIX`, the **only** positive causal transition is:
  `BASE = FAIL, CANDIDATE = PASS` $\rightarrow$ `CausalTransition.CAUSAL_BUG_FIX_VERIFIED` (`PreliminaryVerdict.VERIFIED`, `is_causally_verified=True`).
- **Zero model authority:** Pure deterministic Python function with zero LLM dependence.

### P-10.05 — Block non-causal outcomes as non-verified states
- **Anti-collapse rules:**
  - `PASS -> PASS`: `UNVERIFIED_TRIVIAL_PASS` (`INCONCLUSIVE`, `is_causally_verified=False`) — base already passed; patch was not causally necessary.
  - `FAIL -> FAIL`: `UNVERIFIED_DEFECT_PERSISTS` (`CONTRADICTED`, `is_causally_verified=False`) — defect persists.
  - `PASS -> FAIL`: `UNVERIFIED_REGRESSION` (`CONTRADICTED`, `is_causally_verified=False`) — regression observed.
  - `TIMEOUT`: `NON_VERIFIED_TIMEOUT` (`INCONCLUSIVE`, `is_causally_verified=False`).
  - `ERROR`: `NON_VERIFIED_EXECUTION_ERROR` (`INCONCLUSIVE`, `is_causally_verified=False`).
  - `VACUOUS`: `NON_VERIFIED_VACUOUS` (`INCONCLUSIVE`, `is_causally_verified=False`) — detected via AST analysis (e.g. constant assertions) or runtime 0 tests collected.
  - `INVALID_PRECONDITION`: `NON_VERIFIED_INVALID_PRECONDITION` (`BLOCKED`, `is_causally_verified=False`).
  - `INTEGRITY_FAILURE`: `NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE` (`CONTRADICTED`, `is_causally_verified=False`).

### P-10.06 — Produce local causal receipt with cryptographic binding
- **Implementation:** `src/basebreak/causal/receipt.py` (`LocalCausalReceipt`, `create_causal_receipt`, `verify_causal_receipt_integrity`)
- **Canonical Digest:** SHA-256 over canonical JSON representation of all execution facts.
- **Tamper Detection:** Modifying any field (verdict, outcomes, tree digests, timestamps) immediately invalidates the receipt digest and raises `CausalReceiptTamperingError` at construction and validation time.

### P-10.07 — Build judge-readable proof summary
- **Implementation:** `src/basebreak/causal/harness.py` (`format_judge_proof_summary`, `render_judge_proof_markdown`, `run_causal_verification_slice`)
- **Developer Integration Harness:** Minimal internal integration function connecting the complete vertical slice without prematurely freezing public CLI (`basebreak verify` remains scheduled for P-19).
- **Dual summary formats:**
  - Structured machine-readable dictionary for automated auditors.
  - Formatted GitHub-flavored markdown with side-by-side behavioral comparison and digest audit table.

---

## Test Verification
- All 27 causal unit and integration tests passing (`tests/causal/`):
  - `tests/causal/test_engine.py`: 5 passed
  - `tests/causal/test_reconciliation.py`: 10 passed
  - `tests/causal/test_receipt.py`: 3 passed
  - `tests/causal/test_harness.py`: 3 passed
  - `tests/causal/test_p10_closure.py`: 5 passed (1 live test gracefully skipped when remote VM project ID not configured)
- Zero regressions across the full Basebreak repository suite.
- Zero personal money spent ($0.00). Promotional balance safety floor ($5.00) preserved.
