# PERFORMANCE_LIMITS.md — Basebreak Performance & Cost Limits

## 1. Executive Summary & Causal Invariant

Basebreak enforces causal verification:
> **“If the patch matters, the base must break.”**

Because Basebreak runs multiple isolated worlds (BASE, CANDIDATE, and optionally COUNTERFACTUAL) to certify that a patch is causally necessary, its execution profile differs fundamentally from traditional single-pass continuous integration (CI). This document records the empirical latency breakdown, resource limits, deterministic routing rules, and causal overhead measurements.

---

## 2. Phase Latency Breakdown

| Phase | Operation | Typical Duration (Local Measured) | Typical Duration (Sandbox Illustrative) | Determinism |
|---|---|---|---|---|
| **P-1** | Contract Compilation & Freeze | < 10 ms | N/A | 100% Deterministic (AST/Digest) |
| **P-2** | BASE Execution | 50 – 500 ms | 1.5 – 4.0 s | Deterministic (Sealed Witness) |
| **P-3** | CANDIDATE Execution | 50 – 500 ms | 1.5 – 4.0 s | Deterministic (Sealed Witness) |
| **P-4** | COUNTERFACTUAL Execution | 50 – 500 ms | 1.5 – 4.0 s | Deterministic (Delta Inversion) |
| **P-5** | AST Vacuity Analysis | < 5 ms | N/A | 100% Deterministic (Python AST) |
| **P-6** | Reconciliation & Receipt Signing | < 15 ms | N/A | 100% Deterministic (HMAC/Ed25519) |

*Note on Provenance:*
- **Local Measured:** Actual execution duration measured on the operator development host (`LOCAL_EXECUTION`). Total local latency is typically **under 1.5 seconds**.
- **Sandbox Illustrative:** Estimated ranges derived from P-01.03–P-01.05 platform discovery runs, **not** live benchmark measurements. Containerized sandboxes typically run in **4 to 12 seconds**.

---

## 3. Causal Verification Overhead vs Baseline CI

Traditional CI runs a single pass of the existing test suite against the candidate branch ($1.0\times$ baseline). Basebreak requires:

$$\text{Causal Multiplier} = \frac{T_{\text{freeze}} + T_{\text{base}} + T_{\text{cand}} + T_{\text{cf}} + T_{\text{recon}}}{T_{\text{baseline}}}$$

- **Two-World Verification (BASE + CANDIDATE):** $\approx 2.0\times - 2.3\times$ single-run CI.
- **Three-World Verification (+ COUNTERFACTUAL):** $\approx 3.0\times - 3.4\times$ single-run CI.

### What the Overhead Buys:
1. **Rejection of Vacuous Passes:** Traditional CI cannot distinguish between a patch that fixed the defect versus a test suite that was already green. Basebreak guarantees BASE=FAIL.
2. **Rejection of Coincidental Passes:** Counterfactual execution guarantees that removing the patch logic re-breaks the witness.
3. **Protection Against Test Deletion:** Builder attempting to delete tests or weaken assertions is caught at Phase 1 before running any code.

---

## 4. Token & Context Envelopes

| Workload Category | Prompt Envelope | Completion Envelope | Max Context Window |
|---|---|---|---|
| **Contract Freeze** | 1,024 – 2,048 tokens | 512 – 1,024 tokens | 8,192 tokens |
| **Builder Patch Generation** | 2,048 – 6,144 tokens | 1,024 – 2,048 tokens | 16,384 tokens |
| **Witness Generation** | 1,536 – 4,096 tokens | 512 – 1,536 tokens | 16,384 tokens |
| **Reflection / Repair** | 4,096 – 8,192 tokens | 1,024 – 2,048 tokens | 32,768 tokens |

---

## 5. Model Routing & Strategy Matrix (P-26.04)

Basebreak separates deterministic routing policy from model availability and empirical optimization:
- **Verified Provider Model:** `nvidia/Nemotron-3_5-Lightning` is the sole live-proven model in Basebreak architecture (verified in P-01.02).
- **Candidate Deep Model:** `nvidia/nemotron-3-super-120b-a12b` is catalog-confirmed on Nebius Token Factory, but has not yet undergone live validation; it must not be the default.
- **Policy Stance on Optimality:** Hard-coded model assignments are **not** claimed to be empirically optimal. Empirical optimality claims are strictly prohibited without measured provider quality/cost benchmark evidence.
- **Fail-Closed Routing:** Unverified models (e.g. models not present in verified provider configuration) are rejected fail-closed with `UnsupportedModelError`. Speculative automatic model switching is prohibited.

### Deterministic Verifier Strategy Matrix

| Risk Tier | Change Class | Verified Provider Model | Verifier Strategy | Temperature | Max Tokens |
|---|---|---|---|---|---|
| **CRITICAL** | Any / Security Boundary | `nvidia/Nemotron-3_5-Lightning` | `TEMPLATE_GUIDED` | 0.0 | 4,096 |
| **HIGH** | Bug Fix / Deep Reasoning | `nvidia/Nemotron-3_5-Lightning` | `MULTI_TURN_REFLECTION` | 0.2 | 4,096 |
| **MEDIUM** | Standard Bug Fix | `nvidia/Nemotron-3_5-Lightning` | `MULTI_TURN_REFLECTION` | 0.2 | 2,048 |
| **LOW** | Refactor / Documentation | `nvidia/Nemotron-3_5-Lightning` | `SINGLE_SHOT` | 0.3 | 2,048 |

---

## 6. Sandbox Concurrency & Resource Floors

- **Sandbox Timeout Watchdog:** Hard ceiling of **60 seconds** per sandbox execution.
- **Memory Ceiling:** Default limit of **2,048 MB** per container.
- **Freshness Invariant:** Every world (BASE, CANDIDATE, COUNTERFACTUAL) executes in an entirely fresh sandbox instance to prevent filesystem or state leakage.
- **Budget Floor Policy:** Execution halts immediately if promotional credit drops below the **$5.00** safety threshold (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD`).

---

## 7. Factual Classification of Evidence & Benchmarks

Under the **Zero-Cost Law** and Section 12 of `AGENTS.md`:

1. **Measured Local Values (`LOCAL_EXECUTION`):** Local execution durations (< 1.5s) and AST analyses are measured directly on the host.
2. **Illustrative Calculations (`FIXTURE`):** Multiplier equations (2.0x–3.4x) and synthetic benchmark evaluations are illustrative models.
3. **Platform Documentation Facts:** Token limits and endpoints are derived from official Nebius documentation and initial discovery.
4. **Live External Benchmarks (`LIVE_EXTERNAL`):** Comparative live model benchmarks against paid endpoints remain strictly:
   `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`
   Development personal spend remains strictly **$0.00**.
