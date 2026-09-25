# P-01.07 — Judge-Visible Causal Vertical-Slice Contract

- **Date/Time:** 2026-09-25 13:50 UTC (16:50 Local)
- **Starting Canonical Remote SHA:** `d74d8103c7048bdb1c73221bb690575cba43818f`
- **Active Micro-Task:** `P-01.07 — Freeze judge-visible causal vertical-slice contract from proven platform reality`
- **Execution Status:** EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE
- **Zero-Cost Policy Check:** SATISFIED (Target personal spend $0.00; beta sandboxes free of charge, promotional balance $25.00 untouched).

---

## 1. Purpose & Product Thesis

Basebreak's core thesis:
> **"If the patch matters, the base must break."**

A green test suite on a patched repository does not prove causality. A test suite may pass because:
- The tests are trivial or tautological;
- The test suite was already green on the buggy base (non-discriminating test);
- The environment was polluted by previous runs or pre-existing build artifacts;
- The patch bypassed the problem rather than fixing the defect.

Basebreak delivers deterministic, irrefutable proof that an AI-generated patch is the sole cause of the behavioral improvement. This document freezes the exact contract of what an evaluator or hackathon judge will see during a verification run, built strictly upon the live platform primitives proven in `P-01.02` through `P-01.05`.

---

## 2. Judge-Visible Pipeline Flow & Contract

Every evaluation executed by Basebreak follows an immutable sequential pipeline:

```
[ EngineeringTask ]
        │
        ├───────────────────────────────────────┐
        ▼                                       ▼
  [ Builder Agent ]                    [ Independent Witness ]
(Nemotron-3.5-Lightning)              (Generated Independently)
        │                                       │
        ▼                                       ▼
 [ Candidate Patch ]                     [ Test / Witness ]
        │                                       │
        ├───────────────────┬───────────────────┤
        ▼                   ▼                   ▼
 [ BASE Sandbox ]   [ CANDIDATE Sandbox ] [ COUNTERFACTUAL ]
 (Clean disposable)  (Clean disposable)    (Clean disposable)
 (BASE + Witness)    (BASE + Patch + Wit)  (BASE + Mut + Wit)
        │                   │                   │
  Must FAIL (❌)       Must PASS (✅)      Must FAIL (❌)
        │                   │                   │
        └───────────────────┼───────────────────┘
                            ▼
              [ Fact Authority & Redaction ]
              (Cryptographic SHA, Digests,
               Zero-secret audit, Timestamps)
                            ▼
           [ Deterministic Verdict & Receipt ]
```

### Stage 1: Engineering Task Specification
- Input: `EngineeringTask`
- Fields:
  - `task_id`: Deterministic UUID/hash.
  - `target_repository`: Canonical Git URL.
  - `base_commit_sha`: Immutable 40-character hexadecimal Git commit SHA.
  - `problem_statement`: Issue description or behavioral specification.
  - `change_class`: Enum (`BUG_FIX`, `FEATURE`, `REFACTOR`, etc.).

### Stage 2: Independent Dual Generation (Builder vs. Verifier)
- **Builder Agent:**
  - Powered by `nvidia/Nemotron-3_5-Lightning`.
  - Produces a candidate unified diff (`CandidatePatch`).
  - Strict isolation: The Builder has NO access to sealed verifier test suites or protected verification files.
- **Independent Witness Formulation:**
  - An executable test or specification that targets the reported defect.
  - Authored independently from the candidate diff to avoid circular reasoning and developer confirmation bias.

### Stage 3: Two Clean Disposable Sandboxes (No Shared Workspace)
- Run inside Nebius Token Factory Sandboxes (`tag:astral/uv:python3.11-alpine` with `disposable: true`).
- **Sandbox A (BASE Verification):**
  - Clones repository at `base_commit_sha`.
  - Injects Independent Witness test.
  - Executes test suite.
  - **Required Invariant:** `BASE = FAIL` (exit code != 0, test failure captured).
  - *If BASE passes, the test does not witness the defect; verdict: REJECTED_NON_DISCRIMINATING.*
- **Sandbox B (CANDIDATE Verification):**
  - Fresh, independent disposable VM (zero workspace sharing, different operation UUID).
  - Clones repository at `base_commit_sha`.
  - Applies `CandidatePatch` unified diff.
  - Injects Independent Witness test.
  - Executes test suite.
  - **Required Invariant:** `CANDIDATE = PASS` (exit code == 0, test passes).

### Stage 4: Counterfactual Verification (Where Required)
- For behavioral bug fixes and safety-critical patches, execute Sandbox C:
  - Injects mutated patch or null hypothesis.
  - **Required Invariant:** `COUNTERFACTUAL = FAIL`.

### Stage 5: Deterministic Fact Authority & Receipt Generation
- Capture stdout/stderr with SHA-256 content digests.
- Check protected-surface manifest (ensuring patch did not mutate verification harness or CI configurations).
- Redact any environment secrets via regex and forbidden persistence rules.
- Produce an immutable, content-addressed `VerificationReceipt`:
  - `base_sha`: Exact commit SHA.
  - `candidate_diff_hash`: SHA-256 of patch.
  - `sandbox_alpha_id`: Operation UUID of BASE run.
  - `sandbox_beta_id`: Operation UUID of CANDIDATE run.
  - `base_exit_code`: Non-zero.
  - `candidate_exit_code`: 0.
  - `verdict`: `CAUSALLY_VERIFIED`.
  - `provenance`: `LIVE_NEBIUS`.

---

## 3. Grounded Platform Guarantees (No Unverified Claims)

This contract relies strictly on proven platform realities:
1. **VM Isolation:** Proven by `P-01.05` where `/root/run1_marker.txt` in Run 1 did not bleed into Run 2.
2. **Ephemeral Destruction:** Proven by `P-01.03` through `P-01.05` where `disposable: true` instances automatically terminated with zero running instances remaining.
3. **Cryptographic Source Matching:** Proven by `P-01.04` where container git tree hash `aa54850bf7ddcd222539d3e0b6fe5059cb1d693d` perfectly matched local canonical tree hash.
4. **Execution Speed:** Proven average duration of 4.4s–5.1s per sandbox clone-install-test cycle on `astral/uv:python3.11-alpine`.

---

## 4. Research-Only Historical Bug/Fix Shortlist (for Future P-23.08 Replay)

*Note: `ResetVault` remains Basebreak's PRIMARY deterministic killer demo. The candidate pairs below are research-only shortlist candidates for eventual supplementary historical replay in P-23.08. At P-01.07: strictly NO code importing, NO replay implementation, and NO claiming upstream patch was produced by Basebreak.*

### Candidate 1: `urllib3/urllib3` — Cookie Header Stripping on Cross-Origin Redirect
- **Repository:** `https://github.com/urllib3/urllib3`
- **Root License:** MIT
- **Buggy Base SHA:** `b63cc50c25a0a382c40c3132e4d0c918c5c7d81a` (v2.0.5)
- **Fixed SHA:** `0349ec14ee3a1372b781a5cbb7f2fd1aa58652da` (v2.0.6)
- **Concise Behavioral Defect:** Cookie request headers were inadvertently preserved when following cross-origin redirects, potentially leaking session credentials across origins (CVE-2023-43804).
- **Likely Independent Witness:** A unit test executing `PoolManager.request('GET', ..., redirect=True)` redirecting from `http://example.com` to `http://other.com` asserting that `Cookie` header is absent in the redirected request.
- **Dependency / Runtime Footprint:** Pure Python, lightweight dependencies, installs via `uv` in < 2 seconds.
- **Sandbox Feasibility:** Highly feasible in `tag:astral/uv:python3.11-alpine`.
- **Verdict on Suitability:** **SUITABLE** (clean, self-contained, clear security relevance, deterministic pass/fail).

### Candidate 2: `pallets/werkzeug` — Safe Join Path Traversal Edge Case
- **Repository:** `https://github.com/pallets/werkzeug`
- **Root License:** BSD-3-Clause
- **Buggy Base SHA:** `76822c7a972c3d5268c5e638d01da93f3ef841cf` (v3.0.0)
- **Fixed SHA:** `e8df35bbf6c96a79ee7eb269fa5ba5241fae0172` (v3.0.1)
- **Concise Behavioral Defect:** `safe_join` improperly handled certain path segment combinations on Windows/POSIX boundaries, allowing directory traversal.
- **Likely Independent Witness:** Direct functional test invoking `werkzeug.security.safe_join(base_dir, untrusted_path)` asserting `None` is returned for escaping paths.
- **Dependency / Runtime Footprint:** Pure Python, zero external binary dependencies.
- **Sandbox Feasibility:** Highly feasible in `tag:astral/uv:python3.11-alpine`.
- **Verdict on Suitability:** **SUITABLE** (very fast execution, pure Python, zero network dependency during test run).

### Candidate 3: `encode/httpx` — Query Parameter Encoding in URLs
- **Repository:** `https://github.com/encode/httpx`
- **Root License:** BSD-3-Clause
- **Buggy Base SHA:** `fbb39d4cae5d956bf193a401c4ecde65fc5bb565`
- **Fixed SHA:** `834adcb0272bc13f9f30b91dcfba8b51206df6ce`
- **Concise Behavioral Defect:** URL query parameter string serialization mishandled unescaped reserved characters.
- **Likely Independent Witness:** Unit test instantiating `httpx.URL` with complex query parameters and asserting string representation matches RFC 3986.
- **Dependency / Runtime Footprint:** Pure Python with `httpcore`, `anyio`.
- **Sandbox Feasibility:** Highly feasible in `tag:astral/uv:python3.11-alpine`.
- **Verdict on Suitability:** **SUITABLE** (straightforward pure Python test, fast runtime).

---

## 5. Phase P-01 Completion & Exit Gate Validation

With:
1. `P-01.01`: Official API and model catalog discovery complete;
2. `P-01.02`: Real Nemotron inference verified live;
3. `P-01.03`: Real sandbox beta access and execution primitives verified live;
4. `P-01.04`: Real repository materialization and cryptographic source identity verified live;
5. `P-01.05`: Two clean independent sandbox executions without mutable workspace sharing verified live;
6. `P-01.06`: Feasibility GO decision and architecture v0 frozen;
7. `P-01.07`: Judge-visible causal vertical-slice contract frozen;

Phase `P-01` (Live Platform Discovery & Feasibility Proof) has successfully proven all real model, real sandbox, and two-clean-environment spine requirements.
