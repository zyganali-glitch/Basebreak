# P-07.06 — Live Candidate Reproduction Proof Report

- **Date / Time (UTC):** 2026-10-03T18:40:17.515977+00:00 to 2026-10-03T18:41:11.173970+00:00
- **Exact Active Task:**
  `P-07.06 — Reproduce candidate from trusted base + captured patch in a fresh sandbox`
- **Execution Status:** EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE
- **Evidence Provenance:** `LIVE_NEBIUS`
- **Phase Exit Gate:** P-07 Phase Exit
  (a real AI-written candidate can be produced and independently reproduced)
- **Tested Implementation SHA:** `0f6bfa1121a164e410a849261990ff0b04820609`
- **Tested Source Commit SHA:** `0f6bfa1121a164e410a849261990ff0b04820609`
- **Tested Source Tree SHA:** `85bd13c5dce92df11a0fe50b0252846cd745c7d3`
- **Configured Model Identity:** `nvidia/Nemotron-3_5-Lightning`
- **Provider Returned Model Identity:** `nvidia/Nemotron-3_5-Lightning`
- **Total Duration:** `53.658s`
- **Frozen Contract Digest:** `ade94b823e8f0624ffa6d04a742903211f668efbcbb1b9ea107b29f92fd2d4d9`
- **Builder Context Digest:** `f5b2396dcf17d9c0ceae4c09c1bf8bafe8ec1fe38ebc6e26a7bbd6c619ce55ab`
- **Sandbox Image:** `tag:astral/uv:python3.11-alpine`
- **Builder Sandbox Identity (Sandbox #1):** `sbx-06b1b18023e84dbf`
- **Reproduction Sandbox Identity (Sandbox #2):** `sbx-12f47dac72c947e3`
- **Sandboxes Distinct Verified:** `True`
- **Patch Digest:** `7cccbf81d7a947bcb308dea86e404b95696d3ac2d3dfa4789ff038190ff55c96`
- **Captured Candidate Tree Digest:** `385eed7e67e6b16e1caa102c9820b9ada947e508`
- **Reproduced Tree Digest:** `385eed7e67e6b16e1caa102c9820b9ada947e508`
- **Deterministic Tree Equality:** `True` (EXACT BIT-FOR-BIT MATCH)
- **Prompt Tokens:** `1020`
- **Completion Tokens:** `726`
- **Total Consumed Tokens:** `1746`
- **Files Added:** `['tests/test_candidate_probe.py']`
- **Files Modified:** `[]`
- **Files Deleted:** `[]`
- **Builder Authored Tests Count:** `1`
- **is_authoritative:** `False` (zero causal verdict authority)
- **is_causally_verified:** `False` (reproduction proves reproducibility only)
- **grants_pass:** `False` (does NOT grant final Basebreak PASS)

---

## 1. Verified End-to-End P-07 Phase Exit Chain

The live run exercised the unbroken, genuine Basebreak authority and reproduction chain:

```
Authoritative FrozenContract (ade94b823e8f0624...)
  -> Minimized Builder Context (f5b2396dcf17d9c0...)
  -> Real Nemotron Model Call (nvidia/Nemotron-3_5-Lightning)
  -> Real Token Factory Builder Sandbox (sbx-06b1b18023e84dbf)
  -> Base Repo Materialization (git clone @ 0f6bfa1121a1)
  -> Real File Action Applied in Sandbox VM
  -> Bounded Command / Test Execution in Sandbox VM
  -> P-07.05 Canonical Protected-Surface Enforcement
  -> P-07.04 Candidate State & Tree Capture (385eed7e67e6b16e...)
  -> Builder Sandbox Teardown & State Destruction
  -> NEW Real Token Factory Reproduction Sandbox (sbx-12f47dac72c947e3)
  -> Rematerialization of Exact Trusted Base Repository
  -> Safe Transport and Application of Exact Captured Patch (git apply)
  -> Deterministic Staging (git add -A) & Tree Calculation (git write-tree)
  -> Exact Cryptographic Tree Hash Verification
  -> Reproduction Sandbox Teardown
```

---

## 2. Deterministic Cryptographic Tree Equality

| Entity | Hash / Identifier | Match? |
|---|---|:---:|
| **Candidate Tree (Sandbox #1)** | `385eed7e67e6b16e1caa102c9820b9ada947e508` | **EXACT MATCH** |
| **Reproduced Tree (Sandbox #2)** | `385eed7e67e6b16e1caa102c9820b9ada947e508` | **EXACT MATCH** |
| **Builder Sandbox Identity** | `sbx-06b1b18023e84dbf` | Distinct |
| **Reproduction Sandbox Identity** | `sbx-12f47dac72c947e3` | Distinct |

Exact tree equality confirms that:
`TRUSTED BASE + EXACT CAPTURED PATCH -> FRESH SANDBOX -> EXACT CANDIDATE TREE`
holds unconditionally in a real cloud container execution environment
without Builder workspace state inheritance.

---

## 3. Captured Unified Patch Content

```diff
diff --git a/tests/test_candidate_probe.py b/tests/test_candidate_probe.py
new file mode 100644
index 0000000000000000000000000000000000000000..6c3771629d2066a5e217ff03d082df86051800f3
--- /dev/null
+++ b/tests/test_candidate_probe.py
@@ -0,0 +1,17 @@
+"""Candidate probe tests for basebreak package."""
+
+import importlib
+import importlib.metadata
+
+import basebreak
+
+
+def test_candidate_probe() -> None:
+    """Verify that the basebreak package can be imported and has valid module spec."""
+    mod = importlib.import_module("basebreak")
+    assert mod is not None
+    assert mod.__name__ == "basebreak"
+    assert hasattr(basebreak, "__version__")
+    assert basebreak.__version__ == "0.1.0"
+    dist_version = importlib.metadata.version("basebreak")
+    assert dist_version == basebreak.__version__
```

---

## 4. Security, Billing & Provenance Verification

- **Sandbox Freshness:** Sandbox #1 (`sbx-06b1b18023e84dbf`) and Sandbox #2
  (`sbx-12f47dac72c947e3`) are mechanically distinct cloud instances.
  Sandbox #1 was torn down before reproduction.
- **Protected Surface Policy:** Canonical P-04 manifest enforced across both execution
  and reproduction.
- **Zero-Cost Law:** Total inference consumed `1746` tokens; two disposable sandboxes
  executed within promotional ceilings (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`).
  Target personal spend: `$0.00`.
- **Zero Self-Certification:** `is_authoritative=False`, `is_causally_verified=False`,
  `grants_pass=False`.
- **Secret Safety Check:** PASS. 0 secrets present in durable evidence.
