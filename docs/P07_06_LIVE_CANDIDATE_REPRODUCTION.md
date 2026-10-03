# P-07.06 — Live Candidate Reproduction Proof Report

- **Date / Time (UTC):** 2026-10-03T20:24:27.109054+00:00 to 2026-10-03T20:24:48.086120+00:00
- **Exact Active Task:**
  `P-07.06 — Reproduce candidate from trusted base + captured patch in a fresh sandbox`
- **Execution Status:** EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE
- **Evidence Provenance:** `LIVE_NEBIUS`
- **Phase Exit Gate:** P-07 Phase Exit
  (a real AI-written candidate can be produced and independently reproduced)
- **Tested Implementation SHA:** `2343e42007751e9d38f81f50df9c7153c18ea454`
- **Tested Source Commit SHA:** `2343e42007751e9d38f81f50df9c7153c18ea454`
- **Tested Source Tree SHA:** `8f9774b8b0c41b7b3eda2cf26fd3c9dcbc48d5cc`
- **Configured Model Identity:** `nvidia/Nemotron-3_5-Lightning`
- **Provider Returned Model Identity:** `nvidia/Nemotron-3_5-Lightning`
- **Total Duration:** `20.977s`
- **Frozen Contract Digest:** `17f4bd49a4bb8ef4550612567f6d3c49b4934cda391057d13b06365102ffa154`
- **Builder Context Digest:** `9bb0139eb4ea5cbe39251341a9582c310ef339dfaf96e35c875b125547dfc3dd`
- **Sandbox Image:** `3b95cff8-2ad1-4c23-81b9-a41358959b76`
- **Builder Sandbox Identity (Sandbox #1):** `sbx-c139b271fe2346d3`
- **Reproduction Sandbox Identity (Sandbox #2):** `sbx-70efb321e04f4efb`
- **Sandboxes Distinct Verified:** `True`
- **Patch Digest:** `1b80dbb7754d70dc7ce6e42c1dc1667b6855e48424bd9d71c190de5d83facde7`
- **Captured Candidate Tree Digest:** `94c6ddb2af9ae5c954cbe934068ed57b946ecfa9`
- **Reproduced Tree Digest:** `94c6ddb2af9ae5c954cbe934068ed57b946ecfa9`
- **Deterministic Tree Equality:** `True` (EXACT BIT-FOR-BIT MATCH)
- **Prompt Tokens:** `1024`
- **Completion Tokens:** `1020`
- **Total Consumed Tokens:** `2044`
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
Authoritative FrozenContract (17f4bd49a4bb8ef4...)
  -> Minimized Builder Context (9bb0139eb4ea5cbe...)
  -> Real Nemotron Model Call (nvidia/Nemotron-3_5-Lightning)
  -> Real Token Factory Builder Sandbox (sbx-c139b271fe2346d3)
  -> Base Repo Materialization (git clone @ 2343e4200775)
  -> Real File Action Applied in Sandbox VM
  -> Bounded Command / Test Execution in Sandbox VM
  -> P-07.05 Canonical Protected-Surface Enforcement
  -> P-07.04 Candidate State & Tree Capture (94c6ddb2af9ae5c9...)
  -> Builder Sandbox Teardown & State Destruction
  -> NEW Real Token Factory Reproduction Sandbox (sbx-70efb321e04f4efb)
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
| **Candidate Tree (Sandbox #1)** | `94c6ddb2af9ae5c954cbe934068ed57b946ecfa9` | **EXACT MATCH** |
| **Reproduced Tree (Sandbox #2)** | `94c6ddb2af9ae5c954cbe934068ed57b946ecfa9` | **EXACT MATCH** |
| **Builder Sandbox Identity** | `sbx-c139b271fe2346d3` | Distinct |
| **Reproduction Sandbox Identity** | `sbx-70efb321e04f4efb` | Distinct |

Exact tree equality confirms that:
`TRUSTED BASE + EXACT CAPTURED PATCH -> FRESH SANDBOX -> EXACT CANDIDATE TREE`
holds unconditionally in a real cloud container execution environment
without Builder workspace state inheritance.

---

## 3. Captured Unified Patch Content

```diff
diff --git a/tests/test_candidate_probe.py b/tests/test_candidate_probe.py
new file mode 100644
index 0000000000000000000000000000000000000000..43fb2f29a00fb1bf7534a229270e9a39c689a473
--- /dev/null
+++ b/tests/test_candidate_probe.py
@@ -0,0 +1,5 @@
+"""Candidate probe tests for basebreak package."""
+
+def test_candidate_probe() -> None:
+    """Probe test verifying candidate infrastructure is operational."""
+    assert True
```

---

## 4. Security, Billing & Provenance Verification

- **Sandbox Freshness:** Sandbox #1 (`sbx-c139b271fe2346d3`) and Sandbox #2
  (`sbx-70efb321e04f4efb`) are mechanically distinct cloud instances.
  Sandbox #1 was torn down before reproduction.
- **Protected Surface Policy:** Canonical P-04 manifest enforced across both execution
  and reproduction.
- **Zero-Cost Law:** Total inference consumed `2044` tokens; two disposable sandboxes
  executed within promotional ceilings (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`).
  Target personal spend: `$0.00`.
- **Zero Self-Certification:** `is_authoritative=False`, `is_causally_verified=False`,
  `grants_pass=False`.
- **Secret Safety Check:** PASS. 0 secrets present in durable evidence.
