# P-07.06 — Live Candidate Reproduction Proof Report

- **Date / Time (UTC):** 2026-10-04T06:48:34.697682+00:00 to 2026-10-04T06:48:51.183746+00:00
- **Exact Active Task:**
  `P-07.06 — Reproduce candidate from trusted base + captured patch in a fresh sandbox`
- **Execution Status:** EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE
- **Evidence Provenance:** `LIVE_NEBIUS`
- **Phase Exit Gate:** P-07 Phase Exit
  (a real AI-written candidate can be produced and independently reproduced)
- **Tested Implementation SHA:** `f427d2e921bfbc17adfc2f4762c06bcfb1925d05`
- **Tested Source Commit SHA:** `f427d2e921bfbc17adfc2f4762c06bcfb1925d05`
- **Tested Source Tree SHA:** `579ac1080b4663b72fa20dcae04a3452c3a6d336`
- **Configured Model Identity:** `nvidia/Nemotron-3_5-Lightning`
- **Provider Returned Model Identity:** `nvidia/Nemotron-3_5-Lightning`
- **Total Duration:** `16.486s`
- **Frozen Contract Digest:** `17f4bd49a4bb8ef4550612567f6d3c49b4934cda391057d13b06365102ffa154`
- **Builder Context Digest:** `4ebaf893b09c10bd14788819b6e84f0acd99b4dd55e7add0836f42a312b5bf3f`
- **Sandbox Image:** `29ce762a-dbe6-4fdc-bfae-0d5345f40152`
- **CLEAN BASE Checkpoint Provider Operation ID:** `01a105ac-058f-7660-8d7a-cb1ea9c78e0a`
- **CLEAN BASE Checkpoint Image UUID:** `29ce762a-dbe6-4fdc-bfae-0d5345f40152`
- **Builder Sandbox Correlation ID (Sandbox #1):** `sbx-d30897c215744524`
- **Builder Provider Operation ID:** `01a105ac-19cc-73cd-8489-598ab2f52df5`
- **Builder Result Image UUID:** `None` (strictly None / disposable)
- **Reproduction Sandbox Correlation ID (Sandbox #2):** `sbx-1f3550b6159b4461`
- **Reproduction Provider Operation ID:** `01a105ac-24b1-7328-92e2-1b160a9958b8`
- **Reproduction Result Image UUID:** `None` (None)
- **Sandboxes Distinct Verified:** `True`
- **Patch Digest:** `b0fede7982258e9bc104ae040b4b9a9da3ccaacc083fa17418d3261a1731d077`
- **Captured Candidate Tree Digest:** `f31c6dd288bc29cafd481829fc7c3ecd3289d805`
- **Reproduced Tree Digest:** `f31c6dd288bc29cafd481829fc7c3ecd3289d805`
- **Deterministic Tree Equality:** `True` (EXACT BIT-FOR-BIT MATCH)
- **Prompt Tokens:** `1024`
- **Completion Tokens:** `492`
- **Total Consumed Tokens:** `1516`
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
  -> Minimized Builder Context (4ebaf893b09c10bd...)
  -> Real Nemotron Model Call (nvidia/Nemotron-3_5-Lightning)
  -> Clean Base (op=01a105ac-058f-7660-8d7a-cb1ea9c78e0a, img=29ce762a...)
  -> Real Disposable Builder Sandbox (sbx-d30897c215744524, op=01a105ac-19cc-73cd-8489-598ab2f52df5)
  -> Real File Action Applied in Sandbox VM
  -> Bounded Command / Test Execution in Sandbox VM
  -> P-07.05 Canonical Protected-Surface Enforcement
  -> P-07.04 Candidate State & Tree Capture (f31c6dd288bc29ca...)
  -> Disposable Builder Sandbox Disposed (result_image_uuid=None)
  -> NEW Disposable Reproduction Sandbox (sbx-1f3550b6159b4461)
  -> From Immutable Clean Base Checkpoint (29ce762a-dbe6-4f...)
  -> Safe Transport and Application of Exact Captured Patch (git apply)
  -> Deterministic Staging (git add -A) & Tree Calculation (git write-tree)
  -> Exact Cryptographic Tree Hash Verification
  -> Disposable Reproduction Sandbox Disposed (result_image_uuid=None)
```

---

## 2. Deterministic Cryptographic Tree Equality & Runtime Evidence

| Entity | Hash / Identifier | Match / Policy Status |
|---|---|:---:|
| **Candidate Tree (Sandbox #1)** | `f31c6dd288bc29cafd481829fc7c3ecd3289d805` | **EXACT MATCH** |
| **Reproduced Tree (Sandbox #2)** | `f31c6dd288bc29cafd481829fc7c3ecd3289d805` | **EXACT MATCH** |
| **Builder Sandbox Identity** | `sbx-d30897c215744524` | Distinct |
| **Reproduction Sandbox Identity** | `sbx-1f3550b6159b4461` | Distinct |
| **Clean Base Checkpoint Image** | `29ce762a-dbe6-4fdc-bfae-0d5345f40152` | Verified Checkpoint |
| **Builder Provider Operation ID** | `01a105ac-19cc-73cd-8489-598ab2f52df5` | Verified Provider Fact |
| **Builder Result Image UUID** | `None` | None (Disposable) |
| **Repro Provider Op ID** | `01a105ac-24b1-7328-92e2-1b160a9958b8` | Verified Provider Fact |
| **Reproduction Result Image UUID** | `None` | None (Disposable) |

Exact tree equality confirms that:
`TRUSTED BASE + EXACT CAPTURED PATCH -> FRESH SANDBOX -> EXACT CANDIDATE TREE`
holds unconditionally in a real cloud container execution environment
without Builder workspace state inheritance.

---

## 3. Captured Unified Patch Content

```diff
diff --git a/tests/test_candidate_probe.py b/tests/test_candidate_probe.py
new file mode 100644
index 0000000000000000000000000000000000000000..aba2705f388419f6d2e58f112933450720dc86a8
--- /dev/null
+++ b/tests/test_candidate_probe.py
@@ -0,0 +1,5 @@
+"""Candidate probe tests for basebreak package."""
+
+def test_candidate_probe() -> None:
+    """Verify candidate probe is functional."""
+    assert True
```

---

## 4. Security, Billing & Provenance Verification

- **Sandbox Freshness:** Sandbox #1 (`sbx-d30897c215744524`) and Sandbox #2
  (`sbx-1f3550b6159b4461`) are mechanically distinct cloud instances.
  Sandbox #1 was torn down before reproduction.
- **Protected Surface Policy:** Canonical P-04 manifest enforced across both execution
  and reproduction.
- **Zero-Cost Law:** Total inference consumed `1516` tokens; two disposable sandboxes
  executed within promotional ceilings (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`).
  Target personal spend: `$0.00`.
- **Zero Self-Certification:** `is_authoritative=False`, `is_causally_verified=False`,
  `grants_pass=False`.
- **Secret Safety Check:** PASS. 0 secrets present in durable evidence.
