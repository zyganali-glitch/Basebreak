# P-07.06 — Live Candidate Reproduction Proof Report

- **Date / Time (UTC):** 2026-10-04T08:03:59.068797+00:00 to 2026-10-04T08:04:23.563866+00:00
- **Exact Active Task:**
  `P-07.06 — Reproduce candidate from trusted base + captured patch in a fresh sandbox`
- **Execution Status:** EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE
- **Evidence Provenance:** `LIVE_NEBIUS`
- **Phase Exit Gate:** P-07 Phase Exit
  (a real AI-written candidate can be produced and independently reproduced)
- **Tested Implementation SHA:** `b1c93ee1e00f3617d6d2d7c17fbf9a530eac3f72`
- **Tested Source Commit SHA:** `b1c93ee1e00f3617d6d2d7c17fbf9a530eac3f72`
- **Tested Source Tree SHA:** `8dbb3d5f36b30b05c2e65036b95a3d759bba2025`
- **Configured Model Identity:** `nvidia/Nemotron-3_5-Lightning`
- **Provider Returned Model Identity:** `nvidia/Nemotron-3_5-Lightning`
- **Total Duration:** `24.495s`
- **Frozen Contract Digest:** `17f4bd49a4bb8ef4550612567f6d3c49b4934cda391057d13b06365102ffa154`
- **Builder Context Digest:** `6f6b458234862de49c67fa37632ceb961e52ed35777834446d8670434e129a3f`
- **Patch Digest:** `d0d986a1c6f9136a457a78c92a886fef345b461fe49a4d8dc4a4c3fd31212ebd`
- **Captured Candidate Tree Digest:** `c61f4e4f0bfcdb82509243b39d84361782620588`
- **Reproduced Tree Digest:** `c61f4e4f0bfcdb82509243b39d84361782620588`
- **Deterministic Tree Equality:** `True` (EXACT BIT-FOR-BIT MATCH)
- **Prompt Tokens:** `1024`
- **Completion Tokens:** `1440`
- **Total Consumed Tokens:** `2464`
- **Files Added:** `['tests/test_candidate_probe.py']`
- **Files Modified:** `[]`
- **Files Deleted:** `[]`
- **Builder Authored Tests Count:** `1`
- **is_authoritative:** `False` (zero causal verdict authority)
- **is_causally_verified:** `False` (reproduction proves reproducibility only)
- **grants_pass:** `False` (does NOT grant final Basebreak PASS)

---

## 1. Verified Four Auditable Provider Operations

### Builder trusted base
- **Builder clean-base checkpoint provider operation ID:**
  `01a105f1-1aae-775b-b376-8755687822a6`
- **Builder clean-base checkpoint image UUID:**
  `fd7328f0-210f-43fb-8758-0365de3d5baf`
- **Exact resolved source commit:** `b1c93ee1e00f3617d6d2d7c17fbf9a530eac3f72`
- **Exact resolved source tree:** `8dbb3d5f36b30b05c2e65036b95a3d759bba2025`

### Builder candidate
- **Builder disposable provider operation ID:** `01a105f1-2e96-7051-9600-8bbb55d2939d`
- **Builder result image UUID:** `None` (strictly None)
- **Builder correlation ID:** `sbx-1e5ecaafe0884b0f`

### Reproduction trusted base
- **Reproduction clean-base checkpoint provider operation ID:**
  `01a105f1-3a71-7757-9ac1-e6c293165017`
- **Reproduction clean-base checkpoint image UUID:**
  `93a119d7-fd65-4ee5-b8eb-0901531f03eb`
- **Exact resolved source commit:** `b1c93ee1e00f3617d6d2d7c17fbf9a530eac3f72`
- **Exact resolved source tree:** `8dbb3d5f36b30b05c2e65036b95a3d759bba2025`

### Reproduction candidate
- **Reproduction disposable provider operation ID:** `01a105f1-4b8b-72ed-8978-02817942c5c1`
- **Reproduction result image UUID:** `None` (strictly None)
- **Reproduction correlation ID:** `sbx-2c1f25803bb44e97`

---

## 2. Verified End-to-End P-07 Phase Exit Chain

The live run exercised the unbroken, genuine Basebreak authority and reproduction chain:

```
Authoritative FrozenContract (17f4bd49a4bb8ef4...)
  -> Minimized Builder Context (6f6b458234862de4...)
  -> Real Nemotron Model Call (nvidia/Nemotron-3_5-Lightning)
  -> Builder Clean Base Checkpoint (op=01a105f1-1aae-775b-b376-8755687822a6)
  -> Disposable Builder Sandbox (sbx-1e5ecaafe0884b0f)
  -> Real File Action & Bounded Command Execution in Sandbox VM
  -> P-07.05 Canonical Protected-Surface Enforcement
  -> P-07.04 Candidate State & Tree Capture (c61f4e4f0bfcdb82...)
  -> Disposable Builder Sandbox Disposed (result_image_uuid=None)
  -> Reproduction Clean Base Checkpoint (op=01a105f1-3a71-7757-9ac1-e6c293165017)
  -> NEW Disposable Repro Sandbox (sbx-2c1f25803bb44e97)
  -> Safe Transport & Application of Exact Captured Patch (git apply)
  -> Deterministic Staging & Tree Calculation (git write-tree)
  -> Exact Cryptographic Tree Hash Verification
  -> Disposable Reproduction Sandbox Disposed (result_image_uuid=None)
```

---

## 3. Deterministic Cryptographic Tree Equality & Runtime Evidence

| Entity | Hash / Identifier | Match / Policy Status |
|---|---|:---:|
| **Candidate Tree (Sandbox #1)** | `c61f4e4f0bfcdb82509243b39d84361782620588` | **EXACT MATCH** |
| **Reproduced Tree (Sandbox #2)** | `c61f4e4f0bfcdb82509243b39d84361782620588` | **EXACT MATCH** |
| **Builder Sandbox Identity** | `sbx-1e5ecaafe0884b0f` | Distinct |
| **Reproduction Sandbox Identity** | `sbx-2c1f25803bb44e97` | Distinct |
| **Builder Checkpoint** | `fd7328f0-210f-43fb-8758-0365de3d5baf` | Checkpoint #1 |
| **Repro Checkpoint** | `93a119d7-fd65-4ee5-b8eb-0901531f03eb` | Checkpoint #2 |
| **Builder Provider Op ID** | `01a105f1-2e96-7051-9600-8bbb55d2939d` | Provider Fact |
| **Builder Result Image UUID** | `None` | None (Disposable) |
| **Reproduction Provider Op ID** | `01a105f1-4b8b-72ed-8978-02817942c5c1` | Provider Fact |
| **Reproduction Result Image UUID** | `None` | None (Disposable) |

Exact tree equality confirms that:
`TRUSTED BASE + EXACT CAPTURED PATCH -> FRESH SANDBOX -> EXACT CANDIDATE TREE`
holds unconditionally in a real cloud container execution environment
without Builder workspace state inheritance.

---

## 4. Captured Unified Patch Content

```diff
diff --git a/tests/test_candidate_probe.py b/tests/test_candidate_probe.py
new file mode 100644
index 0000000000000000000000000000000000000000..73d00324a2afda702ed1152cdd4a5b8459e89d78
--- /dev/null
+++ b/tests/test_candidate_probe.py
@@ -0,0 +1,6 @@
+"""Probe test for candidate functionality."""
+
+
+def test_candidate_probe() -> None:
+    """Verify candidate probe is operational."""
+    assert True
```

---

## 5. Security, Billing & Provenance Verification

- **Sandbox Freshness:** Sandbox #1 (`sbx-1e5ecaafe0884b0f`) and Sandbox #2
  (`sbx-2c1f25803bb44e97`) are mechanically distinct cloud instances.
  Sandbox #1 was torn down before reproduction.
- **Independent Materialization:** Builder and Reproduction clean-base checkpoints were
  independently created by the internal source materializer bound to the authoritative envelope.
- **Protected Surface Policy:** Canonical P-04 manifest enforced across both execution
  and reproduction.
- **Zero-Cost Law:** Total inference consumed `2464` tokens; two disposable sandboxes
  executed within promotional ceilings (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`).
  Target personal spend: `$0.00`.
- **Zero Self-Certification:** `is_authoritative=False`, `is_causally_verified=False`,
  `grants_pass=False`.
- **Secret Safety Check:** PASS. 0 secrets present in durable evidence.
