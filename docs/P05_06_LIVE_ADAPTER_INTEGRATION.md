# P-05.06 — Live Adapter Integration Suite Report

- **Date / Time (UTC):** 2026-10-15T09:20:18.567074+00:00 to 2026-10-15T09:20:29.943526+00:00
- **Exact Active Task:** `P-05.06 — Execute live adapter integration suite`
- **Execution Status:** EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE
- **Evidence Provenance:** `LIVE_NEBIUS`
- **Tested Candidate Canonical Commit SHA:** `bee7a22e77195e21ba5bc6341a72caed6ef675d9`
- **Tested Candidate Canonical Tree SHA:** `63e522e074ad0ca3c1a12f042af56c907c5dca89`
- **Tested Model Identity:** `nvidia/Nemotron-3_5-Lightning`
- **Tested Sandbox Image:** `tag:astral/uv:python3.11-alpine`
- **Token Factory Project ID:** `aiproject-e00mae0nmzkxjswr1k`

---

## 1. Executive Summary & Required Live Chain

Basebreak P-05 adapter implementation was executed against real Nebius Token Factory production
services, establishing the complete unbroken live chain:

```
real Nemotron model call
  → real Token Factory Sandbox
  → exact canonical Basebreak repo materialization
  → deterministic source/hash verification
  → real command execution
  → live telemetry normalization
  → lifecycle/teardown observation
  → secret-safe durable evidence
```

Zero mock, zero fixture, zero local substitution.
No silent fallback.

---

## 2. Step 1: Real Nemotron Model Call Facts

- **Configured Model Identifier:** `nvidia/Nemotron-3_5-Lightning`
- **Provider Returned Model Identifier:** `nvidia/Nemotron-3_5-Lightning`
- **Prompt:** `Basebreak live adapter connectivity check. Return only BASEBREAK_LIVE_OK.`
- **Returned Output Snippet:** `Here's a thinking process:

1.  **Analyze User Input:**
   - User says: "Basebreak live adapter conn`
- **Prompt Tokens:** `33`
- **Completion Tokens:** `32`
- **Total Consumed Tokens:** `65`
- **Duration:** `0.892s`
- **Request ID:** `chatcmpl-5a0803b9`
- **Model Telemetry Digest:** `bdc8824d51b596f8e62c5d9c8a367517218b1d36e9b3294136a78ec64cccaaa7`
- **Telemetry Provenance:** `LIVE_NEBIUS`
- **is_authoritative:** `False` (zero causal verdict authority)

---

## 3. Step 2 & 3: Live Sandbox & Canonical Repository Materialization

- **Sandbox Image:** `tag:astral/uv:python3.11-alpine`
- **Target Repository:** `https://github.com/zyganali-glitch/Basebreak.git`
- **Materialization Workspace:** `/workspace/Basebreak`
- **Operation UUID:** `01a13edc-c560-76b7-9492-d09b82f79546`
- **Result Image UUID (Snapshot Layer):** `c26253c2-173f-4033-97a5-3eba0ebbb67f`
- **Materialization Duration:** `3.322s`
- **Workspace Cleanliness Verified:** `True` (absent prior to clone)
- **Source Verification Status:** `True`

### Deterministic Cryptographic Hash Verification

| Metric | Requested Truth | Live Sandbox Resolved Fact | Match? |
|---|---|---|:---:|
| **Commit SHA (`HEAD`)** | `bee7a22e77195e21ba5bc6341a72caed6ef675d9` | `bee7a22e77195e21ba5bc6341a72caed6ef675d9` | **EXACT MATCH** |
| **Tree SHA (`write-tree`)** | `63e522e074ad0ca3c1a12f042af56c907c5dca89` | `63e522e074ad0ca3c1a12f042af56c907c5dca89` | **EXACT MATCH** |

The git tree hash and commit hash resolved directly inside the container VM match the
canonical candidate repository state down to the exact bit.

---

## 4. Step 4: Real Command Execution Inside Materialized Repo

- **Executed Command:** `python3 -m pytest tests/test_bootstrap.py`
- **Execution Operation UUID:** `01a13edc-d9cd-755b-b520-a503ff214399`
- **Process Exit Code:** `0`
- **Duration:** `2.405s`

### Captured Stdout:
```
============================= test session starts ==============================
platform linux -- Python 3.11.14, pytest-9.1.1, pluggy-1.6.0
rootdir: /workspace/Basebreak
configfile: pyproject.toml
collected 3 items

tests/test_bootstrap.py ...                                              [100%]

============================== 3 passed in 0.02s ===============================
```

### Captured Stderr:
```
(empty)
```

---

## 5. Step 5: Live Telemetry Normalization

- **Sandbox Telemetry Digest:** `a222aba2ec2b90226a73a45529ce382ec0d236484ad74936f9a2940bc2132a6b`
- **Sandbox Provenance:** `LIVE_NEBIUS`
- **is_authoritative:** `False`
- **Secret Safety Findings:** `None (0 findings)`

---

## 6. Step 6: Lifecycle & Teardown Observation

- **Handle Final Lifecycle State:** `DISPOSED`
- **Disposed:** `True`
- **Post-Disposal Contract:** Subsequent execution on disposed handle fails closed.

---

## 7. Cost & Zero-Cost Policy Verification

- **Token Factory Pricing Policy:** Sandboxes remain free while in beta.
- **Model Consumed Tokens:** `65` tokens.
- **Promotional Balance Floor:** Pre-execution and post-execution promotional balance satisfied
  safety threshold (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`).
- **Target Personal Spend:** Strictly `$0.00`.
