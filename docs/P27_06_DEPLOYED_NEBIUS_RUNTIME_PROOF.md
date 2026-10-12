# Deployed Nebius/NVIDIA Runtime Verification Specification (P-27.06)

> **STATUS:** `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`  
> **GOVERNANCE:** In compliance with the **Zero-Cost Law** and the **Bounded Billing Exception**, live cost-consuming inference and sandbox creation against the deployed endpoint remain strictly held until explicit operator credit authorization is granted. No mocks or synthetic simulations are substituted for live proof.

---

## 1. Objective

To provide a deterministic verification protocol proving that the deployed Basebreak application triggers genuine calls to the **Nebius Token Factory** using the eligible **NVIDIA open-source model** (`nvidia/Nemotron-3_5-Lightning`) inside isolated sandboxes, producing authentic `LIVE_NEBIUS` verification receipts.

---

## 2. Preflight Prerequisites (Operator Authority)

1. **Promotional Budget Inspection:**
   - Operator must inspect Nebius Token Factory promotional balance prior to live execution.
   - Requirement: Balance must exceed the mandatory safety reserve floor:
     $$\text{Balance} > \text{TOKEN\_FACTORY\_PROMO\_STOP\_THRESHOLD} = \$5.00$$
   - Target personal spend remains strictly **$0.00**.
2. **Environment Configuration:**
   - Deployed instance configured with operator secret `BASEBREAK_BEARER_TOKEN` (or `BASEBREAK_API_TOKEN`).
   - Instance supplied with valid `NEBIUS_API_KEY` and `NEBIUS_PROJECT_ID`.
3. **Exact-State Source Binding:**
   - The deployed runtime must report source SHA parity with canonical repository commit.
4. **Target Scenario:**
   - Canonical ResetVault bug fix (`tests/fixtures/reset_vault`) or pinned upstream pallets/click replay.

---

## 3. Current Runtime Reality & Protocol

### 3.1 Current Runtime Fail-Closed State
Under the current execution pipeline (`src/basebreak/cli/runner.py`):
- Any request with `allow_live=True` is stopped **fail-closed** under the Zero-Cost Law:
  ```json
  {
    "status": "BLOCKED",
    "exit_code": 2,
    "error_message": "Live execution unauthorized under Zero-Cost Law."
  }
  ```
- Because no valid public receipt is produced for a blocked run, requesting `"publish": true` with `allow_live=true` is rejected with **HTTP 422 Unprocessable Entity** (`UnpublishableRunError: missing public verification receipt`).
- Basebreak does NOT pretend `allow_live=True` currently emits live receipts in the absence of verified provider execution authority.

### 3.2 Post-Authorization Live Verification Protocol
When promotional credits are redeemed, balance verified $> \$5.00$, and operator authorization is granted:

```bash
curl -X POST "https://<deployed-url>/v1/runs" \
  -H "Authorization: Bearer <operator-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "tests/fixtures/reset_vault",
    "change_class": "BUG_FIX",
    "allow_live": true,
    "publish": true
  }'
```

### 3.3 Expected Canonical Receipt Schema (`PublicVerificationReceipt`):
1. **HTTP Status Code:** `201 Created`
2. **Canonical Public Receipt (`GET /v1/runs/{run_id}/receipt`):**
   - `schema_version`: `"1.0.0"`
   - `receipt_digest`: 64-character lowercase SHA-256 digest
   - `frozen_contract_digest`: 64-character lowercase SHA-256 digest
   - `task_id`: exact task identifier
   - `repo_locator`: target repository identifier
   - `source_commit_id`: exact 40-character commit SHA
   - `candidate_tree_digest`: 64-character hex digest
   - `candidate_patch_digest`: 64-character hex digest
   - `provenance`: strictly `"LIVE_NEBIUS"` (canonical allowed values: `FIXTURE`, `LOCAL_EXECUTION`, `LIVE_NEBIUS`, `RECORDED_LIVE`)
   - `executions`: tuple of `PublicExecutionFact` records:
     - `BASE`: `world: "BASE"`, `outcome: "FAIL"`, `exit_code: != 0`, real sandbox ID, stdout/stderr digests
     - `CANDIDATE`: `world: "CANDIDATE"`, `outcome: "PASS"`, `exit_code: 0`, real sandbox ID, stdout/stderr digests
   - `counterfactual`: `PublicCounterfactualFact`:
     - `is_required`: `true`
     - `delta_digest`: 64-character hex digest
     - `outcome`: `"FAIL"`
     - `execution_fact`: `PublicExecutionFact` with `world: "COUNTERFACTUAL"`, `outcome: "FAIL"`
   - `coverage_summary`: `CausalCoverageSummary`:
     - `overall_verdict`: `"VERIFIED"`
     - `is_fully_verified`: `true`
     - `per_requirement_facts`: tuple of `RequirementVerificationFact`
   - `accounting`: `PublicCostAccountingFact` (with `is_metered: true`, token counts, and cost)
3. **Cryptographic Integrity Verification:**
   - Client executes `verify_public_receipt_integrity(receipt)` which returns `True`.
4. **Public Signed-Out Inspection:**
   - Signed-out judge visits `https://<deployed-url>/judge/{run_id}`:
     - Header displays `LIVE_NEBIUS` badge with verified green status.
     - Telemetry displays verified token count, sandbox count, and metered cost.
     - Tamper-evident receipt digest matches published record.

---

## 4. Current Closure Status

| Verification Dimension | Required Provenance | Current Execution Status |
| :--- | :--- | :--- |
| Local Packaging & Health Check (P-27.02) | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Health / Source SHA Parity Path (P-27.04) | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Signed-Out Access Control (P-27.05) | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Public Cloud Deployment (P-27.03) | `LIVE_DEPLOYMENT` | `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN` |
| Deployed Live Nebius Execution (P-27.06) | `LIVE_NEBIUS` | `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN` |

Phase P-27 cannot receive full `PASS` or `GO` while deployment and live runtime remain unexecuted.
