# Deployed Nebius/NVIDIA Runtime Verification Specification (P-27.06)

> **STATUS:** `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`  
> **GOVERNANCE:** In compliance with the **Zero-Cost Law** and the **Bounded Billing Exception**, live cost-consuming inference and sandbox creation against the deployed endpoint remain strictly held until explicit operator credit authorization is granted. No mocks or synthetic simulations are substituted for live proof.

---

## 1. Objective

To provide an end-to-end deterministic verification procedure proving that the deployed Basebreak application triggers genuine calls to the **Nebius Token Factory** using the eligible **NVIDIA open-source model** (`nvidia/Nemotron-3_5-Lightning`) inside isolated sandboxes, producing authentic `LIVE_NEBIUS` verification receipts.

---

## 2. Preflight Prerequisites (Operator Authority)

1. **Promotional Budget Inspection:**
   - Operator must inspect Nebius Token Factory promotional balance prior to execution.
   - Requirement: Balance must exceed the mandatory safety reserve floor:
     $$\text{Balance} > \text{TOKEN\_FACTORY\_PROMO\_STOP\_THRESHOLD} = \$5.00$$
   - Target personal spend remains strictly **$0.00**.
2. **Environment Configuration:**
   - Deployed instance configured with operator secret `BASEBREAK_BEARER_TOKEN`.
   - Instance supplied with valid `NEBIUS_API_KEY` and `NEBIUS_PROJECT_ID`.
3. **Target Scenario:**
   - Canonical ResetVault bug fix (`tests/fixtures/reset_vault`) or pinned upstream pallets/click replay.

---

## 3. Deterministic Verification Protocol

When authorized by operator, execute the following request against the deployed instance:

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

### Expected Deterministic Responses & Artifacts:
1. **HTTP Status Code:** `201 Created`
2. **Emitted Public Receipt (`GET /v1/runs/{run_id}/receipt`):**
   - `provenance`: `"LIVE_NEBIUS"`
   - `model_id`: `"nvidia/Nemotron-3_5-Lightning"`
   - `three_world_outcomes`:
     - Base: `FAIL` (exit code $\neq 0$)
     - Candidate: `PASS` (exit code $0$)
     - Counterfactual: `FAIL` (exit code $\neq 0$)
   - `causal_transition`: `"BUG_FIX_VERIFIED"`
   - `receipt_digest`: 64-character lowercase SHA-256 digest
3. **Cryptographic Integrity Verification:**
   - Client executes `verify_public_receipt_integrity(receipt)` which must return `True`.
4. **Public Signed-Out Inspection:**
   - An unauthenticated client visits `https://<deployed-url>/judge/{run_id}` and successfully renders the single-screen dashboard with authentic `LIVE_NEBIUS` badge.

---

## 4. Current Closure Status

| Verification Dimension | Required Provenance | Current Execution Status |
| :--- | :--- | :--- |
| Local Packaging & Health Check | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Signed-Out Access Control | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Public Cloud Deployment (P-27.03) | `LIVE_DEPLOYMENT` | `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN` |
| Deployed Live Nebius Execution (P-27.06) | `LIVE_NEBIUS` | `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN` |

Phase P-27 cannot receive full `PASS` or `GO` while deployment and live runtime remain unexecuted.
