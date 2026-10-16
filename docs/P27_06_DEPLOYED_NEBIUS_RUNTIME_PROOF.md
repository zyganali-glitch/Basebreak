# Deployed Nebius/NVIDIA Runtime Verification Specification (P-27.06)

> **STATUS:** `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`  
> **GOVERNANCE:** In compliance with the **Zero-Cost Law** and the **Bounded Billing Exception**, live cost-consuming inference and sandbox creation against the deployed endpoint remain strictly held until explicit operator credit authorization is granted. No mocks or synthetic simulations are substituted for live proof.

---

## 1. Objective

To provide a deterministic verification protocol proving that the deployed Basebreak application triggers genuine calls to the **Nebius Token Factory** using the eligible **NVIDIA open-source model** (`nvidia/Nemotron-3_5-Lightning`) inside isolated sandboxes, producing authentic `LIVE_NEBIUS` verification receipts.

---

## 2. Preflight Prerequisites (Operator Authority)

1. **Promotional Budget Inspection:**
   - Current verified promotional balance and promotional-credit expiration are **UNVERIFIED** in this offline batch.
   - Requirement before any live call:
     $$\text{Balance} > \text{TOKEN\_FACTORY\_PROMO\_STOP\_THRESHOLD} = \$5.00$$
   - Target personal spend remains strictly **$0.00**.
   - A provider-enforced hard spending stop was **NOT independently verified** from current official Nebius documentation; zero-personal-spend safety therefore remains blocked until the operator confirms current billing behavior on the real account.
2. **Current Official Provider Facts (Verified from Nebius docs during this batch):**
   - Inference base URL: `https://api.tokenfactory.nebius.com/v1/`
   - Auth: `Authorization: Bearer <NEBIUS_API_KEY>`
   - Model discovery: `GET /v1/models` with documented query parameter `ai_project_id` (older `project_id` wording is stale)
   - Sandboxes base URL: `https://api.tokenfactory.nebius.com/sandboxes/v1`
   - Sandbox auth: `Authorization: Bearer ...` plus `Project: <project-id>` header
   - Sandbox create: `POST /instances`
   - Operation polling / result collection: `GET /operations/{operationId}?inflight=1`
   - Cancellation: `DELETE /operations/{operationId}`
   - Effective account limits/timeouts must still be read from authenticated `whoami`; they cannot be guessed from static docs.
3. **Environment Configuration:**
   - Public Cloudflare Worker must continue to expose only operator-controlled live settings:
     - `EXPECTED_SOURCE_COMMIT`
     - `LIVE_RUN_ESTIMATED_COST_USD`
     - `TRUSTED_VERIFIER_BRIDGE_URL`
     - `TRUSTED_VERIFIER_BRIDGE_SHARED_SECRET`
     - optional `TRUSTED_VERIFIER_BRIDGE_AUDIENCE`
   - Private Python bridge must be configured separately with:
     - `TRUSTED_VERIFIER_BRIDGE_SHARED_SECRET`
     - `EXPECTED_SOURCE_COMMIT`
     - `ALLOWLISTED_TARGET`
     - `BASEBREAK_LIVE_EXECUTION_ENABLED=true`
     - `NEBIUS_API_KEY`
     - `NEBIUS_PROJECT_ID`
   - Basebreak's `NEBIUS_PROJECT_ID` is the internal configuration name; when calling current official APIs it maps to `ai_project_id` for model discovery and to the `Project` header for Sandboxes.
4. **Exact-State Source Binding:**
   - The deployed runtime must report source SHA parity with canonical repository commit.
   - The Worker must never accept caller-supplied `source_commit_id` as authority.
5. **Operator-Bound Grant Facts:**
   - Single-use grants may now bind `verified_balance`, `balance_timestamp`, and `estimated_cost_cap`.
   - Callers may **not** supply or override those values in `POST /v1/runs`.
6. **Target Scenario:**
   - First live proof target remains canonical ResetVault (`tests/fixtures/reset_vault`).

---

## 3. Current Runtime Reality & Protocol

### 3.1 Current Deployed Public Worker Truth

The current deployed worker at `https://basebreak.zyganali.workers.dev` remains intentionally read-only and fail-closed:

- `/health` currently reports:
  - `source_commit_id = 22652c5ff2b0fc76350008901cc671ae052f62c8`
  - `source_commit_status = CONFIGURED_UNVERIFIED`
  - `deployment_readiness = NOT_READY_FOR_DEPLOYMENT`
  - `live_enabled = false`
  - `total_runs = 0`
- The public root page explicitly states that public live execution is disabled and that no provider call or causal verdict is issued from that page.
- No Cloudflare deployment mutation, no provider secret configuration, and no Nebius/NVIDIA/Tavily paid call were performed in this offline readiness batch.

### 3.2 Implemented Offline Trusted-Bridge Contract

The bounded P-27.06 offline batch now implements the minimum deployable trust boundary without claiming live proof:

1. **Cloudflare Worker admission path**
   - rejects caller-controlled authority fields (`verified_balance`, `balance_timestamp`, `estimated_cost`, `source_commit_id`, receipt/proof/provider authority fields);
   - binds live admission to server-configured expected source SHA plus server-configured estimated live cost;
   - records ambiguous bridge/provider outcomes conservatively as failures / unknown cost.
2. **Durable Object ledger**
   - stores operator-bound grant facts (`verified_balance`, `balance_timestamp`, `estimated_cost_cap`);
   - preserves single-use atomic reservation, duplicate/idempotency control, and fail-closed uncertain-cost handling.
3. **Trusted Python verifier bridge**
   - authenticates Worker requests with HMAC over canonical JSON plus timestamp/audience;
   - enforces exact target and source-commit binding;
   - refuses to start if live execution is disabled, provider credentials are missing, or a trusted signer is unavailable.
4. **Receipt authority**
   - the Worker will only accept `LIVE_NEBIUS` after verifying both receipt integrity and a separate verifier-signed receipt proof;
   - fixture-only, self-hashed, forged, or unverifiable receipts remain rejected.

### 3.3 Post-Authorization Live Verification Protocol

When promotional credits are redeemed, balance verified `> $5.00`, the private bridge is deployed, and operator authorization is granted:

1. **Step 1: Operator issues a single-use grant bound to current preflight facts**
```bash
curl -X POST "https://<deployed-url>/admin/grants" \
  -H "Authorization: ******" \
  -H "Content-Type: application/json" \
  -d '{
    "ttl_seconds": 3600,
    "client_info": "p27_proof",
    "verified_balance": 15.00,
    "balance_timestamp": 1792100000000,
    "estimated_cost_cap": 0.50
  }'
```

2. **Step 2: Trigger genuine remote execution via admitted endpoint**
```bash
curl -X POST "https://<deployed-url>/v1/runs" \
  -H "X-Judge-Grant: <grant_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "tests/fixtures/reset_vault",
    "change_class": "BUG_FIX",
    "allow_live": true
  }'
```

3. **Step 3: Private bridge performs the real provider work**
   - authenticates the Worker request;
   - performs genuine Token Factory / Sandboxes execution using operator-held credentials;
   - obtains authentic BASE, CANDIDATE, and COUNTERFACTUAL execution facts;
   - signs a receipt proof with the trusted verifier authority;
   - returns the receipt plus proof to the Worker.

### 3.4 Required Receipt and Proof Outputs

1. **HTTP Status Code:** `201 Created`
2. **Canonical public receipt (`GET /v1/runs/{run_id}/receipt`):**
   - `schema_version`: `"1.0.0"`
   - `receipt_digest`: 64-character lowercase SHA-256 digest
   - `frozen_contract_digest`: 64-character lowercase SHA-256 digest
   - `task_id`: exact task identifier
   - `repo_locator`: target repository identifier
   - `source_commit_id`: exact 40-character commit SHA
   - `candidate_tree_digest`: 64-character hex digest
   - `candidate_patch_digest`: 64-character hex digest
   - `provenance`: strictly `"LIVE_NEBIUS"`
   - `executions`: real `BASE` and `CANDIDATE` execution facts with sandbox identity and stdout/stderr digests
   - `counterfactual.execution_fact`: real `COUNTERFACTUAL` execution fact when required
   - `coverage_summary.overall_verdict`: `"VERIFIED"`
   - `accounting`: metered token / cost facts
3. **Separate verifier-signed proof (`receipt_proof`):**
   - must bind `receipt_digest`, `source_commit_id`, `candidate_tree_digest`, verdict, provenance, and normalized execution facts;
   - must verify against the trusted verifier public key;
   - must fail closed on any digest, signature, source, or execution-fact mismatch.
4. **Public signed-out inspection:**
   - signed-out judge visits `https://<deployed-url>/judge/{run_id}`;
   - UI displays `LIVE_NEBIUS` only after the Worker has accepted the signed proof and persisted the authenticated receipt.

---

## 4. Current Closure Status

| Verification Dimension | Required Provenance | Current Execution Status |
| :--- | :--- | :--- |
| Local Packaging & Health Check (P-27.02) | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Health / Source SHA Parity Path (P-27.04) | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Signed-Out Access Control (P-27.05) | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Public Cloud Deployment (P-27.03) | `LIVE_DEPLOYMENT` | `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN` |
| Deployed Live Nebius Execution (P-27.06) | `LIVE_NEBIUS` | `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN` |

### Remaining hard blockers

- Current verified promotional balance and expiration: **UNVERIFIED**
- Provider-enforced hard spending stop / PAYG hard cap: **UNVERIFIED**
- Private trusted bridge deployment: **NOT DEPLOYED**
- Worker bridge URL/shared secret configuration: **NOT CONFIGURED ON PUBLIC DEPLOYMENT**
- Provider credentials on the private bridge: **NOT CONFIGURED**
- Public Worker `LIVE_ENABLED`: intentionally **false**

Phase P-27 cannot receive full `PASS` or `GO` while deployment and live runtime remain unexecuted.

---

## 5. Türkçe Operatör Ön Uçuş Özeti

- **Doğrulanmış promo bakiye / bitiş tarihi:** **UNVERIFIED**. Bu offline partide gerçek Nebius hesap bakiyesi veya kredi son kullanma tarihi doğrulanmadı.
- **Sağlayıcı tarafından zorlanan kesin harcama limiti:** **UNVERIFIED**. Mevcut resmi dokümanlardan Nebius tarafında kişisel harcamayı kesin olarak durduran bir hard cap bağımsız doğrulanmadı.
- **Tek sınırlı canlı denemenin azami maliyet / süre maruziyeti:** Amaçlanan akış tek kabul edilmiş istek + en fazla bir gerçek doğrulama partisi (BASE / CANDIDATE / COUNTERFACTUAL). Worker tarafında tek eşzamanlı çalışma ve `estimated_cost_cap` var; ancak gerçek USD üst sınırı ve sağlayıcı tarafı kesin timeout davranışı canlı hesap + gerçek executor olmadan **UNVERIFIED**. Bu yüzden canlı çalışma şu an **BLOCKED**.
- **Gerekli servisler:** Nebius Token Factory inference API, Nebius Sandboxes API, özel Python trusted bridge servisi ve mevcut Cloudflare Worker.
- **Mevcut promo krediler bu servisleri karşılıyor mu?:** **UNVERIFIED**. Operatör gerçek panelden bakiye + son kullanma tarihini görmeden “evet” denemez.
- **Operatörün yapması gerekenler:** (1) Token Factory panelinden güncel promo bakiyeyi ve son kullanma tarihini kontrol et, (2) PAYG / kart sonrası otomatik ücret riskini doğrula, (3) özel bridge ortamına `NEBIUS_API_KEY` ve `NEBIUS_PROJECT_ID` sırlarını gir, (4) Cloudflare tarafına bridge URL/shared secret ve beklenen source SHA değerlerini koy, (5) tek kullanımlık grant üretirken `verified_balance`, `balance_timestamp`, `estimated_cost_cap` değerlerini bağla, (6) açık canlı denemeden önce ayrı yetki ver.
- **İlk gerçek denemede ne test edilecek?:** `tests/fixtures/reset_vault` için tek bir uçtan uca canlı koşu: gerçek Nebius/NVIDIA inference + gerçek izole Python doğrulayıcı + gerçek BASE=FAIL / CANDIDATE=PASS / COUNTERFACTUAL=FAIL sonucu + imzalı `LIVE_NEBIUS` receipt proof.

> **Sonuç:** Sıfır kişisel harcama güvenliği bugün için kanıtlanmış değil; bu nedenle canlı geçiş **BLOCKED** kalmalıdır.
