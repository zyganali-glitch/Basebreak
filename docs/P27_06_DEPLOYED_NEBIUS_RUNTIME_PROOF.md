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
     - **`BASEBREAK_VERIFIER_SIGNING_KEY`** — the genuine trusted verifier signing
       authority. This is mandatory and is currently MISSING from deployment.
       Without it the bridge fails closed with `BLOCKED_MISSING_SIGNING_AUTHORITY`
       before any chargeable provider operation.
     - **`TRUSTED_VERIFIER_BRIDGE_STATE_DIR`** — a writable, persistent path used
       for atomic durable single-execution idempotency. Without durable protection
       the bridge fails closed with `BLOCKED_DURABLE_IDEMPOTENCY_UNAVAILABLE` rather
       than dispatch a second chargeable execution.
   - **Signer compatibility contract:** the configured private signing authority
     MUST correspond to the pinned canonical public verification authority
     (`PINNED_VERIFIER_MODULUS` / `PINNED_VERIFIER_EXPONENT`) that the public Worker
     independently verifies against. A signer that does not match fails closed with
     `BLOCKED_INCOMPATIBLE_SIGNING_AUTHORITY` before any provider call. The bridge
     never generates, prints, commits, exposes, or substitutes an ephemeral test
     signer in production. Creating/configuring the real signing secret is a
     separate operator-authorized step and is NOT performed by this batch.
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
   - binds the canonical ResetVault bridge request to the current frozen contract digest `93eeeb2cc7eb02a988da3c8a8543ad40b4816608c1452d048ff62ee93702f812`;
   - records ambiguous bridge/provider outcomes conservatively as failures / unknown cost.
2. **Durable Object ledger**
   - stores operator-bound grant facts (`verified_balance`, `balance_timestamp`, `estimated_cost_cap`);
   - preserves single-use atomic reservation, duplicate/idempotency control, and fail-closed uncertain-cost handling.
3. **Trusted Python verifier bridge**
   - authenticates Worker requests with HMAC over canonical JSON plus timestamp/audience;
   - enforces exact target and source-commit binding;
   - uses current official Nebius request semantics (`ai_project_id` for inference, `cwd` for sandbox spawn, `DELETE /operations/{operationId}` for cancellation);
   - derives the canonical ResetVault candidate patch and exact candidate tree digest from the actual source commit instead of trusting caller-supplied patch/tree claims;
   - records observed Nebius sandbox operation IDs and validates independent execution authority before any receipt proof is signed;
   - refuses to start if live execution is disabled, provider credentials are missing, or a trusted signer is unavailable;
   - refuses to sign executor-reported `LIVE_NEBIUS` receipts unless an independent live execution authority is configured.
4. **Receipt authority**
   - the Worker will only accept `LIVE_NEBIUS` after verifying both receipt integrity and a separate verifier-signed receipt proof;
   - fixture-only, self-hashed, forged, or unverifiable receipts remain rejected.

### 3.2.1 Offline Validation Executed In This Batch

- `python -m pytest tests\adapters\test_p05_02_closure.py tests\adapters\test_nebius_sandbox_adapter.py tests\adapters\test_nebius_model_client.py tests\deployment\test_live_bridge.py -q` → `106 passed`
- `python -m ruff format --check .` → pass
- `python -m ruff check .` → pass
- `python -m mypy src tests` → pass
- `npm --prefix .\cloudflare run test:node` → `32 passed`
- `npm --prefix .\cloudflare run typecheck` → pass
- `npm --prefix .\cloudflare run test:workerd-preflight` → `7/7` checks passed

> These are strictly `LOCAL_EXECUTION` results. No live Nebius/NVIDIA/Tavily API call, private bridge deployment, or Cloudflare production mutation was performed in this batch.

### 3.2.2 P-27.06 Live-Trust Surgical Repair (Independent-QA Defects A–E)

Independent QA identified five live-execution trust defects. This batch repairs them
without enabling live execution. All evidence below is `LOCAL_EXECUTION` only.

1. **DEFECT A — synthetic operations can no longer be certified.**
   The production proof-issuance boundary now requires *firsthand canonical provider
   grounding*. The bridge executor positively confirms that it used the canonical
   `NebiusSandboxAdapter` (via the real urllib transport on an HTTPS endpoint),
   `NebiusModelClient`, `CausalRepositoryMaterializer`, and `TrustedVerifierWorker`,
   with a signer bound to the pinned authority. Injected fake/mock/simulation
   dependencies downgrade provenance to `FIXTURE`. Even if `production_grounded` is
   attacker-asserted, the independent authority verifier re-verifies the embedded
   `VerifierExecutionAttestation` against the pinned canonical key and cross-binds it
   to the public receipt (sandbox IDs, outcomes, tree/source identity). Synthetic
   operation IDs and fabricated three-world receipts therefore fail closed.
2. **DEFECT B — estimated cost is never presented as observed cost.**
   `BridgeExecutionResult` now separates `approved_estimate_usd`,
   `reserved_exposure_usd`, `observed_cost_usd`, and `cost_provenance`. The bridge no
   longer sets `observed_cost_usd = max_estimated_cost_usd`; when genuine provider
   cost is unmeasured it reports `observed_cost_usd = null` and
   `cost_provenance = UNKNOWN`. `estimated_cost_cap` is documented as an operator
   admission bound, NOT a provider-enforced hard maximum. The Durable Object accounts
   successful-but-unknown-cost runs by shifting the reserved exposure into
   `unknown_cost` (never `observed_cost`, never zero), keeping spending authority closed.
3. **DEFECT C — replay and deadline enforcement.**
   The bridge enforces `issued_at_ms`/`deadline_ms` windows and rejects already-expired
   requests (HTTP 410 `EXPIRED_REQUEST`) before any inference or sandbox dispatch. It
   uses an atomic, durable, file-backed single-execution idempotency store keyed by
   `request_id`; replaying an accepted request returns the stored outcome without a
   second execution. Ambiguous dispatch is persisted as `AMBIGUOUS` and never
   automatically retried. When durable protection is unavailable the bridge fails
   closed (`BLOCKED_DURABLE_IDEMPOTENCY_UNAVAILABLE`).
4. **DEFECT D — production signer prerequisites.**
   `BASEBREAK_VERIFIER_SIGNING_KEY` and `TRUSTED_VERIFIER_BRIDGE_STATE_DIR` are now
   explicit deployment prerequisites. The bridge validates that the configured signer
   matches the pinned public verification authority and fails closed before any
   chargeable operation otherwise. No secret generation, printing, or fixture
   substitution occurs.
5. **DEFECT E — decorative inference is not AI patch generation.**
   The bounded `ResetVault` flow still derives its candidate patch deterministically;
   the Nebius inference call is a *runtime identity probe*, not candidate generation.
   The bridge marks `candidate_origin = DETERMINISTIC_BRIDGE_FIXTURE` in the result and
   runtime identities. It is therefore NOT claimed that the deployed model writes the
   candidate patch. Integrating genuine model-generated candidate content through the
   existing committed Builder candidate-generation contracts (`BuilderPlanCodeLoop` /
   `validate_candidate_proposal`) cannot be completed safely within this surgical
   no-live batch and remains a **documented blocker**; the deployed AI-written
   candidate-generation claim remains UNVERIFIED / NOT_RUN.

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
| Public Cloud Deployment (P-27.03) | `LOCAL_EXECUTION` | **Previously independently QA-verified public deployment, supported by `LOCAL_EXECUTION` observations against remotely hosted Cloudflare Workers; deployment remains unchanged in this offline repair batch** |
| Deployed Live Nebius Execution (P-27.06) | `LIVE_NEBIUS` | `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN` |

> **Provenance Note:** The P-27.03 public Cloudflare deployment must NOT be classified as `RECORDED_LIVE`. That provenance is strictly reserved for recorded genuine live execution evidence, not for HTTPS deployment observations. P-27.03 is described as previously independently QA-verified public deployment, supported by `LOCAL_EXECUTION` observations against remotely hosted Cloudflare Workers. P-27.06 `LIVE_NEBIUS` execution remains strictly `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`.

### Remaining hard blockers

- Current verified promotional balance and expiration: **UNVERIFIED**
- Provider-enforced hard spending stop / PAYG hard cap: **UNVERIFIED**
- Private trusted bridge deployment: **NOT DEPLOYED**
- Worker bridge URL/shared secret configuration: **NOT CONFIGURED ON PUBLIC DEPLOYMENT**
- Provider credentials on the private bridge: **NOT CONFIGURED**
- Trusted verifier signing authority (`BASEBREAK_VERIFIER_SIGNING_KEY`): **NOT CONFIGURED**
- Durable bridge idempotency state directory (`TRUSTED_VERIFIER_BRIDGE_STATE_DIR`): **NOT CONFIGURED**
- Genuine model-generated candidate patch (DEFECT E): **NOT INTEGRATED / UNVERIFIED** — candidate remains deterministic
- Public Worker `LIVE_ENABLED`: intentionally **false**

Phase P-27 cannot receive full `PASS` or `GO` while required live Nebius/NVIDIA causal execution remains NOT_RUN. Public Cloudflare deployment is complete and was previously independently QA-verified; required live Nebius/NVIDIA causal execution remains held at `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`.

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
