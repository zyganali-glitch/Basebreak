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
       authority. This is mandatory. A production key now exists and is held only in root-protected storage on the Oracle host, loaded into the isolated bridge via a systemd credential (see §3.5); it remains unconfigured on the public Worker live path.
       Without it the bridge fails closed with `BLOCKED_MISSING_SIGNING_AUTHORITY`
       before any chargeable provider operation.
     - **`TRUSTED_VERIFIER_BRIDGE_STATE_DIR`** — a writable, persistent path used
       for atomic durable single-execution idempotency. It is a hard prerequisite:
       the bridge never silently substitutes ephemeral `tempfile` storage. Without a
       configured durable directory the bridge fails closed with
       `BLOCKED_DURABLE_IDEMPOTENCY_UNAVAILABLE` rather than dispatch a chargeable
       execution. Durability scope is a single host with a persistent volume;
       cross-host durability is NOT claimed.
   - **Signer compatibility contract:** the configured private signing authority
     MUST correspond to the pinned canonical public verification authority
     (`PINNED_VERIFIER_MODULUS` / `PINNED_VERIFIER_EXPONENT`) that the public Worker
     independently verifies against. Matching public parameters is insufficient: the
     bridge performs a deterministic local challenge-signature round trip to prove the
     private exponent is compatible. A signer that does not match fails closed with
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

### 3.2.3 P-27.06 Final Pre-Live Safety Repair (Defects A–D + incident safeguard)

A second pre-live safety repair hardened four remaining trust defects and added a
live-test opt-in safeguard. All evidence is `LOCAL_EXECUTION` only; no live provider
call, secret creation, or deployment mutation was performed.

1. **DEFECT A — durable idempotency is never silently ephemeral.** The trusted bridge
   no longer falls back to `tempfile.mkdtemp()` when `TRUSTED_VERIFIER_BRIDGE_STATE_DIR`
   is missing. A production-shaped bridge with no configured durable state directory
   fails closed with `BLOCKED_DURABLE_IDEMPOTENCY_UNAVAILABLE` before any chargeable
   execution. Ephemeral state is permitted only behind an explicit, fixture-test-only
   flag. Durability scope is documented as **single-host with a persistent volume**;
   cross-host durability is explicitly NOT claimed.
2. **DEFECT B — the signer is cryptographically proven, not just structurally matched.**
   The bridge performs a deterministic local challenge-signature round trip against the
   pinned production public authority. A signer with the correct public modulus/exponent
   but an incompatible private exponent is now rejected with
   `BLOCKED_INCOMPATIBLE_SIGNING_AUTHORITY` before any provider dispatch. No production
   signing key is generated or exposed.
3. **DEFECT C — unknown provider cost is never released on failure.** The dispatch path
   now tracks whether a chargeable provider operation may have started. When consumption
   is unknown after dispatch, the Durable Object retains the reserved exposure as
   `unknown_cost` (status `FAILED_UNRECONCILED_COST`) even for deterministic failures,
   and subsequent live admission is held with `BLOCKED_UNRECONCILED_UNKNOWN_COST` until
   an explicit, evidence-backed operator reconciliation
   (`POST /admin/reconcile-unknown-cost`) clears it. `FAILED`, missing receipt,
   and missing usage are never inferred as zero cost. (The reconciliation evidence
   contract was subsequently hardened — see §3.2.4 DEFECT 2.)
4. **DEFECT D — canonical provider identity and transport are positively verified.**
   Production `LIVE_NEBIUS` grounding now requires the canonical live urllib transport
   for the inference client AND the canonical Token Factory inference/sandbox endpoint
   identities (`https://api.tokenfactory.nebius.com/v1` and
   `https://api.tokenfactory.nebius.com/sandboxes/v1`). Injected fake model transports
   and arbitrary HTTPS hosts are downgraded to `FIXTURE`.
5. **INCIDENT SAFEGUARD — live tests cannot run by default.** A prior validation run
   executed `@pytest.mark.live` tests while provider credentials were present. A global
   `tests/conftest.py` now skips every live-marked test unless the operator explicitly
   sets `BASEBREAK_ALLOW_LIVE_TESTS=1`. Offline validation cannot inherit live
   credentials, issue provider calls, or rewrite historical proof documents.

| Verification Dimension | Required Provenance | Current Execution Status |
| :--- | :--- | :--- |
| Durable idempotency / restart replay (Defect A) | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Signer challenge-signature compatibility (Defect B) | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Unknown-cost hold + operator reconciliation (Defect C) | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Canonical provider identity/transport grounding (Defect D) | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Live-test opt-in safeguard (incident) | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Deployed Live Nebius Execution (P-27.06) | `LIVE_NEBIUS` | `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN` |

> The incident observation is recorded as `UNKNOWN`, not "no live calls": deterministic
> artifacts (`.pytest_cache` lastfailed entries and rewritten live proof docs) establish
> that live-marked tests were collected and at least four executed, but whether real
> provider network operations occurred cannot be established from the available
> artifacts.

### 3.2.4 P-27.06 Final Deployment-Gate Repair (Defects 1–2)

A two-defect surgical repair closed the last pre-live gaps between the deployed Worker,
the durable Durable Object authorization state, and the cost-hold reconciliation path.
All evidence is `LOCAL_EXECUTION` only.

1. **DEFECT 1 — persistent Durable Object config no longer blocks or silently follows a
   deployment transition.**
   - The durable live gate is **never seeded from the runtime environment**. A new Worker
     deployment that supplies `LIVE_ENABLED=true` does NOT enable the durable operator
     gate; it always starts disabled.
   - Pre-existing durable `EXPECTED_SOURCE_COMMIT` values are never overwritten by a
     newer deployment. A deployment whose runtime commit differs from the durable commit
     fails closed with `INVALID_SOURCE`; the two are never silently reconciled.
   - The only post-initialization writers are the explicit, admin-authenticated operator
     actions: `POST /admin/configure-source-commit` (align the durable expected source
     commit with the independently verified deployed commit) and
     `POST /admin/configure-live-gate` (change the durable operator gate). Both are
     validated, audited (`SOURCE_COMMIT_CONFIGURED` / `DURABLE_LIVE_GATE_CONFIGURED`),
     and never touch run/accounting/history state.
   - Admission still requires BOTH the durable operator gate AND the runtime live
     authorization.
   - Preflight inspection now reports the gates separately and the source consistency:
     `/health` and `/admin/ledger` expose `runtime_live_enabled`, `durable_live_enabled`,
     the effective `live_enabled` (their conjunction), `durable_expected_source_commit`,
     `runtime_expected_source_commit`, and `source_commit_consistent`.
   - Adversarial test: an existing Durable Object initialized with `LIVE_ENABLED=false`
     and an older source SHA, then a newer Worker deployment supplying `LIVE_ENABLED=true`
     and a newer SHA → no implicit authorization (`BLOCKED`), no stale-source admission
     (`INVALID_SOURCE`), and correct behavior only after explicit operator configuration.
2. **DEFECT 2 — unverified reconciliation can no longer clear the cost hold.**
   - `POST /admin/reconcile-unknown-cost` now requires a complete, auditable record:
     `operator_decision` (`NO_PROVIDER_CHARGE` | `PROVIDER_CHARGE_OBSERVED`),
     `provider_billing_observation`, `evidence_reference`, `observed_cost_usd`,
     `verification_timestamp`, and `reconciled_by`.
   - Empty/malformed evidence is rejected and the hold is preserved
     (`hold_preserved: true`). Contradictory amounts are rejected
     (e.g. `NO_PROVIDER_CHARGE` with non-zero cost, or attested cost exceeding the
     released exposure).
   - Attestation honesty: only `OPERATOR_ATTESTED` records are accepted. `PROVIDER_VERIFIED`
     is rejected while no independent provider verifier is configured; the response always
     reports `provider_verification_claimed: false`. An operator billing observation is
     never represented as independently verified provider fact.
   - Reconciliation releases held unknown exposure only. It never records or fabricates
     provider-observed metered cost and never silently converts unknown cost into zero
     measured spend. Each accepted record is persisted in a dedicated `reconciliations`
     table and the audit log.
   - Focused tests prove that a bare admin request or arbitrary free-text note cannot
     silently clear the hold.

| Verification Dimension | Required Provenance | Current Execution Status |
| :--- | :--- | :--- |
| Durable gate / deployment-transition safety (Defect 1) | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Explicit operator source/gate configuration (Defect 1) | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Evidence-required cost-hold reconciliation (Defect 2) | `LOCAL_EXECUTION` | **VERIFIED / PASS** |
| Deployed Live Nebius Execution (P-27.06) | `LIVE_NEBIUS` | `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN` |

### 3.2.5 P-27.06 Authorized One-Time Cost-Hold Exception (implemented + deployed; live run BLOCKED)

Under explicit operator authorization (one bounded live run), the smallest possible
exception to the unreconciled `unknown_cost > 0` admission hold was implemented, tested,
and deployed. It is an explicit, auditable, single-use operator control — **not** a bypass
flag, ledger reset, or permanent override.

- `AdmissionLedgerDO.authorizeCostHoldException()` is reachable only through the
  admin-authenticated `POST /admin/cost-hold-exception`. It issues exactly ONE single-use
  exception bound to exactly one existing, unexpired, unconsumed **single-use** grant.
- It requires an explicit operator identity and reason (audited as
  `COST_HOLD_EXCEPTION_AUTHORIZED`), the grant's operator-bound `estimated_cost_cap`, and
  an operator-verified promotional balance. It is refused when no unknown-cost hold exists.
- The promotional-budget calculation includes **BOTH** the historical unknown exposure
  **AND** the new maximum estimated run exposure, while preserving the `$5.00` safety
  reserve (`verified_balance − unknown_cost − estimated_cost_cap ≥ reserve_floor`).
- `reserveAdmission()` consumes the exception atomically together with the reservation
  (audited as `COST_HOLD_EXCEPTION_CONSUMED`, `consumed_run_id` bound); the historical
  unknown exposure is **retained** (never cleared, reconciled, or reset); the general hold
  continues to block every ordinary grant; duplicate, concurrent, replayed, or unauthorized
  attempts are rejected; at most one exception may be active at a time and at most one may
  ever be issued per grant token.
- Receipt, sandbox, and verifier authority are untouched by this control.

`LOCAL_EXECUTION` evidence:

- `npm --prefix .\cloudflare run test:node` → **57 passed** (adds focused ledger tests 21–23
  and a Worker admin-route test for the exception, including replay/duplicate/unauthorized
  and reserve-floor rejection).
- `npm --prefix .\cloudflare run typecheck` → pass.
- `npm --prefix .\cloudflare run test:workerd-preflight` → **7/7** checks passed.
- `python -m ruff format --check .`, `python -m ruff check .`, `python -m mypy src tests` → pass.
- `python -m pytest tests\deployment tests\adapters\test_nebius_model_client.py -q` → **143 passed**.

Deployment: the updated Worker was deployed with `wrangler deploy` as version
`ff33667f-9cbf-4461-b292-29bca37cc141`. Post-deploy `https://basebreak.zyganali.workers.dev/health`
still reports `live_enabled=false`, `durable_live_enabled=false`, `runtime_live_enabled=false`,
`durable_expected_source_commit=80b43b84014fa61b941c7ebcd87836a56dcd7c92`; the new admin
route returns `401` without operator auth; `/judge` returns `200`. The runtime live gate was
intentionally **not** enabled.

**Live run status: BLOCKED.** The genuine deployed live run could not be executed from the
agent environment because the required external prerequisites are unavailable:

- The operator's Cloudflare `BASEBREAK_ADMIN_KEY` is not available to the executing agent.
  Consequently the durable operator gate could not be enabled, no operator grant could be
  issued, and the one-time exception could not be authorized (every admin route returns
  `401`). Admission requires the durable gate + runtime authorization + an operator grant.
- The private trusted Python verifier bridge runs only on the Oracle Free-tier host and is
  reachable only over the private tailnet / Workers VPC. The agent has no host access (no
  Tailscale/SSH path), and the bridge is documented with no Nebius credentials and
  `BASEBREAK_LIVE_EXECUTION_ENABLED=false`.
- No genuine Nebius/NVIDIA inference or sandbox call was executed, no BASE/CANDIDATE/
  COUNTERFACTUAL execution was produced, and no signed receipt/proof exists. The `$0.50`
  historical unknown exposure is retained unchanged.

Deployed `LIVE_NEBIUS` runtime proof therefore remains `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`.

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
| Deployed Live Nebius Execution (P-27.06) | `LIVE_NEBIUS` | **Tenth authorized run COMPLETED & VERIFIED (2026-10-22, `run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9`): genuine Nemotron inference (chatcmpl-f5c5e28a, 1123 prompt / 693 completion tokens) + real Nebius sandbox three-world execution (11 operations across 3 worlds): BASE=FAIL (exit 1), CANDIDATE=PASS (exit 0), COUNTERFACTUAL=FAIL (exit 1). VERIFIED causal triplet achieved, bridge-COMPLETED signed LIVE_NEBIUS receipt ACCEPTED, PERSISTED and PUBLISHED by the Worker, verified independently in Python and Node with RSA proof validated against pinned authority. Public signed-out judge access verified. Mandatory shutdown verified: all 3 gates OFF. P-27.06 CLOSURE ACHIEVED.** |

> **Provenance Note:** The P-27.03 public Cloudflare deployment must NOT be classified as `RECORDED_LIVE`. That provenance is strictly reserved for recorded genuine live execution evidence, not for HTTPS deployment observations. P-27.03 is described as previously independently QA-verified public deployment, supported by `LOCAL_EXECUTION` observations against remotely hosted Cloudflare Workers. P-27.06 is classified as `LIVE_NEBIUS` (VERIFIED / PASS) based on the tenth authorized live run (`run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9`), which achieved a verified live causal triplet and published an accepted signed receipt.

### 3.5 Oracle SHA-aligned signing readiness (`LOCAL_EXECUTION`)

A production verifier signing authority now exists and is pinned consistently in
`src/basebreak/verifier/trust_bridge.py` and `cloudflare/src/provider_dispatcher.js`
(rotation commit `20428deb024bd795696133358f9874e44f337edb`): a new 2048-bit RSA
public modulus (SHA-256 `a13605cbf0b074300f56ee1cca01d53ef8bd9b7b998dca7c864502399a3917b2`,
exponent 65537). The corresponding private exponent is generated on and held only in
root-protected storage on the Oracle Free-tier host `basebreak-verifier`
(`/etc/basebreak/verifier-signing-key.hex`, `0600` root:root) and is never present in
source, tests, logs, reports, Git, or model context.

The Oracle host runs a private, fail-closed verifier bridge prepared for a later live
batch:

- private Tailscale node (`basebreak-verifier`); no Tailscale SSH, no advertised routes,
  no exit-node advertisement;
- dedicated non-root `basebreak` service account (`nologin`, no sudo);
- hardened systemd unit `basebreak-bridge` bound strictly to `127.0.0.1:8787`
  (`ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=yes`, empty capability set);
- persistent idempotency state directory `/var/lib/basebreak` (`0700 basebreak`);
- signer loading via a systemd credential / protected startup wrapper so that only the
  isolated trusted verifier receives `BASEBREAK_VERIFIER_SIGNING_KEY`; the private value
  never appears in the environment file, source, logs, or command output.

Signer compatibility with both canonical public pins is proven by an opaque local
challenge-signature round trip (`signer_matches_canonical_authority=true`). With
`BASEBREAK_LIVE_EXECUTION_ENABLED=false`, no Nebius credentials, and no shared secret
configured, effective live readiness remains `false` and the localhost endpoint returns a
truthful fail-closed response with no provider dispatch.

**Evidence limits:** all of the above is `LOCAL_EXECUTION` only. No Nebius/NVIDIA/Tavily
provider call, no Cloudflare redeployment, no public live enablement, and no paid
operation were performed. Deployed `LIVE_NEBIUS` runtime proof therefore remains
`OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN` and is NOT marked PASS.

### 3.6 Worker→Oracle bridge connectivity readiness (Workers VPC preferred; operator decision required)

The trusted Python verifier bridge runs on the Oracle Free-tier host `basebreak-verifier`
bound strictly to `127.0.0.1:8787`; it is currently reachable **only** over the private
Tailscale tailnet and has **no public ingress**. No Cloudflare Worker → bridge connection
is configured, so the public Worker cannot dispatch a live verification run.

Preferred transport — **Workers VPC Services over Cloudflare Tunnel** (this corrects the
earlier over-narrow decision that reduced the options to Tunnel+Access-with-a-domain or
public Funnel):

- Topology: existing public judge Worker → a narrow private **VPC Service binding**
  (`vpc_services`) → **outbound-only Cloudflare Tunnel** (`cloudflared` on the Oracle host)
  → Oracle loopback bridge at `127.0.0.1:8787`. **No public hostname and no
  Cloudflare-managed custom domain are required**.
- Official docs (checked 2026-10-17): Workers VPC is **"available on Free and Paid plans"**
  and **"free to all Workers plans" during the open beta**; the Worker reaches the private
  service via `env.<BINDING>.fetch(...)`. A VPC Service is registered against a Cloudflare
  Tunnel to a host/port (HTTP to `127.0.0.1:8787` for our bridge).
- HMAC request signing, pinned verifier-authority proof verification, `issued_at_ms`/
  `deadline_ms` expiry, durable single-execution idempotency, source binding, and durable
  budget admission are all preserved — only the fetch transport changes.
- **Account-level availability CONFIRMED (operator-authorized deployment, 2026-10-18)**:
  Workers VPC worked on the existing Cloudflare Free account — a Tunnel and VPC Service
  were created and the Worker deployed with the binding. No payment or plan change was
  required.

Secondary options (only if Workers VPC is unavailable):

- **Cloudflare Tunnel + Access service token** — requires a Cloudflare-managed
  zone/domain; Access is free ≤ 50 users but Zero Trust onboarding requests payment details
  even on the free plan (not charged).
- **Tailscale Funnel** — free and domain-free, but **publicly reachable**
  (`https://<node>.<tailnet>.ts.net`), *not* a private tailnet path; requires **explicit
  operator approval** of public exposure.

Random `TryCloudflare` quick-tunnel URLs are rejected as a stable dependency.

Fail-closed seam (implemented offline, `LOCAL_EXECUTION`):
`cloudflare/src/provider_dispatcher.js` `resolveBridgeTransport()` selects the bridge fetch
transport — explicit test override → private VPC Service binding → (if
`TRUSTED_VERIFIER_BRIDGE_MODE=vpc` and the binding is missing) **fail closed with a null
transport and never fall back to global fetch** → otherwise the backward-compatible direct
fetch. `cloudflare/src/index.js` resolves the transport at the existing `fetchImpl` seam
before dispatch. The `vpc_services` binding is now configured in `wrangler.jsonc`
(`TRUSTED_VERIFIER_BRIDGE` → Service ID `01a14dbe-e68f-7b31-b207-4d71aff2987e`, Tunnel
`c4977eda-47ab-412b-9f93-970972867465`) and the existing Worker is deployed with it.
Focused Node tests cover the resolution and the fail-closed dispatch path.

Current exposure: **none**. `BASEBREAK_LIVE_EXECUTION_ENABLED=false`, no Nebius
credentials, and both Cloudflare live gates disabled. Rollback is non-destructive: remove
the Tunnel/VPC Service (or `tailscale funnel reset`) and unset the Worker secret; the bridge
stays bound to `127.0.0.1:8787` and fail-closed.

Deployment status (2026-10-18, operator-authorized, **non-provider**): a Cloudflare Tunnel
connector runs on the Oracle host (outbound-only, no inbound ports), the VPC Service
`basebreak-bridge` maps to `127.0.0.1:8787`, and the existing Worker is deployed with the
VPC binding. A real Cloudflare-edge → VPC Service → Tunnel → Oracle fetch returned the
bridge's `401 UNAUTHORIZED` response (`provider_dispatched=false`), proving the private
transport with **no provider call**. The bridge has no public ingress (loopback-only; no
Funnel). Both Cloudflare live gates remain disabled (`live_enabled=false`,
`runtime_live_enabled=false`, `durable_live_enabled=false`), `BASEBREAK_LIVE_EXECUTION_ENABLED=false`,
and no Nebius credentials are configured. This is **not** `LIVE_NEBIUS`; P-27.06 live proof
remains `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`. Rollback: `wrangler vpc service delete
01a14dbe-e68f-7b31-b207-4d71aff2987e`, `wrangler tunnel delete
c4977eda-47ab-412b-9f93-970972867465`, stop/remove the `cloudflared` unit, and unset the
Worker secret; the bridge stays bound to `127.0.0.1:8787` and fail-closed.

### 3.7 Eighth Authorized Live Run & Cross-Language Receipt Digest Repair (2026-10-22)

Under the operator's eighth explicit single-run authorization, after a complete
offline causal-chain preflight (24/24 checks, `LOCAL_EXECUTION`/`FIXTURE`:
generation → binding → real-git tree digest → secret/protected-surface
validation → sealed witness → subtraction → real local three-world execution
BASE=FAIL/CANDIDATE=PASS/COUNTERFACTUAL=FAIL → signed receipt + proof round
trip), all three live gates were enabled, one single-use grant
(`grant_78a8843e-6f4f-4200-bac1-2e0d54b19ded`) was issued, and exactly ONE
production request was submitted (idempotency key
`a544fda6-dd41-4e75-bf9c-2b12595db3f9`).

**Eighth run `run_d82ee30a-481f-4e83-b187-03a189d4eae4` (LIVE_NEBIUS facts,
executor- and bridge-record-verified):**

- Genuine `nvidia/Nemotron-3_5-Lightning` candidate generation: provider request
  `chatcmpl-14a0928e66d69c756366d08cbb078e27`, 945/375/1320 tokens
  (`model-usage:complete`), `candidate_origin=MODEL_GENERATED_NEBIUS`, candidate
  patch digest `ec5cd82499b9f25f2f240f234ae0afb28cdfb2f101196186ed3211ee28338033`,
  candidate tree digest `0700291800f836ef529046b77ffadfbd7b49fb20` (the run-7
  secret false-positive did NOT recur — the repair held).
- Real Nebius Sandbox three-world execution: 11 operation IDs
  (`01a16202-…`), BASE `sbx-18822309cd8c49c7` FAIL (exit 1, tree
  `824fa2c69a222cc2204950bb6eb974abfd2abb7d`), CANDIDATE
  `sbx-fe3eb51d64b2437b` **ERROR (exit 2 — pytest collection error)**, and
  COUNTERFACTUAL `sbx-7a183a86b0944e6a` FAIL (exit 1, tree identical to the
  base tree — the reverse delta reverted the candidate exactly).
- The bridge returned `status=COMPLETED` with a genuine signed
  `LIVE_NEBIUS` receipt (receipt digest
  `5c8c8554c8ed7f9c0a4fac4ffec4e009a3bc88e3c7a49668a350bf90ce1a606b`) and
  verifier-signed receipt proof (proof digest
  `8c8cd88b921f9718ff10d582128ad7f815cd728d404e08fe0acd575831f62f22`; the RSA
  signature independently verified against the pinned production authority).
- Overall verdict: `INCONCLUSIVE` (`NON_VERIFIED_EXECUTION_ERROR`, rationale
  "Execution error encountered (BASE: FAIL, CANDIDATE: ERROR, COUNTERFACTUAL:
  FAIL)"). The CANDIDATE world failed at pytest collection (exit 2) while BASE
  and COUNTERFACTUAL ran the identical witness normally in the same sandbox
  image. **Evidence-honest classification (re-examined 2026-10-22):** all three
  worlds' stderr is empty (stderr digests equal the SHA-256 of the empty
  string), no stdout excerpts were retained (only one-way stdout digests; the
  CANDIDATE stdout digest `68a583bd…` differs from BASE/CF `5a7a5f3b…`), the
  bridge journal records no errors, and the original candidate bytes are not
  persisted — therefore the exact import/collection failure cause CANNOT be
  determined from retained evidence. The only controlled variable that differed
  in the CANDIDATE world was the model-proposed candidate content; this is
  classified as a candidate-world collection failure of undetermined exact
  cause, NOT asserted as a verified invalid-model-patch defect and NOT a
  verified product defect. The system correctly refused to certify it.
- The Worker nevertheless recorded the run as `FAILED_UNRECONCILED_COST` with
  error "Bridge receipt proof verification failed: Receipt digest verification
  failed." — a **genuine product defect** at the receipt-import boundary
  (unknown-cost exposure 0.50 USD retained; ledger: total_runs=8,
  unknown_cost=4.00).

**Root cause (independently reproduced offline with the actual run-8 receipt
bytes, `LOCAL_EXECUTION`):** the trusted bridge computed the receipt digest over
`build_canonical_public_receipt_payload`, which SORTS the `disclaimers`,
`not_run_obligations`, and `runtime_identities` list fields and distinguishes
Python ints from floats, while the wire receipt (`to_dict()`) preserved insertion
order and integral-valued floats (`0.0`, `30.0`). ECMAScript `JSON.parse`
collapses `0.0` and `0` into the same number, so the Worker could never
recompute a genuine Python bridge receipt digest (JS recomputed
`f8b46939…`/wire-unsorted vs declared `5c8c8554…`). The retained Node test
fixtures were built in JS (already-sorted lists, integer-typed numbers), which
kept the defect invisible to the Node suite; the Python-side proof round trip
never exercised the JS verifier with Python-produced bytes.

**Surgical repair (same batch, verified BASE=FAIL → CANDIDATE=PASS):**

1. `src/basebreak/causal/public_receipt.py`: canonical digest payloads are now
   normalized to JSON-portable values (integral-valued floats become ints,
   recursively), and `PublicVerificationReceipt.to_dict()` emits EXACTLY the
   canonical payload plus `receipt_digest` — the wire form IS the digest
   payload, so external verifiers can recompute it byte-for-byte.
2. `cloudflare/src/crypto_utils.js`: the ECMAScript canonicalization now mirrors
   the Python canonical builder (sorted `disclaimers`/`not_run_obligations`/
   `runtime_identities`, lowercased digest-like fields, trimmed string fields)
   and escapes non-ASCII exactly like Python `ensure_ascii=True`, so genuine
   Python receipts verify cross-language while tampering is still rejected.
3. Regression tests: `tests/causal/test_p27_06_receipt_wire_canonicalization.py`
   (6 tests: wire==canonical invariant, portable numbers, sorted lists,
   JSON round trip, pure-wire digest reproducibility, and a live
   Python→Node cross-language verification that skips when `node` is
   unavailable) and `cloudflare/test/receipt.crosslanguage.test.js` (4 tests
   against the committed Python-generated fixture
   `cloudflare/test/fixtures/python_public_receipt_fixture.json`, regenerated
   deterministically by
   `cloudflare/test/fixtures/generate_python_receipt_fixture.py` with
   deliberately unsorted lists, integral floats, and non-ASCII content).
   Causal evidence: the Python-built fixture FAILS verification under the
   pre-repair JS (digest `575c5fff…`) and PASSES under the repaired JS
   (`458d1fd5…`); five tamper shapes remain rejected.
4. Validation (`LOCAL_EXECUTION`): full Python suite 2942 passed / 12 skipped
   (live-marked tests correctly skipped), Node suite 68 passed (64 prior + 4
   new), workerd preflight pass, `ruff format --check`, `ruff check`, and
   `mypy src tests` (282 files) all pass.

**Evidence limits:** the run-8 receipt was created under the legacy
canonicalization; it does not (and cannot) verify under the repaired rules and
is preserved as immutable historical evidence in the Oracle bridge durable
record, authenticatable through its RSA-signed proof (which binds
`receipt_digest=5c8c8554…` and the execution facts) and through the legacy
Python canonicalization. The repaired receipt-import path remains UNVERIFIED by
live execution (no ninth run is authorized); the deployed live
`LIVE_NEBIUS` runtime proof remains `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`
for a future authorized run.

### 3.8 Residual Cross-Language Number Canonicalization Repair (2026-10-22, offline)

Independent re-examination after the first canonicalization repair identified a
residual defect: Python `json.dumps` and ECMAScript `JSON.stringify` serialize
the same non-integral double differently whenever its shortest round-trip form
crosses an exponent threshold — Python uses exponent notation below `1e-4` and
at/above `1e16` with two-digit exponents (`1e-05`, `1e+16`), ECMAScript below
`1e-7`... precisely: below `1e-6` and above `1e21`, unpadded (`0.00001`,
`10000000000000000`, `1e-7`). A genuine receipt containing small fractional
timings (e.g. `duration_seconds=0.00001`) therefore still failed Worker
verification.

**Reproduction (BASE=FAIL, `LOCAL_EXECUTION`, actual production code paths):** a
production-factory Python receipt with sub-1e-4 fractional values
(duration 0.00001/0.0000125/0.00002, total 0.0000425) declared digest
`81ffdb0b…` (old `json.dumps` canonical bytes) while the production Node
verifier recomputed `b24f4914…` (`verifyReceiptIntegrity: false`).

**Deterministic numeric canonicalization contract (repair):**

1. `src/basebreak/causal/public_receipt.py` computes receipt digest bytes with a
   dedicated canonical serializer (`_canonical_receipt_json_bytes`) whose number
   formatting mirrors ECMAScript `Number::toString` exactly
   (`_ecmascript_number_bytes`: Python's shortest round-trip digits re-formatted
   per ECMA-262 §6.1.6.1.20 — plain decimals between the ECMAScript thresholds,
   unpadded exponents outside, `-0` → `0`). No rounding is performed and no
   measurement precision is lost: the shortest round-trip representation is
   preserved verbatim, only its NOTATION is normalized.
2. Fail-closed domain (rejected BEFORE receipt signing): non-finite floats
   (NaN/±Infinity), integers beyond the ECMAScript safe-integer range
   `[-(2^53-1), 2^53-1]` (which ECMAScript cannot round-trip), non-string and
   non-ASCII object keys (ASCII keys sort identically under Python code-point
   and ECMAScript UTF-16 code-unit ordering).
3. `cloudflare/src/crypto_utils.js` `canonicalJson` additionally escapes object
   KEYS with the same `ensure_ascii` semantics as values, so Python
   `json.dumps(ensure_ascii=True)` and the Worker never hash different bytes
   for the same supported object.
4. Wire format unchanged: the wire remains valid JSON produced by
   `json.dumps`; both verifiers canonicalize the PARSED VALUES, so Python-style
   exponent literals on the wire (e.g. `1e-05`) parse to the same double in
   both languages.

**Cross-language verification:** a 4,044-value boundary+random fuzz (fixed
seed; subnormals like `5e-324`, `1.7976931348623157e308`, exponent thresholds
`1e-6`/`1e21`, `2^53` boundaries, random bit-pattern doubles) confirmed the
Python formatter and a real Node process produce byte-identical number
serialization for every value; all fail-closed rejections verified. Causal
proof: the small-float receipt fails under the pre-repair code and passes after
(CANDIDATE=PASS, digest `b24f4914…`); tampering with durations, timing, or
coverage values is still rejected. Backward compatibility: the first repair's
committed fixture digest is UNCHANGED (`458d1fd5…`) because all its values lie
in the pre-existing agreement zone — receipts created under the first repair
still verify.

**Regression tests:** `tests/causal/test_p27_06_receipt_wire_canonicalization.py`
(now 34 tests: boundary parametrization, fail-closed domain, committed-fixture
digest stability, small-float cross-language verification, 300-value seeded
cross-language fuzz) and `cloudflare/test/receipt.crosslanguage.test.js`
(now 7 tests: original + small-float fixtures, key-escaping parity, tamper
rejection). The Node suite is now executed deterministically by GitHub CI
(`actions/setup-node` + `npm --prefix cloudflare ci` + typecheck + test:node).
A standalone fuzz tool is retained at `tools/cross_lang_number_fuzz.py`.

**Evidence limits:** production RSA-signed proof verification, source/candidate
binding, and the legacy run-8 receipt record are untouched; the run-8 receipt
remains immutable legacy-canonicalization evidence. The repaired path is NOT
verified by live execution (no ninth run is authorized).

### 3.9 Ninth Authorized Live Run — COMPLETED, Receipt Accepted & Published (2026-10-22)

Under the operator's ninth explicit single-run authorization (one grant
`grant_d311c3f0-31b6-4282-8c80-d6a26088b76e`, idempotency key
`27c62d35-cbfa-407b-a560-7b9c83522846`, exactly ONE `POST /v1/runs`), after a
focused zero-spend preflight (offline causal-chain preflight 24/24 PASS at
`dfc3656`, 199 focused Python tests, 71 Node tests, workerd preflight,
operational state verification), all three live gates were enabled, verified by
independent read-back, and the run executed.

**Run `run_f499c6e8-c037-416d-b5cd-65f7b3a562f6` — HTTP 201 CREATED in 33.8 s
(the first non-error HTTP response of any live run):**

- **Status `COMPLETED`, provenance `LIVE_NEBIUS`, `receipt_available: true`.**
  The Worker ACCEPTED the bridge-generated Python receipt and PERSISTED it —
  the run-8 receipt-import defect (and both canonicalization repairs) is now
  verified LIVE end-to-end.
- Genuine `nvidia/Nemotron-3_5-Lightning` candidate generation: provider
  request `chatcmpl-27b0b373312cb8e8f37e805fda2873ab`, 945/382/1327 tokens,
  `MODEL_GENERATED_NEBIUS` candidate (patch digest
  `3458bba091ad573599d78e9feb04e27e36a54cf18e2ed80bf86f135edeb2f3b2`, candidate
  tree `f345525ab32fc42518f95a830e683cccb2e22571`), distinct response/proposal
  digests from run 8 (genuine independent generation, no caching).
- 11 real Nebius sandbox operations across three fresh worlds:
  BASE `sbx-e87511a47ce0416b` **FAIL** (exit 1, tree `824fa2c6…`), CANDIDATE
  `sbx-8cb84393f30e406c` **ERROR** (exit 2 — pytest collection error, tree
  `f345525a…`), COUNTERFACTUAL `sbx-4b3566d1730a429b` **FAIL** (exit 1, tree
  reverted exactly to the base tree `824fa2c6…`).
- Signed `LIVE_NEBIUS` receipt (digest
  `72118e27a15bb2a525e2f06ddff2e0b1016c20b65e2af227bf96692d99272ca5`) with
  verifier-signed proof (proof digest
  `5f0a187e67274a997ca33af9a6edf788be5274a1987c912a6488457d207a00d1`).
- **Independent post-run verification:** the PUBLISHED receipt
  (`GET /v1/runs/run_f499c6e8-…/receipt`, HTTP 200) is byte-identical to the
  bridge receipt, re-verifies under the Python canonical serializer
  (`PublicVerificationReceipt.from_dict` → PASS) AND the production Node
  verifier (`verifyReceiptIntegrity` → true, same digest), and the proof's RSA
  signature independently verifies against the pinned production authority
  while binding the published receipt digest. The public judge route serves
  the run (`/judge/run_f499c6e8-…`, HTTP 200).
- Overall verdict: `INCONCLUSIVE` (`NON_VERIFIED_EXECUTION_ERROR` — BASE: FAIL,
  CANDIDATE: ERROR, COUNTERFACTUAL: FAIL).

**CANDIDATE-world error triage (honest limits):** the CANDIDATE stdout digest
is byte-identical to run 8 (`68a583bd…`) despite a different candidate patch
and tree, while BASE/CF stdout digests are also stable across runs
(`5a7a5f3b…`). An identical collection-error signature for different candidate
bytes is consistent with a content-independent import failure (most plausibly
a vault.py that does not export `ResetVault`), but the exact cause is NOT
determinable from retained evidence: the original candidate bytes, the raw
pytest output, and stdout excerpts are not retained (only one-way digests),
and the bridge path discards raw stdout after digesting (`stdout_excerpt` is
populated by the CLI runner path but not plumbed through the trusted bridge).
Per operator instruction the error is NOT classified as definitively
model-caused or product-caused. The verified facts: the staged candidate tree
matched the tree computed from the model's patch exactly, BASE/CF ran the
identical witness normally in the same sandbox image, and the local offline
chain preflight proves a valid candidate passes the same command — no product
defect is provable, and none was fabricated.

**Shutdown & accounting:** all three gates verified OFF immediately after the
run (`live_enabled=false`, `runtime_live_enabled=false`,
`durable_live_enabled=false`); `in_flight_count=0`; ledger preserved:
`total_runs=9`, `completed_runs=1` (first ever), `unknown_cost=$4.50`
(historical $4.00 + run-9 reserved $0.50 with UNKNOWN provenance),
`observed_cost=0`; grant consumed; no second POST; zero additional paid
operations during cleanup.

**Task status:** the deployed app provably triggers the real required
Nebius/NVIDIA runtime (genuine inference + genuine sandbox three-world
execution) AND now publishes an independently verifiable signed `LIVE_NEBIUS`
receipt through the public production path. A `VERIFIED` causal triplet
(BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL) remains NOT achieved: the
CANDIDATE world errored at pytest collection with an undetermined,
non-retained cause. Any tenth run requires new explicit operator
authorization. Recommended (not implemented, out of scope): plumb bounded
sanitized `stdout_excerpt` retention through the trusted bridge execution path
so future candidate-world collection errors are triageable.

### 3.10 Tenth Authorized Live Run — CAUSAL TRIPLET VERIFIED & RECEIPT PUBLISHED (2026-10-22)

Under the operator's consolidated P-27.06 closure authorization (grant
`grant_c5b6ab9e-1cff-47f2-8fbe-7a5d5e14ddc8`, idempotency key
`268728c6-e8f1-492d-8c8c-24edbc33141f`, exactly ONE `POST /v1/runs`), after
root-cause repair of the repeating CANDIDATE collection failure (the prompt now
explicitly requires full file content for MODIFY actions; candidate pre-execution
validation and bounded model-guided repair cycle implemented; bounded diagnostic
classification and operator excerpt storage added), all three live gates were
enabled, verified by independent read-back, and the run executed.

**Run `run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9` — HTTP 201 CREATED in 35.89 s:**

- **Status `COMPLETED`, provenance `LIVE_NEBIUS`, outcome `VERIFIED`, `receipt_available: true`.**
- Genuine `nvidia/Nemotron-3_5-Lightning` candidate generation: provider request
  `chatcmpl-f5c5e28a90ae7b935630d6f9fe1683ae`, 1,123 prompt / 693 completion tokens
  (`model-usage:complete`), `candidate_origin=MODEL_GENERATED_NEBIUS`, candidate
  patch digest `5f3ac8d9dcef8b046c58f58f3d2c44a340b13191235637169b781cf54abe592e`,
  candidate tree digest `6c4f46cbb51119d8e93534a1e2ee922498ee450b` (distinct proposal
  and response digests from runs 8 and 9; genuine independent generation).
- 11 real Nebius sandbox operations across three fresh isolated worlds:
  - **BASE:** `sbx-7da8ae8d855b45f1` → **FAIL** (exit 1, tree `824fa2c6…`, stdout digest `5a7a5f3b…`, category `TEST`)
  - **CANDIDATE:** `sbx-c1057ebc4528465c` → **PASS** (exit 0, tree `6c4f46cb…`, stdout digest `f4c77b58…`, category `PASS`, 1 passed in 0.04s)
  - **COUNTERFACTUAL:** `sbx-de5d5ca163034441` → **FAIL** (exit 1, tree reverted to base tree `824fa2c6…`, stdout digest `5a7a5f3b…`, category `TEST`)
- **Causal Invariant Achieved:** `BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL` → **VERIFIED**.
- Signed `LIVE_NEBIUS` receipt (digest `a7857896f3f701264bed995f3b0a70115a9ab007a84d5deece3ae8bcef876500`) with verifier-signed proof (proof digest `e738d961e200f1df07af046d6a0adc56b7284b13b469249359ae0120e9a6cd2a`).
- **Independent post-run verification:**
  - Published receipt (`GET /v1/runs/run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9/receipt`, HTTP 200) re-verified under Python `verify_public_receipt_integrity` (PASS) and Node `computeReceiptDigest` (PASS, identical digest `a7857896…`).
  - Verifier-signed RSA proof verified against pinned production authority in Node (`verifyBridgeReceiptProof: PASS`).
  - Public signed-out judge URL verified: `https://basebreak.zyganali.workers.dev/judge/run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9` (HTTP 200).
  - Diagnostic record securely persisted at `/var/lib/basebreak/diag-40134311c0bf83764a280689b37663952b225ea73c08a1b184430b2b6e9255a5.json` (mode `0600 basebreak:basebreak`).
- **Shutdown & accounting:**
  - All three live gates verified OFF immediately after the run (`live_enabled=false`, `runtime_live_enabled=false`, `durable_live_enabled=false`).
  - Concurrency `in_flight_count=0`.
  - Ledger preserved: `total_runs=10`, `completed_runs=2`.
  - Single grant consumed; exactly ONE production POST executed; zero additional paid operations.


### 4.1 Closure Status & Post-Run State

- **P-27.06 Deployed Live Nebius Execution:** **VERIFIED / PASS**
- **Verified Causal Triplet:** `BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL` achieved in production on genuine Nebius/NVIDIA Nemotron-3_5-Lightning model and Nebius Sandboxes runtime.
- **Signed Receipt Authority:** Bridge-signed `LIVE_NEBIUS` receipt accepted, persisted, and published by Cloudflare Worker (`run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9`), with RSA proof verified against pinned authority in both Python and Node.
- **Public Judge Endpoint:** Serving verified run receipt at `https://basebreak.zyganali.workers.dev/judge/run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9`.
- **Mandatory Safe Shutdown Verified:**
  - Oracle bridge: `BASEBREAK_LIVE_EXECUTION_ENABLED=false` set in `/etc/basebreak/bridge.env`, systemd service restarted.
  - Cloudflare Worker Durable Object live gate: `durable_live_enabled: false` confirmed via `/admin/configure-live-gate`.
  - Cloudflare Worker runtime live gate: `wrangler.jsonc` restored to `"LIVE_ENABLED": "false"`, deployed version `294e7c78-b48b-43d7-b99d-5f2f6c0225c6`.
  - Effective live gate status on public `/health`: `live_enabled=false`, `runtime_live_enabled=false`, `durable_live_enabled=false`.
- **Operational Accounting:**
  - `total_runs=10`, `completed_runs=2`, `in_flight_count=0`.
  - Exactly ONE production run executed in Tenth Batch; zero additional paid operations.
  - Zero personal spend incurred ($0.00 personal cost).

Phase P-27 has satisfied all verification criteria and is **CLOSED / PASS**.


### 4.2 Final Integrity & Security Closure (Defects A & B + Evidence Packet)

- **DEFECT A — Untrusted Code Host Isolation:**
  - Removed all `compile()` and `exec()` calls from `validate_candidate_preexecution()` in `src/basebreak/deployment/model_candidate.py`.
  - Untrusted candidate code is NEVER evaluated or executed inside the privileged Python bridge process.
  - Replaced with static AST inspection (`ast.parse`) checking syntax, class preservation (`ResetVault`), and required method preservation.
  - Added adversarial regression tests proving top-level side effects, class-body side effects, and malicious imports never affect the host process.
- **DEFECT B — Multi-Call Accounting Parity:**
  - Propagated actual `model_call_count`, cumulative prompt/completion/total tokens, and all `provider_request_ids` across repair turns through `BridgeExecutionResult` and receipt runtime identities (`model-calls:<count>`, `candidate-generation:request:<req_id>`).
- **Independent Cryptographic Read-Back & Evidence Packet:**
  - Retrieved tenth-run published receipt (`a7857896f3f701264bed995f3b0a70115a9ab007a84d5deece3ae8bcef876500`) and bridge response proof (`e738d961e200f1df07af046d6a0adc56b7284b13b469249359ae0120e9a6cd2a`).
  - Cryptographically re-verified in both production Python (`verify_public_receipt_integrity`, `verify_receipt_proof`: PASS) and Node (`computeReceiptDigest`, `verifyBridgeReceiptProof`: PASS).
  - Sanitized evidence packet exported to `docs/evidence/p27_06_live_run_10_evidence_packet/` with exact independent reproduction instructions (`VERIFICATION_AUDIT.md`).
- **Safe State Confirmed:**
  - Zero additional provider calls or spend ($0.00 personal spend).
  - All three live gates verified OFF.

---

## 5. Türkçe Operatör Kapanış Özeti

- **Canlı Çalıştırma Sonucu:** Onuncu yetkili canlı koşu (`run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9`) başarıyla tamamlandı ve **VERIFIED** sonucuna ulaştı.
- **Gerçek Model Çıktısı:** `nvidia/Nemotron-3_5-Lightning` modeli (`chatcmpl-f5c5e28a90ae7b935630d6f9fe1683ae`, 1.123 prompt / 693 completion token) tam `ResetVault` sınıfını ve yöntemlerini içeren eksiksiz adayı başarıyla üretti.
- **3 Dünyalı Nedensellik Doğrulaması:** Nebius Sandboxes üzerinde 11 işlemle üç bağımsız dünyada çalıştırıldı:
  - `BASE`: FAIL (exit 1 — hata yeniden üretildi)
  - `CANDIDATE`: PASS (exit 0 — adayın hatayı düzelttiği kanıtlandı, 1 passed in 0.04s)
  - `COUNTERFACTUAL`: FAIL (exit 1 — yamanın geri alınmasıyla hatanın geri döndüğü, yani yamanın zorunlu olduğu kanıtlandı)
  - **Nedensellik Değişmezi:** `BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL` → **VERIFIED / KANITLANDI**.
- **İmzalı Makbuz & Jüri Erişimi:** Bridge tarafından üretilen imzalı RSA kanıtlı `LIVE_NEBIUS` makbuzu Cloudflare Worker tarafından kabul edildi, kalıcı depolandı ve yayınlandı. Hem Python hem Node ortamlarında RSA imzası ve digest doğrulamaları başarıyla geçti (`GET /judge/run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9` 200 OK).
- **Güvenli Kapatma:** Koşu tamamlanır tamamlanmaz tüm canlı kapılar kapatıldı (Oracle bridge servisi, Cloudflare Worker DO kapısı ve Worker runtime kapısı `live_enabled=false`). Operatör bakiyesinden kişisel harcama yapılmadı ($0.00 kişisel maliyet).
- **Sonuç:** P-27.06 ve P-27 fazı eksiksiz başarıyla kapatıldı.
