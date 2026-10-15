# Basebreak Deployment Architecture & Platform Reality (P-27.01)

## 1. Executive Summary

This document establishes the deployment architecture decision for **Basebreak** in compliance with the **Nebius x NVIDIA Global AI Hackathon** rules, the official Hackathon FAQ, and the **Zero-Cost Law**.

- **Product Thesis:** *"If the patch matters, the base must break."*
- **Primary Architecture:** **Cloudflare Workers Free + Static Assets + SQLite-backed Durable Object + Nebius Token Factory / Token Factory Sandboxes**.
- **Core Judge Value:** Single public URL, integrated responsive judge dashboard, real BASE/CANDIDATE/COUNTERFACTUAL causal triplet evidence, and authentic on-demand Nebius/NVIDIA verification under strict $0.00 personal spend.
- **Judging Window:** Project submissions freeze late October 2026; judging and review continue through **December 15, 2026**.
- **Target Personal Spend:** Strictly **$0.00**.
- **Promotional Budget Guard:** `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` operator policy safety reserve floor.

---

## 2. Competition Reality & Hosting Criteria

### 2.1 Official Rules & FAQ
- **Rules URL:** `https://nebiusglobalaihackathon.devpost.com/rules`
- **FAQ URL:** `https://nebiusglobalaihackathon.devpost.com/details/faqs`
- **Key Clarification:**
  > *"Does the whole app need to be hosted on Nebius AI Cloud?"*  
  > *"No. The entire frontend/backend does not have to be hosted on Nebius AI Cloud. A genuine runtime call to Nebius Token Factory using an eligible NVIDIA open-source model can satisfy the platform requirement."*
- **Judge Access Requirement:**
  > *"Submissions must provide a working demo or test build accessible to judges free of charge through the judging period."*

### 2.2 Operator Non-Negotiable Requirement
The operator has established that Basebreak's submission must provide:
1. **One public URL:** A single live website where judges interact directly.
2. **Integrated full-stack experience:** Web UI and verification runtime served seamlessly together (not a simulation-looking static dump).
3. **Genuine on-demand runtime capability:** Able to trigger authentic Nebius/NVIDIA causal verification.
4. **No local Docker requirement:** Judges and operator must not be forced to install local Docker daemons.
5. **Strict $0.00 personal spend:** Zero credit-card charges or auto-billed paid tiers.

---

## 3. Primary Architecture Evaluation: Cloudflare Workers Free + SQLite Durable Object

Under P-27.01, we evaluate **Cloudflare Workers Free + Static Assets + SQLite-backed Durable Object** as the primary candidate for single-live-site hosting across 9 critical operational dimensions:

### Dimension 1: One Public Web App URL & Same-Origin Routing
- **Evaluation:** Cloudflare Workers provisions a single public domain (`https://basebreak.<subdomain>.workers.dev` or a custom zone).
- **Runtime Topology:** The single URL serves:
  1. The HTML Judge Dashboard (`/`, `/judge`, `/judge/{id}`) via Static Assets (`public/index.html`).
  2. The REST API (`/v1/runs`, `/v1/runs/{id}/receipt`, `/health`) on the exact same origin.
  3. Administrative grant issuance and kill-switch endpoints (`/admin/grants`, `/admin/killswitch`).
- **Verdict:** **FEASIBLE**. Unified user experience with zero cross-origin or CORS fragmentation.

### Dimension 2: Edge Routing & Instant Availability (No Cold-Start Sleep)
- **Evaluation:** Unlike container hosts that sleep after 15 minutes of idle time (imposing 30–60 second wake-up delays), Cloudflare Workers execute at edge locations with negligible cold starts (sub-5ms).
- **Judge Impact:** Judges experience instantaneous page loads and immediate receipt inspection without waiting for dormant server wake-ups.
- **Verdict:** **HIGHLY FEASIBLE**.

### Dimension 3: Free-Tier Limits & Absence of Automatic Billing
- **Evaluation:** Cloudflare Workers Free provides **100,000 requests per day** and requires **NO credit card** on file.
- **Billing Safeguard:** If daily request quotas are reached, Cloudflare hard-stops further execution (returning HTTP 429) rather than billing personal payment methods.
- **Personal Spend:** Guaranteed strictly **$0.00**.
- **Verdict:** **STRICTLY COMPLIANT WITH ZERO-COST LAW**.

### Dimension 4: Python Runtime Isolation Boundary
- **CRITICAL PLATFORM FACT:** Cloudflare Workers execute inside a V8 JavaScript/WebAssembly sandbox (`workerd`) and **cannot execute native Python C-extensions or the full Python Basebreak causal verification runtime directly**.
- **Architecture Enforcement:**
  1. We do **NOT** port the complete Python causal engine into JavaScript or recreate its verification logic independently.
  2. The Cloudflare Worker acts as the HTTP presentation gateway, admission authority, quota ledger, and public receipt store.
  3. The trusted Python Basebreak runtime must execute in a genuinely isolated supported environment: **Nebius Token Factory Sandboxes** (`https://api.tokenfactory.nebius.com/sandboxes/v1`).
- **Verdict:** **FEASIBLE UNDER GENUINE PROVIDER BOUNDARY**.

### Dimension 5: Enforceable Admission Boundary (Single Canonical SQLite Durable Object)
- **Zero-Cost Law Rule (Section 12):** *"Never expose an unauthenticated public live endpoint capable of silently draining free Token Factory or Tavily credits."*
- **Single Canonical Ledger:** A single SQLite-backed Durable Object (`AdmissionLedgerDO`) manages global live execution admission:
  1. Default `LIVE_ENABLED=false`.
  2. Operator-issued, single-use, server-validated access grants (`max_uses: 1`).
  3. No anonymous self-service live execution.
  4. Fixed allowlisted target repository (`tests/fixtures/reset_vault`) and immutable source commit SHA.
  5. Global total invocation cap (e.g. 5 lifetime runs).
  6. Maximum **1 in-flight cost-consuming run** globally.
  7. Atomic check-and-reserve before calling external APIs.
  8. Idempotency and replay prevention.
  9. Fail-closed recovery after restarts, worker crashes, and network loss (shifting ambiguous costs to `unknown_cost` without automatic retries).
  10. Strict rejection of missing, stale (>15 min), or below-floor (<= $5.00) promotional balance.
  11. Operator-policy $5.00 safety reserve floor (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`).
  12. Emergency administrative kill switch.
- **Verdict:** **STRICTLY ENFORCED**.

### Dimension 6: Durable Public Receipt Persistence Across Restarts
- **CRITICAL PLATFORM FACT:** The SQLite database embedded inside the Durable Object (`ctx.storage.sql`) persists transactionally across Worker restarts, deployments, and edge evictions.
- **Verification Integrity:** Receipts stored in the `receipts` table are cryptographically verified upon storage and re-verified before serving (`verifyReceiptIntegrity(receipt) === true`). Any tampered or secret-bearing receipt is rejected.
- **Verdict:** **FEASIBLE VIA SQLITE-BACKED DURABLE OBJECT**.

### Dimension 7: Unrestricted Signed-Out Public Evidence Inspection
- **Evaluation:** Even after the live execution budget is exhausted or when the kill switch is engaged, signed-out judges can freely inspect all pre-verified, cryptographically authentic receipts via `GET /`, `GET /health`, `GET /judge`, and `GET /v1/runs/{id}/receipt` without needing access grants or incurring provider costs.
- **Verdict:** **FEASIBLE**.

### Dimension 8: Judge Access Grant Delivery Procedure
- **Evaluation:** Because Devpost does not provide a private per-judge credential delivery field on public submissions without exposing secrets:
  1. The operator issues single-use grants via `POST /admin/grants` using the private `BASEBREAK_ADMIN_KEY`.
  2. Dedicated single-use URLs (`https://basebreak.workers.dev/judge?grant=bb_grant_xxx`) can be provided directly to hackathon judges via private evaluation channels.
  3. For unrestricted public inspection, the site presents authentic pre-generated `RECORDED_LIVE` receipts with full cryptographic proofs, requiring zero credentials.
- **Verdict:** **FEASIBLE**.

### Dimension 9: Account & Operator Authorization Boundary
- **Evaluation:** Deploying Cloudflare Workers requires the operator to authenticate with Cloudflare and run `wrangler deploy` or link via Git integration.
- **Status:** Per AGENTS.md Constitution, the coding assistant must not initiate external cloud deployments autonomously.
- **Classification:** **`OPERATOR_DECISION_REQUIRED / NOT_RUN`**.

---

## 4. Hosting Truth Repair & Unsupported Claims Correction

To ensure 100% adherence to repository governance and Section A of the Master Plan, we formally correct all previously identified unsupported claims:

| Prior Unsupported Claim | Platform & Architectural Reality | Status |
| :--- | :--- | :--- |
| **"Automatically recovered baked-in receipts"** | Receipts do **not** magically auto-recover without physical storage. In the Cloudflare architecture, authentic receipts are explicitly persisted in the SQLite Durable Object `receipts` table and bundled into static assets. | **CORRECTED** |
| **"Runtime-enforced Nebius balance hard stops"** | Nebius platform APIs provide **no** automated billing hard stops or balance cutoff APIs. The $5.00 safety reserve (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`) is an operator policy floor enforced by Basebreak client/worker preflight verification, **not** a provider-side guarantee. | **CORRECTED** |
| **"Existing public live demo buttons"** | No anonymous public live execution exists. On-demand execution is strictly guarded by operator-issued single-use access grants and rejected fail-closed if unauthenticated. | **CORRECTED** |
| **"Existing rate limits"** | Concurrency limits (maximum 1 in-flight) and total invocation caps are enforced deterministically by the application's SQLite Durable Object ledger, **not** by cloud provider infrastructure. | **CORRECTED** |
| **"Verified hosting uptime"** | Hosting uptime is **not** verified because public cloud deployment has not yet occurred (`P-27.03` is `NOT_RUN`). | **CORRECTED** |
| **"Already working remote Python execution"** | Remote Python execution on a public cloud instance is **not** already operational; it is held fail-closed at `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`. | **CORRECTED** |
| **"GitHub Pages as primary host"** | GitHub Pages is retained strictly as an optional static archive and fallback mirror, **never** the primary live product. | **CORRECTED** |

---

## 5. Platform Comparison & Role Matrix

| Platform | Role in Basebreak | Single Public URL? | Card Required? | Personal Spend | Disk/State Persistence | Concurrency & Cost Ledger | Feasibility Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Cloudflare Workers Free + DO SQLite** | **Primary Candidate Live Site** | **YES** (`*.workers.dev`) | **NO** | **$0.00** | Persistent SQLite in DO | Enforced by `AdmissionLedgerDO` | **FEASIBLE (Ready for Operator Preflight)** |
| **Render Free (Hobby)** | **Alternative Container Host** | YES (`*.onrender.com`) | NO | $0.00 | Ephemeral (wiped on 15m idle) | In-memory only (lost on sleep) | Secondary fallback only |
| **GitHub Pages** | **Static Archive & Fallback** | YES (`*.github.io`) | NO | $0.00 | Permanent (Git-backed) | None (Static HTML only) | Read-only inspection of authentic evidence |
| **HF Docker Space** | **Disqualified** | YES | YES (Mandates card) | Billed if exceed | Ephemeral | None | Violates Zero-Cost Law |
| **Nebius Compute VM**| **Disqualified** | YES | YES (Hourly billing) | >$50/mo | Persistent | None | Violates Zero-Cost Law |

---

## 6. Architectural Topology: Edge Admission & Remote Sandbox Boundary

```
   ┌────────────────────────────────────────────────────────────────────────┐
   │                   PRIMARY SINGLE-LIVE-SITE ARCHITECTURE                 │
   │               Cloudflare Workers Free (No Credit Card, $0.00)           │
   │                                                                        │
   │   ┌────────────────────────────────────────────────────────────────┐   │
   │   │               Integrated Single-Screen Judge Dashboard         │   │
   │   │  - Front-and-center causal thesis & 3-World comparison cards   │   │
   │   │  - Read-only inspection of authentic pre-verified receipts     │   │
   │   │  - Single-use grant input field (protected live admission)     │   │
   │   │  - Cryptographic verification badge ("AUTHENTIC SHA-256")      │   │
   │   └────────────────────────────────────────────────────────────────┘   │
   │                                   │                                    │
   │             ┌─────────────────────┴─────────────────────┐              │
   │             ▼                                           ▼              │
   │   ┌───────────────────────────────┐   ┌────────────────────────────┐   │
   │   │   Single Canonical Ledger     │   │   Remote Sandbox Boundary  │   │
   │   │  SQLite Durable Object (DO)   │   │  Nebius Token Factory API  │   │
   │   │  - Default LIVE_ENABLED=false │   │  - Remote Cloud Sandboxes  │   │
   │   │  - Single-use access grants   │   │  - Nemotron-3.5-Lightning  │   │
   │   │  - Max 1 in-flight run        │   │  - Python Basebreak Engine │   │
   │   │  - $5.00 safety reserve floor │   │  (OPERATOR_AUTHORIZATION_  │   │
   │   │  - Persistent receipts store  │   │   REQUIRED / NOT_RUN)      │   │
   │   └───────────────────────────────┘   └────────────────────────────┘   │
   └────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ Fallback / Archive
                                       ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │               STATIC ARCHIVE & DISASTER RECOVERY LAYER                 │
   │                   GitHub Pages (100% Free CDN, No Card)                │
   │   - Pre-rendered HTML export via `basebreak ui <run_id> --output`      │
   │   - Raw canonical JSON receipt via `basebreak receipt <run_id>`        │
   │   - Accessible permanently through judging period ending Dec 15, 2026   │
   └────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Implementation & Verification Status Matrix

| Subsystem / Capability | Implementation Component | Testing Provenance | Current Execution Status |
| :--- | :--- | :--- | :--- |
| **Worker HTTP Router & Endpoints** | `cloudflare/src/index.js` | `LOCAL_EXECUTION` (Node test runner) | **IMPLEMENTED_AND_TESTED (9/9 pass)** |
| **SQLite Durable Object Ledger** | `cloudflare/src/ledger.js` | `LOCAL_EXECUTION` (Node test runner) | **IMPLEMENTED_AND_TESTED (11/11 pass)** |
| **Cryptographic Receipt Integrity** | `cloudflare/src/crypto_utils.js` | `LOCAL_EXECUTION` (Python & JS tests) | **IMPLEMENTED_AND_TESTED** |
| **Static Judge Dashboard** | `cloudflare/public/index.html` | `LOCAL_EXECUTION` | **IMPLEMENTED_AND_TESTED** |
| **Wrangler Configuration & Parity** | `cloudflare/wrangler.jsonc` | `LOCAL_EXECUTION` (Python pytest) | **IMPLEMENTED_AND_TESTED (4/4 pass)** |
| **100 Clicks Single Grant Admission** | `cloudflare/test/ledger.test.js` | `LOCAL_EXECUTION` (Node test runner) | **VERIFIED (1 admitted, 99 rejected)** |
| **Global Concurrency Ceiling (Max 1)** | `cloudflare/test/ledger.test.js` | `LOCAL_EXECUTION` (Node test runner) | **VERIFIED (1 in-flight, 9 rejected)** |
| **Fail-Closed Stale/Low Balance ($5)** | `cloudflare/test/ledger.test.js` | `LOCAL_EXECUTION` (Node test runner) | **VERIFIED (All floor violations blocked)** |
| **Public Cloud Worker Deployment** | `wrangler deploy` | N/A | **OPERATOR_DECISION_REQUIRED / NOT_RUN** |
| **Live Nebius Sandbox Execution** | `dispatchVerificationRun` | N/A | **OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN** |
| **Live Production Health Parity** | `verify_health_parity` | N/A | **NOT_RUN against live production** |
