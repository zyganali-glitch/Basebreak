# Basebreak Deployment Architecture & Platform Reality (P-27.01)

## 1. Executive Summary

This document establishes the deployment architecture for **Basebreak** in compliance with the **Nebius x NVIDIA Global AI Hackathon** rules, the official Hackathon FAQ, and the **Zero-Cost Law**.

- **Product Thesis:** *"If the patch matters, the base must break."*
- **Judging Window:** Project submissions freeze late October 2026; judging and review continue through **December 15, 2026**.
- **Target Personal Spend:** Exactly **$0.00**.
- **Promotional Budget Guard:** `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` safety floor.

---

## 2. Competition Hosting & Platform Reality

### 2.1 Official Competition Rules & FAQ Analysis
- **Rules URL:** `https://nebiusglobalaihackathon.devpost.com/rules`
- **FAQ URL:** `https://nebiusglobalaihackathon.devpost.com/details/faqs`
- **Key Clarification from Hackathon FAQ:**
  > *"Does the whole app need to be hosted on Nebius AI Cloud?"*
  > *"No. The entire frontend/backend does not have to be hosted on Nebius AI Cloud. A genuine runtime call to Nebius Token Factory using an eligible NVIDIA open-source model can satisfy the platform requirement."*
- **Judge Access Requirement:**
  > *"Submissions must provide a working demo or test build accessible to judges free of charge through the judging period."*

### 2.2 Hosting Platform Constraints & Card Policy Realities
1. **Nebius Cloud Compute:**
   - Nebius Token Factory provides serverless API inference for NVIDIA models (`nvidia/Nemotron-3_5-Lightning`).
   - Nebius does NOT provide a permanent free web hosting tier for persistent 24/7 web applications. Running a persistent VM on Nebius Compute incurs hourly charges that would rapidly drain promotional credits or bill personal payment cards over the judging window.
2. **Hugging Face Spaces (Compute / Docker):**
   - **Current Platform Reality:** While CPU Basic hardware has a $0/hr rate, Hugging Face **requires a paid subscription (PRO account) or an attached payment card** to create new Docker/compute Spaces.
   - Instructing a non-expert operator to create a Docker Space violates the Zero-Cost Law unless the operator already possesses an existing paid entitlement.
   - If an operator with pre-existing entitlement deploys to HF Spaces Docker, the configuration requires `app_port: 8080` in `README.md` YAML frontmatter.
3. **GitHub Pages (Primary Zero-Cost Judge Access Path):**
   - **100% Free, Zero Card Required:** Built into GitHub for public repositories.
   - **Guaranteed Availability:** Accessible 24/7 through the December 15, 2026 judging period and beyond without ephemeral container sleep, teardown, or billing risk.
   - **Decoupled Architecture:** Serves pre-compiled, secret-safe, integrity-verified Basebreak Judge UI HTML (generated via `basebreak ui <run_id> --output ...`) and canonical public receipt JSON (`basebreak receipt <run_id> --format json --output ...`).
   - **Persistence Guarantee:** Public artifacts are committed to git or GitHub Pages branch, making evidence immune to container restarts or ephemeral disk wipes.
4. **Hugging Face Static Spaces (Alternative Zero-Cost Static Path):**
   - Free static HTML/JS hosting (`sdk: static`) on Hugging Face without requiring Docker compute or payment card.

---

## 3. Platform Comparison Matrix

| Hosting Option | Web / UI Host | Execution Runtime | Personal Spend | Card Required | Uptime / Sleep Risk | Eligibility Compliance |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Option A: GitHub Pages (Selected Primary)** | GitHub Pages CDN | Operator local / CI CLI | **$0.00** | **NO** | 100% Uptime (Global CDN) | **Fully Compliant (Zero-spend test build)** |
| **Option B: HF Static Space** | Hugging Face Static | Operator local / CI CLI | **$0.00** | **NO** | High (Static CDN) | **Fully Compliant** |
| **Option C: HF Docker Space** | Hugging Face Docker | Deployed Container | $0.00 (if PRO/card held) | **YES (Card/PRO needed to create)** | Sleeps on inactivity | Compliant only with pre-existing entitlement |
| **Option D: Nebius Compute VM** | Nebius Cloud VM | Nebius VM | >$50 - $200+ | **YES (Violates $0 Law)** | High cost | Disqualified by Zero-Cost Law |

---

## 4. Selected Architecture: Decoupled Public Judge Presentation & Trusted Execution Runtime

```
   ┌─────────────────────────────────────────────────────────────┐
   │                  PUBLIC JUDGE ACCESS LAYER                  │
   │  GitHub Pages / HF Static Space (Zero Cost, No Card Needed) │
   │                                                             │
   │  ┌───────────────────────┐     ┌─────────────────────────┐  │
   │  │ Single-Screen Judge   │     │ Canonical Public        │  │
   │  │ Verification UI (HTML)│     │ Receipt (JSON)          │  │
   │  └───────────────────────┘     └─────────────────────────┘  │
   │         ▲                                   ▲               │
   └─────────┼───────────────────────────────────┼───────────────┘
             │ Exported HTML                     │ Exported JSON
             │ (basebreak ui --output ...)       │ (basebreak receipt ...)
   ┌─────────┴───────────────────────────────────┴───────────────┐
   │             TRUSTED OPERATOR EXECUTION RUNTIME              │
   │     Local Machine / Isolated CI / Container Environment     │
   │                                                             │
   │  - Verification Orchestrator (BasebreakApiServer / CLI)     │
   │  - Three-World Causal Verification Engine                   │
   │  - Protected Surfaces & Secret Redaction Policy             │
   │  - Nebius Token Factory Adapter (Protected Operator Token)  │
   │  - Durable Local Persistence (/data/runs or --runs-dir)     │
   └─────────────────────────────────────────────────────────────┘
```

### 4.1 Topology & Responsibilities
1. **Public Read-Only Judge Experience:**
   - Signed-out judges access the published verification UI freely without accounts, credentials, or payment.
   - Public artifacts are generated directly from genuine verification runs using `basebreak ui <run_id> --output ...` and `basebreak receipt <run_id> --format json --output ...`.
   - Never fabricates evidence, live runs, or demo results.
   - Zero promotional or personal money consumed by judges.
2. **Trusted Execution Boundary:**
   - Verification execution (POST `/v1/runs`) and run publication (POST `/v1/runs/{id}/publish`) are strictly protected by `BASEBREAK_BEARER_TOKEN` (or `BASEBREAK_API_TOKEN`).
   - Mutations fail closed: anonymous callers can never execute verifications or drain API credits.
3. **Durable Persistence Across Restarts:**
   - Stored in persistent runs directory via `BASEBREAK_RUNS_DIR` environment variable or `--runs-dir` CLI option.
   - Survives process restart; `recover_from_disk` validates receipt integrity before restoring publication state.
4. **Reproducible Container Package:**
   - Multi-stage Docker image built on `python:3.11-slim` with rootless user `appuser:appgroup` (UID 10001).
   - Injects exact git commit SHA at build time via `BUILD_COMMIT_SHA` argument.
   - Verified via automated GitHub Actions `container-build` smoke test.

---

## 5. Security & Operator Guardrails

- **Zero Personal Spend:** Target spend strictly $0.00.
- **Fail-Closed Default:** Server defaults to read-only judge mode if no Bearer token is configured; all mutation endpoints return `401 Unauthorized`.
- **Integrity Guarantee:** Every public receipt served is cryptographically checked via `verify_public_receipt_integrity`. Tampered records are rejected with `400 Bad Request`.
- **Public Cloud Deployment Boundary:** Actual public cloud deployment remains `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN` until explicit operator approval.
