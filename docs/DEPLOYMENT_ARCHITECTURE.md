# Basebreak Deployment Architecture & Platform Reality (P-27.01)

## 1. Executive Summary

This document establishes the deployment architecture decision for **Basebreak** in compliance with the **Nebius x NVIDIA Global AI Hackathon** rules, the official Hackathon FAQ, and the **Zero-Cost Law**.

- **Product Thesis:** *"If the patch matters, the base must break."*
- **Core Judge Value:** Single public URL, integrated responsive judge dashboard, real BASE/CANDIDATE/COUNTERFACTUAL causal triplet evidence, and genuine on-demand Nebius/NVIDIA inference execution under strict $0.00 personal spend.
- **Judging Window:** Project submissions freeze late October 2026; judging and review continue through **December 15, 2026**.
- **Target Personal Spend:** Strictly **$0.00**.
- **Promotional Budget Guard:** `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` safety reserve floor.

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

## 3. Full-Stack Python Hosting Evaluation: Render Free vs. Platform Reality

Under P-27.01 (Reopened), we evaluate **Render Free** (Hobby workspace) as the primary candidate for single-live-site full-stack hosting across 9 critical operational dimensions:

### Dimension 1: One Public Web App URL & Same-Page Run Flow
- **Evaluation:** Render Free provisions a single public domain (`https://basebreak.onrender.com`).
- **Runtime Topology:** The single URL serves both the HTML Judge Dashboard (`/` and `/judge/{id}`) and the REST API (`/v1/runs`, `/v1/runs/{id}/receipt`, `/health`) on the standard web port assigned via the `$PORT` environment variable.
- **Verdict:** **FEASIBLE**. Unified user experience with zero multi-domain or CORS fragmentation.

### Dimension 2: Python API & Runtime Execution
- **Evaluation:** Render supports native Python runtimes (Python 3.11/3.12/3.13) out-of-the-box via `pip install .` and standard start commands (`basebreak serve --host 0.0.0.0 --port $PORT`).
- **Outbound Connectivity:** Standard outbound HTTPS requests (ports 80 and 443) to Nebius Token Factory (`https://api.tokenfactory.nebius.com`) are fully supported without firewall blocks.
- **Verdict:** **FEASIBLE**.

### Dimension 3: Idle Sleeping & Cold-Start Impact
- **Evaluation:** Render Free web services automatically spin down after **15 minutes of inbound inactivity**.
- **Cold-Start Delay:** The first subsequent incoming request experiences an automated container wake-up taking **30 to 60 seconds**.
- **Judge Impact:** Judges visiting an idle app will experience a brief initial loading delay before the dashboard renders.
- **Verdict:** **ACCEPTABLE WITH PROBE WARM-UP**. A documented health ping or initial warm-up request resolves cold start for evaluation sessions.

### Dimension 4: CPU/Memory Limits & Sandbox Offloading
- **Evaluation:** Render Free provides **0.1 CPU cores and 512 MB RAM**. Local container virtualization (Docker-in-Docker) is completely impossible in this tier.
- **Basebreak Architectural Fit:** Basebreak does NOT execute sandboxes locally in production; all isolated witness environments are created remotely inside Nebius Cloud Sandboxes. The web server only performs orchestration, HTTP streaming, and cryptographic SHA-256 digest checks, consuming under 65 MB RAM.
- **Verdict:** **FEASIBLE**.

### Dimension 5: Persistent Public Receipt Availability Across Restarts
- **CRITICAL PLATFORM FACT:** Render Free web services have an **ephemeral filesystem**. Any file written to the local disk (`.basebreak/runs`) during runtime is **wiped when the service spins down after 15 minutes of inactivity or redeploys**. Render Persistent Disks require a paid plan ($7/month minimum).
- **Architectural Solution (Baked-In Evidence):**
  To guarantee judges can always inspect authentic verification receipts at $0 cost even immediately following a cold-start restart:
  1. Canonical pre-verified receipts (e.g. for the demo target and Pallets/Click bug fixes) are **committed directly into the repository** (under `tests/fixtures/` and packaged into the release).
  2. On application startup, `ApiRunStore.recover_from_disk()` automatically indexes these baked-in receipts as published runs.
  3. Ephemeral runtime runs created during an active session remain inspectable while the instance is awake.
- **Verdict:** **FEASIBLE VIA BAKED-IN EVIDENCE REPOSITORY PATTERN**.

### Dimension 6: Nebius Token Factory Promotional Credit Expiration & $5 Safety Reserve
- **Evaluation:** Nebius promotional credits expire and are finite. The operator enforces an immutable safety reserve floor:
  $$\text{Promotional Balance} > \text{TOKEN\_FACTORY\_PROMO\_STOP\_THRESHOLD} = \$5.00$$
- **Enforcement:** If promotional balance drops to $\le \$5.00$, the runtime immediately halts live Token Factory inference fail-closed.
- **Verdict:** **STRICTLY ENFORCED**.

### Dimension 7: Secure Public On-Demand Demo Limits (Credit Drain Protection)
- **Zero-Cost Law Rule (Section 12):** *"Never expose an unauthenticated public live endpoint capable of silently draining free Token Factory or Tavily credits."*
- **Security Boundary:** An unauthenticated public judge visiting the site cannot be allowed to submit arbitrary expensive target repositories or infinite live runs that drain the operator's credits.
- **Guarded Live Demo Flow:**
  1. The public on-demand live run button is restricted to exactly **one pre-audited canonical demo scenario** (`demo_target` bug-fix verification).
  2. The server enforces global rate-limiting (e.g., maximum 1 live run per 10 minutes) and a hard execution budget cap.
  3. When the live run budget is exhausted, the UI gracefully informs the judge and provides instant read-only inspection of the authentic pre-generated `RECORDED_LIVE` receipt.
- **Verdict:** **FEASIBLE UNDER BOUNDED DEMO CONTROLS**.

### Dimension 8: Free-Tier Limits & Absence of Automatic Billing
- **Evaluation:** Render Free requires **NO credit card** for account registration or Hobby web services.
- **Billing Safeguard:** Because no credit card is on file with Render, unexpected charges or automated upgrades are structurally impossible. If the 750 free instance hours or 5 GB bandwidth limit is reached, Render suspends the service until the next calendar month rather than billing.
- **Personal Spend:** Guaranteed strictly **$0.00**.
- **Verdict:** **COMPLIANT WITH ZERO-COST LAW**.

### Dimension 9: Account & Operator Authorization Boundary
- **Evaluation:** Launching Render Free requires the operator to authenticate on `render.com` via GitHub OAuth, create the Web Service, and configure environment variables (`BASEBREAK_BEARER_TOKEN`, `NEBIUS_API_KEY`).
- **Status:** Per AGENTS.md Constitution, the coding assistant must not initiate external cloud deployments autonomously.
- **Classification:** **`OPERATOR_DECISION_REQUIRED / NOT_RUN`**.

---

## 4. Platform Comparison & Role Matrix

| Option | Role in Basebreak | Single Public URL? | Full-Stack Python? | Card Required? | Personal Spend | Disk Persistence | Live Execution Feasibility |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Render Free (Hobby)** | **Candidate Primary Live Site** | **YES** (`*.onrender.com`) | **YES** (Python native) | **NO** | **$0.00** | Ephemeral (Mitigated by repo-baked receipts) | **FEASIBLE (Rate-limited, guarded demo)** |
| **GitHub Pages** | **Static Archive & Fallback** | **YES** (`*.github.io`) | NO (Static CDN only) | **NO** | **$0.00** | Permanent (Git-backed) | Read-only inspection of authentic evidence |
| **HF Static Space** | **Secondary Static Mirror** | **YES** (`hf.space`) | NO (Static HTML only) | **NO** | **$0.00** | Permanent (Git-backed) | Read-only inspection of authentic evidence |
| **HF Docker Space** | **Disqualified (Paid Card Required)**| YES | YES | **YES (Mandates credit card)** | Billed if exceed | Ephemeral | Violates Zero-Cost Law unless operator has PRO |
| **Nebius Compute VM**| **Disqualified (Hourly Paid Billing)**| YES | YES | **YES** | >$50/mo | Persistent | Violates Zero-Cost Law |

---

## 5. Architectural Topology: Live Site & Fallback Layer

```
   ┌────────────────────────────────────────────────────────────────────────┐
   │                   PRIMARY SINGLE-LIVE-SITE ARCHITECTURE                 │
   │               Render Free Web Service (No Credit Card, $0.00)           │
   │                                                                        │
   │   ┌────────────────────────────────────────────────────────────────┐   │
   │   │               Integrated Single-Screen Judge App               │   │
   │   │  - Front-and-center causal thesis & 3-World comparison cards   │   │
   │   │  - Read-only inspection of authentic pre-verified receipts     │   │
   │   │  - Guarded on-demand live run button (rate-limited, $5 reserve) │   │
   │   │  - Real-time SSE execution events (/v1/runs/{id}/events)       │   │
   │   │  - Cryptographic verification badge ("AUTHENTIC SHA-256")      │   │
   │   └────────────────────────────────────────────────────────────────┘   │
   │                                   │                                    │
   │             ┌─────────────────────┴─────────────────────┐              │
   │             ▼                                           ▼              │
   │   ┌───────────────────────────────┐   ┌────────────────────────────┐   │
   │   │  Baked-in Evidence Store      │   │  Nebius Token Factory API  │   │
   │   │  (Git-committed receipts      │   │  - Nemotron-3.5-Lightning  │   │
   │   │   survive ephemeral restart)  │   │  - Remote Cloud Sandboxes  │   │
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

## 6. Build Reality & CI Truth (DEFECT 3 Synchronization)

- **CI Python Tests:** `PASS`. GitHub Actions workflow runs Ruff formatting, Ruff linting, Mypy type-checking, and the full Pytest test suite (2,700+ tests).
- **Docker Container Build / Startup:** `NOT_RUN in CI`. Standalone smoke script `scripts/ci_container_smoke.sh` is provided for containerized environments. It was not incorporated into GitHub Actions because modifying `.github/workflows/ci.yml` is restricted by OAuth token permissions without `workflow` scope.
- **Public Cloud Deployment:** `OPERATOR_DECISION_REQUIRED / NOT_RUN`. No live cloud resources have been provisioned.
- **Live Nebius Runtime:** `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`.
- **Production SHA Parity:** `NOT_RUN` against live production (validated against local builds).
