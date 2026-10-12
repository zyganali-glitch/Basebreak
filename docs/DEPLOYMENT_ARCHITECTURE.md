# Basebreak Deployment Architecture & Platform Reality (P-27.01)

## 1. Executive Summary

This document establishes the deployment architecture for **Basebreak** in compliance with the **Nebius x NVIDIA Global AI Hackathon** rules, the official Hackathon FAQ, and the **Zero-Cost Law**.

- **Product Thesis:** *"If the patch matters, the base must break."*
- **Judging Period:** Project submissions freeze late October 2026; judging and review continue through **December 15, 2026**.
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

### 2.2 Nebius Cloud Pricing & Platform Reality
1. **Nebius Token Factory / Studio:**
   - Serverless LLM inference API (OpenAI-compatible) for open-source models including `nvidia/Nemotron-3_5-Lightning` and `nvidia/nemotron-3-super-120b-a12b`.
   - Bounded Token Factory Sandbox execution for isolated ephemeral environments.
   - Pay-per-token / metered billing against promotional credits.
   - **Critical Fact:** Nebius does NOT provide a permanent free web hosting tier for persistent 24/7 web application servers. Running a persistent GPU or CPU VM on Nebius Compute incurs hourly charges that would rapidly drain promotional credits or incur personal credit-card charges over the 6-8 week judging window.
2. **Personal Spend Protection ($0.00 Law):**
   - Hosting a 24/7 web service directly on paid Nebius Compute is strictly forbidden under the Zero-Cost Law.
   - Unauthenticated public endpoints that trigger live Nebius inference are strictly forbidden because bots or judges could silently drain promotional credits.

---

## 3. Comparison of Deployment Options

| Architecture Option | Web/API Server Host | Inference Runtime | Estimated Spend (Oct–Dec 2026) | Judge Access | Security / Quota Protection | Eligibility Compliance |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Option A: Pure Nebius Compute VM** | Nebius Cloud VM (Ubuntu/Docker) | Nebius Token Factory | **>$50 - $200+** (Violates $0 Law) | Free | High Risk: Card billed after promo exhaustion | Compliant, but financially non-viable |
| **Option B: Serverless Container + Token Factory** | Hugging Face Spaces (Docker) / Render Free / Fly.io Free | Nebius Token Factory | **$0.00** | Free public URL | Fail-closed Bearer auth for mutations; public read-only judge UI | **Fully Compliant (FAQ explicitly validates)** |
| **Option C: Reproducible Standalone Docker Package** | Local/Operator Container or Self-Hosted | Nebius Token Factory | **$0.00** | Reproducible local & curl verification | Local-first, zero egress risk | **Fully Compliant as test build** |

---

## 4. Selected Architecture Decision: Hybrid Standalone / Container with Zero-Cost Public Read-Only Judge Mode

### 4.1 Topology
1. **Application Core:**
   - Standalone Python 3.11+ zero-external-framework HTTP daemon (`BasebreakApiServer`).
   - Serves both REST API (`/v1/runs`, `/v1/runs/{id}/receipt`, `/v1/runs/{id}/evidence`) and responsive Judge UI (`/`, `/judge`, `/judge/{run_id}`).
   - Embedded static assets, zero CDN dependencies, zero external npm/node requirements.
2. **Public Read-Only Judge Experience:**
   - Signed-out judges access `/`, `/judge`, and `/judge/{run_id}` freely without credentials, accounts, or payment.
   - Published verified receipts and factual verification runs are delivered with cryptographic SHA-256 integrity checks.
   - No inference is run for read-only viewing; zero promotional credits consumed by judges.
3. **Execution Boundary / Live Inference:**
   - POST `/v1/runs` (verification run creation) strictly requires `Authorization: Bearer <token>`.
   - Fail-closed: anonymous callers cannot execute verifications or drain API credits.
   - Live Nebius calls require operator credential configuration (`NEBIUS_API_KEY`, `NEBIUS_PROJECT_ID`) and explicit `allow_live=True` flag.
4. **Containerization & Deployment Target:**
   - Minimal reproducible OCI/Docker container image based on `python:3.11-slim`.
   - Single command local run: `docker run -p 8080:8080 basebreak:latest`.
   - Production deployment targets supported: Hugging Face Spaces Docker (free tier, persistent public HTTPS URL) or Render Free Web Service.
   - Source commit SHA, version, and build timestamp injected at build time and served at `/health` and `/v1/status`.

---

## 5. Security & Operator Guardrails

- **Secret Safety:** No credentials baked into Dockerfile, images, or default configs.
- **Fail-Closed Default:** Server defaults to read-only judge mode if no `BASEBREAK_BEARER_TOKEN` is configured; mutation endpoints return `401 Unauthorized`.
- **Integrity Guarantee:** Every public receipt served is cryptographically checked via `verify_public_receipt_integrity`. Tampered records are rejected with `400 Bad Request`.
- **Public Deployment Authorization Gate:** Public deployment to external cloud hosts requires explicit operator approval before launching cloud instances.
