# P-01.06 — Phase Feasibility Decision and Architecture Freeze v0

- **Date/Time:** 2026-09-25 13:45 UTC (16:45 Local)
- **Starting Canonical Remote SHA:** `d74d8103c7048bdb1c73221bb690575cba43818f`
- **Active Micro-Task:** `P-01.06 — Phase feasibility decision and architecture freeze v0`
- **Decision:** **GO**
- **Execution Status:** EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE
- **Zero-Cost Policy Check:** SATISFIED (Target personal spend $0.00; beta sandboxes free of charge, promotional balance $25.00 untouched).

---

## 1. Feasibility Decision Summary

Based strictly and exclusively on deterministic runtime evidence gathered across `P-01.02` (real model inference), `P-01.03` (real sandbox execution), `P-01.04` (real repository materialization), and `P-01.05` (two clean independent executions), the core platform capabilities required to support Basebreak's causal verification runtime are proven feasible. The executor issues an unambiguous:

# **DECISION: GO**

The fundamental platform prerequisites (real Nemotron model call + real container sandbox execution + real repository materialization + two clean executions without mutable workspace bleeding) have been proven through live execution against official Nebius Token Factory infrastructure. No mock, simulation, or local checkout substitution was accepted.

---

## 2. Evidence Reconciliation Across P-01

| Task | Core Requirement | Proven Platform Fact | Provenance | Result |
|---|---|---|:---:|:---:|
| **P-01.02** | Real Nemotron model inference | `nvidia/Nemotron-3_5-Lightning` executed live via OpenAI-compatible endpoint; returned deterministic output; latency 0.74s; zero secret leakage | `RECORDED_LIVE` | **PASS** |
| **P-01.03** | Real Token Factory sandbox execution & capability probe | Disposable execution of `echo BASEBREAK_SANDBOX_OK` succeeded in 0.338s with exit code 0; teardown confirmed; non-disposable checkpoint created immutable layer `28f5d6d6-f977-42a8-94b5-d8db23e62c8c`; child execution spawned successfully from snapshot | `RECORDED_LIVE` | **PASS** |
| **P-01.04** | Live repository materialization inside sandbox | Cloned canonical repository over HTTPS in `tag:astral/uv:python3.11-alpine`; resolved exact base SHA `d74d8103c7048bdb1c73221bb690575cba43818f` and tree SHA `aa54850bf7ddcd222539d3e0b6fe5059cb1d693d`; executed 28 pytest tests with exit code 0 in 5.062s | `RECORDED_LIVE` | **PASS** |
| **P-01.05** | Two independent clean sandbox executions | Created two unique execution instances (`01a0d8ce-9ce0-7310-846b-8b556856ce48` & `01a0d8ce-9f6c-7314-98c8-a30d7cef5af7`); verified zero workspace bleeding (`RUN1_MARKER_LEAKED_TO_RUN2=NO`); verified identical cryptographic tree hash; captured independent outputs; teardown confirmed for both | `RECORDED_LIVE` | **PASS** |

---

## 3. Architecture Freeze v0

With live platform realities proven, the Basebreak architecture v0 is frozen around the following concrete primitives:

### A. Inference Engine
- **Primary Model (LIVE_PROVEN):** `nvidia/Nemotron-3_5-Lightning`
  - *Provenance & Verification Level:* `LIVE_PROVEN` in `P-01.02` (executed live via `/v1/chat/completions` and corroborated via operator reproduction in the Token Factory Playground).
  - *Intended Runtime Role:* Builder patch generation, independent witness generation, and core causal pipeline orchestration.
  - *Empirically Verified Scope:* Verified for low-latency live HTTPS completion (0.72s duration, valid reasoning token generation). Specific benchmark quality or causal-patch superiority was not measured in P-01 and is not claimed.
- **Candidate Deep Model (CATALOG_CONFIRMED / NOT_YET_LIVE_VALIDATED):** `nvidia/nemotron-3-super-120b-a12b`
  - *Provenance & Verification Level:* `CATALOG_CONFIRMED / NOT_YET_LIVE_VALIDATED / CANDIDATE_DEEP_MODEL`.
  - *Provider Availability:* Catalog-confirmed active in Nebius Token Factory (`GET /v1/models`).
  - *Intended Future Role:* Potential candidate for complex multi-file causal reasoning and verifier formulation in later phases.
  - *Runtime Constraint:* Not executed live in P-01. P-01.02 proved live connectivity with `nvidia/Nemotron-3_5-Lightning`, not the Super model. Its final runtime role, operational stability, and performance suitability require later bounded live validation before any implementation reliance.
- **Transport:** Official Token Factory OpenAI-compatible API (`https://api.tokenfactory.nebius.com/v1/chat/completions`).

### B. Sandbox Execution Engine
- **Platform:** Nebius Token Factory Sandboxes (REST API v1).
- **Isolation Boundary:** LinuxKit container VMs spun up on demand with configurable resource limits.
- **Base Environment:** `tag:astral/uv:python3.11-alpine` (standardized pre-warmed image containing Python 3.11 and uv).
- **Ephemeral Disposable Mode:** `disposable: true` by default for all test runs, ensuring automatic VM destruction, zero retained storage, and zero cross-test bleeding.
- **Checkpoint / Snapshot Mode:** `disposable: false` when capturing an immutable pre-materialized repository layer (`result_image_uuid`) to accelerate parallel runs without re-cloning.

### C. Independent Two-Clean-Environment Verification Spine
- **Thesis Invariant:** `BASE=FAIL, CANDIDATE=PASS`.
- **Execution Rule:** Verification of the BASE environment and CANDIDATE patch environment MUST always take place in distinct, non-communicating sandbox instances.
- **No Shared Workspace:** Shared volume mounts or mutable workspace reuse across runs is strictly forbidden.

### D. Zero-Cost & Spend Governance
- Sandboxes are verified free while in beta (*"Free while in beta — runs don't consume your credits"*).
- Promotional credit balance remains at `$25.00`.
- Personal spend remains strictly `$0.00`.
- Operator threshold floor: `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`.
