# Basebreak

> **If the patch matters, the base must break.**

Basebreak is a planned causal verification runtime for AI-written software changes.

Instead of accepting "tests are green" as proof, Basebreak is designed to independently challenge the candidate patch in clean execution environments and ask whether the requested behavior fails on the trusted base and succeeds on the candidate.

---

## Canonical Claim

**Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green.**

---

## The Problem

AI coding agents are rapidly writing and modifying software. Today, verification typically stops at:
- "The model says it fixed the bug."
- "The test suite passes."
- "Linter and type checker are green."

None of these prove that the AI-written change **caused** the intended behavioral fix.

### Why Green Tests Are Not Proof

1. **Pre-existing Green Suites:** The existing tests may have been passing before the patch was even applied (vacuous verification).
2. **Weakened Assertions:** An autonomous agent may modify or delete test assertions to force a passing exit code.
3. **Coincidental Passes:** The patch may touch unrelated code while leaving the underlying defect latent.
4. **Self-Certification:** An agent evaluating its own patch has an inherent conflict of interest.

---

## The Basebreak Thesis

> `If the patch matters, the base must break.`

For any behavioral bug fix claiming to solve a problem:
- The behavior **must fail** on the trusted base revision under an independent witness.
- The behavior **must pass** on the candidate revision under the exact same witness.
- If the change delta is subtracted (counterfactual), the behavior **must fail again**.

Without this transition, there is no evidence of causal necessity.

---

## Planned Causal Verification Flow

```
+------------------+       +-------------------------+
| Engineering Task | ----> |    Contract Compiler    |
+------------------+       +-------------------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
            v                                               v
+------------------------+                     +------------------------+
|    Builder Runtime     |                     |   Verifier Isolation   |
| (Nemotron in Sandbox)  |                     |  (Independent Context) |
+------------------------+                     +------------------------+
            |                                               |
            v                                               v
     [Candidate Patch]                            [Independent Witness]
            |                                               |
            +-----------------------+-----------------------+
                                    |
                                    v
                     +-----------------------------+
                     |  Causal Two-World Engine    |
                     +-----------------------------+
                     | 1. Witness on BASE:         |
                     |    -> FAIL (required)       |
                     | 2. Witness on CANDIDATE:    |
                     |    -> PASS (required)       |
                     | 3. Witness on COUNTERFACTUAL|
                     |    -> FAIL (necessity)      |
                     +-----------------------------+
                                    |
                                    v
                      [Deterministic Causal Receipt]
```

### Simple BUG_FIX Example

| World | Revision | Witness Execution | Meaning |
|---|---|:---:|---|
| **BASE** | Trusted base commit | **FAIL ❌** | The bug actually exists in the baseline |
| **CANDIDATE** | Base + AI patch | **PASS ✅** | The patch satisfies the behavioral requirement |
| **COUNTERFACTUAL** | Candidate minus relevant patch | **FAIL ❌** | The tested patch delta was necessary for this observed transition under the specified witness and constructed counterfactual |

If BASE passes, the witness is vacuous. If CANDIDATE fails, the patch does not satisfy the witness. If COUNTERFACTUAL passes, the subtracted patch delta was not necessary for the observed passing transition under this witness.

---

## Why Builder and Verifier Are Separated

Basebreak is designed to enforce strict separation between:
- **The Builder:** The AI agent that plans, edits code, and runs development tests in a sandbox.
- **The Verifier:** An independent context that generates sealed behavioral witnesses from the accepted contract and trusted base, without Builder visibility.

A builder cannot inspect the verifier's hidden challenge, and a builder cannot certify its own output.

---

## Competition Target & Expected Stack

Target: **Coding and Agentic Engineering Track** at the **Nebius x NVIDIA Global AI Hackathon**.

Expected core runtime stack (subject to live discovery in P-01):
- **Nebius Token Factory:** Managed model inference and Token Factory Sandboxes.
- **NVIDIA Nemotron:** Open-source foundation models for builder and verifier workloads.
- **Tavily Search API:** Conditional grounding for current CVEs/security advisories and library migration facts (only where external truth is materially required).

---

## Evidence Honesty & Provenance

Basebreak is designed to label all evidence deterministically by provenance (PLANNED capability):
- `FIXTURE` — static test fixtures used for internal unit validation.
- `LOCAL_EXECUTION` — commands executed in the local operator environment.
- `LIVE_NEBIUS` — commands and inference executed live against Nebius / NVIDIA infrastructure.
- `RECORDED_LIVE` — verifiable replays of previously captured live runs.

These are planned provenance labels, not PASS/FAIL verdicts. Basebreak will never substitute mocks for required live evidence.

---

## Current Implementation Status

> **STATUS: DEPLOYMENT READINESS & JUDGE EXPERIENCE (Phase P-27 / P-28)**

### Implemented & Tested (P-00 through P-28):
- **Governance & Baseline (P-00):** Agent constitution, operator guidance laws, zero-cost policy, and verified competition contract (`AGENTS.md`, `GEMINI.md`).
- **Platform Discovery & Adapters (P-01, P-05):** Nebius Token Factory inference & sandbox adapters, telemetry normalization, and secret-safe execution logs.
- **Provider-Neutral Domain Contracts (P-02):** Immutable task, change-semantics, sandbox identity, and causal receipt schemas.
- **Deterministic Evidence Store (P-03):** Content-addressed artifact hashing, append-only facts, and tamper-evident storage.
- **Security & Untrusted-Code Policy (P-04):** Secret redaction, protected surfaces, and execution timeout guards.
- **Contract Compiler (P-06):** Invariant locking and frozen contract digest generation (`FrozenContract`).
- **Builder Runtime (P-07):** Bounded file editing and command execution loop in clean sandboxes.
- **Verifier Isolation & Witness Generation (P-08, P-09):** Sealed test generators independent of Builder context.
- **Causal Two-World Engine (P-10):** Deterministic BASE (FAIL) vs CANDIDATE (PASS) differential execution.
- **Counterfactual Third Run (P-11):** Candidate delta subtraction proving causal necessity.
- **Minimal Causal Slices (P-12):** AST-based minimal change extraction.
- **Change-Semantics Expansion (P-13):** BUG_FIX, FEATURE, REFACTOR, SECURITY_FIX, PERFORMANCE, and DEP_API_CHANGE.
- **Sealed Repair Loop (P-14):** Minimized failure feedback without revealing private witness challenges.
- **Risk-Adaptive Budget (P-15):** Deterministic risk tiering and execution budgeting.
- **Grounded External Truth (P-16):** Tavily adapter and grounded CVE/migration contracts.
- **Causal Coverage & Public Receipt (P-17, P-18):** Cryptographic verification receipts with SHA-256 integrity digests.
- **CLI, GitHub, and API Surface (P-19, P-20, P-21):** Full developer CLI, GitHub Actions webhook integration, and FastAPI server.
- **Judge & Operator UI (P-22, P-28):** Single-screen responsive dashboard, "Why Green CI Lies" explainer, 3-world step tags, distinct 5-state verdict views, and WCAG AA/AAA accessibility.
- **Killer Demo Scenarios (P-23):** ResetVault 3-world disk execution and canonical Pallets/Click upstream bug replay.
- **Adversarial Campaign & Recovery (P-24, P-25):** 8-vector security defense, durable run state manager, and CAS deduplication.
- **Performance & Model Routing (P-26):** Provider-verified Nemotron routing (`nvidia/Nemotron-3_5-Lightning`).
- **Deployment Packaging & Parity (P-27):** Rootless `Dockerfile`, health readiness probe, source SHA parity endpoint, and signed-out judge access.

### Explicit Unexecuted Live Obligations (NOT_RUN):
- **P-16.05:** Live Tavily web search API call held at `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`.
- **P-23.04–P-23.07:** Live Nebius Token Factory inference & sandbox runs held at `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`.
- **P-23.08:** Upstream Click live execution held fail-closed at `PreliminaryVerdict.BLOCKED` pending isolated container sandbox runtime.
- **P-26.02:** Live model benchmark comparison held at `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`.
- **P-27.03:** Public cloud endpoint deployment held at `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN` pending operator deployment.
- **P-27.06:** Deployed live Nebius/NVIDIA runtime proof held at `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`.

---

## Running the Judge Server & Container

```bash
# 1. Local development / judge server
basebreak serve --host 127.0.0.1 --port 8080

# 2. Build and run reproducible container locally
docker build --build-arg BUILD_COMMIT_SHA=$(git rev-parse HEAD) -t basebreak .
docker run -p 8080:8080 -e BASEBREAK_BEARER_TOKEN=secret -e BASEBREAK_RUNS_DIR=/data/runs basebreak
```

Unauthenticated signed-out judges can freely inspect published verification runs:
- `GET /` or `GET /judge` — Published judge dashboard
- `GET /health` — Health readiness and source commit SHA parity
- `GET /judge/{run_id}` — Published run visual evidence (tamper-checked before rendering)
- `GET /v1/runs/{run_id}/receipt` — Cryptographic public verification receipt

Mutating endpoints (`POST /v1/runs`, `POST /v1/runs/{run_id}/publish`), private runs, and raw execution internals (`/evidence`, `/events`, raw run metadata) strictly require operator `Authorization: Bearer <token>`. Both `BASEBREAK_BEARER_TOKEN` and `BASEBREAK_API_TOKEN` are supported environment variables.

---

## Development & Tooling Baseline

Basebreak uses a minimal Python packaging and validation baseline (Python `>=3.11`).

### Clean-Checkout Setup

Create and activate a virtual environment, then install the package in editable mode with development dependencies:

```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

### Canonical Root Validation Commands

Run these deterministic gates from the repository root:

```bash
# 1. Format check
python -m ruff format --check .

# 2. Lint check
python -m ruff check .

# 3. Type check
python -m mypy src tests

# 4. Unit tests
python -m pytest
```

All four gates must pass cleanly. All runtime capabilities (causal engine, Builder, Verifier, Nebius adapters, sandboxes) remain planned and unimplemented at this phase.

---

## Security & Zero-Cost Boundary

- **Zero Personal Spend (Frozen Policy Requirement):** Zero Personal Spend is a frozen Basebreak requirement. Development and judge-access architecture must use verified free tiers/promotional credits or fail closed; a guaranteed zero-cost working-project path through the full judging period is not yet proven and remains subject to later live platform/account/deployment verification. Under the operator-approved `TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION`, a payment card was attached solely to enable Builder Program promotional credit activation, while target personal spend remains $0.00, post-promotional paid usage is strictly forbidden, and an operator-enforced $5.00 safety reserve floor is maintained.
- **Untrusted Code Policy (Planned Design & Policy):** Target repositories are treated as untrusted code intended to execute only inside isolated sandboxes with strict runtime resource and timeout enforcement once the runtime sandbox execution layer is implemented.
- **Secret Redaction (Current Policy & Planned Runtime Guard):** No API keys, credentials, or private identifiers are stored in repository history, static documentation, or public assets. Runtime secret redaction in prompts and execution evidence logs will be enforced once provider runtime adapters are implemented.

---

## Roadmap & Documentation

- [Master Execution Plan](plans/BASEBREAK_MASTER_EXECUTION_PLAN.md) — complete phase-by-phase engineering plan
- [Handoff State](docs/HANDOFF.md) — active micro-task and verified baseline SHA
- [Coding Constitution](AGENTS.md) — immutable agent laws and authority rules
- [Competition Contract](docs/COMPETITION_CONTRACT.md) — verified hackathon requirements and criteria
- [Competition Strategy](docs/COMPETITION_STRATEGY.md) — value proposition and judge alignment
- [Operator Requirements](docs/OPERATOR_REQUIREMENTS.md) — frozen operator constraints and zero-cost policy
- [Competition Feedback Log](docs/COMPETITION_FEEDBACK_LOG.md) — factual append-only feedback ledger

---

## License

[Apache-2.0](LICENSE) © 2026 Mehmet Aydogan
