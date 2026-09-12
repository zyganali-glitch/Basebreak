# Basebreak

> **If the patch matters, the base must break.**

Basebreak is a causal verification runtime for AI-written software changes.

Instead of accepting "tests are green" as proof, Basebreak independently challenges the candidate patch in clean execution environments and asks whether the requested behavior fails on the trusted base and succeeds on the candidate.

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

> **STATUS: PRE-IMPLEMENTATION GOVERNANCE (Phase P-00)**

All runtime capabilities described above are **PLANNED** and are not yet implemented.

| Component | Status | Target Phase |
|---|:---:|---|
| Repository Governance & Contracts | **ACTIVE** | P-00 |
| Live Platform Discovery | PLANNED | P-01 |
| Provider-Neutral Domain Contracts | PLANNED | P-02 |
| Deterministic Evidence Store | PLANNED | P-03 |
| Nebius / Nemotron Adapters | PLANNED | P-05 |
| Builder Runtime v1 | PLANNED | P-07 |
| Verifier Isolation & Witness Gen | PLANNED | P-08, P-09 |
| Causal Two-World Engine | PLANNED | P-10 |
| Minimal Judge UI & Killer Demo | PLANNED | P-22, P-23 |
| Live Deployment & Devpost Submit | PLANNED | P-27, P-32 |

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

- **Zero Personal Spend:** Basebreak development and judge access operate entirely within genuine free tiers and sponsor promotional credits. No credit cards, auto-billing, or paid upgrades.
- **Untrusted Code Policy:** Target repositories are treated as untrusted code executed only inside isolated sandboxes with strict resource and timeout limits.
- **Secret Redaction:** No API keys, credentials, or private identifiers are stored in repository history, prompts, evidence, or public assets.

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
