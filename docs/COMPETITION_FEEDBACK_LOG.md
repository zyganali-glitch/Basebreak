# Competition Feedback Log — Basebreak

Append-only factual log for mandatory Nebius x NVIDIA hackathon feedback.
This log may also be used as source material for the "Most Valuable Feedback" prize submission.

## Rules

- Record only genuinely observed experiences of the operator or Basebreak runtime.
- Never invent or fabricate feedback.
- Never store credentials, secrets, or private identifiers.
- Distinguish platform issue from operator error and Basebreak bug when known.
- Append only; do not delete or rewrite past entries.
- Each entry must have deterministic evidence or a clear reference.
- Allowed provenance is strictly limited to:
  - `LIVE_OBSERVATION` — hands-on runtime, API, SDK, or sandbox execution by Basebreak/operator.
  - `DOCUMENTATION_REVIEW` — when Basebreak/operator actually reviewed official documentation and the feedback concerns that direct experience.
- Third-party or community reports are strictly excluded from this competition feedback ledger; external feedback must never be synthesized as the operator's own experience.

## Entry Template

```
### F-NNN — [SHORT TITLE]

- **Date/Time:** YYYY-MM-DD HH:MM UTC
- **Provider/Tool:** Nebius Token Factory | Nebius AI Cloud | NVIDIA Nemotron | Tavily | Other
- **Feature/API:** [specific feature, endpoint, SDK, or UI element]
- **Task/Run Context:** [which Basebreak task or run triggered this observation]
- **What Worked Well:** [positive observation, if any]
- **Friction/Bug/Limitation:** [negative observation, if any]
- **Deterministic Evidence:** [error message, status code, log excerpt, screenshot reference — no secrets]
- **Developer Impact:** [how this affected development velocity, architecture, or cost]
- **Workaround:** [if any was found]
- **Concrete Product Suggestion:** [actionable improvement suggestion for the provider]
- **Severity/Value:** LOW | MEDIUM | HIGH | CRITICAL
- **Provenance:** LIVE_OBSERVATION | DOCUMENTATION_REVIEW
- **Status:** RESOLVED | UNRESOLVED | WORKAROUND_APPLIED
```

## Entries

### F-001 — Nebius Builder Program landing URL 404 / broken redirect

- **Date/Time:** 2026-09-12 11:45 UTC
- **Provider/Tool:** Nebius Token Factory
- **Feature/API:** Builder Program application page / URL navigation
- **Task/Run Context:** P-00.02 (Verify competition eligibility and terms against official sources)
- **What Worked Well:** Once located, the developer portal page (`https://dev.nebius.com/builders`) provided explicit, unambiguous promotional credit figures ($25 Token Factory + $25 Tavily) and clear 90-day expiry terms.
- **Friction/Bug/Limitation:** A previously referenced/encountered Nebius Builder Program URL (`https://nebius.com/builder-program`) returned HTTP 404 during P-00.02 research. The current Official Devpost Rules and active Builder Program portal use https://dev.nebius.com/builders.
- **Deterministic Evidence:** HTTP GET `https://nebius.com/builder-program` returned status 404 Not Found during research fetch on 2026-09-12; active application page was located at `https://dev.nebius.com/builders`.
- **Developer Impact:** Increases friction and creates confusion for new hackathon entrants attempting to verify promotional credit terms or apply for the Builder Program.
- **Workaround:** Located and documented the active URL `https://dev.nebius.com/builders` in project competition governance.
- **Concrete Product Suggestion:** Set up an HTTP 301 permanent redirect from `nebius.com/builder-program` to `dev.nebius.com/builders`.
- **Severity/Value:** LOW
- **Provenance:** DOCUMENTATION_REVIEW
- **Status:** WORKAROUND_APPLIED

### F-002 — Mandatory bank card onboarding requirement conflicts with zero-cost promotional participation

- **Date/Time:** 2026-09-12 14:00 UTC
- **Provider/Tool:** Nebius Token Factory
- **Feature/API:** Billing & Onboarding / Mandatory Bank Card Requirement
- **Task/Run Context:** P-01.01 (Discover current Nebius account/runtime/API/model reality from official docs and live account)
- **What Worked Well:** Comprehensive official documentation of billing mechanics, credit card auto-debit triggers, and promo code top-up procedure at `https://docs.tokenfactory.nebius.com/other-capabilities/billing-new.md`.
- **Friction/Bug/Limitation:** Official documentation states: "When you sign up for Nebius Token Factory, you are prompted to create a billing account during onboarding. Billing setup is mandatory—you cannot complete onboarding without it. Setting up a billing account requires a bank card... Your card is automatically charged in either of the following cases: At the start of the month, if your balance is negative; When the configured billing threshold is reached." This creates direct friction and credit-card liability risk for hackathon participants wishing to build exclusively using the promotional credits ($25 Token Factory + $25 Tavily) granted under the Builder Program.
- **Deterministic Evidence:** Official documentation at `https://docs.tokenfactory.nebius.com/other-capabilities/billing-new.md` retrieved on 2026-09-12 explicitly mandates a bank card during onboarding and automated debit when the balance becomes negative.
- **Developer Impact:** Prevents zero-cost-only developers and hackathon participants from onboarding safely unless an explicit card-free onboarding path exists for promo code holders or a guaranteed hard spending limit ($0.00 personal spend) can be configured.
- **Workaround:** Classified Zero-Cost Gate as OPERATOR_DECISION_REQUIRED; provided operator with strict screen-by-screen guidance in Turkish to inspect whether card entry is bypassable with a promo code and never enter card details without hard spending caps.
- **Concrete Product Suggestion:** Provide a "Hackathon / Builder Program Student Onboarding" mode that activates accounts using promo codes without requiring a bank card, or provide a user-toggleable hard spending cap ($0.00 post-promotional limit) that prevents automatic payment method charges.
- **Severity/Value:** HIGH
- **Provenance:** DOCUMENTATION_REVIEW
- **Status:** UNRESOLVED

### F-003 — Flagship NVIDIA model reported in error status in public API model catalog

- **Date/Time:** 2026-09-12 14:15 UTC
- **Provider/Tool:** Nebius Token Factory / NVIDIA Nemotron
- **Feature/API:** Public Model Catalog / `https://tokenfactory.nebius.com/api/public/models_info`
- **Task/Run Context:** P-01.01 (Discover current Nebius account/runtime/API/model reality from official docs and live account)
- **What Worked Well:** Token Factory provides outstanding machine-readable endpoints (`/model-catalog.md` and `/api/public/models_info`) exposing exact model IDs, parameters, quantization, context windows, and token pricing without requiring authentication.
- **Friction/Bug/Limitation:** The flagship 550B hybrid MoE NVIDIA model `nvidia/Nemotron-3-Ultra-550b-a55b` is reported in `status: "error"` in the public API catalog metadata, rendering it currently unavailable for safe development/inference.
- **Deterministic Evidence:** JSON field `"status":"error"` for `"name":"Nemotron-3-Ultra-550b-a55b"` returned by live HTTP GET to `https://tokenfactory.nebius.com/api/public/models_info` on 2026-09-12. In contrast, `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`, `nvidia/nemotron-3-super-120b-a12b`, and `nvidia/Nemotron-3_5-Lightning` are reported with `status: "active"`.
- **Developer Impact:** Basebreak cannot route inference to `nvidia/Nemotron-3-Ultra-550b-a55b`. Candidate selection must focus on active models: `nvidia/Nemotron-3_5-Lightning`, `nvidia/nemotron-3-super-120b-a12b`, or `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`.
- **Workaround:** Documented exact status in discovery artifact and flagged `nvidia/Nemotron-3-Ultra-550b-a55b` as degraded/error.
- **Concrete Product Suggestion:** Display status badges on the web catalog UI indicating whether a model is temporarily degraded or undergoing maintenance, and provide estimated restoration timelines in the API status response.
- **Severity/Value:** MEDIUM
- **Provenance:** LIVE_OBSERVATION
- **Status:** WORKAROUND_APPLIED
