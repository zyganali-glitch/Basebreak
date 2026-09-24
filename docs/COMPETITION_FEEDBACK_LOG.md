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
  - `LIVE_OBSERVATION` — hands-on runtime, API, SDK, sandbox execution, or direct operator-observed platform, account, and first-party support interactions.
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
- **Follow-up (2026-09-19):** Confirmed by direct Nebius Support communication (see F-005). Cardless activation using only Builder Program credits is not currently supported; payment card setup is strictly mandatory before promo redemption.

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

### F-004 — Tavily Free/Researcher onboarding provides card-free zero-cost access with promotional credits

- **Date/Time:** 2026-09-19 05:25 UTC
- **Provider/Tool:** Tavily
- **Feature/API:** Onboarding / Free Researcher Tier / Promotional Credit Allocation
- **Task/Run Context:** P-01.01 (Discover current Nebius account/runtime/API/model reality from official docs and live account — partner credit onboarding)
- **What Worked Well:** Tavily enabled seamless onboarding through the Free/Researcher path without requiring a bank or credit card. The user dashboard immediately allocated 1,000 monthly plan credits and 3,125 additional promotional credits. Usage-based payment was visibly disabled by default, providing complete peace of mind against surprise billing and perfectly honoring the Zero-Cost Law.
- **Friction/Bug/Limitation:** None observed during account setup and credit activation.
- **Deterministic Evidence:** Operator live dashboard on 2026-09-19 shows 1,000 monthly credits, 3,125 promotional credits, usage-based payment visibly disabled, and zero payment cards configured.
- **Developer Impact:** Ensures Basebreak can safely plan and test P-16 external grounding integration without financial liability, personal card entry, or risk of unexpected pay-as-you-go debit.
- **Workaround:** N/A (Standard card-free onboarding path operated as expected).
- **Concrete Product Suggestion:** Continue offering this card-free developer/researcher onboarding model; it serves as a best practice for hackathon partner tool integrations.
- **Severity/Value:** LOW
- **Provenance:** LIVE_OBSERVATION
- **Status:** RESOLVED

### F-005 — First-party support confirms mandatory payment card requirement before promotional credit redemption

- **Date/Time:** 2026-09-19 05:40 UTC
- **Provider/Tool:** Nebius Token Factory
- **Feature/API:** Billing & Onboarding / Builder Program Credit Redemption
- **Task/Run Context:** P-01.01 (Discover current Nebius account/runtime/API/model reality from official docs and live account)
- **What Worked Well:** First-party support was responsive and offered to inspect internal promo credit status if account/tenant identifiers were provided.
- **Friction/Bug/Limitation:** Nebius Support directly confirmed to the operator: *"Token Factory onboarding requires billing details and a payment card before promotional credits can be redeemed. Promotional credits can be applied after billing setup, but Token Factory cannot currently be activated only with the Builder Program credit and without a payment method."* This confirms that documentation friction observed in F-002 is active platform reality: cardless activation using only Builder Program promotional credits is not currently supported, and promotional codes cannot be redeemed prior to adding a payment card.
- **Deterministic Evidence:** Direct first-party support communication on 2026-09-19 stating: *"Token Factory onboarding requires billing details and a payment card before promotional credits can be redeemed. Promotional credits can be applied after billing setup, but Token Factory cannot currently be activated only with the Builder Program credit and without a payment method."*
- **Developer Impact:** Initially blocked Token Factory usage under the original no-card Zero-Cost policy; the operator subsequently approved a bounded card-attachment exception, while personal paid usage remains forbidden. Participants cannot utilize granted promotional credits without attaching a payment card subject to automated debit upon negative balance.
- **Workaround:** Operator approved `TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION` to attach a payment card solely for Builder Program promotional credit activation with target personal spend = $0.00 and an operator-enforced $5.00 safety reserve floor (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`). Payment card attached; billing currently displays `Suspended`; awaiting separate promo-code email.
- **Concrete Product Suggestion:** Allow Builder Program / hackathon promo-credit accounts to activate without a payment card, or provide a guaranteed user-configurable $0 post-promotional hard spending cap that prevents automated card charges.
- **Severity/Value:** CRITICAL
- **Provenance:** LIVE_OBSERVATION
- **Status:** WORKAROUND_APPLIED

### F-006 — Token Factory Sandboxes requires separate project-level beta access application; API returns HTTP 403 / zero permissions until approved despite active Builder credits

- **Date/Time:** 2026-09-24 10:15 UTC
- **Provider/Tool:** Nebius Token Factory / ConTree Sandboxes
- **Feature/API:** Token Factory Sandboxes (`https://api.tokenfactory.nebius.com/sandboxes/v1/`)
- **Task/Run Context:** P-01.03 (Discover and execute minimal Token Factory Sandbox workflow)
- **What Worked Well:**
  - Token Factory web UI explicitly clarifies zero cost during beta: *"Free while in beta — runs don't consume your credits."*
  - First-party Python SDK (`contree-sdk==0.3.6`) and CLI (`contree-cli==0.9.4`) provide excellent developer experience, comprehensive inline documentation, and clean architecture combining VM isolation with Git-like execution branching.
  - The live `/sandboxes/v1/whoami` endpoint reliably introspects token validity, expiration, and granular permissions (`import`, `spawn`, `spawn_disposable`, `list`, `cancel`, `set_image_tag`).
- **Friction/Bug/Limitation:**
  - Even when an organization has active billing and redeemed Builder Program promotional credits ($25 balance), Sandboxes permissions are disabled by default (`permissions: all False`).
  - Attempting to list images (`GET /sandboxes/v1/images`) or spawn an instance (`POST /sandboxes/v1/instances`) returns HTTP 403 Forbidden (`Insufficient permissions: list` / `Insufficient permissions: spawn or spawn_disposable`).
  - Access is not automatically enabled for Builder Program / hackathon participants; it requires navigating to the web console Sandboxes section, clicking "Request beta access", and submitting an external form with Project ID, email, and use case, then awaiting manual review.
- **Deterministic Evidence:**
  - `GET https://api.tokenfactory.nebius.com/sandboxes/v1/whoami` returned HTTP 200 with `permissions: {'import': False, 'spawn': False, 'spawn_disposable': False, 'list': False, 'cancel': False, 'set_image_tag': False}`.
  - `POST https://api.tokenfactory.nebius.com/sandboxes/v1/instances` returned HTTP 403: `{"status": 403, "error": "Insufficient permissions: spawn or spawn_disposable"}`.
  - `contree-cli/cli/auth.py` lines 278-286 contains explicit first-party warning: `"Warning: token is valid but sandboxes are disabled on %s (no 'list' permission). The profile will be saved but no commands will work until the service is enabled."`
  - Token Factory web console displayed a "Request beta access" modal form.
- **Developer Impact:** Temporarily blocks live sandbox execution in P-01.03 while awaiting Nebius beta enablement for project `aiproject-e00mae0nmzkxjswr1k`.
- **Workaround:** Operator submitted the official beta access form specifying hackathon participation, Project ID `aiproject-e00mae0nmzkxjswr1k`, and Basebreak causal verification use case. Form submission confirmed (`"Teşekkürler, yanıtınız gönderildi"`).
- **Concrete Product Suggestion:** Automatically enable Sandboxes beta access for Builder Program promotional credit recipients and official hackathon participants upon promo redemption, or provide automated instant approval in the web console rather than a manual form review.
- **Severity/Value:** HIGH
- **Provenance:** LIVE_OBSERVATION
- **Status:** UNRESOLVED (awaiting beta access activation)

