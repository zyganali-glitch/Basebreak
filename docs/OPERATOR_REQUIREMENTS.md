# Operator Requirements — Basebreak

These constraints are frozen. All agents and coding executors must obey them.

## 1. ZERO PERSONAL SPEND

The operator has no budget for this project.
The Basebreak hackathon build must use only:
- genuine free tiers;
- hackathon/sponsor promotional credits;
- free open-source/local tools;
- services that stop when the free quota is exhausted.

No agent may authorize spending on behalf of the operator.

## 2. NO BILLING SURPRISES

Forbidden without explicit operator approval:
- paid subscriptions;
- pay-as-you-go enablement;
- automatic paid fallback;
- credit-card charges;
- deposits/pre-authorizations;
- paid certification;
- auto-upgrade after trial;
- any irreversible billing action.

If a UI requests payment, STOP and guide the operator safely.
Never silently proceed past a payment/card request.

### Post-Quota Continuation & Billing Safety Rule
Official Builder Program terms note customers may continue on pay-as-you-go after promotional credits are consumed. Therefore Basebreak must never assume every promotional service automatically hard-stops.
Before using any service that technically supports paid continuation after free/promotional quota:
- verify whether billing/PAYG is disabled or impossible for the operator account;
- verify whether a hard spending cap or equivalent no-charge control exists;
- if charges cannot be deterministically prevented, classify the path `BLOCKED` or `OPERATOR_DECISION_REQUIRED`;
- never add a payment method merely to continue development.

### Token Factory Bounded Billing Exception (Operator Approved)
The operator has explicitly approved `TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION`:
- Attaching a payment card is permitted solely because Token Factory requires it to activate and redeem Builder Program promotional credits.
- Target personal spend remains strictly **$0.00**.
- Forbidden actions: personal paid usage, manual top-ups with personal money, paid subscriptions, reserved/dedicated capacity, committed volume, unrelated paid Nebius services, and paid fallback after promo exhaustion.
- **Manual Safety Reserve (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`):** Because Nebius provides no platform-enforced hard stop upon promo exhaustion, Basebreak enforces an operator policy floor: once remaining promotional balance is `<= $5.00`, all Token Factory inference and sandbox execution must immediately STOP. The final $5.00 reserve must never be deliberately consumed.
- **Mandatory Balance Checks:** The operator must inspect current Token Factory promotional balance before AND after every cost-consuming `LIVE_NEBIUS` batch. The coding agent must provide beginner-grade Turkish screen-by-screen guidance. If balance cannot be verified: `BLOCKED`. If balance `<= $5.00`: `BLOCKED_BUDGET_FLOOR`.
- **Post-Competition Cleanup:** After development and judging obligations conclude and Token Factory is no longer required, the operator must inspect outstanding balance, verify no charges, and remove the payment card or suspend/terminate Token Factory billing access.


## 3. BEGINNER-GRADE GUIDANCE

The operator is non-expert. For every required external account/service setup, the coding agent must provide in Turkish:
- current official URL;
- page/menu name;
- exact button/link to click;
- exact field names;
- what to enter/select;
- what NOT to select;
- whether any card/payment risk exists;
- where to obtain an API key/token;
- how to store it safely without pasting it into chat or committing it;
- how to verify that the step succeeded;
- what to do if the current UI differs from documented UI.

Never tell the operator merely "create an API key" or "configure Nebius".
Never ask the operator to paste a secret into the conversation.

## 4. SECRET SAFETY

Never request secrets in chat.
Use environment variables/secret stores according to later architecture.
The operator may confirm "configured" without revealing the value.
Secrets must never appear in:
- prompts;
- evidence;
- screenshots;
- fixtures;
- logs;
- public judge assets;
- donor manifests;
- commit history.

## 5. FREE-QUOTA AWARENESS

Agents must record current verified free/promotional quota when relevant and design tests/runs to avoid waste.
No assumption that promotional credit renews.
Promotional credits are a budget, not permission to spend beyond them.
If credits are exhausted before the task is complete, classify the task as BLOCKED and explain alternatives.

## 6. HUMAN ACTIONS

Clearly distinguish:
- `AGENT_CAN_DO` — the coding agent can perform this autonomously.
- `OPERATOR_MUST_DO` — requires human action (account creation, button click, approval).
- `OPERATOR_APPROVAL_REQUIRED` — agent can technically do it but needs explicit permission first.
- `BLOCKED` — cannot proceed without external resolution.

Never silently substitute agent action for required human decision.

## 7. OPERATOR ACTION INVENTORY (P-00.02 Anticipated Actions)

Anticipated manual and automated actions for later phases (P-01 and onwards), classified under the four-state taxonomy:

| Action | Classification | Planned Phase | Notes & Safety Safeguards |
|---|---|---|---|
| Verify Devpost hackathon registration | `OPERATOR_MUST_DO` | P-01 | Operator registers via web UI on Devpost. Agent cannot register external accounts. |
| Nebius Builder Program application | `OPERATOR_MUST_DO` | P-01 | Web form application (`dev.nebius.com/builders`) was free; Token Factory onboarding subsequently required a payment card; operator explicitly approved `TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION`; card is now attached; personal paid usage remains strictly forbidden. |
| Nebius Token Factory API key generation | `OPERATOR_MUST_DO` | P-01 | Generated in Nebius web console. Operator stores in local `.env` or secure environment, never pasting into chat. |
| Tavily free tier account registration | `OPERATOR_MUST_DO` | P-01 | Free Researcher plan (1,000 API credits/month). No credit card required. Operator registers and generates API key. |
| Local environment configuration (.env setup) | `OPERATOR_APPROVAL_REQUIRED` | P-01 | Agent prepares template `.env.example`; operator populates `.env` with actual keys. Agent never reads/logs secrets. |
| Billing & spending cap inspection | `OPERATOR_MUST_DO` | P-01 | Verify account billing state; support confirmed no $0 platform hard cap exists and auto-charging cannot be disabled on an active card-backed account. Enforce operational controls: verify promo balance before/after every cost-consuming `LIVE_NEBIUS` batch; enforce `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` as operator policy (never described as a platform hard cap); if balance cannot be verified: `BLOCKED`; if promo balance `<= $5.00`: `BLOCKED_BUDGET_FLOOR`. |
| Token Factory endpoint discovery & probe | `AGENT_CAN_DO` | P-01 | Agent executes minimal live non-billable / low-token probe once API key is configured. |
| Test suite execution (local/sandbox) | `AGENT_CAN_DO` | P-02+ | Agent runs deterministic verification tests within budget constraints. |
| Video recording & demo capture | `OPERATOR_APPROVAL_REQUIRED` | P-30 / P-31 | Agent prepares demo script and deterministic scenario; operator records/approves final video demo. |
| YouTube video upload (publicly visible on YouTube) | `OPERATOR_MUST_DO` | P-31 | Operator uploads strictly < 3:00 video to YouTube (made publicly visible on YouTube) and provides URL. |
| Devpost submission creation & text entry | `OPERATOR_APPROVAL_REQUIRED` | P-32 | Agent prepares submission text and checklist; operator reviews and pastes/submits on Devpost. |
| External billing activation / paid tier fallback | `BLOCKED` | ALL PHASES | Strictly forbidden under Zero-Cost Law. Card attachment solely for Builder Program promotional credit activation is authorized under `TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION`, but personal paid usage, manual top-ups, and paid fallback after promo exhaustion remain strictly forbidden. If promotional credits exhaust without zero-cost recourse, work halts as `BLOCKED`. |

*Note: NONE of these actions are performed during P-00.02. This inventory maps future operational boundaries.*
