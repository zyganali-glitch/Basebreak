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
