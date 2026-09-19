# HANDOFF — Basebreak

## Canonical repository
`zyganali-glitch/Basebreak`
Branch: `main`

## Product
Basebreak is a causal verification runtime for AI-written software changes.

Thesis:
`If the patch matters, the base must break.`

Judge claim:
`Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green.`

## Current state
- P-00.01 (Bootstrap canonical repository governance spine and competition contract) is independently VERIFIED / PASS at SHA `d29a46f68f576dad0b140ec6be6973bb084bdfeb`.
- P-00.01A (Integrate pre-implementation competition strategy and operator constraints) is independently VERIFIED / PASS at SHA `0d92adc3681edddb0dbaf0ccc176c1276a417fb3`.
- P-00.02 (Verify competition eligibility, track fit, deadlines, submission requirements, and judging contract against current official sources) is independently VERIFIED / PASS at SHA `d917c5616e67089323f19bf86eb812af4d5c9683`.
- P-00.03 (Freeze donor research pins and license/preflight status without importing implementation) is independently VERIFIED / PASS at SHA `352d04eb22d7db87faca932ead938d4f4a213268`.
- P-00.04 (Establish repository structure, Python/runtime tooling baseline, formatting/lint/type/test commands) is independently VERIFIED / PASS at SHA `5c4f07bd541db759dfe6b1b5bf7c2fb3e6a06499`.
- P-00.05 (Run first documentation consolidation and focused P-Ω bootstrap audit) is independently VERIFIED / PASS at SHA `08ebfc94a75954d79ee2613f935584de2a9d5900` (P-00 phase closure awarded PASS).
- P-01.01 (Discover current Nebius account/runtime/API/model reality from official docs and live account) is EXECUTOR_COMPLETED (discovery artifact and documentation committed; awaiting independent QA).

## Active exact task
`P-01.01 — Discover current Nebius account/runtime/API/model reality from official docs and live account` (in progress / executor completed / awaiting independent QA)

## Last independently VERIFIED baseline SHA
`08ebfc94a75954d79ee2613f935584de2a9d5900` (P-00.05 and P-00 Phase Closure independent QA PASS).
P-01.01 candidate is submitted for independent QA.
P-01.02 remains PENDING / UNSTARTED.

## Frozen constraints
- zero personal spend / Zero-Cost Law (no credit cards, PAYG, paid tiers, or auto-upgrades);
- post-quota billing safety: verify PAYG disabled/capped before using services that support paid continuation;
- beginner-grade Turkish guidance for all operator setup actions;
- live-first;
- no mock-to-live substitution;
- deterministic facts override models;
- Builder cannot certify itself;
- donor repos are donors only;
- competition-defining logic prefers concept-only/clean-room;
- no irreversible merge/release/deploy autonomy;
- exact Master Plan names are immutable once committed;
- no unmetered public live endpoints that drain promotional credits.

## Immediate next step
1. Await independent QA verification for P-01.01 at current commit.
2. Tavily account onboarding completed under Free/Researcher path (1,000 monthly + 3,125 promo credits, usage-based payment visibly disabled, zero payment cards, 0 API calls executed; integration deferred to P-16).
3. Await separate email from Nebius containing the $25 Token Factory promotional credit code.
4. Upon receiving the Token Factory promo code email: redeem promo code in Token Factory console, generate `NEBIUS_API_KEY`, and proceed to `P-01.02`.
Do NOT advance to P-01.02 before independent QA PASS and Token Factory promotional credit code arrival. Zero personal spend is strictly preserved.
