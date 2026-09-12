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
- P-00.03 (Freeze donor research pins and license/preflight status without importing implementation) executor completion pushed to remote; awaiting independent QA verification.

## Active exact task
`P-00.04 — Establish repository structure, Python/runtime tooling baseline, formatting/lint/type/test commands` (PENDING, awaiting independent QA closure of P-00.03)

## Last independently VERIFIED baseline SHA
`d917c5616e67089323f19bf86eb812af4d5c9683` (P-00.02 closure commit).
Note: P-00.03 commit is pushed to remote but awaits independent QA verification.

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
Independent QA verifies P-00.03 against acceptance criteria.
Only after independent QA awards PASS may P-00.04 execution begin.
