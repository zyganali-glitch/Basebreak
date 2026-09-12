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
- P-00.01A (Integrate pre-implementation competition strategy and operator constraints) is in active repair / awaiting independent QA verification.
- P-00.02 remains PENDING / UNSTARTED.

## Active exact task
`P-00.01A — Integrate pre-implementation competition strategy and operator constraints` (repair / awaiting independent QA)

## Last independently VERIFIED baseline SHA
`d29a46f68f576dad0b140ec6be6973bb084bdfeb` (P-00.01 closure commit).
Note: P-00.01A repair commit is pushed to remote but awaits independent QA verification.

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
Independent QA inspects the P-00.01A repair commit on `origin/main`.
Only after independent QA awards PASS may P-00.02 be started.
