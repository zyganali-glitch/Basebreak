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
Bootstrap governance spine committed and pushed to `origin/main`.
P-00.01 acceptance criteria satisfied by Antigravity executor.
Bootstrap commit SHA is pending independent QA verification.

## Active exact task
`P-00.02 — Verify competition eligibility, track fit, deadlines, submission requirements, and judging contract against current official sources`

## Last independently VERIFIED SHA
PENDING_INDEPENDENT_QA — bootstrap commit pushed but not yet independently verified.

## Frozen constraints
- live-first;
- no mock-to-live substitution;
- deterministic facts override models;
- Builder cannot certify itself;
- donor repos are donors only;
- competition-defining logic prefers concept-only/clean-room;
- no irreversible merge/release/deploy autonomy;
- exact Master Plan names are immutable once committed.

## Immediate next step
Independent QA inspects the bootstrap commit on `origin/main`.
If PASS, proceed to P-00.02.
