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
- P-01.01 (Discover current Nebius account/runtime/API/model reality from official docs and live account) is independently VERIFIED / PASS at SHA `5804702c8901105496d9a23cad799cfac6f61b32`.
- P-01.01A (Establish bounded provider-neutral parallel execution while the live Token Factory gate is externally blocked) is independently VERIFIED / PASS at SHA `b15d4b5ac2123360cd937ee2ffc44a04854475e0`.
- Bounded P-02 batch (P-02.01, P-02.02, P-02.03, P-02.04) is IN_PROGRESS (executor-completed; awaiting independent batch QA).

## Last independently VERIFIED baseline SHA
`b15d4b5ac2123360cd937ee2ffc44a04854475e0` (P-01.01A independent QA PASS).

## Blocking live gate vs active executable task

### Blocking live gate
`P-01.02 — Execute first real Token Factory Nemotron inference call with sanitized minimal prompt`
- Status: `BLOCKED`
- External blocker: Builder Program Token Factory promotional-code email has not yet been delivered/redeemed; billing shows no $25 promotional balance. P-01.02 cannot execute until the promo is redeemed and promotional balance is verified `> TOKEN_FACTORY_PROMO_STOP_THRESHOLD`.
- Policy floor: `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`.
- Gate condition: The `$1.00` trial credit MUST NOT be consumed. No automatic paid fallback.
- Phase impact: P-01 phase remains OPEN; no GO decision can be awarded without required `LIVE_NEBIUS` evidence.

### Current QA candidate
Bounded P-02.01 → P-02.04 batch (provider-neutral domain contracts: source identity, engineering tasks, change semantics, execution/sandbox).

### Next task
Next task MUST NOT be executed before independent batch QA:
`P-02.05 — Define witness, candidate, counterfactual and causal-binding contracts`

*(Note: Exactly ONE executable micro-task is active at a time. P-01.02 remains BLOCKED while P-02 offline lane executes. The offline lane does not substitute for or bypass the live gate).*

## Parallelization boundary & rules
- **Allowlist:** Under P-01.01A amendment, only P-02 (`P-02.01`–`P-02.07`) and, upon independent P-02 phase closure, P-03 (`P-03.01`–`P-03.06`) are allowlisted.
- **Provider neutrality:** P-02 and P-03 must remain strictly provider-neutral; zero Nebius/NVIDIA/Tavily SDK imports; deterministic validation only.
- **Hard stop after P-03:** P-04+ remain strictly forbidden under this exception without a separate explicit Master Plan amendment.
- **Promo-arrival preemption:** If the Builder Program promotional-code email arrives during P-02/P-03 execution: do not start another parallel micro-task; finish or cleanly abort the currently active atomic micro-task; return immediately to P-01.02; operator redeems promo; verify Token Factory promotional balance > $5.00; obtain independent authorization before executing inference. Do not consume the $1 trial.

## Frozen constraints
- zero personal spend / Zero-Cost Law (target personal spend = $0.00; operator-approved `TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION` permits card attachment solely to activate Builder Program credits; personal paid usage/top-ups forbidden);
- post-quota billing safety: manual safety reserve floor (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`) enforced by operator policy; mandatory pre/post balance checks for all cost-consuming LIVE_NEBIUS batches;
- beginner-grade Turkish guidance for all operator setup actions;
- live-first;
- no mock-to-live substitution;
- deterministic facts override models;
- Builder cannot certify itself;
- donor repos are donors only;
- competition-defining logic prefers concept-only/clean-room;
- no irreversible merge/release/deploy autonomy;
- exact Master Plan names are immutable once committed;
- no unmetered public live endpoints that drain promotional credits;
- bounded external-dependency parallelization law strictly enforced.

## Immediate next step
1. Await independent QA verification for bounded P-02.01 → P-02.04 candidate batch.
2. Blocking live gate P-01.02 remains BLOCKED until Builder Program promotional-code email is delivered and redeemed. ($1.00 trial credit MUST NOT be consumed; Token Factory balance must be verified > $5.00; operator authorization required).
3. Next executable task upon independent batch QA PASS: `P-02.05 — Define witness, candidate, counterfactual and causal-binding contracts`.
4. Tavily remains safely onboarded on Free/Researcher (1,000 monthly credits + 3,125 promotional credits, usage-based billing disabled, zero payment cards, zero API calls; runtime integration deferred to P-16).
5. P-01.03+ and P-04+ remain strictly unexecutable at this stage.
