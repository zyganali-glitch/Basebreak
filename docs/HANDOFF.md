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
- P-02.01 (Define repository/source identity and immutable revision contracts) is independently VERIFIED / PASS at SHA `d9b00762d7e8af61d138867825140ba53718da4c`.
- P-02.02 (Define engineering task and acceptance-requirement contracts) is independently VERIFIED / PASS at SHA `d9b00762d7e8af61d138867825140ba53718da4c`.
- P-02.03 (Define change-semantics enum and per-class verification requirements) is independently VERIFIED / PASS at SHA `d9b00762d7e8af61d138867825140ba53718da4c`.
- P-02.04 (Define execution command/result/sandbox identity contracts) is independently VERIFIED / PASS at SHA `d9b00762d7e8af61d138867825140ba53718da4c`.
- P-02.05 (Define witness, candidate, counterfactual and causal-binding contracts) is independently VERIFIED / PASS at SHA `a284f92e11f1ab2e8f8fb8a3278178aace76460c`.
- P-02.06 (Define evidence provenance and preliminary verdict contracts) is independently VERIFIED / PASS at SHA `a284f92e11f1ab2e8f8fb8a3278178aace76460c`.
- P-02.07 (Add schema validation, serialization, compatibility and provider-purity tests) is independently VERIFIED / PASS at SHA `a284f92e11f1ab2e8f8fb8a3278178aace76460c`.
- P-02 phase (Provider-Neutral Domain Contracts) is independently CLOSED / PASS at SHA `a284f92e11f1ab2e8f8fb8a3278178aace76460c`.
- P-03.01 (Implement content-addressed artifact hashing and canonical serialization) is independently VERIFIED / PASS at SHA `82cf9049da0f255632d7d36d74d8a316b0e86415`.
- P-03.02 (Implement run/evidence append model with immutable identifiers) is independently VERIFIED / PASS at SHA `82cf9049da0f255632d7d36d74d8a316b0e86415`.
- P-03.03 (Implement bounded sanitized stdout/stderr capture with digests) is independently VERIFIED / PASS at SHA `82cf9049da0f255632d7d36d74d8a316b0e86415`.
- P-03.04 (Implement evidence provenance validation and forbidden state transitions) is independently VERIFIED / PASS at SHA `83eb91da3caec3d52c22c06cf19fd0d5020b1057`.
- P-03.05 (Implement deterministic verdict-input snapshot binding) is independently VERIFIED / PASS at SHA `83eb91da3caec3d52c22c06cf19fd0d5020b1057`.
- P-03.06 (Add tamper/mismatch/replay tests) is independently VERIFIED / PASS at SHA `83eb91da3caec3d52c22c06cf19fd0d5020b1057`.
- P-03 phase (Evidence Store & Deterministic Fact Authority) is independently CLOSED / PASS at SHA `83eb91da3caec3d52c22c06cf19fd0d5020b1057` (recorded at SHA `666181053b49ebb49cb5fda64b6a5cd4dfb26c9b`).
- P-01.01B (Extend bounded provider-neutral parallel execution to platform-independent P-04 security primitives while the live gate remains externally blocked) is independently VERIFIED / PASS at SHA `9ccf9e8c1ec34927142da69532814a030e0c2290`.
- P-04.01 (Formalize target-repository threat model) is independently VERIFIED / PASS at SHA `4db39b136d2fd12e6ebd67eb5c5577d283f279e2`.
- P-04.02 (Implement secret redaction and forbidden persistence rules) is independently VERIFIED / PASS at SHA `c285379b3a453767db6434786c26ff0c6b6ec34b`.
 
## Last independently VERIFIED baseline SHA
`c285379b3a453767db6434786c26ff0c6b6ec34b` (P-04.02 independent QA PASS).

## Blocking live gate vs active executable task

### Blocking live gate / Active executable task
`P-01.02 — Execute first real Token Factory Nemotron inference call with sanitized minimal prompt`
- Status: `IN_PROGRESS (executor documentation completed; independent QA candidate)`
- Prerequisite status: Builder Program Token Factory promotional code successfully redeemed. Account balance: $25.00; Trial credits: $1.00 (untouched); Billing: Active; `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` satisfied.
- Execution & Reproduction status:
  - Original Builder API inference recorded as `RECORDED_LIVE` candidate evidence (HTTP 200, model `nvidia/Nemotron-3_5-Lightning`, 61 tokens, 0.717s).
  - Independent operator manual reproduction executed in Token Factory web Playground (`https://tokenfactory.nebius.com/playground?models=nvidia/Nemotron-3_5-Lightning`) with prompt `Return only BASEBREAK_QA_OK.`, model `nvidia/Nemotron-3_5-Lightning`, returning reasoning thoughts and completion `BASEBREAK_QA_OK` (`LIVE_NEBIUS`).
  - Account balance ($25.00) and trial credits ($1.00 untouched) verified via provider web console (`LIVE_ACCOUNT`).
  - Misleading post-hoc response-content digest removed entirely; socket digest classified as NOT_INDEPENDENTLY_REPRODUCIBLE_FROM_COMMITTED_RECORD; Usage UI observation wording repaired to reflect "No usage" provided NO provider-side corroboration at observation time.
  - Final evidence documented in `docs/P01_02_LIVE_INFERENCE.md`.
- Policy floor: `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` satisfied ($25.00 post-call balance verified).
- Gate condition: The `$1.00` trial credit MUST NOT be consumed (verified untouched). No automatic paid fallback.
- Phase impact: P-01 phase remains OPEN; no GO decision can be awarded without required `LIVE_NEBIUS` evidence.

### Current QA candidate
`P-01.02 — Execute first real Token Factory Nemotron inference call with sanitized minimal prompt` (executor documentation completed; independent QA candidate).

### Active executable task
`P-01.02 — Execute first real Token Factory Nemotron inference call with sanitized minimal prompt` (executor documentation completed; awaiting independent QA).

*(Note: Exactly ONE executable micro-task is active at a time. P-01 is OPEN. P-04 is OPEN. P-04.04 is PENDING / NOT ACTIVE. P-05+ remain strictly forbidden).*

## Parallelization boundary & rules
- **Allowlist:** Under P-01.01B amendment, the previous P-02 and P-03 lanes are complete and independently closed. The active allowlist permits sequential execution ONLY of platform-independent P-04 security primitives: `P-04.01` (threat model), `P-04.02` (secret redaction / persistence), and `P-04.04` (protected-surface manifest/diff).
- **Promo-arrival preemption rule:** Operator has redeemed promotional credits ($25 balance verified). Under promo-arrival preemption: complete P-04.02 third surgical repair, stop, obtain independent QA, then immediately return to P-01.02.
- **P-04.04 restriction:** P-04.04 is PENDING and MUST NOT START before P-04.02 independent PASS.
- **Provider neutrality:** P-04 allowlisted tasks must remain strictly provider-neutral; zero Nebius/NVIDIA/Tavily SDK imports; deterministic validation only; zero assumptions regarding sandbox filesystem, network, or process isolation capabilities.
- **Not authorized / forbidden:** `P-04.03`, `P-04.05`, and `P-04.06` are NOT authorized under this offline lane because they depend on unverified platform/sandbox realities. `P-05+` remain strictly forbidden.
- **Phase status:** P-04 phase MUST remain OPEN; completion of P-04.01, P-04.02, and P-04.04 cannot close P-04.

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
1. Submit P-01.02 (repaired live evidence and independent operator reproduction recorded in `docs/P01_02_LIVE_INFERENCE.md`) for independent QA review.
2. Do NOT start P-01.03.
3. Do NOT start P-04.04.
4. P-01 phase remains OPEN.
5. P-04 phase remains OPEN.
6. P-04.03, P-04.05, P-04.06 and P-05+ remain strictly unauthorized / forbidden under the current offline lane.
