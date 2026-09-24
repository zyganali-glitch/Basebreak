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
- P-01.02 (Execute first real Token Factory Nemotron inference call with sanitized minimal prompt) is independently VERIFIED / PASS at SHA `5991b29f2c3c1c987d5d24fcd4eeaaf27b4c0fb5`.

## Last independently VERIFIED baseline SHA
`5991b29f2c3c1c987d5d24fcd4eeaaf27b4c0fb5` (P-01.02 independent QA PASS).

## Blocking live gate vs active task

### Blocking live gate / Active task
`P-01.03 — Discover and execute minimal Token Factory Sandbox workflow`
- Status: `BLOCKED` (external platform prerequisite: awaiting Nebius team beta access enablement on project `aiproject-e00mae0nmzkxjswr1k`).
- Discovery & Architecture findings:
  - Official sources, OpenAPI schema (`https://eu-north.nebius.computer/static/api.yaml`), first-party `contree-sdk` (v0.3.6), `contree-client` (v0.4.0), and `contree-cli` (v0.9.4) analyzed in an isolated temporary environment.
  - Auth structure: `Authorization: Bearer <NEBIUS_API_KEY>` + `Project: <NEBIUS_PROJECT_ID>` (enforced at HTTP level; omission returns 400 `Missing "Project" header`).
  - Zero-Cost verified: Web console Sandboxes section explicitly confirms: *"Free while in beta — runs don't consume your credits."* Account balance: $25.00 promotional, $1.00 trial untouched (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` satisfied).
  - Project ID resolved: Operator located and copied Project ID `aiproject-e00mae0nmzkxjswr1k` from Token Factory project settings.
  - Live authentication probe: `GET /sandboxes/v1/whoami` executed with bearer token and project ID returned HTTP 200 OK (`token_uuid: 448346d4-b5bc-5a03-b722-3f90a2bbcf51`), but all permissions returned `false` (`import`, `spawn`, `spawn_disposable`, `list`, `cancel`, `set_image_tag`).
  - Live execution attempt: `POST /sandboxes/v1/instances` with `/bin/echo BASEBREAK_SANDBOX_OK` returned HTTP 403 `{"status": 403, "error": "Insufficient permissions: spawn or spawn_disposable"}`. `GET /sandboxes/v1/images` returned HTTP 403 `{"status": 403, "error": "Insufficient permissions: list"}`.
  - First-party CLI corroboration: `contree-cli` codebase (`contree_cli/cli/auth.py` lines 278-286) explicitly warns: `"Warning: token is valid but sandboxes are disabled on %s (no 'list' permission). The profile will be saved but no commands will work until the service is enabled."`
  - External beta request submitted: Operator clicked "Request beta access" in web console, submitted official form for `aiproject-e00mae0nmzkxjswr1k` with email `zyganali@gmail.com` and hackathon causal verification use case, and platform confirmed submission (`"Teşekkürler, yanıtınız gönderildi"`).
  - Full evidence documented in `docs/P01_03_LIVE_SANDBOX_DISCOVERY.md`.
- Gate condition: Awaiting Nebius team activation of Sandboxes beta access for `aiproject-e00mae0nmzkxjswr1k`.
- Phase impact: P-01 phase remains OPEN; no GO decision can be awarded without required `LIVE_NEBIUS` sandbox execution evidence.

### Current QA candidate
None (P-01.03 is BLOCKED by external Nebius beta access review).

### Active exact task
`P-01.03 — Discover and execute minimal Token Factory Sandbox workflow` (discovery complete; live execution blocked pending external beta access approval).

*(Note: Exactly ONE executable micro-task is active at a time. P-01 is OPEN. P-04 is OPEN. P-04.04 is PENDING / NOT ACTIVE. P-05+ remain strictly forbidden).*

## Parallelization boundary & rules
- **Allowlist:** Under P-01.01B amendment, the previous P-02 and P-03 lanes are complete and independently closed. The offline allowlist permits sequential execution ONLY of platform-independent P-04 security primitives: `P-04.01` (threat model, DONE), `P-04.02` (secret redaction, DONE), and `P-04.04` (protected-surface manifest/diff, PENDING).
- **P-04.04 restriction:** P-04.04 is PENDING and MUST NOT START during P-01.03 unless explicitly instructed by architecture authority.
- **Provider neutrality:** All domain contracts and evidence primitives remain strictly provider-neutral; zero Nebius/NVIDIA/Tavily dependencies in committed application code.
- **Not authorized / forbidden:** `P-01.04+`, `P-04.03`, `P-04.05`, `P-04.06`, and `P-05+` remain strictly unauthorized / forbidden.
- **Phase status:** P-01 phase MUST remain OPEN. P-04 phase MUST remain OPEN.

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
1. Wait for Nebius team to approve and activate Sandboxes beta access on project `aiproject-e00mae0nmzkxjswr1k`.
2. Once beta permissions are granted (`whoami` permissions become `true`), execute harmless command `/bin/echo BASEBREAK_SANDBOX_OK` to complete live execution and teardown observation.
3. Do NOT start P-01.04.
4. Do NOT start P-04.04.
5. P-01 phase remains OPEN.
6. P-04 phase remains OPEN.
7. P-05+ remain strictly unauthorized / forbidden.
