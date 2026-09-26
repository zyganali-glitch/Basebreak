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
- P-04.04 (Implement protected-surface manifest and diff checks) is independently VERIFIED / PASS at SHA `96f032f1165425d88e1bbbc23d6b925ee05e2841`.
- P-01.03 (Discover and execute minimal Token Factory Sandbox workflow) is independently VERIFIED / PASS at SHA `ef5d79b1d421e628877522b16f4ab98dd0f515c2`.
- P-01.04 (Prove live repository materialization inside supported sandbox) is independently VERIFIED / PASS at SHA `ef5d79b1d421e628877522b16f4ab98dd0f515c2`.
- P-01.05 (Prove two independent clean sandbox executions from the same trusted source) is independently VERIFIED / PASS at SHA `ef5d79b1d421e628877522b16f4ab98dd0f515c2`.
- P-01.06 (Phase feasibility decision and architecture freeze v0) is independently VERIFIED / PASS at SHA `ef5d79b1d421e628877522b16f4ab98dd0f515c2`.
- P-01.07 (Freeze judge-visible causal vertical-slice contract from proven platform reality) is independently VERIFIED / PASS at SHA `ef5d79b1d421e628877522b16f4ab98dd0f515c2`.
- P-01 phase (Live Platform Discovery & Feasibility Gate) is independently CLOSED / PASS at SHA `ef5d79b1d421e628877522b16f4ab98dd0f515c2`.
- P-04.03 (Define sandbox resource/network/process policy from proven platform capability) is independently VERIFIED / PASS at SHA `5673b0ae07120151a08626161a21586b44c75bc1`.
- P-04.05 (Implement execution timeout/cancellation/resource-failure normalization) is independently VERIFIED / PASS at SHA `5673b0ae07120151a08626161a21586b44c75bc1`.
- P-04.06 (Add malicious-fixture tests for exfiltration attempts, fork bombs, verifier discovery, and protected-surface mutation) is independently VERIFIED / PASS at SHA `5673b0ae07120151a08626161a21586b44c75bc1`.
- P-04 phase (Security & Untrusted-Code Policy Foundation) is independently CLOSED / PASS at SHA `5673b0ae07120151a08626161a21586b44c75bc1`.

- P-05.01 (Implement bounded model client using discovered model identifiers/config) is independently VERIFIED / PASS at SHA `90e5391b9bd7a406c62b838bfa1f24e85400ad65`.
- P-05.02 (Implement sandbox create/exec/inspect/teardown adapter) is independently VERIFIED / PASS at SHA `bee7a22e77195e21ba5bc6341a72caed6ef675d9`.
- P-05.03 (Implement repository materialization and source-hash verification adapter) is independently VERIFIED / PASS at SHA `f149afffb58b72dfeba301e59868c38eef6a7107`.
- P-05.04 (Implement model/sandbox telemetry normalization with secret-safe logs) is independently VERIFIED / PASS at SHA `899fe27feb8ec530c226a46832d47f886cd6947d`.
- P-05.05 (Implement retry/idempotency policy without duplicating external actions) is independently VERIFIED / PASS at SHA `ef2d55c6ed6195e291b5e3ba8fe753541e5863c4`.
- P-05.06 pre-live harness/CI repair is independently VERIFIED / PASS at SHA `517ad633c5b9ade85dcc8e0e4b9d05361fe4cb15`.
- P-05.06 (Execute live adapter integration suite) is independently VERIFIED / PASS at SHA `eeba36126968f34494ef1c12b1e3ddbccc18ad91` (genuine LIVE_NEBIUS evidence in `docs/P05_06_LIVE_ADAPTER_INTEGRATION.md`).
- P-05 phase (Nebius/Nemotron Adapter Layer) is independently CLOSED / PASS at SHA `eeba36126968f34494ef1c12b1e3ddbccc18ad91`.
- P-Ω broad phase-closure audit: PASS.
- P-06.01 (Define task ingestion and deterministic normalization) is EXECUTOR_COMPLETED / CANDIDATE (deterministic normalization, raw text preservation, bounded size ceiling, SHA-256 digests, secret-safe summary and repr, 16 focused tests passing in `tests/compiler/test_ingestion.py`).

## Last independently VERIFIED baseline SHA
`eeba36126968f34494ef1c12b1e3ddbccc18ad91` (independently VERIFIED baseline at P-05.06 / P-05 phase closure).

## Blocking live gate vs active task

### Blocking live gate
None. P-01 and P-05 live platform/adapter integrations are complete and independently CLOSED / PASS.

### Current QA candidate
P-06.01 (Define task ingestion and deterministic normalization).

### Active exact task
`P-06.02 — Use Nemotron to propose atomic acceptance requirements with citations to task text`
(Batch P-06.01 through P-06.04 conditionally authorized by Independent QA; P-06.05+ remain strictly NOT AUTHORIZED / NOT_RUN).

## Parallelization boundary & rules
- **Task status:** P-00 through P-05 all tasks are independently VERIFIED / PASS.
- **Provider neutrality:** All domain contracts, evidence primitives, security primitives, and Contract Compiler core domain models remain strictly provider-neutral.
- **Phase status:** P-00, P-01, P-02, P-03, P-04, P-05 phases are independently CLOSED / PASS. P-06 phase is OPEN.
- **Authorized batch:** P-06.01, P-06.02, P-06.03, P-06.04 are sequentially and conditionally authorized under strict fail-closed batch execution law.
- **Not authorized / forbidden:** P-06.05, P-06.06, and P-07+ remain strictly NOT AUTHORIZED / NOT_RUN.

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
1. Implement P-06.01: Define task ingestion and deterministic normalization.
2. Execute focused deterministic normalization tests and provider purity tests.
3. Commit and push P-06.01 before progressing to P-06.02.
