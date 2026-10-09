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
- P-06.01 (Define task ingestion and deterministic normalization) is independently VERIFIED / PASS at SHA `a76762c62fffba30a7b8d1ead2a130c192c8c072`.
- P-06.02 (Use Nemotron to propose atomic acceptance requirements with citations to task text) is independently VERIFIED / PASS (live-tested source commit b2410e76028e1d3b1d97ebb087f1113f3f8097cb, tree f476f2c7407d7ec9e7ab0cb138e40bbfb0e66412; canonical evidence/governance closure at SHA c93485892e6c40cfe0f95aa82b94fc2346b70fb0; genuine LIVE_NEBIUS evidence in docs/P06_02_LIVE_REQUIREMENT_PROPOSAL.md).
- P-06.03 (Classify change semantics and uncertainty) is independently VERIFIED / PASS at SHA `6a8fe7756ed0ad3df8d7265d0702ecbc0842ecee`.
- P-06.04 (Deterministically validate requirement IDs, scope, forbidden actions and contradictions) is independently VERIFIED / PASS at SHA `16bc6323a99f971d1cf4e90aedd4b828e240bd5a`.
- P-06.05 (Add human-editable contract review surface/CLI) is independently VERIFIED / PASS at SHA `763d12efb75c4c7a3d8df78d73737bf0bde9cb3e`.
- P-06.06 (Freeze contract digest before Builder execution) is independently VERIFIED / PASS at SHA `4588b7efdd331725364be59a9484a68c39f30d86`.
- P-Ω P-06 phase-closure critical security-truth reconciliation is independently VERIFIED / PASS at SHA `8b6ba8a3003d24a7ed43e455352ea34f45770f71`.
- P-06 phase (Contract Compiler) is independently CLOSED / PASS.
- P-07.01 (Define Builder context allowlist and model input minimization) is independently VERIFIED / PASS at SHA `4cccc112bf4a50448eb81e91cb4902fa3344798f`.
- P-07.02 (Implement Nemotron Builder plan/code loop in real sandbox) is independently VERIFIED / PASS at SHA `8419f86c954313d49d9445a0ef4274fb94bfa0ce`.
- P-07.03 (Implement bounded file editing and command execution) is independently VERIFIED / PASS at SHA `b5a40a589ca4c82255880237abb87f0a52a80a40`.
- P-07.04 (Capture candidate diff/tree hash and Builder-authored tests) is independently VERIFIED / PASS at SHA `49eb9c8c2d03d47d32a6602bbb317b7e97125304`.
- P-07.05 (Enforce protected surfaces and forbidden action policy) is independently VERIFIED / PASS at SHA `21eade65ab81c3f3bc32dd8a071b1c0f5e4f1fe2`.
- P-07.06 (Reproduce candidate from trusted base + captured patch in a fresh sandbox) is independently VERIFIED / PASS at SHA `92ec4aa298c0bba96648d9612d3b5f755bf454f6`.
- P-07 phase (Builder Runtime v1) is independently CLOSED / PASS at SHA `92ec4aa298c0bba96648d9612d3b5f755bf454f6`.
- P-08 phase (Verifier Isolation & Sealed Challenge Boundary) is independently CLOSED / PASS at SHA `55abf808e9fc01d5003ef32d61557800942ceed8`.
- P-09 phase (Witness Generation, P-09.01 through P-09.06) is independently CLOSED / PASS at SHA `2889e20a43581f1d7141c771d33452d6a194d20b` (genuine LIVE_NEBIUS proof bound to implementation SHA `6cdbe613eada838b31d8d97620f3f02bf19a8916` and isolated demo target `zyganali-glitch/basebreak-demo-target.git` in `docs/P09_LIVE_WITNESS_PLAN.md`).
- P-10 phase (Causal Two-World Engine, P-10.01 through P-10.07) is independently CLOSED / PASS at SHA `2889e20a43581f1d7141c771d33452d6a194d20b` (genuine LIVE_NEBIUS proof bound to implementation SHA `6cdbe613eada838b31d8d97620f3f02bf19a8916` and isolated demo target `zyganali-glitch/basebreak-demo-target.git` in `docs/P10_LIVE_CLOSURE_PROOF.md`).
- P-11 phase (Counterfactual Third Run, P-11.01 through P-11.06) is independently CLOSED / PASS at canonical closure SHA `e37b772300c1892304c3ac66358e8125c8cd96f9` (fresh LIVE_NEBIUS triplet verification executed and passed; genuine proof generated in `docs/P11_LIVE_CLOSURE_PROOF.md`; receipt `3b80457c7d1499fef1b160286bbc386fb6b16ae36921e65f775d338d905eb4a2`; bound to implementation SHA `6bb8e0913d08b307ea4382833d4772380389ca78`).
- P-12 phase (Minimal Causal Slice, P-12.01 through P-12.05) is independently CLOSED / PASS at SHA `6e5853da72482d5eb2d875be89c9ed6a48f2bfde` (fresh LIVE_NEBIUS demonstration executed and passed; genuine proof in `docs/P12_LIVE_CLOSURE_PROOF.md`; receipt `d75fa9e685cc5fddfa017c2fe58cb5079060d7a9e7961f702ac24df6a85f2016`; bound to implementation SHA `ca2fe46867a83641c22c47375da966fc701d5878`).
- P-13 phase (Change-Semantics Expansion, P-13.01 through P-13.06) is independently CLOSED / PASS at SHA `0045ad89394758bb6c128b846945f2e7e8b2b955`.
- P-14.01 (Define bounded failure-feedback schema) is EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE at SHA `d098907`.
- P-14.02 (Return minimized counterexample without hidden witness disclosure) is EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE at SHA `ca56f68`.
- P-14.03 (Re-enter Builder in fresh/controlled repair context) is EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE at SHA `7aae566`.
- P-14.04 (Create repaired candidate with new exact hash) is EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE at SHA `bc89df6`.
- P-14.05 (Require fresh verifier reproduction for repaired candidate) is EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE at SHA `6b5ed2c`.
- P-14.06 (Cap repair rounds/cost and return honest non-success) is EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE at SHA `cb3f6a8`.
- P-14 Phase Closure (Sealed Repair Loop Live Verification Proof):
  - Fresh LIVE_NEBIUS demonstration executed against real Nebius Token Factory Sandboxes and real Nemotron AI Builder:
    - Initial candidate Candidate 0 failed exit 1 with AssertionError (`sbx-a0b87cbf31b04eaa`);
    - Verifier extracted execution-derived safe failure feedback (`a398c9797a56110ec1ee7d03788d8183fe0661b8e2982330ecc1d5aada8d8d92`, derived from exit code 1 and error facts, traceable origin, zero hidden witness code disclosed, zero counterexample fabrication);
    - Real Nemotron model client (`nvidia/Nemotron-3_5-Lightning`, request `chatcmpl-0ec89963`, 1492 tokens, 3.73s) received only permitted context, passed mechanical secrecy checks, and produced verified python repair for `src/demo_target/cli.py`;
    - Builder materialized Candidate 1 (`cand-live-repaired-r1-2266ec2c`, lineage `764c9a2120967ebc39af1683adcc1255719dd35367fc87054f17ac7f77d58468`, patch `2d5dc4640352458323e973643e3a2215ec61d7a5a40996ba08a85516b625536e`, tree `31f7ab50a5e0da6da9160ce47bdc5daf71072216`);
    - Fresh disposable verifier sandbox (`sbx-ba6113426b6b486b` distinct from `sbx-a0b87cbf31b04eaa`, fail-closed pre-execution sandbox budget checked) executed sealed witness -> Exit 0 (`WITNESS_PASS`);
    - Reproduction receipt digest: `bd662d4139776d4d34d040520253f3db6209b64dd682a3138cb076fec9197d75`;
    - Terminal loop receipt `RLR-894a0ec47c20` emitted with status `VERIFIED_AFTER_REPAIR`, preliminary verdict `VERIFIED`, `is_causally_verified=True`, `grants_pass=True`, `is_authoritative=False` (zero verdict authority invariant);
    - Cryptographic receipt digest: `357eac30e9642b86b89183ab6bf882112fab63f34e79b7ea0776cc78c2e38bf0`;
    - Bound to exact Basebreak implementation SHA: `de563754148ad5364609127d3079d8d6294c7823`; verified-evidence boundary repair applied;
    - Documented in `docs/P14_LIVE_CLOSURE_PROOF.md`;
  - P-14.06 non-success termination classification repair applied at SHA `eecc93860342432cf00d5f7e65f9ff721e65fe5a`: reproduction outcomes deterministically classified (ERROR, TIMEOUT, INVALID_PRECONDITION, INCONCLUSIVE, BLOCKED, and witness PASS with grants_pass=False); genuine behavioral FAIL continues repair loop; honest non-success terminal receipts emitted; zero unhandled feedback exceptions;
  - P-14.06 surgical verdict-gate repair applied: repair loop continuation strictly restricted to `WitnessOutcome.FAIL` + `PreliminaryVerdict.CONTRADICTED` with pre-append cryptographic integrity verification; tampered reproduction receipts fail closed without promoting digests as verified evidence;
  - Prior LIVE_NEBIUS evidence bound to `de563754148ad5364609127d3079d8d6294c7823` preserved (not relabeled); previous one-time authorization consumed; zero billable live runs executed without renewed operator approval; latest candidate implementation is labeled LIVE_NEBIUS NOT_RUN;
  - P-14 batch is EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE.
- P-15+ remain strictly NOT AUTHORIZED / NOT_RUN. HARD STOP ENFORCED.

## Last independently VERIFIED baseline SHA
`0045ad89394758bb6c128b846945f2e7e8b2b955` (independently VERIFIED / PASS at P-13 closure).
Previous LIVE_NEBIUS-tested implementation SHA: `de563754148ad5364609127d3079d8d6294c7823`.
Prior candidate SHA with verdict-gate drift: `eecc93860342432cf00d5f7e65f9ff721e65fe5a` (corrected from stale reference to `de563754148ad5364609127d3079d8d6294c7823`).
Current executor candidate implementation: surgical verdict-gate repair candidate (LIVE_NEBIUS NOT_RUN).

## Blocking live gate vs active task

### Blocking live gate
OPERATOR_AUTHORIZED_LIVE_EXECUTION_COMPLETED: Operator explicitly confirmed Token Factory balance ($0.93 trial credits + $25.00 Builder Program account balance, active billing card) and authorized ONE bounded P-14 live execution (with personal spend safety cap up to $1.00 and $5.00 safety floor preserved). The authorized live cycle executed cleanly and passed with LIVE_NEBIUS provenance on implementation SHA `de563754148ad5364609127d3079d8d6294c7823`. No new live execution authorized or performed for candidate repair; latest implementation is labeled LIVE_NEBIUS NOT_RUN.

### Current QA candidate
P-14 Sealed Repair Loop Batch — P-14.01 through P-14.06 + Surgical Verdict-Gate Repair + Prior Live Closure Proof (EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE; latest implementation LIVE_NEBIUS NOT_RUN).

### Active exact task
P-14 Sealed Repair Loop Batch — completed as executor candidate; live execution successfully demonstrated on `de563754...`; surgical verdict-gate repair applied. P-15+ are strictly NOT AUTHORIZED / NOT_RUN. Hard stop enforced.

## Parallelization boundary & rules
- **Task status:** P-00 through P-13 all tasks and phases are independently VERIFIED / PASS. P-14.01 through P-14.06 are EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE. P-15+ remain strictly NOT AUTHORIZED / NOT_RUN.
- **Provider neutrality:** All domain contracts, evidence primitives, security primitives, Contract Compiler core, Builder primitives, Verifier primitives, Causal primitives, Causal Slice contracts, Change-Semantics verifiers, and Sealed Repair Loop primitives (SafeRepairFeedback, DisclosureSanitizer, BuilderRepairContextEnvelope, CandidateLineageRecord, RepairedVerificationReceipt, RepairLoopReceipt) remain strictly provider-neutral with zero provider model IDs and zero provider-specific identifiers.
- **Phase status:** P-00 through P-13 phases are independently CLOSED / PASS. P-14 phase remains OPEN awaiting independent QA review. P-15+ are strictly NOT AUTHORIZED / NOT_RUN.
- **Batch restoration & hard stop:** P-14 batch executed and completed. P-15+ remain strictly NOT AUTHORIZED / NOT_RUN. Hard stop enforced.
- **Not authorized / forbidden:** P-15+ remain strictly NOT AUTHORIZED / NOT_RUN.

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
1. Submit P-14 Sealed Repair Loop batch (P-14.01 through P-14.06 + Live Closure Proof) for independent QA verification.
2. Maintain hard stop before P-15; do not activate or implement P-15+.
3. Await independent QA evaluation.

