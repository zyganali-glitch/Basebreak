# BASEBREAK MASTER EXECUTION PLAN

Status vocabulary: `PENDING`, `IN_PROGRESS`, `DONE`, `BLOCKED`.
Exact micro-task titles are immutable once committed. If architecture reality changes, add an ADR and amend acceptance criteria without silently renaming historical tasks.

## Global acceptance laws
1. Remote `main` is canonical.
2. No task closes from an agent report alone.
3. Live-required work needs current `LIVE_NEBIUS` evidence.
4. Builder-authored tests do not automatically satisfy independent verification.
5. Candidate verification binds to exact hashes.
6. No silent mock fallback.
7. Deterministic failure cannot be overridden by model prose.
8. Competition-defining donor logic prefers concept-only/clean-room.
9. Every irreversible external action requires explicit authority.
10. Critical truth updates immediately; harmless documentation parity batches.
11. ZERO-COST LAW: Basebreak hackathon development and judge path must not require the user to spend personal money. Allowed: genuine free tiers, hackathon/sponsor promotional credits, free open-source/local tools, services that stop when the free quota is exhausted. Forbidden without explicit user approval: paid subscriptions, pay-as-you-go enablement, automatic paid fallback, credit-card charges, deposits/pre-authorizations, paid certification, auto-upgrade after trial, any irreversible billing action. Under the operator-approved `TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION`, a payment card was attached solely to enable Builder Program promotional credit activation, while target personal spend remains strictly $0.00, post-promotional paid usage is strictly forbidden, and an operator-enforced $5.00 safety reserve floor (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`) is maintained. If a required external service asks for payment/card/deposit and there is no verified zero-cost path: STOP, classify as BLOCKED or OPERATOR_DECISION_REQUIRED, explain alternatives, never silently proceed. Promotional credits are a budget, not permission to spend beyond them.
12. OPERATOR GUIDANCE LAW: The operator is non-expert and must receive screen-by-screen guidance for every required external account/service setup. For every operator action the coding agent must provide in Turkish: current official URL, page/menu name, exact button/link to click, exact field names, what to enter/select, what NOT to select, whether any card/payment risk exists, where to obtain an API key/token, how to store it safely without pasting it into chat or committing it, how to verify that the step succeeded, what to do if the current UI differs from documented UI. Never tell the operator merely "create an API key" or "configure Nebius". Never ask the operator to paste a secret into the conversation.
13. DOCUMENTATION SYNC MATRIX: Master Plan updates exact task status when task state changes. HANDOFF updates active exact task, blocker and independently verified baseline truth. README updates only when public-facing capability/status/setup/architecture/competition truth materially changes, or at a Documentation Consolidation Gate. Architecture/Security/Evidence docs update only when their actual boundary/contract changes. Donor manifest updates only when donor research/reuse truth changes. Competition Feedback Log appends when real Nebius/NVIDIA/Tavily friction, strength, bug, limitation, or useful product feedback is actually observed. Harmless duplicated wording/count/navigation drift may be batched. Wrong SHA, false capability, false live claim, wrong evidence provenance, security/licensing/eligibility error must be fixed immediately. Every micro-task does NOT require mechanical rewriting of every documentation file.
14. BOUNDED EXTERNAL-DEPENDENCY PARALLELIZATION LAW: When an exact task is BLOCKED solely by a verified external dependency outside Basebreak's control, a later task MAY execute before that blocker clears ONLY when all of the following are true: (1) the later task is explicitly allowlisted by the Master Plan; (2) its correctness does not depend on the missing external/live fact; (3) it can be validated deterministically without pretending LOCAL_EXECUTION is LIVE_NEBIUS; (4) no platform/provider capability is guessed; (5) the blocked gate remains visibly BLOCKED; (6) the blocked phase cannot receive GO/phase closure; (7) only ONE executable micro-task is active at a time; (8) the parallel work may not silently implement any non-allowlisted future phase; (9) if later live reality contradicts a supposedly provider-neutral assumption, affected work MUST reopen rather than override runtime truth. This rule is an exception for verified external blockers, not permission for arbitrary phase skipping. Promo-arrival preemption rule: if the external prerequisite arrives while parallel work is underway, do not start another parallel micro-task; finish or cleanly abort the currently active atomic micro-task; return immediately to the blocked gate; verify prerequisites and obtain independent authorization before execution. Historical parallel lanes: P-02, P-03, and P-04 were completed and independently closed. Following independent closure of P-01 (at SHA ef5d79b1d421e628877522b16f4ab98dd0f515c2) and P-04 (at SHA 5673b0ae07120151a08626161a21586b44c75bc1), no active external blocker remains. P-05+ sequential execution proceeds in strict micro-task order.

## Competition Critical Path

Priority guidance for the Nebius x NVIDIA Global AI Hackathon. This is NOT scope deletion; all phases remain planned.

1. **Platform reality:** P-00 (governance) → P-01 (live platform discovery and feasibility gate). *(Platform status: P-01 live discovery and P-04 security foundation are both independently CLOSED / PASS.)*
2. **Causal vertical spine:** P-02 Provider-Neutral Domain Contracts → P-03 Evidence Store & Deterministic Fact Authority → P-04 Security & Untrusted-Code Policy Foundation → P-05 Nebius/Nemotron Adapter Layer → P-06 Contract Compiler → P-07 Builder Runtime → P-08 Verifier Isolation → P-09 Witness Generation → P-10 Causal Two-World Engine → P-11 Counterfactual Third Run (competition-defining causal proof path producing the canonical high-value demo: BASE = FAIL, CANDIDATE = PASS, COUNTERFACTUAL = FAIL; P-11 is competition-core and not optional/stretch/depth-only). (Prerequisite rationale: P-07 depends on P-04 protected/action/security policy; P-09 depends on P-06 frozen acceptance contract; P-10 depends on P-03 evidence/hash binding).
3. **Judge proof:** first receipt/CLI proof (P-18/P-19 minimal) → judge-visible causal story (P-22/P-23 killer demo).
4. **Deployment/reproducibility/submission:** P-27 (live deployment) → P-29 (competition evidence) → P-30 (demo video) → P-32 (submission freeze).
5. **Depth features:** P-12 Minimal Causal Slice and subsequent depth features (P-13 semantics expansion, P-14 sealed repair, P-15 risk-adaptive budget, P-16 Tavily grounding, P-17 coverage, P-20 GitHub integration, P-24 adversarial, P-25 reliability, P-26 performance) remain planned and continue after the first coherent vertical slice.

---

# P-00 — Repository, Competition Contract & Governance Bootstrap
Goal: create the trustworthy empty-repo baseline before implementation.

### P-00.01 — Bootstrap canonical repository governance spine and competition contract
Status: DONE
Deliver: root governance/docs/plan/license/readme from starter pack.
Acceptance:
- canonical repo public on `main`;
- Apache-2.0 visible;
- exact product thesis and current competition contract committed;
- no application/runtime code;
- HANDOFF points to P-00.02;
- pushed remote SHA independently verifiable.

### P-00.01A — Integrate pre-implementation competition strategy and operator constraints
Status: DONE
Deliver: competition strategy docs, operator requirements, zero-cost/guidance laws, competition feedback log, README expansion, HANDOFF/AGENTS/GEMINI governance updates.
Acceptance:
- zero-cost law in Plan and AGENTS.md;
- operator guidance law in Plan and AGENTS.md;
- documentation sync matrix in Plan and AGENTS.md;
- `docs/OPERATOR_REQUIREMENTS.md` created;
- `docs/COMPETITION_FEEDBACK_LOG.md` created;
- `docs/COMPETITION_STRATEGY.md` created;
- `docs/COMPETITION_CONTRACT.md` updated with current verified sources;
- README expanded with honest planned/unimplemented labels;
- HANDOFF updated with independently verified SHA;
- competition critical path section added;
- no runtime/application code;
- P-00.02 remains PENDING;
- no existing task title renamed;
- pushed remote SHA.

### P-00.02 — Verify competition eligibility, track fit, deadlines, submission requirements, and judging contract against current official sources
Status: DONE
Acceptance:
- official source URLs/date snapshot;
- Coding & Agentic Engineering fit explicitly justified;
- public repo/license/demo/<3m/runtime requirements captured;
- resolve zero-cost judging-period coverage, including promotional-credit issuance/expiry and post-quota billing behavior from current official terms/runtime;
- no unverified platform/model claim.

### P-00.03 — Freeze donor research pins and license/preflight status without importing implementation
Status: DONE
Acceptance:
- every candidate donor immutable SHA or explicit NOT_PINNED;
- license read at pin;
- reuse target/class recorded;
- zero donor code copied.

### P-00.04 — Establish repository structure, Python/runtime tooling baseline, formatting/lint/type/test commands
Status: DONE
Acceptance:
- minimal skeleton only;
- deterministic root commands;
- CI-compatible;
- no Nebius fake adapter;
- focused bootstrap tests pass.

### P-00.05 — Run first documentation consolidation and focused P-Ω bootstrap audit
Status: DONE
Acceptance:
- plan/HANDOFF/README critical truth aligned;
- no secrets/local paths except explicitly documented operator path where required;
- no future-phase implementation.
Phase exit: trusted empty-product baseline exists (awarded PASS by independent QA at SHA 08ebfc94a75954d79ee2613f935584de2a9d5900).

---

# P-01 — Live Platform Discovery & Feasibility Gate
Goal: prove real Nebius/NVIDIA capabilities before broad implementation.

### P-01.01 — Discover current Nebius account/runtime/API/model reality from official docs and live account
Status: DONE (independently VERIFIED / PASS at SHA 5804702c8901105496d9a23cad799cfac6f61b32)
Acceptance:
- current endpoints/SDK/auth/model IDs discovered, not guessed;
- eligible NVIDIA open-source model identified;
- capabilities/limits recorded with LIVE_NEBIUS or official-doc provenance.

### P-01.01A — Establish bounded provider-neutral parallel execution while the live Token Factory gate is externally blocked
Status: DONE (independently VERIFIED / PASS at SHA b15d4b5ac2123360cd937ee2ffc44a04854475e0)
Deliver: Master Plan amendment and governance rules establishing bounded provider-neutral parallel execution (P-02/P-03) while P-01.02 is externally blocked.
Acceptance:
- P-01.01 marked DONE;
- P-01.02 marked BLOCKED with explicit external blocker metadata;
- Bounded External-Dependency Parallelization Law codified in AGENTS.md and Master Plan;
- strict allowlist defined: P-02 (P-02.01–P-02.07) and P-03 (P-03.01–P-03.06);
- explicit hard stop after P-03 (P-04+ strictly forbidden without new amendment);
- promo-arrival preemption rule codified;
- P-01 phase remains OPEN (no GO without LIVE_NEBIUS evidence);
- HANDOFF clearly distinguishes blocking live gate vs executable task;
- no product/source code modified;
- candidate pushed and remote SHA verified.

### P-01.01B — Extend bounded provider-neutral parallel execution to platform-independent P-04 security primitives while the live gate remains externally blocked
Status: DONE (independently VERIFIED / PASS at SHA 9ccf9e8c1ec34927142da69532814a030e0c2290)
Deliver: Master Plan amendment and governance rules extending bounded provider-neutral parallel execution to the platform-independent P-04 security primitives (P-04.01, P-04.02, P-04.04) while P-01.02 is externally blocked.
Acceptance:
- P-01.01A status preserved as DONE;
- P-01.02 remains BLOCKED with explicit external blocker metadata;
- Bounded External-Dependency Parallelization Law updated in AGENTS.md and Master Plan;
- completed P-02 and P-03 status recorded as independently closed;
- new strict allowlist defined: P-04.01, P-04.02, P-04.04 only;
- P-04.03, P-04.05, P-04.06 explicitly NOT AUTHORIZED under current offline lane;
- P-05+ strictly forbidden;
- P-04 phase explicitly remains OPEN (cannot close from offline subset);
- explicit hard stop after P-04.04 (if P-04.01, P-04.02, P-04.04 close while P-01.02 is still blocked, stop and return for independent architecture decision);
- promo-arrival preemption rule preserved;
- P-01 phase remains OPEN (no GO without LIVE_NEBIUS evidence);
- HANDOFF clearly distinguishes blocking live gate vs executable task;
- no product/source code modified;
- candidate pushed and remote SHA verified.

### P-01.02 — Execute first real Token Factory Nemotron inference call with sanitized minimal prompt
Status: DONE (independently VERIFIED / PASS at SHA 5991b29f2c3c1c987d5d24fcd4eeaaf27b4c0fb5)
Prerequisite status: Builder Program Token Factory promotional code successfully redeemed. Account balance: $25.00; Trial credits: $1.00 (untouched); Billing: Active; TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00 satisfied.
Acceptance:
- real request/response;
- model/runtime identity recorded;
- no secret leakage;
- no mock fallback.

### P-01.03 — Discover and execute minimal Token Factory Sandbox workflow
Status: DONE (independently VERIFIED / PASS at SHA ef5d79b1d421e628877522b16f4ab98dd0f515c2; live whoami confirmed all permissions true; minimal disposable execution succeeded with exit code 0; teardown observed; checkpoint, snapshot, and clone/fork tested live; documented in docs/P01_03_LIVE_SANDBOX_DISCOVERY.md)
Acceptance:
- create supported sandbox;
- execute harmless command;
- collect deterministic exit/output;
- teardown observed;
- exact API/SDK constraints recorded;
- explicitly test and discover whether the current platform supports: checkpoint, snapshot, clone/fork, branch, rollback/reset, or equivalent clean-world/reproduction primitive;
- for every investigated capability record one of: `SUPPORTED`, `UNSUPPORTED`, `NOT_FOUND`;
- bind every capability finding to current official documentation and/or current `LIVE_NEBIUS` execution evidence;
- do NOT canonicalize any external-AI claim (such as "Git-like branching", checkpoint semantics, instant rollback, concurrency limits, or retention durations) until P-01 proves them;
- architecture adapts to proven platform reality.

### P-01.04 — Prove live repository materialization inside supported sandbox
Status: DONE (independently VERIFIED / PASS at SHA ef5d79b1d421e628877522b16f4ab98dd0f515c2; canonical repo cloned inside container VM; base SHA and tree SHA verified against local truth; 28 tests passed in 5.06s; documented in docs/P01_04_LIVE_REPO_MATERIALIZATION.md)
Acceptance:
- synthetic/public test repo materialized;
- base SHA resolved inside sandbox;
- command/test run executed;
- filesystem/network assumptions recorded.

### P-01.05 — Prove two independent clean sandbox executions from the same trusted source
Status: DONE (independently VERIFIED / PASS at SHA ef5d79b1d421e628877522b16f4ab98dd0f515c2; two independent disposable sandboxes executed; zero workspace bleeding verified via marker test; identical tree SHA; independent test outputs; documented in docs/P01_05_TWO_CLEAN_EXECUTIONS.md)
Acceptance:
- unique sandbox identities;
- no workspace sharing;
- reproducible source hash;
- independent outputs captured.

### P-01.06 — Phase feasibility decision and architecture freeze v0
Status: DONE (independently VERIFIED / PASS at SHA ef5d79b1d421e628877522b16f4ab98dd0f515c2; evidence-driven GO decision issued based strictly on live P-01.02 through P-01.05 facts; architecture freeze v0 recorded in docs/P01_06_FEASIBILITY_DECISION.md)
Acceptance:
- GO/BLOCKED decision;
- actual platform constraints drive architecture;
- mocked substitutes cannot produce GO.

### P-01.07 — Freeze judge-visible causal vertical-slice contract from proven platform reality
Status: DONE (independently VERIFIED / PASS at SHA ef5d79b1d421e628877522b16f4ab98dd0f515c2; judge-visible causal pipeline flow frozen; 3 research-only historical bug/fix pairs shortlisted without code importing; documented in docs/P01_07_VERTICAL_SLICE_CONTRACT.md)
Acceptance:
- written after P-01 proves actual platform capabilities;
- defines what a judge will eventually see: task → Builder → independent witness → BASE result → CANDIDATE result → counterfactual where required → provenance → receipt;
- does not implement future UI;
- does not contain unverified platform claims;
- research-only shortlist 2–3 candidate real open-source bug/fix pairs for eventual P-23.08 replay (ResetVault remains the PRIMARY deterministic killer demo; P-23.08 is supplementary historical replay);
- for each candidate, record: repository, immutable buggy/base SHA, immutable fixed SHA, root license, concise behavioral defect, likely independent witness, dependency/runtime footprint, sandbox/platform feasibility, reasons suitable/unsuitable;
- at P-01.07: strictly NO donor/source importing, NO replay implementation, and NO claiming upstream patch was produced by Basebreak (early de-risking only).
Phase exit: real model + real sandbox + two-clean-environment spine proven. (P-01 phase independently CLOSED / PASS at SHA ef5d79b1d421e628877522b16f4ab98dd0f515c2).

---

# P-02 — Provider-Neutral Domain Contracts
Goal: encode truth before orchestration.
*(Allowlisted for parallel execution under P-01.01A amendment while P-01.02 is externally blocked. P-02 defines deterministic domain contracts and imports zero provider SDKs; its correctness does not depend on live platform access.)*

Why P-02 is safe to parallelize:
- P-02 must remain strictly provider-neutral.
- It may define deterministic contracts for: repository/source identity, immutable revisions/hashes, engineering tasks, acceptance requirements, change semantics, execution command/result abstractions, abstract sandbox identity, witness identity, candidate identity, counterfactual identity, evidence provenance, preliminary verdicts.
- It MUST NOT encode: current Nebius model IDs, Token Factory API paths, Contree-specific classes, Nebius-specific sandbox fields, current sandbox limits, checkpoint/branch assumptions, current region names as domain invariants, Tavily, or provider SDK objects.

### P-02.01 — Define repository/source identity and immutable revision contracts
Status: DONE (independently VERIFIED / PASS at SHA d9b00762d7e8af61d138867825140ba53718da4c)
### P-02.02 — Define engineering task and acceptance-requirement contracts
Status: DONE (independently VERIFIED / PASS at SHA d9b00762d7e8af61d138867825140ba53718da4c)
### P-02.03 — Define change-semantics enum and per-class verification requirements
Status: DONE (independently VERIFIED / PASS at SHA d9b00762d7e8af61d138867825140ba53718da4c)
### P-02.04 — Define execution command/result/sandbox identity contracts
Status: DONE (independently VERIFIED / PASS at SHA d9b00762d7e8af61d138867825140ba53718da4c)
### P-02.05 — Define witness, candidate, counterfactual and causal-binding contracts
Status: DONE (independently VERIFIED / PASS at SHA a284f92e11f1ab2e8f8fb8a3278178aace76460c)
### P-02.06 — Define evidence provenance and preliminary verdict contracts
Status: DONE (independently VERIFIED / PASS at SHA a284f92e11f1ab2e8f8fb8a3278178aace76460c)
### P-02.07 — Add schema validation, serialization, compatibility and provider-purity tests
Status: DONE (independently VERIFIED / PASS at SHA a284f92e11f1ab2e8f8fb8a3278178aace76460c)
Phase exit:
- domain imports no Nebius/NVIDIA/UI SDKs;
- exact hash/state semantics deterministic;
- no orchestration yet.
(P-02 phase independently CLOSED / PASS at SHA a284f92e11f1ab2e8f8fb8a3278178aace76460c)

---

# P-03 — Evidence Store & Deterministic Fact Authority
Goal: implement provider-neutral deterministic evidence primitives.
*(Allowlisted for parallel execution under P-01.01A amendment only after independent P-02 phase closure while P-01.02 is externally blocked.)*

Why P-03 is safe to parallelize:
- P-03 may implement provider-neutral deterministic evidence primitives: canonical serialization, content-addressed hashes, immutable evidence/run identifiers, bounded sanitized stdout/stderr capture with digests, evidence provenance validation, forbidden state transitions, exact candidate/run snapshot binding, tamper/mismatch/replay tests.
- It MUST NOT implement: Nebius storage, Token Factory runtime calls, sandbox APIs, model calls, cloud persistence assumptions, or provider-specific telemetry.
- Provenance separation: FIXTURE and LOCAL_EXECUTION evidence remain explicitly distinct from LIVE_NEBIUS. P-03 green tests close only P-03 local deterministic requirements; they can NEVER satisfy P-01 live platform gates.

### P-03.01 — Implement content-addressed artifact hashing and canonical serialization
Status: DONE (independently VERIFIED / PASS at SHA 82cf9049da0f255632d7d36d74d8a316b0e86415)
### P-03.02 — Implement run/evidence append model with immutable identifiers
Status: DONE (independently VERIFIED / PASS at SHA 82cf9049da0f255632d7d36d74d8a316b0e86415)
### P-03.03 — Implement bounded sanitized stdout/stderr capture with digests
Status: DONE (independently VERIFIED / PASS at SHA 82cf9049da0f255632d7d36d74d8a316b0e86415)
### P-03.04 — Implement evidence provenance validation and forbidden state transitions
Status: DONE (independently VERIFIED / PASS at SHA 83eb91da3caec3d52c22c06cf19fd0d5020b1057)
### P-03.05 — Implement deterministic verdict-input snapshot binding
Status: DONE (independently VERIFIED / PASS at SHA 83eb91da3caec3d52c22c06cf19fd0d5020b1057)
### P-03.06 — Add tamper/mismatch/replay tests
Status: DONE (independently VERIFIED / PASS at SHA 83eb91da3caec3d52c22c06cf19fd0d5020b1057)
Phase exit: evidence facts cannot be silently rebound to another candidate/run. (P-03 phase independently CLOSED / PASS at SHA 83eb91da3caec3d52c22c06cf19fd0d5020b1057)

### Status after P-03 closure:
P-03 phase was independently CLOSED / PASS at SHA 83eb91da3caec3d52c22c06cf19fd0d5020b1057 (recorded in repo at SHA 666181053b49ebb49cb5fda64b6a5cd4dfb26c9b). P-01 phase was independently CLOSED / PASS at SHA ef5d79b1d421e628877522b16f4ab98dd0f515c2. All P-04 tasks were completed and P-04 phase was independently CLOSED / PASS at SHA 5673b0ae07120151a08626161a21586b44c75bc1.


---

# P-04 — Security & Untrusted-Code Policy Foundation
Goal: establish bounded execution and integrity contracts before autonomous building.
*(All P-04 tasks P-04.01 through P-04.06 completed and independently VERIFIED / PASS. P-04 phase independently CLOSED / PASS at SHA 5673b0ae07120151a08626161a21586b44c75bc1).*

Why the allowlisted tasks were executed offline:
- P-04.01 is provider-neutral threat modeling. It models generic adversaries and trust boundaries already established by Basebreak: target repository is untrusted input; Builder cannot certify itself; verifier assets must remain independent; repository content may attempt prompt injection; repository code may attempt secret discovery/exfiltration; generated patches may mutate protected verification/governance surfaces; logs/evidence must not persist credentials; deterministic facts have authority over model prose. It MUST NOT claim provider-specific sandbox protections.
- P-04.02 is provider-neutral secret redaction / persistence policy. It implements deterministic: secret-shaped value redaction; forbidden durable-secret persistence rules; safe evidence/log serialization boundaries; synthetic-credential tests. It MUST NOT implement provider credential delivery/injection or claim that a specific live runtime protects secrets.
- P-04.04 is provider-neutral repository integrity policy. It implements deterministic: protected-surface manifest contracts; normalized repository path validation; diff/change detection; protected-surface mutation rejection; traversal/symlink/path-normalization adversarial tests where relevant. It MUST NOT assume any specific sandbox filesystem API.

Live platform integration for remaining P-04 tasks:
- P-04.03 derives sandbox resource, network, and process policies directly from proven live platform capabilities from P-01 (disposable instances, LinuxKit VMs, pre-warmed uv images, outbound HTTPS, lack of platform egress filtering).
- P-04.05 normalizes execution timeout, cancellation, and resource failures using proven platform semantics.
- P-04.06 adds bounded malicious-fixture security tests covering exfiltration, process explosion, verifier discovery, and protected-surface mutation.

### P-04.01 — Formalize target-repository threat model
Status: DONE (independently VERIFIED / PASS at SHA 4db39b136d2fd12e6ebd67eb5c5577d283f279e2)
Acceptance:
- formal threat model document in docs/;
- generic adversaries and trust boundaries defined;
- treats target repository as untrusted code;
- Builder self-certification prohibited;
- verifier asset independence specified;
- prompt injection, credential exfiltration, and protected-surface mutation threats analyzed;
- no provider-specific sandbox capability assumed;
- deterministic facts recognized as authoritative over model prose.

### P-04.02 — Implement secret redaction and forbidden persistence rules
Status: DONE (independently VERIFIED / PASS at SHA c285379b3a453767db6434786c26ff0c6b6ec34b)
Acceptance:
- deterministic secret-shaped value redaction engine;
- forbidden durable-secret persistence rules for evidence store and logs;
- safe log and serialization boundaries;
- synthetic-credential unit and property tests;
- no provider credential injection implemented;
- no claim that any live runtime guarantees secret protection.

### P-04.03 — Define sandbox resource/network/process policy from proven platform capability
Status: DONE (independently VERIFIED / PASS at SHA 5673b0ae07120151a08626161a21586b44c75bc1; sandbox resource, network, and process policy derived from proven platform capabilities; PID_PROCESS_LIMIT explicitly classified as UNPROVEN at platform layer; operational timeouts and disposable teardown documented as application policy; OpenAPI facts reconciled; documented in docs/SANDBOX_POLICY.md and implemented in src/basebreak/security/sandbox_policy.py)
Acceptance:
- requires proven live platform capabilities from P-01;
- defines resource ceilings, network policy, and process limits from verified facts.

### P-04.04 — Implement protected-surface manifest and diff checks
Status: DONE (independently VERIFIED / PASS at SHA 96f032f1165425d88e1bbbc23d6b925ee05e2841)
Acceptance:
- protected-surface manifest contract;
- normalized repository path validation;
- diff and change-detection logic rejecting mutations to protected verification/governance paths;
- path-traversal, symlink, and case-normalization boundary tests;
- no assumptions about specific sandbox filesystem APIs.

### P-04.05 — Implement execution timeout/cancellation/resource-failure normalization
Status: DONE (independently VERIFIED / PASS at SHA 5673b0ae07120151a08626161a21586b44c75bc1; deterministic outcome normalization into NormalizedExecutionRecord with fail-closed classification; removed unproven regexes and HTTP status heuristics; provider-neutral normalizer driven strictly by authoritative facts; raw payloads digested for audit trail without circular parsing; ambiguous signals fail closed as UNKNOWN_PROVIDER_FAILURE; implemented in src/basebreak/security/normalization.py)
Acceptance:
- requires proven platform timeout/cancellation semantics.

### P-04.06 — Add malicious-fixture tests for exfiltration attempts, fork bombs, verifier discovery, and protected-surface mutation
Status: DONE (independently VERIFIED / PASS at SHA 5673b0ae07120151a08626161a21586b44c75bc1; malicious-fixture test suite covering secret exfiltration, process explosion/command-length budget, verifier discovery, protected-surface mutation, and network egress policy; unproven cgroup prose fails closed; PID_PROCESS_LIMIT verified as UNPROVEN; all 465 security tests passing deterministically; implemented in tests/security/test_malicious_fixtures.py and tests/security/test_p04_06_closure.py)
Acceptance:
- malicious-fixture test suite exercising boundary enforcement without unverified sandbox assumptions.

Phase exit: safe bounded execution contracts exist before autonomous building.
(P-04 phase independently CLOSED / PASS at SHA 5673b0ae07120151a08626161a21586b44c75bc1).

---

# P-05 — Nebius/Nemotron Adapter Layer
### P-05.01 — Implement bounded model client using discovered model identifiers/config
Status: DONE (independently VERIFIED / PASS at SHA 90e5391b9bd7a406c62b838bfa1f24e85400ad65)
### P-05.02 — Implement sandbox create/exec/inspect/teardown adapter
Status: DONE (independently VERIFIED / PASS at SHA bee7a22e77195e21ba5bc6341a72caed6ef675d9)
### P-05.03 — Implement repository materialization and source-hash verification adapter
Status: DONE (independently VERIFIED / PASS at SHA f149afffb58b72dfeba301e59868c38eef6a7107)
### P-05.04 — Implement model/sandbox telemetry normalization with secret-safe logs
Status: DONE (independently VERIFIED / PASS at SHA 899fe27feb8ec530c226a46832d47f886cd6947d)
### P-05.05 — Implement retry/idempotency policy without duplicating external actions
Status: DONE (independently VERIFIED / PASS at SHA ef2d55c6ed6195e291b5e3ba8fe753541e5863c4)
### P-05.06 — Execute live adapter integration suite
Status: DONE (independently VERIFIED / PASS at SHA eeba36126968f34494ef1c12b1e3ddbccc18ad91; genuine LIVE_NEBIUS execution across complete unbroken adapter chain against real Token Factory services; verified candidate commit bee7a22e77195e21ba5bc6341a72caed6ef675d9 and tree 63e522e074ad0ca3c1a12f042af56c907c5dca89 down to exact bit; test command passed with exit code 0; lifecycle observed; durable evidence committed in docs/P05_06_LIVE_ADAPTER_INTEGRATION.md; P-05 phase independently CLOSED / PASS at SHA eeba36126968f34494ef1c12b1e3ddbccc18ad91)
Phase exit: provider adapter is real, fail-closed, and replaceable from domain core. (P-05 phase independently CLOSED / PASS at SHA eeba36126968f34494ef1c12b1e3ddbccc18ad91; P-Ω broad phase-closure audit: PASS; P-06.01 through P-06.04 batch conditionally authorized).

---

# P-06 — Contract Compiler
Goal: convert natural-language task into reviewable verification contract.

### P-06.01 — Define task ingestion and deterministic normalization
Status: DONE (independently VERIFIED / PASS at SHA a76762c62fffba30a7b8d1ead2a130c192c8c072; deterministic task ingestion and normalization with raw text preservation, NFC Unicode normalization, BOM stripping, line-ending standardization, indentation-preserving whitespace rules, bounded byte ceilings, SHA-256 digests, and secret-safe representations in src/basebreak/compiler/ingestion.py; 16 focused tests passing in tests/compiler/test_ingestion.py)
### P-06.02 — Use Nemotron to propose atomic acceptance requirements with citations to task text
Status: DONE (independently VERIFIED / PASS; live-tested source commit b2410e76028e1d3b1d97ebb087f1113f3f8097cb, tree f476f2c7407d7ec9e7ab0cb138e40bbfb0e66412; canonical evidence/governance closure at SHA c93485892e6c40cfe0f95aa82b94fc2346b70fb0; genuine LIVE_NEBIUS execution documented in docs/P06_02_LIVE_REQUIREMENT_PROPOSAL.md)
### P-06.03 — Classify change semantics and uncertainty
Status: DONE (independently VERIFIED / PASS at SHA 6a8fe7756ed0ad3df8d7265d0702ecbc0842ecee; final serialization authority-invariant repair complete; ChangeSemanticsClassification enforces authoritative fields strictly equal deterministic facts at construction and deserialization; verification_requirement canonically validated; DeterministicClassificationFact and ModelChangeProposal enforce certainty/class semantic invariants during all construction paths; ModelChangeProposal is_authoritative strictly False; provider-neutral compiler core with zero provider identifiers or model client calls; 52 tests passing in tests/compiler/test_change_semantics.py)
### P-06.04 — Deterministically validate requirement IDs, scope, forbidden actions and contradictions
Status: DONE (independently VERIFIED / PASS at SHA 16bc6323a99f971d1cf4e90aedd4b828e240bd5a)
### P-06.05 — Add human-editable contract review surface/CLI
Status: DONE (independently VERIFIED / PASS at SHA 763d12efb75c4c7a3d8df78d73737bf0bde9cb3e; implemented deterministic contract review session in src/basebreak/compiler/review.py and review CLI adapter in src/basebreak/compiler/review_cli.py; repaired review-authority and fail-closed guarantees: constructor-level authority invariant centralized in ReviewResult.__post_init__ requiring authoritative ReviewBundle revalidation for any APPROVED / READY_FOR_FREEZE result across all construction paths; direct constructor with tampered contract or missing source_bundle fails closed; ReviewSession.approve and ReviewResult.from_dict/from_json both bind source_bundle through the single constructor authority path; source_bundle is non-serialized InitVar and excluded from to_dict/to_json; validate-before-write enforced across CLI edit commands leaving original files byte-for-byte unchanged on failure; strict nested schema on ReviewBundle requirements rejecting injected/unknown keys; strict type checking without silent string coercion; create_review_bundle_from_contract factory revalidation and equality verification; secret-safe nested diagnostics; 40 unit tests in test_review.py and 25 CLI tests in test_review_cli.py passing; 229 non-live compiler tests passing; 1515 non-live tests passing; ruff check, ruff format --check, and mypy all passing clean)
### P-06.06 — Freeze contract digest before Builder execution
Status: DONE (independently VERIFIED / PASS at SHA 4588b7efdd331725364be59a9484a68c39f30d86; implemented deterministic contract freezing in src/basebreak/compiler/freeze.py; enforced constructor-level authority invariant requiring authoritative decision == APPROVED and status == READY_FOR_FREEZE ReviewResult via source_review InitVar across all construction paths; direct constructor with missing source_review, tampered contract/requirements, or non-matching review fails closed; freeze_review_result factory derives identity payload exclusively from review_result.contract with canonical requirement_id ordering and SHA-256 digest; FrozenContract.from_dict/from_json requires source_review and fails closed against tampered or attacker-recomputed digests; FrozenContract and FrozenRequirement are immutable dataclasses with zero mutation methods; deterministic verification via verify_frozen_contract; provider-neutral with zero adapter/provider imports; 46 unit/invariant tests passing in test_freeze.py; 275 compiler tests passing; 1561 full non-live tests passing; ruff check, ruff format --check, and mypy passing clean)
Acceptance:
- contract digest computed deterministically from normalized acceptance requirements;
- frozen contract digest cannot be modified by Builder or Verifier;
- establishes root link of evidence chain: `requirement → frozen contract digest → witness digest → BASE/CANDIDATE/COUNTERFACTUAL execution evidence`.
Phase exit: Builder cannot silently rewrite the task it will later “prove”. (P-06.01 through P-06.06 all independently VERIFIED / PASS; P-Ω P-06 phase-closure documentation integrity and critical security-truth reconciliation audit in progress as EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE; P-06 phase remains OPEN pending independent P-Ω closure; P-07+ remain NOT AUTHORIZED / NOT_RUN).

---

# P-07 — Builder Runtime v1
### P-07.01 — Define Builder context allowlist and model input minimization
Status: DONE (independently VERIFIED / PASS at SHA 4cccc112bf4a50448eb81e91cb4902fa3344798f)
Acceptance:
- Builder input envelope distinguishes trusted contract/control instructions from untrusted repository context;
- explicit deny-by-default allowlist bounds repository files entering context;
- model-input minimization bounds single-file and total byte sizes;
- deterministic provenance, canonical path ordering, and cryptographic context digest;
- fail-closed rejection of protected governance surfaces, verifier-only / witness assets, secrets, and path traversal;
- untrusted repository text remains unprivileged data with zero governance authority.
### P-07.02 — Implement Nemotron Builder plan/code loop in real sandbox
Status: DONE (independently VERIFIED / PASS at SHA 8419f86c954313d49d9445a0ef4274fb94bfa0ce; implemented Nemotron Builder plan/code loop in disposable sandbox in src/basebreak/builder/loop.py; authoritative FrozenContract and BuilderContextEnvelope integration; real live Nemotron inference via canonical NebiusModelClient on nvidia/Nemotron-3_5-Lightning; real disposable sandbox execution via canonical NebiusSandboxAdapter on tag:astral/uv:python3.11-alpine; structured Builder proposal with plan, proposed file actions, and proposed commands; zero self-certification with is_authoritative strictly False; secret-safe prompts and outputs; no file edits or command execution in P-07.02; surgically repaired: removed unsafe TypeError model fallback ensuring exactly one model_client.complete invocation per bounded call, clarified timeout authority belongs strictly to canonical P-05 ModelClientConfig.timeout_seconds, and honest zero-cost promotional balance wording; tested source commit df13707106bf92bc027a6268c92903c1795c2793, tree 1d6b10e810f7e56c918c52c255d9509add256f0d; genuine LIVE_NEBIUS evidence in docs/P07_02_LIVE_BUILDER_LOOP.md; 27 unit tests passing in tests/builder/test_loop.py; 1647 full non-live tests passing; ruff check, ruff format --check, and mypy passing clean)
### P-07.03 — Implement bounded file editing and command execution
Status: DONE (independently VERIFIED / PASS at SHA b5a40a589ca4c82255880237abb87f0a52a80a40; final surgical repair: eliminated caller-asserted materialized_source authority path from CandidateWorkspaceExecutor.execute(); removed caller-constructible VerifiedMaterializedSource dataclass; enforced mandatory source materializer invocation inside candidate sandbox VM before any candidate file mutations or commands run; verified materialization record proves commit match, locator match, subpath consistency, workspace match, and sandbox identity match; fail-closed rejection of caller-supplied materialization records and bare digests; 51 focused unit tests passing in tests/builder/test_candidate_execution.py; 1718 full non-live tests passing; ruff check, ruff format --check, and mypy passing clean)

### P-07.04 — Capture candidate diff/tree hash and Builder-authored tests
Status: DONE (independently VERIFIED / PASS at SHA 49eb9c8c2d03d47d32a6602bbb317b7e97125304)
### P-07.05 — Enforce protected surfaces and forbidden action policy
Status: DONE (independently VERIFIED / PASS at SHA 21eade65ab81c3f3bc32dd8a071b1c0f5e4f1fe2)
### P-07.06 — Reproduce candidate from trusted base + captured patch in a fresh sandbox
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (surgical clean-base authority elimination repair: completely removed clean_base_record and caller clean-base authority from CandidateExecutionConfig and CandidateReproductionConfig; CandidateWorkspaceExecutor and CandidateReproductionExecutor now internally and independently invoke trusted materializer for clean-base checkpoints bound to authoritative envelope source commit and tree; 4 distinct auditable provider operations verified: Builder clean base checkpoint 01a105f1-1aae-775b-b376-8755687822a6 with image fd7328f0-210f-43fb-8758-0365de3d5baf, Builder disposable candidate execution 01a105f1-2e96-7051-9600-8bbb55d2939d with sbx-1e5ecaafe0884b0f and result_image_uuid=None, Reproduction clean base checkpoint 01a105f1-3a71-7757-9ac1-e6c293165017 with image 93a119d7-fd65-4ee5-b8eb-0901531f03eb, and Reproduction disposable execution 01a105f1-4b8b-72ed-8978-02817942c5c1 with sbx-2c1f25803bb44e97 and result_image_uuid=None; fresh genuine LIVE_NEBIUS proof in docs/P07_06_LIVE_CANDIDATE_REPRODUCTION.md tested against implementation SHA b1c93ee1e00f3617d6d2d7c17fbf9a530eac3f72 on nvidia/Nemotron-3_5-Lightning; patch digest d0d986a1c6f9136a457a78c92a886fef345b461fe49a4d8dc4a4c3fd31212ebd, candidate tree c61f4e4f0bfcdb82509243b39d84361782620588, reproduced tree c61f4e4f0bfcdb82509243b39d84361782620588, deterministic tree equality True; 20 surgical repair tests in tests/builder/test_p07_06_repairs.py; 34 focused reproduction tests in tests/builder/test_candidate_reproduction.py; 272 builder non-live tests; 1833 full non-live tests passing; ruff check, ruff format --check, and mypy clean)
Phase exit: a real AI-written candidate can be produced and independently reproduced. (P-07 Phase Exit complete: all micro-tasks P-07.01 through P-07.06 completed; genuine LIVE_NEBIUS proof in docs/P07_06_LIVE_CANDIDATE_REPRODUCTION.md; P-07 phase status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE; P-08+ remain NOT AUTHORIZED / NOT_RUN)

---

# P-08 — Verifier Isolation & Sealed Challenge Boundary
### P-08.01 — Define minimum trusted inputs visible to Verifier
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (implemented VerifierContextEnvelope, VerifierExecutionPolicy, VerifierInputClassification in src/basebreak/verifier/context.py; classifies inputs as TRUSTED_CONTROL vs UNTRUSTED_CANDIDATE; deny-by-default blocks Builder summaries, proposals, reasoning, and self-certification claims; enforces pinned 40-char commit SHA; canonical SHA-256 context digest; 11 unit tests in tests/verifier/test_context.py)
### P-08.02 — Create separate verifier sandbox/context with no Builder workspace inheritance
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (implemented VerifierSandboxManager, VerifierSandboxConfig, VerifierSandboxSession in src/basebreak/verifier/sandbox.py; enforces fresh disposable sandbox creation; rejects Builder sandbox reuse with BuilderSandboxReuseError; rejects Builder workspace collisions with BuilderWorkspaceInheritanceError; fails closed on missing/ambiguous sandbox identity; zero host/simulation fallback; zero self-certification with is_authoritative=False, is_causally_verified=False, grants_pass=False; surgical repair enforces mandatory materializer, removes broad TypeError trial-and-error retry loops in favor of deterministic pre-invocation signature inspection with exactly one invocation attempt, and validates commit, tree digest, workspace, sandbox, and locator facts with zero fallback to expected values; 17 unit tests in tests/verifier/test_sandbox.py; 57 verifier suite tests passing; 1890 full non-live tests passing)
### P-08.03 — Implement sealed witness storage/integrity contract
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (implemented WitnessArtifact, SealedWitnessRecord, TrustedWitnessVault in src/basebreak/verifier/witness_store.py; deterministic artifact and seal SHA-256 digests; immutable fail-closed integrity verification; rejects caller-asserted unverified authority with UntrustedWitnessAuthorityError; enforces path normalization and blocks protected-surface collisions; scans for secrets with WitnessSecretError; 8 unit tests in tests/verifier/test_witness_store.py)
### P-08.04 — Prevent Builder access to hidden witness implementation/artifacts
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (implemented VerifierBoundaryEnforcer in src/basebreak/verifier/boundary.py; mechanically excludes verifier/witness paths from Builder context; filters repo file enumeration; protects Builder environment variables from verifier tokens/paths; sanitizes verifier tracebacks and errors; rejects candidate patch diffs targeting verifier surfaces with ProtectedSurfaceViolation; scans public results for unredacted witness code with WitnessLeakageInResultError; protected surfaces augmented in src/basebreak/security/protected_surfaces.py; 7 unit tests in tests/verifier/test_boundary.py)
### P-08.05 — Add adversarial isolation tests
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (14 adversarial isolation tests in tests/verifier/test_isolation.py covering Builder sandbox reuse, workspace inheritance, input forgery, caller-created witness records, artifact tampering, path traversal, file enumeration, patch mutation against verifier assets, error/result leakage, missing sandbox identity, mutable ref substitution, fake LIVE_NEBIUS laundering, host/simulation fallback, and Builder regression without verifier visibility; 57 focused verifier tests; 1890 full non-live tests passing; ruff check, ruff format, and mypy clean)
Phase exit: verifier independence is mechanically stronger than “another prompt”. (Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE; all micro-tasks P-08.01 through P-08.05 completed; P-09+ remain strictly NOT AUTHORIZED / NOT_RUN; HARD STOP ENFORCED)

---

# P-09 — Witness Generation
### P-09.01 — Implement Nemotron witness-plan generation from frozen contract + trusted source
Status: DONE (implemented ProposedWitnessArtifact, WitnessPlanProposal, generate_witness_plan in src/basebreak/verifier/witness_plan.py; bounded invocation of canonical Nemotron client; strict contract digest and requirement ID binding; zero Builder authority leakage; deterministic JSON extraction with brace balancing; 13 tests in tests/verifier/test_witness_plan.py)
Acceptance:
- witness plan must carry and reference the exact frozen contract digest;
- deterministic binding between contract identity and planned witness.
### P-09.02 — Validate witness plans against scope/security/runtime policy
Status: DONE (implemented ValidatedWitnessArtifact, ValidatedWitnessPlan, WitnessPlanValidator in src/basebreak/verifier/witness_plan.py; enforces BUG_FIX scope, allowed test executables, path normalization, protected-surface/verifier boundary separation, secret scanning, and zero Builder authority; tests in tests/verifier/test_witness_plan.py)
### P-09.03 — Generate executable independent behavioral witnesses for BUG_FIX
Status: DONE (implemented WitnessGenerator in src/basebreak/verifier/witness_generator.py; converts validated plans into WitnessArtifacts, checks against Builder test collisions and imports, and seals into TrustedWitnessVault with authentic HMAC-SHA256 signatures; 5 tests in tests/verifier/test_witness_generator.py)
### P-09.04 — Add witness determinism/timeout/result normalization
Status: DONE (implemented WitnessOutcome enum, NormalizedWitnessResult, normalize_witness_execution in src/basebreak/verifier/witness_result.py; anti-collapse invariants prevent TIMEOUT/ERROR from masquerading as FAIL or PASS; sanitizes streams and computes deterministic result digest; 7 tests in tests/verifier/test_witness_result.py)
### P-09.05 — Detect vacuous witnesses and invalid preconditions
Status: DONE (implemented static AST analysis and runtime execution output analysis in src/basebreak/verifier/vacuity.py; detects zero assertions, trivial constant assertions, 0 tests collected, and setup/import failures; 6 tests in tests/verifier/test_vacuity.py)
### P-09.06 — Preserve witness digest before candidate execution
Status: DONE (implemented ImmutableWitnessLock, create_witness_lock, verify_witness_lock_chain in src/basebreak/verifier/witness_lock.py; locks witness digest before candidate execution; validates unbroken chain requirement_id -> frozen_contract_digest -> witness_digest; 4 tests in tests/verifier/test_witness_lock.py)
Acceptance:
- compute and preserve immutable witness digest bound to the frozen contract digest;
- witness identity/digest is mechanically locked before candidate execution.
Phase exit: at least one independent witness can exist without Builder knowledge. (P-09 Phase Exit complete: all micro-tasks P-09.01 through P-09.06 completed; genuine LIVE_NEBIUS proof bound to implementation SHA `6cdbe613eada838b31d8d97620f3f02bf19a8916` and isolated demo target `zyganali-glitch/basebreak-demo-target.git` in docs/P09_LIVE_WITNESS_PLAN.md; P-09 phase status: EXECUTOR_REPAIRED / INDEPENDENT_QA_CANDIDATE)

---

# P-10 — Causal Two-World Engine
### P-10.01 — Execute identical witness on trusted base
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (implemented in src/basebreak/causal/engine.py; executes sealed witness in fresh disposable verifier sandbox against clean materialized base source commit; normalizes outcome to FAIL under BUG_FIX; verified in tests/causal/test_engine.py and tests/causal/test_p10_closure.py)

### P-10.02 — Execute identical witness on exact candidate
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (implemented in src/basebreak/causal/engine.py; executes identical sealed witness in fresh disposable verifier sandbox against candidate tree with patch applied; normalizes outcome to PASS under BUG_FIX; verified in tests/causal/test_engine.py and tests/causal/test_p10_closure.py)

### P-10.03 — Bind both executions to source/sandbox/witness hashes
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (implemented in src/basebreak/causal/engine.py; validates distinct sandbox identities, rejects Builder sandbox reuse with BuilderSandboxReuseError, enforces pre-execution witness lock chain of custody via verify_witness_lock_chain, rejects identical tree digests under BUG_FIX as empty patch; verified in tests/causal/test_engine.py and tests/causal/test_p10_closure.py)
Acceptance:
- BASE and CANDIDATE execution evidence records must explicitly carry and bind to the exact frozen contract digest and witness digest;
- no reliance on loose prose matching; execution evidence is mechanically and cryptographically bound to contract and witness identities.

### P-10.04 — Reconcile BUG_FIX FAIL→PASS deterministically
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (implemented in src/basebreak/causal/reconciliation.py; reconcile_causal_transition enforces invariant truth: BASE=FAIL and CANDIDATE=PASS is the sole positive causal transition yielding CAUSAL_BUG_FIX_VERIFIED and PreliminaryVerdict.VERIFIED; zero model authority; 10 tests in tests/causal/test_reconciliation.py)

### P-10.05 — Handle PASS→PASS, FAIL→FAIL, ERROR/TIMEOUT as non-verified states
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (implemented in src/basebreak/causal/reconciliation.py; anti-collapse blocks PASS->PASS as UNVERIFIED_TRIVIAL_PASS / INCONCLUSIVE, FAIL->FAIL as UNVERIFIED_DEFECT_PERSISTS / CONTRADICTED, PASS->FAIL as UNVERIFIED_REGRESSION / CONTRADICTED, TIMEOUT as NON_VERIFIED_TIMEOUT / INCONCLUSIVE, ERROR as NON_VERIFIED_EXECUTION_ERROR / INCONCLUSIVE, vacuous witness as NON_VERIFIED_VACUOUS / INCONCLUSIVE, and precondition failure as NON_VERIFIED_INVALID_PRECONDITION / BLOCKED; verified in tests/causal/test_reconciliation.py and tests/causal/test_p10_closure.py)

### P-10.06 — Produce first local causal receipt
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (implemented in src/basebreak/causal/receipt.py; LocalCausalReceipt with cryptographic binding to contract, witness, candidate, and both worlds; computes deterministic SHA-256 receipt digest over canonical JSON bytes; verify_causal_receipt_integrity detects tampering across all fields; 3 tests in tests/causal/test_receipt.py)

### P-10.07 — Execute first end-to-end causal vertical slice and produce a judge-readable proof summary
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (implemented in src/basebreak/causal/harness.py; run_causal_verification_slice executes coherent vertical slice from contract and plan to sealed witness, two-world execution, and causal receipt; format_judge_proof_summary and render_judge_proof_markdown produce machine-readable JSON and human-inspectable Markdown highlighting thesis 'If the patch matters, the base must break.' and unbroken digest chain; minimal developer harness without prematurely freezing public CLI; verified in tests/causal/test_harness.py and tests/causal/test_p10_closure.py)
Acceptance:
- integration checkpoint, not final UI;
- complete path from task → Builder → independent witness → BASE execution → CANDIDATE execution → causal receipt;
- does not bypass P-08/P-09 independence requirements;
- proof summary is machine-readable and human-inspectable;
- provenance clearly distinguishes FIXTURE/LOCAL_EXECUTION/LIVE_NEBIUS/RECORDED_LIVE;
- validates complete mechanical digest chain: `requirement → frozen contract digest → witness digest → BASE/CANDIDATE execution evidence`;
- exposes a bounded MINIMAL DEVELOPER INVOCATION / INTEGRATION HARNESS capable of executing that coherent slice (may be temporary/internal; must NOT prematurely freeze `basebreak verify` or another public stable CLI contract; stable public CLI remains frozen at P-19 after P-18 receipt contracts stabilize).
Phase exit: Basebreak can prove a real base/candidate behavioral transition. (P-10 Phase Exit complete: all micro-tasks P-10.01 through P-10.07 completed; all 31 causal tests passing; 1962 full non-live tests passing; genuine LIVE_NEBIUS proof bound to implementation SHA `6cdbe613eada838b31d8d97620f3f02bf19a8916` and isolated demo target `zyganali-glitch/basebreak-demo-target.git` in docs/P10_LIVE_CLOSURE_PROOF.md; P-10 phase status: EXECUTOR_REPAIRED / INDEPENDENT_QA_CANDIDATE; P-11+ remain strictly NOT AUTHORIZED / NOT_RUN; HARD STOP ENFORCED)

---

# P-11 — Counterfactual Third Run
### P-11.01 — Define safe candidate-delta subtraction strategies
Status: INDEPENDENTLY VERIFIED / PASS at SHA `d936bd1d6b57d98c5beb783173ae6cae02b1e698`.
### P-11.02 — Select bounded relevant patch region without model authority over verdict
Status: INDEPENDENTLY VERIFIED / PASS at SHA `e37b772300c1892304c3ac66358e8125c8cd96f9`.
### P-11.03 — Materialize counterfactual candidate in fresh sandbox
Status: INDEPENDENTLY VERIFIED / PASS at SHA `e37b772300c1892304c3ac66358e8125c8cd96f9`.
### P-11.04 — Execute same witness against counterfactual
Status: INDEPENDENTLY VERIFIED / PASS at SHA `e37b772300c1892304c3ac66358e8125c8cd96f9`.
### P-11.05 — Reconcile FAIL→PASS→FAIL causal triplet
Status: INDEPENDENTLY VERIFIED / PASS at SHA `e37b772300c1892304c3ac66358e8125c8cd96f9`.
### P-11.06 — Detect invalid counterfactual construction and return INCONCLUSIVE, never false PASS
Status: INDEPENDENTLY VERIFIED / PASS at SHA `e37b772300c1892304c3ac66358e8125c8cd96f9`.
Phase exit: critical demonstrations can show causal necessity under the witness. (P-11 Phase independently CLOSED / PASS at canonical closure SHA `e37b772300c1892304c3ac66358e8125c8cd96f9`; fresh LIVE_NEBIUS-tested implementation SHA `6bb8e0913d08b307ea4382833d4772380389ca78`; genuine LIVE_NEBIUS causal triplet verification executed and passed in docs/P11_LIVE_CLOSURE_PROOF.md with real Nemotron witness generation, 3 isolated Nebius sandboxes sbx-0d559eac1af648ce / sbx-4047f62bcebb4a3b / sbx-3ed738b2ce7d4ea7, BASE=FAIL exit 1, CANDIDATE=PASS exit 0, COUNTERFACTUAL=FAIL exit 1, CAUSAL_TRIPLET_VERIFIED, PreliminaryVerdict.VERIFIED, causal receipt 3b80457c7d1499fef1b160286bbc386fb6b16ae36921e65f775d338d905eb4a2).

---

# P-12 — Minimal Causal Slice
### P-12.01 — Define causal-slice scope and non-formal-proof disclaimer
Status: DONE (independently VERIFIED / PASS at SHA `b8164588c560b12a2599238f05632eb33441a4d0`; implemented provider-neutral deterministic domain contracts for causal-slice scope in src/basebreak/causal/slice.py; binds exact CandidateSnapshot, candidate_tree_digest, candidate_patch_digest, frozen_contract_digest, sealed_witness_digest, P-11 counterfactual delta identity, tested subset identity, remainder identity, receipt digest, and provenance; strictly enforces zero authority with is_authoritative=False, grants_pass=False, is_causally_verified=False; defines canonical NonFormalProofDisclaimer with CANONICAL_DISCLAIMER_TEXT and disclaims mathematical proof, global minimality, universal necessity, untested input guarantees, semantic equivalence, and formal verification; codifies 10 scope and authority rules in CausalSliceScopeRules; prohibits marketing certainty terminology; 37 unit and adversarial tests passing in tests/causal/test_slice.py).
### P-12.02 — Implement bounded hunk/subset minimization algorithm
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (repaired per QA findings: minimizer records authentic SubsetExecutionFact evidence for every evaluated subset; rejects naked WitnessOutcome callback returns fail-closed with TypeError; validates 1-to-1 subset, scope, tree, witness, contract, and runtime_config_digest bindings; implemented BoundedSubsetMinimizer, SliceSearchBudget, PatchUnit, SubsetEvaluationRecord, BoundedMinimizerResult, create_tested_patch_subset_from_hunks, reconstruct_subset_patch in src/basebreak/causal/minimizer.py; builds directly on P-11 subtraction/counterfactual machinery; derives canonical searchable patch units mechanically from ParsedCandidatePatch; searches within explicit configurable budget/strategy; materializes tested subsets in isolated context; executes identical sealed witness; records exact execution identities; deterministic termination; supports statuses TESTED_NECESSARY_SUBSET, NO_REDUCTION_FOUND, MULTIPLE_SUFFICIENT_SUBSETS, AMBIGUOUS_SLICE, NON_MONOTONIC_BEHAVIOR, SEARCH_INCOMPLETE, INVALID_SUBSET; 11 tests in tests/causal/test_minimizer.py).
### P-12.03 — Cache/reuse safe deterministic executions to control cost
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (repaired per QA Defect 1: ExecutionCacheKey, payload, store, lookup, and entry strictly bind deterministic runtime_config_digest; rejects runtime configuration mismatches with CacheRejectionReason.RUNTIME_CONFIG_MISMATCH; binds execution_fact and returns authentic SubsetExecutionFact; binds 12 cryptographic dimensions: source identity, source commit, subpath, candidate/subset tree digest, retained patch/subset digest, removed delta digest, frozen contract digest, sealed witness digest, requirement ID, command/spec, runtime config digest, provenance; strictly prohibits FIXTURE/LOCAL_EXECUTION/RECORDED_LIVE -> LIVE_NEBIUS substitution, witness/contract/tree divergence, mutable workspace reuse, and stale/tampered cache reuse; auditable hit/miss/rejection reasons; preserves original evidence provenance; 14 tests in tests/causal/test_cache.py).
### P-12.04 — Bind requirement → witness → minimal necessary candidate slice
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (repaired per QA Defect 2: canonical factory create_causal_slice_receipt_from_result mechanically derives receipt tested subsets, execution facts, evaluated outcomes, and counterfactual deltas directly from result.evaluated_subsets; forbids caller-supplied fabricated outcome sequences; binds execution_facts tuple and runtime_config_digest; verifies 1-to-1 counts, order, digests, and scope bindings fail-closed; binds requirement -> frozen contract -> sealed witness -> source identity -> candidate snapshot -> tested subset identities -> structured execution facts -> counterfactual identities -> search budget -> completeness -> empirical slice result -> runtime_config_digest -> provenance -> mandatory P-12.01 non-formal-proof disclaimer; enforces is_authoritative=False, grants_pass=False, is_causally_verified=False; 8 tests in tests/causal/test_slice_receipt.py).
### P-12.05 — Test interacting hunks, non-monotonic behavior, and ambiguous slices
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (comprehensive adversarial test suite in tests/causal/test_p12_adversarial.py covering 42 focused test cases including required QA repair cases A through O: A runtime config cache divergence, B fake receipt PASS override rejection, C swapped subset records rejection, D foreign witness fact rejection, E foreign contract fact rejection, F tampered scope digest fail-closed, G foreign candidate identity fact rejection, H subset count/order mismatch rejection, I receipt status mismatch rejection, J receipt completeness mismatch rejection, K cached fact provenance preservation, L ERROR/TIMEOUT anti-collapse invariant, M tampered execution digest fail-closed, N naked WitnessOutcome rejection with TypeError, O deterministic identical identity generation; plus interaction, ambiguity, and non-monotonicity tests).
Phase exit: Basebreak can explain which tested change subset is necessary under a witness. (P-12 Bounded Surgical Repair complete: Defect 1 and Defect 2 resolved; all 233 causal tests passing; 2161 non-live tests passing; fresh LIVE_NEBIUS closure demonstration executed and passed in docs/P12_LIVE_CLOSURE_PROOF.md with real Nemotron witness generation, 4 isolated Nebius sandboxes sbx-b2d1317ce8d44f76 / sbx-4e6f4c47e392468b / sbx-96ebe259fa714734, BASE=FAIL exit 1, FULL CANDIDATE=PASS exit 0, SUBSET IRRELEVANT=FAIL exit 1, SUBSET CAUSAL=PASS exit 0, TESTED_NECESSARY_SUBSET, minimal 1 hunk retained and 1 irrelevant hunk removed, bound to implementation SHA ca2fe46867a83641c22c47375da966fc701d5878, causal slice receipt d75fa9e685cc5fddfa017c2fe58cb5079060d7a9e7961f702ac24df6a85f2016; P-12 status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE; P-13+ remain strictly NOT AUTHORIZED / NOT_RUN; HARD STOP ENFORCED)

---

# P-13 — Change-Semantics Expansion
### P-13.01 — FEATURE ABSENT→PRESENT verifier
Status: DONE (independently VERIFIED / PASS at SHA `0045ad89394758bb6c128b846945f2e7e8b2b955`)

### P-13.02 — SECURITY_FIX EXPLOITABLE→BLOCKED verifier
Status: DONE (independently VERIFIED / PASS at SHA `0045ad89394758bb6c128b846945f2e7e8b2b955`)

### P-13.03 — REFACTOR behavioral-equivalence verifier
Status: DONE (independently VERIFIED / PASS at SHA `0045ad89394758bb6c128b846945f2e7e8b2b955`)

### P-13.04 — PERFORMANCE parity + benchmark-delta verifier
Status: DONE (independently VERIFIED / PASS at SHA `0045ad89394758bb6c128b846945f2e7e8b2b955`)

### P-13.05 — DEP/API contract migration + regression verifier
Status: DONE (independently VERIFIED / PASS at SHA `0045ad89394758bb6c128b846945f2e7e8b2b955`)

### P-13.06 — Cross-class classification error tests
Status: DONE (independently VERIFIED / PASS at SHA `0045ad89394758bb6c128b846945f2e7e8b2b955`)
Phase exit: product is not a one-demo bug-fix trick. (Phase P-13 independently CLOSED / PASS at SHA `0045ad89394758bb6c128b846945f2e7e8b2b955`).

---

# P-14 — Sealed Repair Loop
### P-14.01 — Define bounded failure-feedback schema
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (committed at SHA `d098907`; implemented SafeRepairFeedback, SanitizedCounterexample, DisclosureClassification, and FailureConditionCategory; canonical hashing, tamper detection, and zero verdict authority enforced)

### P-14.02 — Return minimized counterexample without hidden witness disclosure
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (committed at SHA `ca56f68`; implemented DisclosureSanitizer, secret redaction, and counterexample minimization without leaking sealed witness internals)

### P-14.03 — Re-enter Builder in fresh/controlled repair context
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (committed at SHA `7aae566`; implemented BuilderRepairContextEnvelope, context digest binding, verifier leak prevention)

### P-14.04 — Create repaired candidate with new exact hash
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (committed at SHA `bc89df6`; implemented CandidateLineageRecord, RepairedCandidateSnapshot, anti-candidate-reuse and anti-stagnation rules)

### P-14.05 — Require fresh verifier reproduction for repaired candidate
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (committed at SHA `6b5ed2c`; implemented RepairedVerificationReceipt, execute_repaired_verifier_reproduction, anti-sandbox-reuse, anti-receipt-replay, and fresh reproduction from base)

### P-14.06 — Cap repair rounds/cost and return honest non-success
Status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE (committed at SHA `cb3f6a8`; implemented RepairLoopBudget, RepairLoopReceipt, run_sealed_repair_loop orchestration, honest terminal status classification, and receipt integrity validation)
Phase exit: agent improves from evidence without memorizing the hidden exam. (Phase P-14 batch fully executed and validated; all 6 micro-tasks P-14.01 through P-14.06 completed; P-14 final evidence-authority repair applied eliminating caller-authored failure justification strings for exit code 0 and enforcing valid non-dummy execution identity matching originating receipt digest; 2,327 non-live tests passing; genuine prior LIVE_NEBIUS demonstration executed cleanly (exit code 0) bound to clean Basebreak implementation SHA `dcfa538459340ae5adbd0e001ecf5aaa87971fb5` in `docs/P14_LIVE_CLOSURE_PROOF.md`; fresh live execution blocked at billing preflight awaiting operator promotional balance verification; P-14 status: EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE; P-15+ remain strictly NOT AUTHORIZED / NOT_RUN; HARD STOP ENFORCED)

---

# P-15 — Risk-Adaptive Verification Budget
### P-15.01 — Define deterministic risk features and policy levels
### P-15.02 — Map low/medium/high risk to verification depth
### P-15.03 — Add cost/token/sandbox budget accounting
### P-15.04 — Add policy for when counterrun/slicing is mandatory
### P-15.05 — Add fail-closed behavior when required budget cannot execute
Phase exit: strong verification is economically usable.

---

# P-16 — External Grounding & Tavily
Policy:
- Tavily activates only when correctness materially depends on current external facts;
- preferred competition scenario: current CVE/security advisory or API/library migration facts;
- source provenance must bind to the contract/evidence;
- Tavily never overrides deterministic execution facts;
- runtime use must remain inside verified free/promotional credits;
- no paid Tavily upgrade;
- if bonus participation remains justified, use a real runtime Tavily call rather than bolted-on decoration.
### P-16.01 — Define when external current facts are materially required
### P-16.02 — Implement Tavily adapter with source provenance and strict minimization
### P-16.03 — Bind release-note/CVE/API facts into Grounded Contract evidence
### P-16.04 — Prevent web evidence from overriding deterministic execution
### P-16.05 — Execute real runtime Tavily path if bonus remains strategically justified
Phase exit: current-fact tasks are grounded without bolted-on bonus theater.

---

# P-17 — Causal Coverage & Multi-Requirement Reconciliation
### P-17.01 — Define eligibility denominator for behavioral requirements
### P-17.02 — Aggregate per-requirement causal states
### P-17.03 — Compute deterministic Causal Coverage
### P-17.04 — Handle mixed semantic classes and NOT_RUN requirements
### P-17.05 — Prevent model confidence from entering coverage math
Phase exit: project-level verification is honest and understandable.

---

# P-18 — Verification Receipt
### P-18.01 — Define public receipt schema
### P-18.02 — Bind base/candidate/counterfactual hashes, witnesses and outcomes
### P-18.03 — Include provenance, runtime identities, timing/cost and NOT_RUN
### P-18.04 — Add integrity digest/signature strategy appropriate to hackathon scope
### P-18.05 — Render human-readable receipt without losing machine truth
Phase exit: judges/developers can inspect one proof object.

---

# P-19 — CLI & Developer Workflow
### P-19.01 — Implement `basebreak verify` happy path
### P-19.02 — Implement run/status/evidence/receipt commands
### P-19.03 — Add config schema and safe defaults
### P-19.04 — Add clear blocked/inconclusive/contradicted UX
### P-19.05 — Validate clean-checkout install/run instructions
Phase exit: coherent developer tool exists before dashboard polish.

---

# P-20 — GitHub Integration
### P-20.01 — Implement read-only repository/task ingestion path
### P-20.02 — Resolve exact remote/base SHA and protect against moving refs
### P-20.03 — Generate review artifact/comment text without external mutation
### P-20.04 — Add bounded optional draft-PR/comment integration only if competition value justifies it
### P-20.05 — Require human authority for irreversible GitHub action
Phase exit: real-world repo workflow without autonomous merge theater.

---

# P-21 — API / Orchestrator Surface
### P-21.01 — Define run API contracts from domain types
### P-21.02 — Implement create/status/evidence/receipt endpoints
### P-21.03 — Implement event stream for live build/verify states
### P-21.04 — Enforce authorization and secret-safe serialization
### P-21.05 — Add idempotency/recovery for run creation
Phase exit: UI can consume deterministic runtime state.

---

# P-22 — Judge & Operator UI
Acceptance:
- eventual UI exposes sanitized deterministic reality: base/candidate/counterfactual hashes, evidence provenance, current vs recorded-live status, model/runtime identity where safe, execution timestamps/latency where available, bounded/sanitized sandbox/run identity where safe, NOT_RUN/blocked states;
- does not expose secrets or sensitive provider identifiers.
### P-22.01 — Design single-screen causal story before implementation
### P-22.02 — Implement task/contract and live execution timeline
### P-22.03 — Implement BASE/CANDIDATE/COUNTERFACTUAL comparison
### P-22.04 — Implement requirement→witness→causal-slice map
### P-22.05 — Implement receipt/provenance/NOT_RUN inspection
### P-22.06 — Add responsive judge mode with no fake animations/data
Phase exit: complete coherent product experience, not technical-only proof.

---

# P-23 — Killer Demo Fixture & Live Scenario
### P-23.01 — Build minimal ResetVault-style synthetic repo with genuinely green baseline suite and real hidden bug
### P-23.02 — Freeze task: make reset tokens single-use without breaking first valid reset
### P-23.03 — Validate existing tests remain green while independent witness fails on base
### P-23.04 — Run real Nemotron Builder in Nebius sandbox
### P-23.05 — Run live base/candidate causal verification in fresh sandboxes
### P-23.06 — Run live counterfactual third execution
### P-23.07 — Produce real LIVE_NEBIUS receipt and UI playback
### P-23.08 — Reproduce one immutable real-world open-source bug-fix replay with upstream SHA and license provenance
Acceptance:
- does NOT replace the deterministic ResetVault killer demo;
- choose a genuinely public open-source repository/fix later;
- pin buggy base SHA and fixed SHA;
- record upstream license and provenance;
- independently reproduce a relevant failing witness on the buggy revision and passing witness on the fixed revision;
- do not claim the upstream fix was produced by Basebreak;
- use it to demonstrate that Basebreak can verify a non-staged real-world historical change.
Phase exit: competition killer demo is real, deterministic and repeatable.

---

# P-24 — Adversarial Verification Campaign
### P-24.01 — Builder weakens/deletes tests attack
### P-24.02 — Builder modifies acceptance contract attack
### P-24.03 — Builder attempts verifier/hidden-witness discovery
### P-24.04 — Prompt injection from target repo
### P-24.05 — Evidence tampering/hash rebinding
### P-24.06 — Moving branch/ref race
### P-24.07 — Sandbox timeout/resource exhaustion/network misuse
### P-24.08 — False-positive/vacuous witness campaign
Phase exit: product survives relevant agent/repo adversarial behavior.

---

# P-25 — Reliability, Recovery & Idempotency
### P-25.01 — Persist recoverable run state without trusting mutable workspace
### P-25.02 — Implement crash/retry semantics for model calls
### P-25.03 — Implement sandbox-loss recovery
### P-25.04 — Implement duplicate-run/idempotency protection
### P-25.05 — Implement evidence write deduplication and replay safety
### P-25.06 — Fresh-process recovery E2E
Phase exit: demo/runtime does not depend on one lucky uninterrupted session.

---

# P-26 — Performance, Cost & Model Routing
### P-26.01 — Establish latency/token/sandbox-cost measurement
### P-26.02 — Compare eligible Nemotron models for Builder workload
### P-26.03 — Compare eligible model strategy for Verifier/witness workload
### P-26.04 — Add routing only when quality/cost evidence supports it
### P-26.05 — Benchmark causal verification overhead
### P-26.06 — Publish honest performance/cost limits
Phase exit: technical implementation is efficient, not merely elaborate.

---

# P-27 — Live Deployment
Policy:
- judge access must remain free of charge;
- add abuse/rate/cost controls;
- never expose an unauthenticated endpoint capable of silently draining all free Token Factory/Tavily credits;
- any public live-run capability must be hard-budgeted/rate-limited or otherwise bounded;
- read-only inspection of verified evidence must remain available even if live-call budget is exhausted, with provenance clearly shown.
### P-27.01 — Select eligible Nebius hosting path from current platform reality
### P-27.02 — Containerize/package app with reproducible build
### P-27.03 — Deploy public judge endpoint/test build
### P-27.04 — Verify health/version/source SHA parity
### P-27.05 — Verify signed-out/free judge access
### P-27.06 — Prove deployed app triggers real required Nebius/NVIDIA runtime
Phase exit: working public product exists.

---

# P-28 — Product Design & Judge Comprehension
### P-28.01 — Conduct 30-second comprehension audit
### P-28.02 — Simplify terminology around one memorable claim
### P-28.03 — Surface causal transition before architecture detail
### P-28.04 — Make failure/contradiction visually as valuable as PASS
### P-28.05 — Accessibility/responsive/browser QA
### P-28.06 — Documentation consolidation
Phase exit: judges can understand value without reading architecture docs.

---

# P-29 — Competition Evidence & Reproducibility
### P-29.01 — Create clean-checkout install test
### P-29.02 — Run full test/security/type/lint gates
### P-29.03 — Run fresh live Nebius end-to-end evidence capture
### P-29.04 — Bind deployed source SHA and runtime evidence
### P-29.05 — Final donor/license/provenance audit
### P-29.06 — Final secret/privacy/public-artifact scan
Phase exit: claims are reproducible and provenance-clean.

---

# P-30 — Demo Video & Submission Narrative
Policy:
- P-29 competition evidence must still produce fresh, exact-state `LIVE_NEBIUS` evidence where required;
- P-30 video/demo capture may reuse an immutable real run from P-23/P-29 when: (1) source/release SHA is bound, (2) exact run/evidence identifier is retained, (3) original live provenance is preserved, (4) presentation/replay is clearly labelled `RECORDED_LIVE`, and (5) the replay is NEVER represented as a current live invocation;
- goal: reduce token/sandbox spend, reduce nondeterministic video-recording failure, avoid duplicate credit-consuming live executions, while strictly preserving evidence honesty;
- does not weaken P-29 fresh live evidence requirements.
### P-30.01 — Freeze <3 minute storyboard around causal surprise
### P-30.02 — Capture real live sequence: green baseline → base witness fail → candidate pass → counterfactual fail
Acceptance:
- capture real sequence demonstrating causal triplet;
- permitted to capture either fresh live execution or reuse an immutable `RECORDED_LIVE` run from P-23/P-29 strictly adhering to the RECORDED_LIVE video reuse policy.
### P-30.03 — Record concise English audio and captions
### P-30.04 — Verify no unsupported claim or secret in video
### P-30.05 — Draft Devpost story mapped to four judging criteria
### P-30.06 — Prepare screenshots/architecture only from verified product truth
Phase exit: submission communicates the product as strongly as it is built.

---

# P-31 — Release Candidate & Whole-Repo P-Ω
### P-31.01 — Freeze RC source and dependency lock
### P-31.02 — Run clean-checkout reproduction from RC
### P-31.03 — Run whole-repository P-Ω integrity audit
### P-31.04 — Repair blockers without weakening evidence/tests
### P-31.05 — Re-run affected/full/live gates after repair
### P-31.06 — Create immutable release tag
Phase exit: immutable competition candidate exists.

---

# P-32 — Devpost Submission Freeze
Acceptance:
- required Nebius/NVIDIA feedback field must be verified;
- feedback must come from the factual feedback ledger (`docs/COMPETITION_FEEDBACK_LOG.md`), not invented at submission time;
- public judge/test path remains free of charge through the required judging period;
- zero paid dependency is disclosed honestly if relevant.
### P-32.01 — Revalidate official competition rules at submission time
### P-32.02 — Verify public repo, visible open-source license and README setup
### P-32.03 — Verify working demo/test URL signed-out
### P-32.04 — Verify public YouTube playback <3 minutes and English accessibility
### P-32.05 — Verify Nebius/NVIDIA usage claims and Tavily bonus eligibility if used
### P-32.06 — Complete submission before internal buffer deadline
Acceptance:
- internal operational target is frozen at `October 27, 2026 20:00 Europe/Istanbul` (approximately 72 hours before official deadline of October 30, 2026 10:00 AM PDT / 17:00 UTC);
- explicitly classified as an INTERNAL SAFETY BUFFER to absorb potential submission hiccups, platform outages, or final packaging checks;
- the official competition deadline remains October 30, 2026 10:00 AM PDT;
- this internal buffer does NOT delete planned phases and does NOT authorize premature scope cutting.
### P-32.07 — Perform post-submit signed-out verification without mutating frozen release
Phase exit: submitted, publicly testable, evidence-consistent entry.

---

# P-Ω — Continuous Integrity
P-Ω runs focused throughout and broad at defined boundaries.
It never substitutes for task-specific evidence and never proves itself.
