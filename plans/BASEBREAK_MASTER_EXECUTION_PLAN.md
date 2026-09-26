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
Status: IN_PROGRESS / PRE-LIVE HARNESS REPAIR (NOT COMPLETE; blocked on pre-live harness and clean CI repair, not on unresolved P-05.02; must NOT be presented as PASS)
Phase exit: provider adapter is real, fail-closed, and replaceable from domain core. (P-05 phase NOT closed; P-06+ remain strictly NOT AUTHORIZED / NOT_RUN).

---

# P-06 — Contract Compiler
Goal: convert natural-language task into reviewable verification contract.

### P-06.01 — Define task ingestion and deterministic normalization
### P-06.02 — Use Nemotron to propose atomic acceptance requirements with citations to task text
### P-06.03 — Classify change semantics and uncertainty
### P-06.04 — Deterministically validate requirement IDs, scope, forbidden actions and contradictions
### P-06.05 — Add human-editable contract review surface/CLI
### P-06.06 — Freeze contract digest before Builder execution
Acceptance:
- contract digest computed deterministically from normalized acceptance requirements;
- frozen contract digest cannot be modified by Builder or Verifier;
- establishes root link of evidence chain: `requirement → frozen contract digest → witness digest → BASE/CANDIDATE/COUNTERFACTUAL execution evidence`.
Phase exit: Builder cannot silently rewrite the task it will later “prove”.

---

# P-07 — Builder Runtime v1
### P-07.01 — Define Builder context allowlist and model input minimization
### P-07.02 — Implement Nemotron Builder plan/code loop in real sandbox
### P-07.03 — Implement bounded file editing and command execution
### P-07.04 — Capture candidate diff/tree hash and Builder-authored tests
### P-07.05 — Enforce protected surfaces and forbidden action policy
### P-07.06 — Reproduce candidate from trusted base + captured patch in a fresh sandbox
Phase exit: a real AI-written candidate can be produced and independently reproduced.

---

# P-08 — Verifier Isolation & Sealed Challenge Boundary
### P-08.01 — Define minimum trusted inputs visible to Verifier
### P-08.02 — Create separate verifier sandbox/context with no Builder workspace inheritance
### P-08.03 — Implement sealed witness storage/integrity contract
### P-08.04 — Prevent Builder access to hidden witness implementation/artifacts
### P-08.05 — Add adversarial isolation tests
Phase exit: verifier independence is mechanically stronger than “another prompt”.

---

# P-09 — Witness Generation
### P-09.01 — Implement Nemotron witness-plan generation from frozen contract + trusted source
Acceptance:
- witness plan must carry and reference the exact frozen contract digest;
- deterministic binding between contract identity and planned witness.
### P-09.02 — Validate witness plans against scope/security/runtime policy
### P-09.03 — Generate executable independent behavioral witnesses for BUG_FIX
### P-09.04 — Add witness determinism/timeout/result normalization
### P-09.05 — Detect vacuous witnesses and invalid preconditions
### P-09.06 — Preserve witness digest before candidate execution
Acceptance:
- compute and preserve immutable witness digest bound to the frozen contract digest;
- witness identity/digest is mechanically locked before candidate execution.
Phase exit: at least one independent witness can exist without Builder knowledge.

---

# P-10 — Causal Two-World Engine
### P-10.01 — Execute identical witness on trusted base
### P-10.02 — Execute identical witness on exact candidate
### P-10.03 — Bind both executions to source/sandbox/witness hashes
Acceptance:
- BASE and CANDIDATE execution evidence records must explicitly carry and bind to the exact frozen contract digest and witness digest;
- no reliance on loose prose matching; execution evidence is mechanically and cryptographically bound to contract and witness identities.
### P-10.04 — Reconcile BUG_FIX FAIL→PASS deterministically
### P-10.05 — Handle PASS→PASS, FAIL→FAIL, ERROR/TIMEOUT as non-verified states
### P-10.06 — Produce first local causal receipt

### P-10.07 — Execute first end-to-end causal vertical slice and produce a judge-readable proof summary
Status: PENDING
Acceptance:
- integration checkpoint, not final UI;
- complete path from task → Builder → independent witness → BASE execution → CANDIDATE execution → causal receipt;
- does not bypass P-08/P-09 independence requirements;
- proof summary is machine-readable and human-inspectable;
- provenance clearly distinguishes FIXTURE/LOCAL_EXECUTION/LIVE_NEBIUS/RECORDED_LIVE;
- validates complete mechanical digest chain: `requirement → frozen contract digest → witness digest → BASE/CANDIDATE execution evidence`;
- exposes a bounded MINIMAL DEVELOPER INVOCATION / INTEGRATION HARNESS capable of executing that coherent slice (may be temporary/internal; must NOT prematurely freeze `basebreak verify` or another public stable CLI contract; stable public CLI remains frozen at P-19 after P-18 receipt contracts stabilize).
Phase exit: Basebreak can prove a real base/candidate behavioral transition.

---

# P-11 — Counterfactual Third Run
### P-11.01 — Define safe candidate-delta subtraction strategies
### P-11.02 — Select bounded relevant patch region without model authority over verdict
### P-11.03 — Materialize counterfactual candidate in fresh sandbox
### P-11.04 — Execute same witness against counterfactual
Acceptance:
- counterfactual execution evidence must retain the identical frozen contract digest and witness digest as the BASE and CANDIDATE runs.
### P-11.05 — Reconcile FAIL→PASS→FAIL causal triplet
Acceptance:
- causal triplet receipt validates unbroken identity: `requirement → frozen contract digest → witness digest → BASE/CANDIDATE/COUNTERFACTUAL execution evidence`.
### P-11.06 — Detect invalid counterfactual construction and return INCONCLUSIVE, never false PASS
Phase exit: critical demonstrations can show causal necessity under the witness.

---

# P-12 — Minimal Causal Slice
### P-12.01 — Define causal-slice scope and non-formal-proof disclaimer
### P-12.02 — Implement bounded hunk/subset minimization algorithm
### P-12.03 — Cache/reuse safe deterministic executions to control cost
### P-12.04 — Bind requirement → witness → minimal necessary candidate slice
### P-12.05 — Test interacting hunks, non-monotonic behavior, and ambiguous slices
Phase exit: Basebreak can explain which tested change subset is necessary under a witness.

---

# P-13 — Change-Semantics Expansion
### P-13.01 — FEATURE ABSENT→PRESENT verifier
### P-13.02 — SECURITY_FIX EXPLOITABLE→BLOCKED verifier
### P-13.03 — REFACTOR behavioral-equivalence verifier
### P-13.04 — PERFORMANCE parity + benchmark-delta verifier
### P-13.05 — DEP/API contract migration + regression verifier
### P-13.06 — Cross-class classification error tests
Phase exit: product is not a one-demo bug-fix trick.

---

# P-14 — Sealed Repair Loop
### P-14.01 — Define bounded failure-feedback schema
### P-14.02 — Return minimized counterexample without hidden witness disclosure
### P-14.03 — Re-enter Builder in fresh/controlled repair context
### P-14.04 — Create repaired candidate with new exact hash
### P-14.05 — Require fresh verifier reproduction for repaired candidate
### P-14.06 — Cap repair rounds/cost and return honest non-success
Phase exit: agent improves from evidence without memorizing the hidden exam.

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
