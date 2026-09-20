# AGENTS.md — Basebreak Coding-Agent Constitution

## 1. Authority and source of truth
Canonical repository: `zyganali-glitch/Basebreak`
Canonical branch: `main`.

Before editing:
1. fetch/inspect remote `main`;
2. record starting remote SHA;
3. read `plans/BASEBREAK_MASTER_EXECUTION_PLAN.md`;
4. read `docs/HANDOFF.md`;
5. read only the architecture/security/evidence docs relevant to the exact active task.

Never trust a prior agent summary over repository state.

## 2. Exact-task execution
Work on exactly one active Master Plan micro-task unless the task itself explicitly declares a bounded batch.
(Under Section 18 Bounded External-Dependency Parallelization Law, execution of an allowlisted later micro-task is permitted while an earlier task is externally BLOCKED, but strictly ONE executable micro-task may be active at any time).
Do not rename, reinterpret, merge, split, or pre-implement future tasks.
If required information is absent, report the blocker instead of inventing future architecture.

## 3. Closure contract
A task is not complete because files were edited.

Every completion report must include:
- starting remote SHA;
- final remote SHA;
- exact changed files;
- exact commands executed;
- results and exit status;
- provenance of evidence: FIXTURE / LOCAL_EXECUTION / LIVE_NEBIUS / RECORDED_LIVE;
- checks explicitly NOT_RUN;
- donor reuse, if any;
- statement that the final commit was pushed and remote SHA re-checked.

Do not claim PASS for a check you did not run.

## 4. Basebreak causal rules
Green tests alone are insufficient.
Do not label a candidate causally verified unless the exact task's required runtime evidence exists.

For behavioral bug fixes the target invariant is normally:
BASE=FAIL, CANDIDATE=PASS.

For counterfactual verification:
BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL.

Never fabricate these states from expected values or fixtures when live execution is required.

## 5. Builder/verifier independence
Builder-authored tests are useful development evidence but are not automatically independent witnesses.
Do not expose complete sealed verifier assets to the Builder.
Do not copy Builder summaries into verifier truth without deterministic validation.
Never let the Builder mutate protected verification contracts merely to obtain PASS.

## 6. Deterministic authority
Hashes, source identity, sandbox identity, process exit codes, timeouts, test output and protected-surface mutation are deterministic facts.
Model prose cannot override them.

## 7. Live-first and no silent fallback
If a task requires live Nebius/Nemotron/Sandbox evidence, mock or simulation does not close it.
Fail explicitly if live prerequisites are unavailable.
Do not silently fall back.

## 8. Donors
Existing user repositories are donors only.
Competition-defining logic should prefer CONCEPT_ONLY or CLEAN_ROOM_REIMPLEMENTED.
Any actual copied/adapted code requires a provenance record before closure.
Never copy old product terminology into Basebreak by habit.

## 9. Security
Never commit credentials.
Never place secrets in prompts, evidence, fixtures, logs, screenshots or public judge assets.
Treat target repositories as untrusted code.
Provider credentials belong only in runtime adapters/config loaded from environment/secret stores.

## 10. Tests
Do not weaken assertions to obtain green.
Focused tests are preferred during micro-tasks.
Run broader suites at planned gates or when impact justifies them.
A known required failure blocks closure.

## 11. Documentation sync matrix
- Master Plan: update exact task status when task state changes.
- HANDOFF: update active exact task, blocker and independently verified baseline truth.
- README: update only when public-facing capability/status/setup/architecture/competition truth materially changes, or at a Documentation Consolidation Gate.
- Architecture/Security/Evidence docs: update only when their actual boundary/contract changes.
- Donor manifest: update only when donor research/reuse truth changes.
- Competition Feedback Log (`docs/COMPETITION_FEEDBACK_LOG.md`): append when real Nebius/NVIDIA/Tavily friction, strength, bug, limitation, or useful product feedback is actually observed.
- Harmless duplicated wording/count/navigation drift may be batched.
- Wrong SHA, false capability, false live claim, wrong evidence provenance, security/licensing/eligibility error must be fixed immediately.
- Every micro-task does NOT require mechanical rewriting of every documentation file.

## 12. Zero-Cost Law & Billing Safeguards
Basebreak development and judge path must not require the operator to spend personal money.
Allowed: genuine free tiers, hackathon/sponsor promotional credits, free open-source/local tools, services that hard-stop when free quota is exhausted.
Strictly forbidden without explicit operator approval:
- paid subscriptions;
- pay-as-you-go enablement;
- automatic paid fallback;
- credit-card charges;
- deposits/pre-authorizations;
- paid certification;
- auto-upgrade after trial;
- any irreversible billing action.
If an external service demands payment/card/deposit and no verified zero-cost path exists: STOP, classify as BLOCKED or OPERATOR_DECISION_REQUIRED, explain alternatives, never silently proceed.
Promotional credits are a finite budget, not permission to spend beyond them.
Never assume promotional services automatically hard-stop upon quota exhaustion. If a service technically supports pay-as-you-go continuation, verify that billing/PAYG is disabled or hard-capped before execution, or classify as BLOCKED / OPERATOR_DECISION_REQUIRED.
Prohibition against unmetered public endpoints: Never expose an unauthenticated public live endpoint capable of silently draining free Token Factory or Tavily credits. Any public live-run capability must be hard-budgeted or rate-limited; read-only inspection of verified evidence must remain accessible even when live budget is exhausted.

### Token Factory Bounded Billing Exception (Operator Approved)
Under `TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION`, attaching a payment card is permitted solely because Token Factory mandates a payment method to activate and redeem Builder Program promotional credits.
- Target personal spend remains strictly `$0.00`.
- Forbidden: personal paid usage, manual top-ups with personal money, paid subscriptions, reserved/dedicated capacity, committed volume, unrelated paid Nebius services, and paid fallback after promo exhaustion.
- Operational safety margin: `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` (operator policy floor; once promotional balance is <= $5.00, all Token Factory inference and sandbox execution must immediately halt; the $5 reserve must never be deliberately consumed).
- Mandatory balance checks: operator must inspect Token Factory balance before and after any cost-consuming LIVE_NEBIUS batch. If balance cannot be verified, status is BLOCKED; if balance <= $5.00, status is BLOCKED_BUDGET_FLOOR.
- Post-competition cleanup: after development/judging obligations no longer require Token Factory, the payment card must be removed or billing suspended, outstanding balance verified at $0.00, and completion recorded.

## 13. Operator Guidance Rule
The operator is non-expert and must receive screen-by-screen guidance in Turkish for every required external account/service setup:
- current official URL;
- page/menu name;
- exact button/link to click;
- exact field names;
- what to enter/select;
- what NOT to select;
- whether any card/payment risk exists;
- where to obtain an API key/token;
- how to store it safely without pasting it into chat or committing it;
- how to verify that the step succeeded;
- what to do if the current UI differs from documented UI.
Never tell the operator merely "create an API key" or "configure Nebius".
Never ask the operator to paste a secret into the conversation.

## 14. Factual Competition Feedback Logging
Log real observed friction, strengths, bugs, limitations, and product suggestions into `docs/COMPETITION_FEEDBACK_LOG.md`.
Never invent feedback. Record only observed experiences with deterministic evidence. Never store credentials. Distinguish platform issues from operator errors and Basebreak bugs.

## 15. Platform Facts Authority
Current platform facts (model IDs, sandbox capabilities, SDK versions, rate limits, credit amounts) must come from current official documentation or live discovery, never from stale model memory or unverified third-party AI summaries.
Do not assume Git-like branching, specific checkpoint durations, or specific concurrency limits in Token Factory Sandboxes without official verification.
Do not declare external sandboxes (E2B, Daytona) as equivalent to Token Factory Sandboxes for track compliance.

## 16. Git
Commit messages must identify the exact task, e.g. `feat(p00.01): ...` or `docs(p00.01a): ...`.
Push to `origin/main` unless the active task explicitly says otherwise.
A local commit is not closure.

## 17. Report template
Use:
- Task
- Starting remote SHA
- Final remote SHA
- Changed files
- Implementation
- Commands and results
- Evidence provenance
- NOT_RUN
- Donor reuse
- Risks/blockers
- Remote push confirmation

Do not self-award independent QA PASS.

## 18. Bounded External-Dependency Parallelization Law
When an exact task is BLOCKED solely by a verified external dependency outside Basebreak's control, a later task MAY execute before that blocker clears ONLY when all of the following are true:
1. the later task is explicitly allowlisted by the Master Plan;
2. its correctness does not depend on the missing external/live fact;
3. it can be validated deterministically without pretending LOCAL_EXECUTION is LIVE_NEBIUS;
4. no platform/provider capability is guessed;
5. the blocked gate remains visibly BLOCKED;
6. the blocked phase cannot receive GO/phase closure;
7. only ONE executable micro-task is active at a time;
8. the parallel work may not silently implement any non-allowlisted future phase;
9. if later live reality contradicts a supposedly provider-neutral assumption, affected work MUST reopen rather than override runtime truth.

This rule is an exception for verified external blockers, not permission for arbitrary phase skipping.

### Promo-Arrival Preemption Rule
If the Builder Program promo-code email arrives while allowlisted parallel work is underway:
- do not start another parallel micro-task;
- finish or cleanly abort the currently active atomic micro-task;
- return to the blocked P-01.02 gate;
- operator redeems promo;
- verify Token Factory promotional balance > $5.00;
- obtain independent authorization before executing inference.

Do not consume the $1 trial. No automatic paid fallback.

### Current Parallel Allowlist & Hard Stop
The previous parallel lane for P-02 (P-02.01 through P-02.07) and P-03 (P-03.01 through P-03.06) is COMPLETED and independently CLOSED.

Under amendment P-01.01B, for the ongoing active P-01.02 external blocker, allow sequential execution ONLY of the platform-independent security primitives from P-04:
- P-04.01 — Formalize target-repository threat model
- P-04.02 — Implement secret redaction and forbidden persistence rules
- P-04.04 — Implement protected-surface manifest and diff checks

These tasks may execute sequentially only after P-01.01B receives independent QA PASS. Exactly ONE executable micro-task may be active at any time. P-04.04 may execute after independently verified P-04.02 even though P-04.03 remains unexecuted, because its correctness does not depend on unverified platform/sandbox facts.

NOT AUTHORIZED under current offline lane:
- P-04.03 — Define sandbox resource/network/process policy from proven platform capability (depends on live platform/sandbox capability; cannot guess network policy, process isolation, sandbox privilege model, resource ceilings, filesystem guarantees, checkpoint/snapshot/fork/reset semantics, teardown, runtime limits, concurrency, or provider error semantics).
- P-04.05 — Implement execution timeout/cancellation/resource-failure normalization (keep timeout/resource behavior from encoding unverified platform semantics before live sandbox discovery).
- P-04.06 — Add malicious-fixture tests for exfiltration attempts, fork bombs, verifier discovery, and protected-surface mutation (keep fork-bomb/resource behavior from encoding unverified platform semantics before live sandbox discovery).
- P-05+ remain strictly FORBIDDEN.

P-04 phase status:
P-04 phase MUST remain OPEN. Completing P-04.01, P-04.02, and P-04.04 cannot close P-04. Phase exit remains unavailable until the remaining exact tasks are legitimately completed.

Hard stop after P-04 offline subset:
If P-04.01, P-04.02, and P-04.04 all independently close while P-01.02 is still blocked: execution MUST STOP again. Do NOT automatically start P-04.03, P-04.05, P-04.06, P-05+, P-06+, or any other future phase. Return for another independent architecture decision.
