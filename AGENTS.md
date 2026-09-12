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
Prohibition against unmetered public endpoints: Never expose an unauthenticated public live endpoint capable of silently draining free Token Factory or Tavily credits. Any public live-run capability must be hard-budgeted or rate-limited; read-only inspection of verified evidence must remain accessible even when live budget is exhausted.

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
