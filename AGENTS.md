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

## 11. Documentation friction
Update critical truth immediately: task/status, baseline/final SHA, architecture/security/evidence boundary, live platform facts, donor provenance and blockers.
Batch harmless README wording/count/navigation drift until a consolidation gate.

## 12. Git
Commit messages must identify the exact task, e.g. `feat(p00.01): ...`.
Push to `origin/main` unless the active task explicitly says otherwise.
A local commit is not closure.

## 13. Report template
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
