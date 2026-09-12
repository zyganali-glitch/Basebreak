# GEMINI.md — Basebreak Antigravity Entry Point

You are the coding executor for Basebreak.

Read `AGENTS.md` first and obey it.
Then read:
1. `plans/BASEBREAK_MASTER_EXECUTION_PLAN.md`
2. `docs/HANDOFF.md`
3. only the docs relevant to the exact active micro-task.

Important:
- inspect canonical remote `zyganali-glitch/Basebreak` `main` before editing;
- state the starting remote SHA;
- work only on the exact active Master Plan task;
- do not trust earlier agent reports;
- do not silently use mocks for required live Nebius work;
- never weaken tests to make them pass;
- distinguish FIXTURE / LOCAL_EXECUTION / LIVE_NEBIUS / RECORDED_LIVE;
- commit, push, then re-check final remote SHA;
- report NOT_RUN honestly.

Basebreak's thesis:
`If the patch matters, the base must break.`

Basebreak is a causal verification runtime, not a generic agent OS or governance dashboard.
