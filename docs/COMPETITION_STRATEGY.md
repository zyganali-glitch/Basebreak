# Competition Strategy — Basebreak

Compact strategic map for the Nebius x NVIDIA Global AI Hackathon.
This is NOT a duplicate Master Plan. It is a judge-oriented value summary.

## Judging Criteria (Equal Weight)

1. **Technological Implementation** — How well is the project built, and how effectively does it use Nebius Token Factory or AI Cloud and NVIDIA Nemotron?
2. **Design** — Does the project deliver a complete, coherent product experience, not just a technical proof of concept?
3. **Potential Impact** — Does the project make a credible, specific case for solving a real problem for a real audience, and does the solution actually address it?
4. **Quality of the Idea** — Is this a creative, non-obvious use of Nebius Token Factory or AI Cloud and NVIDIA Nemotron, and does the team show genuine understanding of the problem space?

## One Memorable Claim

**Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green.**

## Core WOW Moment

The judge sees a real task go through the full causal verification loop:

1. AI coding agent receives a task and builds a candidate patch.
2. An independent witness (behavioral test) is generated without Builder knowledge.
3. The witness executes on the trusted **BASE** → result: **FAIL** ❌
4. The same witness executes on the exact **CANDIDATE** → result: **PASS** ✅
5. Where required, the witness executes on a **COUNTERFACTUAL** (candidate minus the relevant patch) → result: **FAIL** ❌
6. Conclusion: the patch **caused** the behavior change — this is causal verification under an independently executed witness, not merely green tests.

## Killer Demo

**Primary:** ResetVault-style deterministic scenario.
A synthetic repository with a genuinely green baseline test suite and a real hidden bug.
The AI agent fixes the bug, tests remain green — but Basebreak independently proves the fix was causal.
This demo is fully deterministic and repeatable.

**Secondary:** Immutable real-world open-source bug-fix replay.
A genuinely public open-source repository with a known historical fix.
Basebreak independently reproduces the causal transition on the historical base and fixed revisions.
Basebreak does NOT claim to have produced the fix — it verifies it.

## Early Vertical-Slice Principle

Before polishing any layer, build a thin path from task → Builder → Witness → BASE execution → CANDIDATE execution → causal receipt.
A working ugly vertical slice beats a polished incomplete layer.

## Design Principle

Show causal transition before architecture detail.
The judge should understand the value in 30 seconds.
Failure/contradiction is as visually valuable as PASS.

## Potential Impact

**Audience:** Teams and organizations using AI coding agents (Copilot, Cursor, Codex, custom agents) who need confidence that a patch caused the requested behavior.

**Problem:** Current AI coding tools say "tests pass" but cannot prove that the patch — and only the patch — caused the required change. Tests might have been green before the patch. Tests might have been weakened.

**Basebreak's answer:** Causal verification under an independently executed witness, not confidence from model prose.

## Tavily Strategy

Tavily activates only when task correctness materially depends on current external facts.
Preferred scenario: current CVE/security advisory or API/library migration facts grounded into the verification contract.
Tavily never overrides deterministic execution facts.
Runtime use must remain inside verified free/promotional credits.
If bonus participation remains justified, use a real runtime Tavily call, not bolted-on decoration.

## Language Discipline

Preferred: `causal verification under an independently executed witness`
Avoid: `mathematically proves global program causality`

Basebreak proves causality under its witness suite, not global program correctness.
This distinction is honest and defensible.

## No Schedule-Based Scope Deletion

All Master Plan phases remain planned.
The competition critical path identifies priority, not scope deletion.
Depth features continue after the first coherent vertical slice.
