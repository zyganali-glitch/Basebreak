# Basebreak

> **If the patch matters, the base must break.**

Basebreak is a causal verification runtime for AI-written software changes.

Instead of accepting “tests are green” as proof, Basebreak independently challenges the exact candidate in clean execution environments and asks whether the requested behavior fails on the trusted base and succeeds on the candidate.

## Status
Early competition build for the Nebius x NVIDIA Global AI Hackathon.
Do not treat planned capabilities as implemented.

## Canonical claim
**Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green.**

## Competition target
Coding and Agentic Engineering Track.

Expected core stack is subject to live discovery:
- Nebius Token Factory
- NVIDIA Nemotron
- supported Token Factory Sandbox/runtime capabilities
- Tavily only where current external grounding is materially relevant

## Evidence honesty
Basebreak distinguishes:
- FIXTURE
- LOCAL_EXECUTION
- LIVE_NEBIUS
- RECORDED_LIVE

These are provenance labels, not PASS/FAIL verdicts.

## Development
The implementation has not started yet. See:
- `plans/BASEBREAK_MASTER_EXECUTION_PLAN.md`
- `docs/HANDOFF.md`
- `AGENTS.md`

## License
Apache-2.0.
