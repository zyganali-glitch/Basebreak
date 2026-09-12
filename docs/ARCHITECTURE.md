# Basebreak Architecture Contract

## Product boundary
Basebreak accepts:
1. trusted repository/base revision;
2. engineering task;
3. bounded execution policy.

It returns a candidate plus causal verification evidence.

It is not a generic SDLC OS, CI/CD replacement, deployment platform, project manager, or generic code reviewer.

## Logical planes

### Control Plane
Owns mission/task contracts, run state, scheduling, policy and evidence indices.
Must not execute untrusted target code directly.

### Model Plane
Nebius Token Factory / NVIDIA Nemotron adapters.
Models interpret, plan, build and propose witnesses.
Models never own deterministic verdict facts.

### Execution Plane
Ephemeral isolated sandboxes/runtimes.
Separate Builder and Verifier execution contexts.
Target repository code is treated as untrusted.

### Verification Plane
Produces witness plans, executes on trusted base and exact candidate, reconciles outcomes, performs bounded counterfactual checks and optional causal slicing.

### Evidence Plane
Stores immutable-ish content-addressed run facts, hashes, command results, provenance and verdict inputs.
Presentation layers consume evidence; they do not rewrite it.

### Product Plane
CLI/API/UI surfaces.
Judge UI should expose causal transition and provenance without hiding NOT_RUN/FAIL.

## Mandatory boundaries
- provider-specific SDKs stay in adapters/infrastructure;
- core domain contracts must not import provider SDKs;
- model result != deterministic execution result;
- Builder workspace != Verifier workspace;
- evidence provenance != verdict;
- human irreversible authority remains separate.

## Initial package direction
`src/domain/` provider-neutral contracts
`src/adapters/nebius/` provider integration
`src/runtime/` sandbox orchestration
`src/builder/` build workflow
`src/verifier/` challenge/witness/counterrun
`src/evidence/` evidence and receipts
`src/security/` policy/redaction/protected surfaces
`src/api/` API
`src/ui/` judge/operator surface if selected
`tests/` tests by boundary

Exact implementation stack is intentionally deferred until P-01 platform discovery.
