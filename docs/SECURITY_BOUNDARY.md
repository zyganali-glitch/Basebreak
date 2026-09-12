# Security Boundary

## Threat model baseline
Basebreak executes repositories that may contain hostile or accidental unsafe code.
Assume target code can:
- read local files;
- attempt network calls;
- spawn processes;
- consume resources;
- inspect environment variables;
- modify workspace files;
- attempt to discover verifier assets.

## Required architecture posture
- untrusted code runs only in the supported isolated execution runtime;
- credentials are least-privilege and adapter-only;
- verifier secrets/assets are not mounted into Builder context;
- protected surfaces use allow/deny policy and hash checks;
- network access is deny-by-default where platform support allows;
- time, CPU/memory/disk/process limits are explicit;
- logs/evidence are sanitized before persistence;
- no repo prompt/instruction is treated as a security boundary.

## Credential law
Never commit credentials or embed them in:
- prompts;
- evidence;
- screenshots;
- fixtures;
- example configs;
- donor manifests.

## Sandbox claims
Document only guarantees proven by current Nebius/runtime documentation and actual observed behavior.
Never call a repository instruction, temp folder or subprocess an isolation boundary.

## Protected surfaces
Candidate defaults to protect:
- Basebreak verification policy
- sealed witnesses
- verifier harness
- integrity manifests
- competition evidence schemas

Target-repository own tests are not automatically protected; policy is task-specific.

## Irreversible writes
Initial Basebreak product should avoid autonomous merge/release/deploy.
Any future external mutation must have explicit policy and human authority.
