# Donor Reuse Policy

## Goal
Reuse lessons without turning Basebreak into a renamed mixture of prior projects.

## Reuse classes
### CONCEPT_ONLY
Idea/pattern learned from donor; no donor implementation copied.

### CLEAN_ROOM_REIMPLEMENTED
Behavioral idea studied, then independently implemented in Basebreak domain language without copying implementation text/code.

### ADAPTED_WITH_PROVENANCE
Actual donor code/structure adapted. Requires license compatibility, immutable pin, target mapping and tests.

### UNCHANGED_INFRASTRUCTURE
Generic infrastructure reused unchanged when legally/competition-safe and non-defining.

Competition-defining logic should prefer CONCEPT_ONLY or CLEAN_ROOM_REIMPLEMENTED.

## Mandatory record before closure of actual reuse
- donor repo
- immutable donor SHA
- source path/concept
- donor license
- reuse class
- Basebreak target
- reason
- transformation
- introduced commit
- verification/tests
- reviewer note on competition originality

## Candidate donor map

### Universal-Agent-OS
Candidate lessons:
- honesty boundary
- exact-task planning
- handoff discipline
- NOT_RUN semantics
Default: CONCEPT_ONLY.
Do NOT import broad bureaucracy or product terminology.

### universal-agent-os-uipath
Candidate lessons:
- external human decision must be read back/verified, not trusted from chat
Default: CONCEPT_ONLY.
No UiPath dependency intended.

### codex-control-tower
Candidate lessons:
- independent/blind semantic challenge
- destructive preflight
- evidence vs model-claim separation
Default: CLEAN_ROOM_REIMPLEMENTED / CONCEPT_ONLY.
Do not copy Control Tower naming.

### zerokit-ai-control-plane
Candidate lessons:
- privacy preflight
- bounded model context
- strict artifact validation
Default: CONCEPT_ONLY.

### ContextSeal
Candidate lessons:
- provenance binding
- tamper-aware evidence
- scoped approval and read-back mentality
Default: CLEAN_ROOM_REIMPLEMENTED / CONCEPT_ONLY.
Do not import Change Passport branding.

### ChangeMesh
Candidate lessons:
- deterministic authority separation
- execution/evidence mode honesty
- idempotency/recovery
- donor governance
Default: CONCEPT_ONLY; selected generic infrastructure only after dedicated preflight.
Do not import ShadowLab/Approval Compression/Capability Passport terminology.

### GitLab UAOS / Qwen UAOS
Potential lessons:
- repository-native workflow and cross-session memory
Status: DO_NOT_REUSE until dedicated audit pins immutable SHAs/licenses and identifies an actual Basebreak need.

## Known GitHub donor pins at bootstrap
These are research pins, not approvals to copy:
- Universal-Agent-OS: 6b83b06212101c238ec28076a2ba7ae819f483f2
- universal-agent-os-uipath: dc2267939c2aef0aba2737da65f53352c5cf8fb2
- codex-control-tower: 65ee1b72faf9a7202d9166eed43fb671804815a8
- zerokit-ai-control-plane: d663db8c706cb914e1af5caf651df08edb5c50c0
- ContextSeal: b8d87ad05e323b7366c8e0817839e01034c4438d
- ChangeMesh: 7b349f0e005ccb416034df318baae67f43a1099d

Every actual reuse must re-check the donor license at the pinned SHA.
