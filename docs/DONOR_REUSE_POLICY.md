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
Root license: `VERIFIED_PROPRIETARY_OR_ALL_RIGHTS_RESERVED` (All Rights Reserved; copyright Mehmet Aydogan).
Default: `CONCEPT_ONLY`.
Crucial boundary: ownership by the same operator does NOT automatically turn it into competition-safe copied implementation. Under competition open-source rules and its All Rights Reserved root license, ZERO code copying is permitted. All Basebreak causal logic must be concept-only and clean-room reimplemented.
Do not import ShadowLab/Approval Compression/Capability Passport/Change Passport terminology.

### GitLab UAOS / Qwen UAOS
Audited at P-00.03:
- `gitlab.com/zyganali/universal-agent-os-qwen` (SHA `a43b3411856f41a4be9424d11c01a5e637cdc410`, MIT License, `VERIFIED_PERMISSIVE`)
- `gitlab.com/zyganali/universal-agent-os-gitlab-edition` (SHA `3c4a412b6040d8a8154c15325943c409be9105f2`, MIT License, `VERIFIED_PERMISSIVE`)
Potential lessons: model adapter patterns and repository-native workflow automation.
Status: `NO_CURRENT_REUSE_NEED`. Kept as verified research pins; no code imported.

## Verified donor research pins (P-00.03)
These are immutable research pins for architectural study only, NOT approvals to copy code:
- Universal-Agent-OS: `6b83b06212101c238ec28076a2ba7ae819f483f2` (MIT — `VERIFIED_PERMISSIVE`)
- universal-agent-os-uipath: `dc2267939c2aef0aba2737da65f53352c5cf8fb2` (MIT — `VERIFIED_PERMISSIVE`)
- codex-control-tower: `65ee1b72faf9a7202d9166eed43fb671804815a8` (MIT — `VERIFIED_PERMISSIVE`)
- zerokit-ai-control-plane: `d663db8c706cb914e1af5caf651df08edb5c50c0` (MIT — `VERIFIED_PERMISSIVE`)
- ContextSeal: `b8d87ad05e323b7366c8e0817839e01034c4438d` (Apache-2.0 — `VERIFIED_PERMISSIVE`)
- ChangeMesh: `7b349f0e005ccb416034df318baae67f43a1099d` (All Rights Reserved — `VERIFIED_PROPRIETARY_OR_ALL_RIGHTS_RESERVED`)
- universal-agent-os-qwen: `a43b3411856f41a4be9424d11c01a5e637cdc410` (MIT — `VERIFIED_PERMISSIVE`)
- universal-agent-os-gitlab-edition: `3c4a412b6040d8a8154c15325943c409be9105f2` (MIT — `VERIFIED_PERMISSIVE`)

Every actual future reuse candidate must re-check the donor license at the pinned SHA and undergo a dedicated preflight task.
