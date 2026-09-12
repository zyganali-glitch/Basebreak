# Donor Reuse Manifest

This manifest documents all candidate donor repositories evaluated for Basebreak.
It enforces the **Basebreak Originality Law** and **Donor Reuse Policy**: donor repositories are sources of inspiration and governance lessons only; competition-defining causal verification logic is original to Basebreak.

---

## Section 1: Approved Implementation Reuse (EMPTY)

**Current Approved Code Introductions: 0**
**Total Donor Source Lines Imported: 0**

| ID | Donor Repository | Approved SHA | Target Path in Basebreak | License Compatibility Verified | Preflight Task | Approved Commit | Verifier Tests | Status |
|---|---|---|---|---|---|---|---|---|
| — | None | None | None | None | None | None | None | EMPTY |

No donor implementation code may be copied, adapted, vendored, or imported without:
1. an approved permissive open-source license at the pinned revision;
2. a dedicated Master Plan micro-task authorizing the specific reuse;
3. a documented transformation rationale proving why clean-room reimplementation was not preferred;
4. a passing license, provenance, and anti-leakage audit.

---

## Section 2: Verified Research Pins & Preflight Governance (P-00.03)

Every candidate donor repository has been audited at an immutable commit revision.
Research pins are immutable references for architectural study only; they grant **NO** authorization to copy code.

| ID | Donor Repository | Pinned Research SHA | Root License State | Source / Concept Inspected | Current Reuse Class | Intended Basebreak Target | Reason | Code Imported | Current Status |
|---|---|---|---|---|---|---|---|---|---|
| D-001 | `zyganali-glitch/Universal-Agent-OS` | `6b83b06212101c238ec28076a2ba7ae819f483f2` | `VERIFIED_PERMISSIVE` (MIT) | `AGENTS.md`, governance spine, task planning, handoff discipline, NOT_RUN semantics | `CONCEPT_ONLY` | Governance & Handoff Spine | Proven execution honesty and state discipline; no agent OS bureaucracy or product vocabulary | NO | `RESEARCH_PIN` |
| D-002 | `zyganali-glitch/universal-agent-os-uipath` | `dc2267939c2aef0aba2737da65f53352c5cf8fb2` | `VERIFIED_PERMISSIVE` (MIT) | `docs/HANDOFF.md`, external human decision read-back / verification pattern | `CONCEPT_ONLY` | Operator Authority & Decision Boundary | Pattern for reading back verified external decisions; zero UiPath dependencies or tooling | NO | `RESEARCH_PIN` |
| D-003 | `zyganali-glitch/codex-control-tower` | `65ee1b72faf9a7202d9166eed43fb671804815a8` | `VERIFIED_PERMISSIVE` (MIT) | `core/evidence`, destructive preflight, blind challenge, model vs evidence separation | `CONCEPT_ONLY` (Clean-Room candidate) | Verifier Isolation & Blind Challenge | Independent witness verification; strictly forbidden to import Control Tower branding or naming | NO | `RESEARCH_PIN` |
| D-004 | `zyganali-glitch/zerokit-ai-control-plane` | `d663db8c706cb914e1af5caf651df08edb5c50c0` | `VERIFIED_PERMISSIVE` (MIT) | `config`, privacy preflight, context minimization, strict artifact validation | `CONCEPT_ONLY` | Untrusted Model Context Boundary | Input/prompt sanitization, bounded context, strict validation; no ZeroKit branding | NO | `RESEARCH_PIN` |
| D-005 | `zyganali-glitch/ContextSeal` | `b8d87ad05e323b7366c8e0817839e01034c4438d` | `VERIFIED_PERMISSIVE` (Apache-2.0) | `src/seal`, evidence hashing, provenance binding, read-back verification | `CONCEPT_ONLY` (Clean-Room candidate) | Evidence Store & Tamper-Aware Provenance | Immutable evidence binding; strictly forbidden to import "Change Passport" / "Capability Passport" branding | NO | `RESEARCH_PIN` |
| D-006 | `zyganali-glitch/ChangeMesh` | `7b349f0e005ccb416034df318baae67f43a1099d` | `VERIFIED_PROPRIETARY_OR_ALL_RIGHTS_RESERVED` (All Rights Reserved) | `domain/authority`, deterministic authority separation, evidence-mode honesty, idempotency, donor governance | `CONCEPT_ONLY` | Deterministic Authority & Execution Honesty | Authority separation and execution-mode honesty lessons; root is All Rights Reserved, so ZERO code copying permitted; operator ownership does NOT override competition OSS requirements | NO | `RESEARCH_PIN` |
| D-007 | `gitlab.com/zyganali/universal-agent-os-qwen` | `a43b3411856f41a4be9424d11c01a5e637cdc410` | `VERIFIED_PERMISSIVE` (MIT) | `backend/`, model adapter patterns, agent prompt orchestration | `CONCEPT_ONLY` | None currently needed | Audited for completeness; no distinct causal verification requirement identified | NO | `NO_CURRENT_REUSE_NEED` |
| D-008 | `gitlab.com/zyganali/universal-agent-os-gitlab-edition` | `3c4a412b6040d8a8154c15325943c409be9105f2` | `VERIFIED_PERMISSIVE` (MIT) | `.gitlab-ci.yml`, pipeline automation, repository workflow patterns | `CONCEPT_ONLY` | None currently needed | Audited for completeness; Basebreak uses GitHub Actions & local deterministic runner | NO | `NO_CURRENT_REUSE_NEED` |

---

## Section 3: Per-Donor Preflight Audit Details

### D-001: Universal-Agent-OS
- **Repository**: `zyganali-glitch/Universal-Agent-OS`
- **Revision Audited**: `6b83b06212101c238ec28076a2ba7ae819f483f2` (2026-07-08T13:44:31Z)
- **Root License**: MIT License (`VERIFIED_PERMISSIVE`). Copyright (c) 2026 Mehmet Aydoğan.
- **Dependency / Subtree Licenses**: Root repo MIT; standard npm/python dependencies in subtrees.
- **Concepts Inspected**: Rigorous handoff state persistence, honesty boundaries (reporting NOT_RUN honestly, never claiming unverified passes), step-by-step task discipline.
- **Originality Boundary**: Do NOT import broad "Agent OS" product branding or multi-agent operating system bureaucracy. Basebreak is a causal verification runtime for software changes.
- **Code Imported**: `NO` (0 bytes).

### D-002: universal-agent-os-uipath
- **Repository**: `zyganali-glitch/universal-agent-os-uipath`
- **Revision Audited**: `dc2267939c2aef0aba2737da65f53352c5cf8fb2` (2026-06-22T14:18:04Z)
- **Root License**: MIT License (`VERIFIED_PERMISSIVE`). Copyright (c) 2026 Zyganali Group.
- **Dependency / Subtree Licenses**: Root repo MIT; UiPath project structure.
- **Concepts Inspected**: Pattern requiring human decisions to be explicitly read back and verified from deterministic state rather than accepted from chat dialogue.
- **Originality Boundary**: Basebreak has zero UiPath dependencies, uses no UiPath runtime, and imports no RPA concepts.
- **Code Imported**: `NO` (0 bytes).

### D-003: codex-control-tower
- **Repository**: `zyganali-glitch/codex-control-tower`
- **Revision Audited**: `65ee1b72faf9a7202d9166eed43fb671804815a8` (2026-07-19T19:22:13Z)
- **Root License**: MIT License (`VERIFIED_PERMISSIVE`). Copyright (c) 2026 Codex Control Tower contributors.
- **Dependency / Subtree Licenses**: Root repo MIT; TypeScript/Node.js dependencies.
- **Concepts Inspected**: Independent blind challenge, destructive preflight verification, strict boundary between model-generated claims and deterministic execution results.
- **Originality Boundary**: Strictly avoid "Control Tower" terminology or naming conventions. Basebreak's verifier is an independent witness runtime for causal differential testing, not a generic control tower.
- **Code Imported**: `NO` (0 bytes).

### D-004: zerokit-ai-control-plane
- **Repository**: `zyganali-glitch/zerokit-ai-control-plane`
- **Revision Audited**: `d663db8c706cb914e1af5caf651df08edb5c50c0` (2026-07-18T18:39:04Z)
- **Root License**: MIT License (`VERIFIED_PERMISSIVE`). Copyright (c) 2026 ZeroKit Build Week contributors.
- **Dependency / Subtree Licenses**: Root repo MIT; frontend/backend JavaScript dependencies.
- **Concepts Inspected**: Strict input/artifact validation, prompt minimization to prevent secret exfiltration or hallucinated prompt context leaks.
- **Originality Boundary**: Strictly avoid "ZeroKit" or "Control Plane" branding.
- **Code Imported**: `NO` (0 bytes).

### D-005: ContextSeal
- **Repository**: `zyganali-glitch/ContextSeal`
- **Revision Audited**: `b8d87ad05e323b7366c8e0817839e01034c4438d` (2026-08-09T13:12:22Z)
- **Root License**: Apache License 2.0 (`VERIFIED_PERMISSIVE`). Copyright 2026 ContextSeal contributors.
- **Dependency / Subtree Licenses**: Root repo Apache-2.0; standard npm dependencies.
- **Concepts Inspected**: Cryptographic/content-addressed provenance chaining, tamper-aware artifact hashing, immutable evidence storage.
- **Originality Boundary**: Strictly avoid "Change Passport", "Capability Passport", or "ContextSeal" branding. Basebreak generates causal verification receipts, not compliance passports.
- **Code Imported**: `NO` (0 bytes).

### D-006: ChangeMesh
- **Repository**: `zyganali-glitch/ChangeMesh`
- **Revision Audited**: `7b349f0e005ccb416034df318baae67f43a1099d` (2026-08-31T15:06:19Z)
- **Root License**: Proprietary / All Rights Reserved (`VERIFIED_PROPRIETARY_OR_ALL_RIGHTS_RESERVED`). Copyright (c) 2026 Mehmet Aydogan. All rights reserved.
- **Dependency / Subtree Licenses**: Root is proprietary; dependencies governed by respective licenses per `docs/BUILD_PERIOD_DISCLOSURE.md`.
- **Concepts Inspected**: Separation of deterministic authority from model prose, evidence-mode honesty (distinguishing live vs fixture execution), idempotency and crash recovery lessons.
- **Originality & Legal Boundary**: **ZERO implementation code may be copied or adapted.** Even though created by the same operator, ChangeMesh's All Rights Reserved license and hackathon open-source rules prohibit importing code. All Basebreak causal logic must be concept-only and clean-room reimplemented. Strictly avoid "ShadowLab", "Approval Compression", "Capability Passport", or "Change Passport" terminology.
- **Code Imported**: `NO` (0 bytes).

### D-007: universal-agent-os-qwen
- **Repository**: `gitlab.com/zyganali/universal-agent-os-qwen`
- **Revision Audited**: `a43b3411856f41a4be9424d11c01a5e637cdc410` (2026-07-01T22:12:18+03:00)
- **Root License**: MIT License (`VERIFIED_PERMISSIVE`). Copyright (c) 2026 Mehmet.
- **Dependency / Subtree Licenses**: Root repo MIT; Python/FastAPI dependencies.
- **Concepts Inspected**: Qwen model adapter and prompt management.
- **Basebreak Need**: `NO_CURRENT_REUSE_NEED`. Basebreak targets NVIDIA Nemotron on Nebius Token Factory.
- **Code Imported**: `NO` (0 bytes).

### D-008: universal-agent-os-gitlab-edition
- **Repository**: `gitlab.com/zyganali/universal-agent-os-gitlab-edition`
- **Revision Audited**: `3c4a412b6040d8a8154c15325943c409be9105f2` (2026-07-12T10:14:22+03:00)
- **Root License**: MIT License (`VERIFIED_PERMISSIVE`). Copyright (c) 2024-2026 Mehmet Aydoğan.
- **Dependency / Subtree Licenses**: Root repo MIT; GitLab CI pipeline configurations.
- **Concepts Inspected**: CI/CD pipeline automation and repository workflow patterns.
- **Basebreak Need**: `NO_CURRENT_REUSE_NEED`. Basebreak is hosted on GitHub with GitHub Actions CI.
- **Code Imported**: `NO` (0 bytes).

---

`RESEARCH_PIN` is not approval to copy code.
Any row moving to actual code reuse requires a dedicated Master Plan task/preflight.
