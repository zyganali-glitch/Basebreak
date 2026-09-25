# Sandbox Execution Security Policy

## Authority & Purpose
This document specifies the authoritative execution, resource, network, process, filesystem, and secret security policies governing all untrusted-code execution inside Nebius Token Factory Sandboxes for Basebreak.

This document satisfies the specification of Master Plan task **P-04.03 — Define sandbox resource/network/process policy from proven platform capability**.

---

## 1. Grounded Platform Capabilities vs. Unproven Assumptions

Basebreak policy is constructed strictly from **empirically proven** and **first-party documented** facts established during P-01 live platform discovery. Basebreak explicitly distinguishes proven capabilities from unknown or unsupported platform attributes.

### Authoritative Capability Matrix

| Capability | Status | Discovery / Provenance | Verified Reality | Basebreak Operational Policy |
|---|:---:|---|---|---|
| **Disposable VM Execution** | `PROVEN_SUPPORTED` | `RECORDED_LIVE` (P-01.03) | `POST /instances` with `disposable: true` creates an ephemeral VM that terminates upon exit code, leaving no persistent layer. | **MANDATORY** for all verification runs (`BASE`, `CANDIDATE`, `COUNTERFACTUAL`). |
| **Checkpoint / Snapshot Layer** | `PROVEN_SUPPORTED` | `RECORDED_LIVE` (P-01.03) | `POST /instances` with `disposable: false` captures post-execution state into an immutable image UUID (`result_image_uuid`). | Permitted **ONLY** for caching clean base materializations; strictly forbidden for sharing mutable state between runs. |
| **Child Execution Forking** | `PROVEN_SUPPORTED` | `RECORDED_LIVE` (P-01.03) | Spawning subsequent executions directly referencing parent image UUID works cleanly. | Used to branch independent `BASE` and `CANDIDATE` runs from an immutable parent image. |
| **Teardown Observability** | `PROVEN_SUPPORTED` | `RECORDED_LIVE` (P-01.03, P-01.05) | `/whoami` endpoint reflects active running instance count returning to 0 after VM exit. | Basebreak verifies post-run instance teardown. |
| **Outbound HTTPS** | `PROVEN_SUPPORTED` | `RECORDED_LIVE` (P-01.04) | Outbound HTTPS egress (`github.com`, package registries) is enabled by default. | Permitted for repo cloning / package resolution; forbidden from receiving credentials. |
| **Arbitrary Egress Filtering** | `UNSUPPORTED` | `OFFICIAL_DOC` (P-01.03 OpenAPI) | Platform REST API supports only binary networking enabled/disabled (`networking: {"enabled": bool}`), no domain allowlist/denylist. | **Fail-Closed:** Assume arbitrary egress is possible if networking is enabled; never pass secrets to network-enabled VMs. |
| **Inbound Network Isolation** | `UNPROVEN` | `UNPROVEN` | Inbound traffic handling, port bindings, and NAT isolation semantics were not tested. | Basebreak never binds or exposes inbound network ports in sandboxes. |
| **CPU Hard Quota Enforcement** | `UNPROVEN` | `UNPROVEN` | API reports consumed CPU time, but whether CPU cores are throttled or capped is unproven. | Enforce CPU bounding through execution timeout. |
| **Memory Hard-Kill / OOM Behavior** | `UNPROVEN` | `UNPROVEN` | API reports consumed memory, but deterministic OOM kill vs host crash behavior is unproven. | Enforce memory limits through bounded workload and timeout; no crash probes. |
| **PID / Process Ceilings** | `UNPROVEN` | `UNPROVEN` | Platform `pids.max` or `RLIMIT_NPROC` values are unproven. | Basebreak requires operational timeouts (<= 600s) and disposable VM cleanup by policy, but provider child-process kill semantics and process-explosion containment remain UNPROVEN. |
| **Syscall Filtering (Seccomp)** | `UNPROVEN` | `UNPROVEN` | Container runs as root in LinuxKit VM; specific seccomp/AppArmor profile unproven. | Treat VM execution as untrusted root; never rely on syscall filtering for host safety. |
| **Filesystem Mount Restrictions** | `UNPROVEN` | `UNPROVEN` | Rootfs is read-write; fine-grained mount restrictions are unproven. | Workspace changes are contained inside the VM; disposable mode discards all mutations. |
| **Provider Secret Protection** | `UNSUPPORTED` | `POLICY_DERIVED` | The sandbox provider does not isolate guest memory or environment variables from guest code. | Zero credentials in sandbox environment. |
| **Sealed Verifier Isolation** | `UNSUPPORTED` | `POLICY_DERIVED` | The platform is a general-purpose runner and has no native verifier isolation concept. | Sealed witness assets and verifier separation must be enforced at Basebreak application layer. |

---

## 2. Resource Budget Policy

Basebreak distinguishes between provider-advertised account maximums and Basebreak's intentionally constrained **operational ceilings**. Basebreak operational ceilings are strictly enforced to prevent runaway spending, denial of service, and resource exhaustion.

### Limits Comparison

| Resource Dimension | Provider Advertised Limit | Basebreak Default | Basebreak Operational Ceiling | Validation Rule |
|---|---|---|---|---|
| **Execution Timeout** | 3,600 s (1 hr) | 180 s | **600 s (10 min)** | `1 <= timeout <= 600` |
| **Concurrency** | 50 instances | 2 instances | **4 instances** | `1 <= concurrency <= 4` |
| **Captured Output Size** | Unlimited (truncated flag) | 65,536 B (64 KB) | **1,048,576 B (1 MB)** | `1 <= output <= 1MB` |
| **Image Layer Size** | 12,884,901,888 B (12 GB) | 2,147,483,648 B (2 GB) | **12,884,901,888 B (12 GB)** | `<= 12 GB` |
| **Commands per Run** | Unbounded | 1 script | **10 commands** | `1 <= commands <= 10` |
| **Command Length** | Unbounded | Bounded | **16,384 B (16 KB)** | `<= 16 KB` |

### Budget Invariants
1. **Never Equate Account Max with Safe Default:** The provider permits 3,600s timeout and 50 instances. Basebreak operations default to 180s and 2 instances. An execution request exceeding 600s is rejected immediately with `ResourceBudgetError`.
2. **Output Stream Bounding:** Output capture is capped at 64 KB by default (matching `BoundedStreamCapture` from P-03.03) and hashed with SHA-256 to ensure complete tamper-evident integrity without host memory exhaustion.

---

## 3. Network Policy

### Proven Platform Reality
1. Outbound network egress over HTTPS is functional by default.
2. Token Factory Sandboxes do **not** provide granular domain/IP allowlisting at the provider API layer. Egress cannot be restricted to specific hosts (e.g. `github.com`) by the platform alone.

### Basebreak Fail-Closed Network Policy
1. **Two Network Modes:**
   - `DISABLED`: Networking disabled (`networking: {"enabled": false}`). This is the mandatory mode for verification test executions once dependencies are pre-materialized.
   - `EGRESS_REQUIRED`: Outbound networking enabled. Used exclusively during repository materialization (`git clone`) and package dependency resolution (`uv pip install`).
2. **Secret Non-Exposure Invariant:**
   - When `EGRESS_REQUIRED` is active, the execution environment (`env`) MUST NOT contain any sensitive or secret-shaped values.
   - Violation raises `NetworkPolicyError`.
3. **No Network Privilege:**
   - Network-dependent commands are never treated as trusted simply because they execute inside an isolated sandbox VM.
   - Untrusted repository code must never be supplied credentials to download private dependencies; all candidate evaluations operate on public or pre-materialized repositories.

---

## 4. Process Policy

### Subprocess Creation & Execution
1. Subprocess creation by standard build tools (`git`, `uv`, `pytest`, `python`, `gcc`, `sh`) is permitted inside the container VM.
2. Commands are executed via the platform's shell execution capability (`shell: true`).
3. Commands must not contain null bytes (`\x00`) and must be <= 16 KB in length.

### Process Fanout & Fork-Bomb Protection
1. Because platform-level PID ceilings (`pids.max`) and child-process termination guarantees under fork-bombs remain `UNPROVEN`:
   - Basebreak's security policy requires a hard operational timeout ceiling (<= 600s) and disposable VM mode (`disposable: true`) intended to destroy the VM environment upon termination.
   - However, Basebreak does NOT claim that provider watchdogs or VM teardown are proven to deterministically prevent or terminate arbitrary process explosions without host degradation; this capability remains `UNPROVEN` at the platform layer. Mechanical prevention depends on subsequent runtime adapter enforcement (P-05).
2. In P-04.05, process termination outcomes must be normalized from explicit authoritative facts, never derived from unproven provider error prose.

### Long-Running Daemons & Background Tasks
1. Background daemons that outlive the requested execution command are strictly prohibited during verification runs.
2. Execution scripts must execute synchronously to completion; background processes that prevent normal process exit will be terminated by the execution timeout.

---

## 5. Filesystem & Image Lifecycle Policy

### Disposable vs. Checkpoint Semantics
1. **Disposable Execution (`SandboxExecutionMode.DISPOSABLE`):**
   - The default and mandatory mode for all verification runs (`BASE`, `CANDIDATE`, `COUNTERFACTUAL`).
   - The VM filesystem is ephemeral; upon exit code emission, the VM is destroyed and no image layer is retained (`result_image_uuid: null`).
   - Guarantees zero cross-run storage leakage.
2. **Checkpoint Execution (`SandboxExecutionMode.CHECKPOINT`):**
   - Retains post-execution filesystem state as an immutable image identified by a cryptographic UUID.
   - Permitted **solely** for caching clean base repository clones before candidate evaluation.

### Two-Clean-Environment Invariant (No Workspace Sharing)
1. Reusing mutable workspace state across `BASE` and `CANDIDATE` runs is strictly prohibited.
2. `BASE` and `CANDIDATE` must execute in distinct sandbox instances with unique platform operation UUIDs.
3. Both runs may fork from a shared immutable parent image, but must fork into separate disposable instances.
4. Violation raises `WorkspaceIsolationError`.

---

## 6. Secret Policy Integration (P-04.02)

Basebreak sandbox policy directly integrates with the canonical secret redaction engine and persistence boundary defined in `src/basebreak/security/secret_policy.py`:

1. **Zero Real Secrets in Sandbox:**
   - Target repositories are untrusted code. Real provider API keys (Nebius, NVIDIA, Tavily) belong exclusively in the host control plane and must NEVER be injected into sandbox environments, command lines, or filesystem layers.
2. **Environment Validation:**
   - Every execution environment dictionary (`env`) is validated with `validate_no_secrets` and `is_sensitive_key`.
   - Any sensitive key (`API_KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `BEARER`) or secret-shaped string raises `SecretPersistenceError`.
3. **Command String Validation:**
   - Command strings are scanned via `find_secret_findings`. Embedded secrets raise `ProcessPolicyError`.
4. **Output Stream Sanitization:**
   - Sandbox stdout and stderr streams are bounded at capture time and sanitized using `redact_log_text` before display or logging.
   - Evidence records fail closed if raw secrets enter persistent evidence.

---

## 7. Protected Surface Integration (P-04.04)

Basebreak sandbox policy integrates with the protected-surface manifest and diff validation engine defined in `src/basebreak/security/protected_surfaces.py`:

1. **Pre-Execution Diff Verification:**
   - Before any candidate patch is dispatched to a sandbox for execution, its unified diff is validated against `get_canonical_basebreak_protected_manifest()`.
   - If the patch modifies, creates, renames into, or deletes any protected governance, verification, security, or evidence file, validation raises `ProtectedSurfaceViolation`.
   - The sandbox execution is blocked before any compute or token consumption occurs.

---

## 8. Verifier Boundary Delineation (P-04 vs. P-08)

1. **What P-04.03 Establishes:**
   - Generic security invariants requiring separate execution instances for baseline and candidate runs.
   - Rejection of mutable workspace sharing.
   - Fail-closed bounding of resource, network, and process parameters.
2. **What P-04.03 Explicitly Does NOT Implement (No Future Phase Leakage):**
   - Does NOT implement the P-08 sealed verifier architecture.
   - Does NOT implement hidden witness challenge generation (P-09).
   - Does NOT implement the causal two-world orchestration engine (P-10).
   - Does NOT implement the Nebius/Token Factory provider adapter (P-05).
