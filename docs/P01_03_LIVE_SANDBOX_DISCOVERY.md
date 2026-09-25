# P-01.03 — Live Token Factory Sandbox Discovery Report

- **Initial Discovery Date/Time:** 2026-09-24 10:15 UTC (13:15 Local)
- **Re-Probe Date/Time:** 2026-09-25 05:25 UTC (08:25 Local)
- **Starting Canonical Remote SHA:** `e4892ea9a2ab98e464d2fc409b280a30d23ff3f0` (baseline SHA `96f032f1165425d88e1bbbc23d6b925ee05e2841` + P-04.04 truth sync)
- **Active Micro-Task:** `P-01.03 — Discover and execute minimal Token Factory Sandbox workflow`
- **Execution Status:** EXECUTOR_COMPLETED / BLOCKED_EXTERNAL_BETA_ACCESS
  (Discovery complete, SDK/CLI analysed, recorded live authentication probe via `/whoami`, exact Project ID identified, harmless execution attempted, official Beta access form submitted on 2026-09-24, re-probed on 2026-09-25; awaiting Nebius team beta enablement on `aiproject-e00mae0nmzkxjswr1k`)
- **Zero-Cost Policy Check:** SATISFIED (Operator observed; target personal spend $0.00)
  - Promotional balance: `$25.00`
  - Trial credit: `$1.00` untouched
  - Operational safety reserve: `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` satisfied
  - Platform confirmation: Token Factory Sandboxes UI explicitly states: *"Free while in beta — runs don't consume your credits."* Target personal spend remains strictly `$0.00`.

---

## 1. Official Sources & Discovery Scope

| Source | Official Location | Documented Facts & Contract | Provenance |
|---|---|---|---|
| Sandboxes Overview | `https://docs.tokenfactory.nebius.com/sandboxes/overview.md` | Beta status; VM-level isolation; Git-like branching; 50 concurrent ops limit; 180-day retention; email `contree@nebius.com` | `OFFICIAL_DOC` |
| Sandboxes SDK Guide | `https://docs.tokenfactory.nebius.com/sandboxes/sdk/python_sdk/getting-started.md` | PyPI `contree-sdk`, `contree-client`; Async & Sync clients (`Contree`, `ContreeSync`); image execution via `image.run()` | `OFFICIAL_DOC` |
| Sandboxes Branching Guide | `https://docs.tokenfactory.nebius.com/sandboxes/sdk/python_sdk/branching.md` | Branching from base filesystem states; reproducible child states; UUID tracking per step; `disposable=False` vs `True` | `OFFICIAL_DOC` |
| CLI Tutorial & Auth | `https://docs.tokenfactory.nebius.com/sandboxes/cli/tutorial/installation.md` | PyPI `contree-cli`; requires bearer token + project ID; auth profiles in `~/.config/contree/auth.ini` | `OFFICIAL_DOC` |
| CLI Sessions & Rollback | `https://docs.tokenfactory.nebius.com/sandboxes/cli/tutorial/sessions.md` | Sessions track image DAG; `contree session branch`, `contree session rollback [N]`, `contree run -D` (disposable) | `OFFICIAL_DOC` |
| OpenAPI Specification | `https://eu-north.nebius.computer/static/api.yaml` | Contree API v1.0.0; Base URL `https://api.tokenfactory.nebius.com/sandboxes/v1`; `IAMBearerAuth` + `IAMProjectHeader` | `OFFICIAL_DOC` |
| Live Token Factory Portal | `https://tokenfactory.nebius.com/` | Web console bundle exposes `sandboxesURL: "https://api.tokenfactory.nebius.com/sandboxes/v1/"`; banner confirms free beta | `OFFICIAL_DOC` / `LIVE_ACCOUNT` |
| Sandboxes Auth API Probe | `GET https://api.tokenfactory.nebius.com/sandboxes/v1/whoami` | Builder-recorded token introspection probe; validates Bearer token and inspects project permissions | `RECORDED_LIVE` |
| Instance Spawn API Probe | `POST https://api.tokenfactory.nebius.com/sandboxes/v1/instances` | Builder-recorded sandbox instance spawn probe; returned HTTP 403 Insufficient permissions | `RECORDED_LIVE` |

---

## 2. SDK, Client & API Architecture Discovery

First-party packages installed in ephemeral virtual environment (outside repository dependencies):
- `contree-sdk==0.3.6` (Python programmatic SDK with `Contree` async and `ContreeSync` interfaces)
- `contree-client==0.4.0` (Core HTTP/REST client, OpenAPI model definitions, retry policies, SSE streaming)
- `contree-cli==0.9.4` (Terminal CLI client with `run`, `use`, `session`, `auth`, `kill`, `show`, `images`, `file`, `export`)

### Authentication & Transport Invariants:
1. **Base URL:** `https://api.tokenfactory.nebius.com/sandboxes/v1` (server prefix `https://api.tokenfactory.nebius.com/sandboxes`).
2. **Auth Scheme:**
   - Header 1: `Authorization: Bearer <NEBIUS_API_KEY>`
   - Header 2: `Project: <NEBIUS_PROJECT_ID>` (Mandatory: omission returns HTTP 400 `{"status": 400, "error": "Missing \"Project\" header"}`)
3. **Canonical Environment Variables:**
   - `NEBIUS_API_KEY` (or `CONTREE_TOKEN`)
   - `NEBIUS_PROJECT_ID` (or `NEBIUS_AI_PROJECT` / `CONTREE_PROJECT`)
4. **Execution Model:**
   - Asynchronous operations: `POST /instances` returns HTTP 201 with `Location: /v1/operations/{operationId}`.
   - Polling: `GET /operations/{operationId}` (with optional `?inflight=1` for live partial streams).
   - Event streaming: Server-Sent Events (SSE) available via `GET /operations/{operationId}/events`.
   - Result extraction: On completion (`status: "SUCCESS"`), stdout, stderr, exit code, resource metrics, and resulting image UUID (`result_image_uuid`) are returned under `metadata.result`.

---

## 3. Account Observation & Recorded Live Probe Findings (`RECORDED_LIVE` & `LIVE_ACCOUNT`)

### A. Pre-Execution Balance & Budget Observation
- **Observation Timestamp:** `2026-09-24T10:08:00Z` (13:08 Local)
- **Account State:**
  - Promotional Balance: `$25.00`
  - Trial Credit: `$1.00` (untouched)
  - Billing Status: Active
  - Safety Floor: `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` satisfied ($25.00 > $5.00).
- **Service Cost Rule:** The Token Factory web console explicitly displays:
  > *"Free while in beta — runs don't consume your credits."*
  Sandbox runs during beta do NOT deplete promotional or trial balances.

### B. Project Identity Discovery
- **Console Inspection:** Operator inspected Project Settings at `https://tokenfactory.nebius.com/`.
- **Project Name:** `default-project`
- **Resolved Project ID:** `aiproject-e00mae0nmzkxjswr1k` (retrieved via console "Copy project ID").

### C. Recorded Live Token Introspection (`GET /sandboxes/v1/whoami`)
Executed as a Builder-recorded live probe (`RECORDED_LIVE`) against `https://api.tokenfactory.nebius.com/sandboxes/v1/whoami`:
- **Headers:** `Authorization: Bearer <redacted>`, `Project: aiproject-e00mae0nmzkxjswr1k`
- **HTTP Status:** `200 OK`
- **Deterministic Response Payload:**
```json
{
  "token_uuid": "<redacted-token-uuid>",
  "token_expiration": 1790244789,
  "permissions": {
    "import": false,
    "spawn": false,
    "spawn_disposable": false,
    "list": false,
    "cancel": false,
    "set_image_tag": false
  },
  "operations_stat": {
    "running_instances": 0,
    "running_imports": 0
  },
  "limits": {
    "instance_max_timeout": 3600,
    "instance_max_concurrency": 50,
    "instance_max_layer_bytes": 12884901888,
    "images_import_max_concurrency": 8,
    "images_import_max_timeout": 3600
  }
}
```
- **Recorded Probe Finding:** The token and project header are valid, authenticated, and return system limits (50 concurrent instances, 12GB max layer, 3600s timeout). However, all functional permissions are currently `false`.

### D. Recorded Harmless Command Execution Attempt (`POST /sandboxes/v1/instances`)
- **Submitted Payload:**
```json
{
  "image": "tag:busybox:latest",
  "command": "echo BASEBREAK_SANDBOX_OK",
  "shell": true,
  "disposable": true
}
```
- **HTTP Status:** `403 Forbidden`
- **Error Response:**
```json
{"status": 403, "error": "Insufficient permissions: spawn or spawn_disposable"}
```

### E. Recorded Image List Probe (`GET /sandboxes/v1/images`)
- **HTTP Status:** `403 Forbidden`
- **Error Response:**
```json
{"status": 403, "error": "Insufficient permissions: list"}
```

### F. First-Party CLI Corroboration
The official `contree-cli` codebase (`contree_cli/cli/auth.py` lines 278-286) contains explicit handling for this exact platform state:
```python
if not check_permission(whoami, REQUIRED_PERMISSION):  # REQUIRED_PERMISSION = "list"
    logger.warning(
        "Warning: token is valid but sandboxes are disabled on %s"
        " (no %r permission). The profile will be saved but no commands"
        " will work until the service is enabled.",
        project_label,
        REQUIRED_PERMISSION,
    )
```

### G. External Beta Access Request Action
- **Operator Action:** The operator navigated to `Sandboxes` in the Token Factory web console, clicked **"Request beta access"**, and submitted the official form:
  - `Project ID`: `aiproject-e00mae0nmzkxjswr1k`
  - `Email`: `[redacted operator contact]`
  - `Use Case`: *"Participating in the official Nebius x NVIDIA Global AI Hackathon. Developing Basebreak, an agent causal verification runtime using NVIDIA Nemotron and Token Factory Sandboxes for isolated execution branching."*
- **Platform Confirmation:** Platform displayed: *"Teşekkürler, yanıtınız gönderildi"*.
- **Post-Submission State:** Application is in review / awaiting enablement by the Nebius team.

### H. Re-Probe of Sandbox Access (2026-09-25 05:25 UTC / 08:25 Local)
Executed as fresh live calls (`RECORDED_LIVE`) starting from remote SHA `e4892ea9a2ab98e464d2fc409b280a30d23ff3f0`:
1. **Live Token Introspection (`GET https://api.tokenfactory.nebius.com/sandboxes/v1/whoami`):**
   - Headers: `Authorization: Bearer <redacted>`, `Project: aiproject-e00mae0nmzkxjswr1k`, `User-Agent: Basebreak-Live-Probe/0.1`
   - **HTTP Status:** `200 OK`
   - **Deterministic Response Payload:**
   ```json
   {
     "token_uuid": "<redacted>",
     "token_expiration": 1790314242,
     "permissions": {
       "import": false,
       "spawn": false,
       "spawn_disposable": false,
       "list": false,
       "cancel": false,
       "set_image_tag": false
     },
     "operations_stat": {
       "running_instances": 0,
       "running_imports": 0
     },
     "limits": {
       "instance_max_timeout": 3600,
       "instance_max_concurrency": 50,
       "instance_max_layer_bytes": 12884901888,
       "images_import_max_concurrency": 8,
       "images_import_max_timeout": 3600
     }
   }
   ```
2. **Live Execution Attempt (`POST https://api.tokenfactory.nebius.com/sandboxes/v1/instances`):**
   - Headers: `Authorization: Bearer <redacted>`, `Project: aiproject-e00mae0nmzkxjswr1k`, `Content-Type: application/json`
   - Payload:
   ```json
   {
     "image": "tag:busybox:latest",
     "command": "echo BASEBREAK_SANDBOX_OK",
     "shell": true,
     "disposable": true
   }
   ```
   - **HTTP Status:** `403 Forbidden`
   - **Response Body:**
   ```json
   {"status": 403, "error": "Insufficient permissions: spawn or spawn_disposable"}
   ```
3. **Factual Conclusion:**
   - Account permissions remain pending Nebius team enablement.
   - P-01.03 remains `BLOCKED_EXTERNAL_BETA_ACCESS`.
   - In accordance with the Master Plan and Conditional Batch Hard-Gate Law, a **HARD STOP** is enforced immediately.
   - P-01.04 is NOT run and must not be started.

---

## 4. Capability Discovery Matrix

| Primitive | Status | Discovery Source | Exact Current API / SDK Primitive | Live Tested? | Notes / Constraints |
|---|:---:|---|---|:---:|---|
| **CHECKPOINT** | `SUPPORTED` | `OFFICIAL_DOC` | `result_image_uuid` in `OperationResponse`; `image.run(disposable=False)` returns child `ContreeImage` with new `uuid` | `NO` (blocked by beta access) | Non-disposable execution produces an immutable image layer retained for 180 days. |
| **SNAPSHOT** | `SUPPORTED` | `OFFICIAL_DOC` | Post-execution filesystem state captured as an immutable image layer referenced by image UUID | `NO` (blocked by beta access) | Filesystem state is captured as an image layer post-execution; can be inspected via `/inspect` without spinning up a VM. Official docs manage execution states as image layers rather than defining a separate snapshot entity. |
| **CLONE / FORK** | `SUPPORTED` | `OFFICIAL_DOC` | Executing multiple commands from the same parent image UUID: `gc1 = await child.run(...)`, `gc2 = await child.run(...)` | `NO` (blocked by beta access) | Documented in `branching.md`. Multiple execution runs can originate from the same parent image UUID without mutating the parent state. |
| **BRANCH** | `SUPPORTED` | `OFFICIAL_DOC` | CLI: `contree session branch <name>`, `contree session checkout <name>`; SDK: local session DAG tracking | `NO` (blocked by beta access) | Client-side feature: `contree-cli` manages named branches via local SQLite database (`sessions-{profile}.db`), referencing remote image UUIDs. Server-side REST API has no branch resource. |
| **ROLLBACK / RESET** | `SUPPORTED` | `OFFICIAL_DOC` | CLI: `contree session rollback [N]`; SDK/API: re-executing from an earlier parent image UUID | `NO` (blocked by beta access) | In CLI, resets the active session pointer to an earlier step in the local DAG. In REST API/SDK, achieved by targeting an earlier parent image UUID. |
| **CLEAN-WORLD / REPRODUCTION** | `SUPPORTED` | `OFFICIAL_DOC` | `disposable: true` (`-D` flag in CLI); running from clean base tag e.g. `tag:busybox:latest` | `NO` (blocked by beta access) | `disposable: true` ensures no modified state is saved; container VM is destroyed without persisting an image layer. |

*Semantic boundary: Capability classifications are derived strictly from official ConTree documentation, first-party SDK/CLI source code, and OpenAPI schema definitions. Primitives are distinct: ConTree manages immutable image layers (UUIDs) at the platform layer, while named branches and linear rollback are client-side session DAG abstractions in contree-cli. No equivalence is assumed, and no capability has been validated via live sandbox execution due to the active beta access blocker.*

---

## 5. Teardown & Lifecycle Semantics Investigation

Investigation of official OpenAPI schema and SDK code reveals the exact platform lifecycle:
1. **Execution Instances (VMs):** Ephemeral. A container instance is spun up to execute the requested command. When the process terminates (exit code emitted or timeout reached), the VM execution terminates automatically.
2. **Cancellation:** In-flight operations can be cancelled via `POST /operations/{operationId}/cancel` (CLI `contree kill UUID` or `contree op cancel`). The operation transitions to `CANCELLED` and execution is interrupted.
3. **State Retention:**
   - In `disposable: true` mode: No image is created; the execution state is immediately discarded upon termination.
   - In `disposable: false` mode: The resulting filesystem layer is saved as an immutable image version with a UUID, retained up to 180 days.
4. **Explicit Delete Primitive:**
   - `DELETE /images/{uuid}` does NOT exist in the ConTree REST API schema.
   - `DELETE /images/tags/{tag}` exists to remove tags from an image.
   - Unreferenced untagged images are garbage-collected by the provider after 180 days.
   - Therefore, on Token Factory Sandboxes, "teardown" is satisfied either by:
     - Using `disposable: true` for throwaway test executions (ensuring no persistent compute or storage remains); or
     - Letting the process exit naturally (VM terminates) while the resulting immutable image state remains available for inspection/branching.

---

## 6. Zero-Cost & Secret Law Audit

- **Secret Audit:**
  - `NEBIUS_API_KEY` was read exclusively from User environment variables via secure process memory.
  - Zero API keys, authorization headers, bearer tokens, or credential substrings are logged or committed.
  - No `.env` files or `~/.config/contree/auth.ini` profiles were created in the repository.
- **Spend Audit:**
  - Pre-run balance: `$25.00`
  - Post-run balance: `$25.00` (unchanged)
  - Trial credit: `$1.00` (untouched)
  - Personal money spent: strictly `$0.00`.
  - Nebius Sandboxes UI invariant confirmed: *"Free while in beta — runs don't consume your credits."*

---

## 7. Checks Explicitly NOT_RUN

- `LIVE_SANDBOX_COMMAND_EXECUTION`: NOT_RUN due to external platform blocker (`BLOCKED_EXTERNAL_BETA_ACCESS` — all sandbox permissions returned `false` pending Nebius beta approval for `aiproject-e00mae0nmzkxjswr1k`).
- `LIVE_CHECKPOINT_CREATION`: NOT_RUN (dependent on live command execution).
- `LIVE_FORK_BRANCH_VERIFICATION`: NOT_RUN (dependent on live command execution).
- `P-01.04` (Repository materialization inside sandbox): STRICTLY NOT STARTED.
- `P-04.04` (Protected-surface manifest): PENDING / NOT ACTIVE.
- `P-05+`: STRICTLY FORBIDDEN.

---

## 8. Summary of Findings & Blocker Classification

1. **Authentication & API Contract:** Documented via official OpenAPI schema, first-party SDK/CLI source, and Builder-recorded live probes at `https://api.tokenfactory.nebius.com/sandboxes/v1/`. Requires Bearer auth plus `Project: <project_id>`. All functional operations currently require beta enablement.
2. **Current Blocker:** `BLOCKED_EXTERNAL_BETA_ACCESS`. The operator has submitted the official beta request form for Project ID `aiproject-e00mae0nmzkxjswr1k`. Until Nebius activates beta permissions on this project, calls to `/sandboxes/v1/instances` return HTTP 403 `Insufficient permissions: spawn or spawn_disposable`.
3. **Next Steps:** When Nebius grants beta access, P-01.03 live execution can proceed using the identified endpoint, resolved project ID, and harmless command workflow.
