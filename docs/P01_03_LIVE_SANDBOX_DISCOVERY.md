# P-01.03 — Live Token Factory Sandbox Discovery Report

- **Initial Discovery Date/Time:** 2026-09-24 10:15 UTC (13:15 Local)
- **Re-Probe Date/Time:** 2026-09-25 05:25 UTC (08:25 Local)
- **Beta Activation & Live Execution Date/Time:** 2026-09-25 13:38 UTC (16:38 Local)
- **Starting Canonical Remote SHA:** `662f6dd1a7a7f7f2f921e3c6ad2a0dfb4d109201`
- **Active Micro-Task:** `P-01.03 — Discover and execute minimal Token Factory Sandbox workflow`
- **Execution Status:** EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE
  (Nebius Token Factory Sandboxes Beta activation confirmed via authenticated `/whoami` returning all permissions `true`; minimal disposable execution succeeded with `echo BASEBREAK_SANDBOX_OK` producing expected stdout, exit code 0; lifecycle/teardown confirmed; live checkpointing, snapshot layer creation, and child execution tested and proven.)
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
   - Account permissions remained pending Nebius team enablement during earlier morning probe.

### I. Beta Activation & Live Sandbox Execution Verification (2026-09-25 13:38 UTC / 16:38 Local)
Executed as fresh live calls (`RECORDED_LIVE`) starting from remote SHA `662f6dd1a7a7f7f2f921e3c6ad2a0dfb4d109201` after official Nebius notification confirming beta activation:

1. **Live Token Introspection (`GET https://api.tokenfactory.nebius.com/sandboxes/v1/whoami`):**
   - Headers: `Authorization: Bearer <redacted>`, `Project: aiproject-e00mae0nmzkxjswr1k`, `User-Agent: Basebreak-Live-Probe/0.2`
   - **HTTP Status:** `200 OK`
   - **Deterministic Response Payload:**
   ```json
   {
     "token_uuid": "<redacted>",
     "token_expiration": 1790343806,
     "permissions": {
       "import": true,
       "spawn": true,
       "spawn_disposable": true,
       "list": true,
       "cancel": true,
       "set_image_tag": true
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
   - **Finding:** All functional permissions (`import`, `spawn`, `spawn_disposable`, `list`, `cancel`, `set_image_tag`) transitioned from `false` to `true`. Hard Gate A passed.

2. **Available Image Enumeration (`GET https://api.tokenfactory.nebius.com/sandboxes/v1/images`):**
   - **HTTP Status:** `200 OK`
   - Catalog contains pre-warmed images including `tag:busybox:latest` (`uuid: 95ba4f1b-a511-325b-af1c-a22b4f52f73b`), `tag:alpine:latest`, `tag:astral/uv:python3.11-alpine`, `tag:astral/uv:python3.11-trixie-slim`, and `tag:gcc:14`.

3. **Minimal Harmless Sandbox Execution (`POST https://api.tokenfactory.nebius.com/sandboxes/v1/instances`):**
   - **Submitted Payload:**
   ```json
   {
     "image": "tag:busybox:latest",
     "command": "echo BASEBREAK_SANDBOX_OK",
     "shell": true,
     "disposable": true
   }
   ```
   - **Spawn HTTP Status:** `201 Created`
   - **Spawn Headers:** `Location: /sandboxes/v1/operations/01a0d8ca-28fd-777e-9d32-0907c4cb6f28`
   - **Operation UUID:** `01a0d8ca-28fd-777e-9d32-0907c4cb6f28`
   - **Polling Status (`GET /sandboxes/v1/operations/01a0d8ca-28fd-777e-9d32-0907c4cb6f28`):** `SUCCESS`
   - **Execution Duration:** `0.338s`
   - **Exit Code:** `0`
   - **Captured Stdout:** `BASEBREAK_SANDBOX_OK\n` (encoding: `ascii`, truncated: `false`)
   - **Captured Stderr:** `""` (empty, truncated: `false`)
   - **Disposable Result:** `result_image_uuid: null`, `result.image: null` (no persistent layer retained)
   - **Post-Execution VM Teardown:** Verified via `whoami.operations_stat.running_instances == 0`.

4. **Live Checkpoint & Fork Capability Probe (`RECORDED_LIVE`):**
   - Non-disposable execution (`disposable: false`) executed `echo CHECKPOINT_TEST > /basebreak_probe.txt && cat /basebreak_probe.txt`.
   - **Operation 1 UUID:** `01a0d8ca-8919-7193-ad87-4afe9c4884e0`, status `SUCCESS`.
   - **Resulting Image UUID:** `28f5d6d6-f977-42a8-94b5-d8db23e62c8c` (immutable checkpoint/snapshot layer captured).
   - Subsequent child execution spawned directly targeting child image `image: "28f5d6d6-f977-42a8-94b5-d8db23e62c8c"` with command `cat /basebreak_probe.txt`.
   - **Operation 2 UUID:** `01a0d8ca-9299-7229-92e3-a20da3f2568a`, status `SUCCESS`.
   - **Operation 2 Captured Stdout:** `CHECKPOINT_TEST\n`.
   - **Live Proved Capabilities:** Checkpoint creation, snapshot layer capture, and execution branching/forking from an immutable parent state are fully functional on the live Nebius Token Factory Sandboxes platform.

---

## 4. Capability Discovery Matrix

| Primitive | Status | Discovery Source | Exact Current API / SDK Primitive | Live Tested? | Notes / Constraints |
|---|:---:|---|---|:---:|---|
| **CHECKPOINT** | `SUPPORTED` | `OFFICIAL_DOC` & `LIVE_NEBIUS` | `result_image_uuid` in `OperationResponse`; `image.run(disposable=False)` produces child image UUID | `YES` | Verified live: non-disposable execution produced image UUID `28f5d6d6-f977-42a8-94b5-d8db23e62c8c`. |
| **SNAPSHOT** | `SUPPORTED` | `OFFICIAL_DOC` & `LIVE_NEBIUS` | Post-execution filesystem state captured as an immutable image layer referenced by image UUID | `YES` | Verified live: filesystem modification (`/basebreak_probe.txt`) captured into immutable child image layer. |
| **CLONE / FORK** | `SUPPORTED` | `OFFICIAL_DOC` & `LIVE_NEBIUS` | Executing multiple commands from the same parent image UUID | `YES` | Verified live: spawned independent execution targeting child image UUID `28f5d6d6-f977-42a8-94b5-d8db23e62c8c` successfully. |
| **BRANCH** | `SUPPORTED` | `OFFICIAL_DOC` | CLI: `contree session branch <name>`, `contree session checkout <name>`; SDK: local session DAG tracking | `NO` (client-side abstraction) | Client-side feature: `contree-cli` manages named branches via local SQLite database (`sessions-{profile}.db`), referencing remote image UUIDs. Server-side REST API has no branch resource. |
| **ROLLBACK / RESET** | `SUPPORTED` | `OFFICIAL_DOC` & `LIVE_NEBIUS` | CLI: `contree session rollback [N]`; SDK/API: re-executing from an earlier parent image UUID | `YES` | In REST API/SDK, achieved by targeting an earlier parent image UUID, verified by spawning from base image and snapshot image. |
| **CLEAN-WORLD / REPRODUCTION** | `SUPPORTED` | `OFFICIAL_DOC` & `LIVE_NEBIUS` | `disposable: true` (`-D` flag in CLI); running from clean base tag e.g. `tag:busybox:latest` | `YES` | Verified live: `disposable: true` executed `echo BASEBREAK_SANDBOX_OK` in 0.338s without creating any persistent image. |

*Semantic boundary: Capability classifications are derived from official ConTree documentation, first-party SDK/CLI source code, OpenAPI schema definitions, and direct live execution probes on Nebius Token Factory Sandboxes. ConTree manages immutable image layers (UUIDs) at the platform layer, while named branches and linear rollback are client-side session DAG abstractions in contree-cli. Both platform layer primitives and client-side mechanisms are verified.*

---

## 5. Teardown & Lifecycle Semantics Investigation

Live execution observations combined with OpenAPI schema confirm the exact platform lifecycle:
1. **Execution Instances (VMs):** Ephemeral. A container instance is spun up to execute the requested command. When the process terminates (exit code emitted or timeout reached), the VM execution terminates automatically. Verified: `running_instances` returned to `0` immediately after command completion.
2. **Cancellation:** In-flight operations can be cancelled via `POST /operations/{operationId}/cancel`.
3. **State Retention:**
   - In `disposable: true` mode: No image is created (`result_image_uuid: null`); execution state is discarded upon termination.
   - In `disposable: false` mode: Resulting filesystem layer is preserved as an immutable image version with a UUID, retained up to 180 days.
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

- `P-01.04` (Prove live repository materialization inside supported sandbox): NOT_RUN / NEXT_IN_BATCH.
- `P-01.05` (Prove two independent clean sandbox executions from the same trusted source): NOT_RUN / PENDING_P01_04.
- `P-01.06` (Phase feasibility decision and architecture freeze v0): NOT_RUN.
- `P-01.07` (Freeze judge-visible causal vertical-slice contract): NOT_RUN.
- `P-04.03`, `P-04.05`, `P-04.06`: NOT_RUN under current batch boundary.
- `P-05+`: STRICTLY FORBIDDEN.

---

## 8. Summary of Findings & Blocker Resolution

1. **Authentication & API Contract:** Documented via official OpenAPI schema, first-party SDK/CLI source, and verified live probes against `https://api.tokenfactory.nebius.com/sandboxes/v1/`. Requires Bearer auth plus `Project: aiproject-e00mae0nmzkxjswr1k`.
2. **Blocker Resolution:** Beta access for `aiproject-e00mae0nmzkxjswr1k` was activated by Nebius on 2026-09-25. Authenticated `/whoami` returned all functional permissions `true`. Minimal execution (`echo BASEBREAK_SANDBOX_OK`) succeeded with exit code 0 and exact expected stdout. Live checkpointing and child execution branching were verified.
3. **Task Status:** `P-01.03 = EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE`.
4. **Next Step:** Proceed to `P-01.04 — Prove live repository materialization inside supported sandbox`.
