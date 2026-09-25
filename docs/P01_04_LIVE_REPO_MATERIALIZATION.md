# P-01.04 — Live Repository Materialization Inside Supported Sandbox Report

- **Date/Time:** 2026-09-25 13:42 UTC (16:42 Local)
- **Starting Canonical Remote SHA:** `d74d8103c7048bdb1c73221bb690575cba43818f`
- **Active Micro-Task:** `P-01.04 — Prove live repository materialization inside supported sandbox`
- **Execution Status:** EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE
- **Evidence Provenance:** `RECORDED_LIVE`
- **Zero-Cost Policy Check:** SATISFIED (Target personal spend $0.00; beta sandboxes free of charge, promotional balance $25.00 untouched).

---

## 1. Objective & Scope

Prove inside a REAL Nebius Token Factory Sandbox:
1. Synthetic/public repository materialization over real network;
2. Exact immutable base SHA resolved inside the sandbox environment;
3. Repository/source hash identity (tree SHA) verified against canonical repository;
4. Harmless repository test suite executed cleanly;
5. Deterministic exit code, stdout, and stderr captured;
6. Actual network, filesystem, and runtime environment assumptions recorded;
7. Ephemeral teardown observed upon completion.

---

## 2. Live Execution Setup & Request

- **Platform Endpoint:** `https://api.tokenfactory.nebius.com/sandboxes/v1/instances`
- **Headers:** `Authorization: Bearer <redacted>`, `Project: aiproject-e00mae0nmzkxjswr1k`
- **Base Image:** `tag:astral/uv:python3.11-alpine` (pre-warmed Python 3.11.14 + uv in Token Factory image catalog)
- **Target Repository:** `https://github.com/zyganali-glitch/Basebreak.git`
- **Command Script:**
  ```bash
  set -e
  apk add --no-cache git >/dev/null 2>&1
  git clone --quiet https://github.com/zyganali-glitch/Basebreak.git /workspace/Basebreak
  cd /workspace/Basebreak
  echo "RESOLVED_BASE_SHA=$(git rev-parse HEAD)"
  echo "TREE_SHA=$(git write-tree)"
  uv pip install --system --quiet pytest -e .
  python3 -m pytest tests/test_bootstrap.py tests/domain/test_task.py
  ```
- **Execution Mode:** `disposable: true`, `timeout: 180`

---

## 3. Deterministic Live Evidence (`RECORDED_LIVE`)

- **Operation UUID:** `01a0d8cd-bca6-7200-80ef-8ce81f49d093`
- **HTTP Spawn Status:** `201 Created`
- **Terminal Operation Status:** `SUCCESS`
- **Total Duration:** `5.062s`
- **Process Exit Code:** `0`
- **Consumed CPU:** `1.494s`
- **Consumed Memory:** `86,960 KB`

### Captured Stdout:
```
RESOLVED_BASE_SHA=d74d8103c7048bdb1c73221bb690575cba43818f
TREE_SHA=aa54850bf7ddcd222539d3e0b6fe5059cb1d693d
============================= test session starts ==============================
platform linux -- Python 3.11.14, pytest-9.1.1, pluggy-1.6.0
rootdir: /workspace/Basebreak
configfile: pyproject.toml
collected 28 items

tests/test_bootstrap.py ...                                              [ 10%]
tests/domain/test_task.py .........................                      [100%]

============================== 28 passed in 0.09s ==============================
```

### Captured Stderr:
```
(empty)
```

---

## 4. Cryptographic & Source Identity Verification

| Identity Metric | Sandbox Live Fact | Local Repository Truth (`git`) | Match? |
|---|---|---|:---:|
| **Commit SHA (`HEAD`)** | `d74d8103c7048bdb1c73221bb690575cba43818f` | `d74d8103c7048bdb1c73221bb690575cba43818f` | **EXACT MATCH** |
| **Tree SHA (`write-tree`)** | `aa54850bf7ddcd222539d3e0b6fe5059cb1d693d` | `aa54850bf7ddcd222539d3e0b6fe5059cb1d693d` | **EXACT MATCH** |

The git tree hash and commit hash resolved inside the container VM match the canonical repository state down to the exact bit.

---

## 5. Platform Network, Filesystem & Runtime Assumptions Proven

1. **Outbound Network:**
   - HTTPS egress to `github.com` is enabled by default (`networking: { "enabled": true }`).
   - Package manager egress (`alpine` apk mirrors, PyPI via `uv`) operates with sub-second package resolution.
2. **Filesystem Structure:**
   - Root filesystem is standard LinuxKit container VM.
   - Working directories (e.g. `/workspace`) are read-write and support standard git metadata directories (`.git/objects`, refs, index).
3. **Execution Teardown:**
   - Querying `GET /sandboxes/v1/whoami` post-execution confirmed `operations_stat.running_instances == 0`.
   - In `disposable: true` mode, no child image layer is allocated (`result_image_uuid: null`).

---

## 6. Zero-Cost & Secret Law Audit

- Zero API keys, bearer tokens, or sensitive credentials leaked into command strings, stdout, stderr, or documentation.
- Promotional credit balance: `$25.00` (unchanged).
- Spend: `$0.00`.
