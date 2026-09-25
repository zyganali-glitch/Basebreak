# P-01.07 — Judge-Visible Causal Vertical-Slice Contract

- **Date/Time:** 2026-09-25 13:50 UTC (16:50 Local)
- **Starting Canonical Remote SHA:** `d74d8103c7048bdb1c73221bb690575cba43818f`
- **Active Micro-Task:** `P-01.07 — Freeze judge-visible causal vertical-slice contract from proven platform reality`
- **Execution Status:** EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE
- **Zero-Cost Policy Check:** SATISFIED (Target personal spend $0.00; beta sandboxes free of charge, promotional balance $25.00 untouched).

---

## 1. Purpose & Product Thesis

Basebreak's core thesis:
> **"If the patch matters, the base must break."**

A green test suite on a patched repository does not prove causality. A test suite may pass because:
- The tests are trivial or tautological;
- The test suite was already green on the buggy base (non-discriminating test);
- The environment was polluted by previous runs or pre-existing build artifacts;
- The patch bypassed the problem rather than fixing the defect.

Basebreak delivers deterministic, irrefutable proof that an AI-generated patch is the sole cause of the behavioral improvement. This document freezes the exact contract of what an evaluator or hackathon judge will see during a verification run, built strictly upon the live platform primitives proven in `P-01.02` through `P-01.05`.

---

## 2. Judge-Visible Pipeline Flow & Contract

Every evaluation executed by Basebreak follows an immutable sequential pipeline:

```
[ EngineeringTask ]
        │
        ├───────────────────────────────────────┐
        ▼                                       ▼
  [ Builder Agent ]                    [ Independent Witness ]
(Nemotron-3.5-Lightning)              (Generated Independently)
        │                                       │
        ▼                                       ▼
 [ Candidate Patch ]                     [ Test / Witness ]
        │                                       │
        ├───────────────────┬───────────────────┤
        ▼                   ▼                   ▼
 [ BASE Sandbox ]   [ CANDIDATE Sandbox ] [ COUNTERFACTUAL ]
 (Clean disposable)  (Clean disposable)    (Clean disposable)
 (BASE + Witness)    (BASE + Patch + Wit)  (BASE + Mut + Wit)
        │                   │                   │
  Must FAIL (❌)       Must PASS (✅)      Must FAIL (❌)
        │                   │                   │
        └───────────────────┼───────────────────┘
                            ▼
              [ Fact Authority & Redaction ]
              (Cryptographic SHA, Digests,
               Zero-secret audit, Timestamps)
                            ▼
           [ Deterministic Verdict & Receipt ]
```

### Stage 1: Engineering Task Specification
- Input: `EngineeringTask`
- Fields:
  - `task_id`: Deterministic UUID/hash.
  - `target_repository`: Canonical Git URL.
  - `base_commit_sha`: Immutable 40-character hexadecimal Git commit SHA.
  - `problem_statement`: Issue description or behavioral specification.
  - `change_class`: Enum (`BUG_FIX`, `FEATURE`, `REFACTOR`, etc.).

### Stage 2: Independent Dual Generation (Builder vs. Verifier)
- **Builder Agent:**
  - Powered by `nvidia/Nemotron-3_5-Lightning`.
  - Produces a candidate unified diff (`CandidatePatch`).
  - Strict isolation: The Builder has NO access to sealed verifier test suites or protected verification files.
- **Independent Witness Formulation:**
  - An executable test or specification that targets the reported defect.
  - Authored independently from the candidate diff to avoid circular reasoning and developer confirmation bias.

### Stage 3: Two Clean Disposable Sandboxes (No Shared Workspace)
- Run inside Nebius Token Factory Sandboxes (`tag:astral/uv:python3.11-alpine` with `disposable: true`).
- **Sandbox A (BASE Verification):**
  - Clones repository at `base_commit_sha`.
  - Injects Independent Witness test.
  - Executes test suite.
  - **Required Invariant:** `BASE = FAIL` (exit code != 0, test failure captured).
  - *If BASE passes, the test does not witness the defect; verdict: REJECTED_NON_DISCRIMINATING.*
- **Sandbox B (CANDIDATE Verification):**
  - Fresh, independent disposable VM (zero workspace sharing, different operation UUID).
  - Clones repository at `base_commit_sha`.
  - Applies `CandidatePatch` unified diff.
  - Injects Independent Witness test.
  - Executes test suite.
  - **Required Invariant:** `CANDIDATE = PASS` (exit code == 0, test passes).

### Stage 4: Counterfactual Verification (Where Required)
- For behavioral bug fixes and safety-critical patches, execute Sandbox C:
  - Injects mutated patch or null hypothesis.
  - **Required Invariant:** `COUNTERFACTUAL = FAIL`.

### Stage 5: Deterministic Fact Authority & Receipt Generation
- Capture stdout/stderr with SHA-256 content digests.
- Check protected-surface manifest (ensuring patch did not mutate verification harness or CI configurations).
- Redact any environment secrets via regex and forbidden persistence rules.
- Produce an immutable, content-addressed `VerificationReceipt`:
  - `base_sha`: Exact commit SHA.
  - `candidate_diff_hash`: SHA-256 of patch.
  - `sandbox_alpha_id`: Operation UUID of BASE run.
  - `sandbox_beta_id`: Operation UUID of CANDIDATE run.
  - `base_exit_code`: Non-zero.
  - `candidate_exit_code`: 0.
  - `verdict`: `CAUSALLY_VERIFIED`.
  - `provenance`: `LIVE_NEBIUS`.

---

## 3. Grounded Platform Guarantees (No Unverified Claims)

This contract relies strictly on proven platform realities:
1. **VM Isolation:** Proven by `P-01.05` where `/root/run1_marker.txt` in Run 1 did not bleed into Run 2.
2. **Ephemeral Destruction:** Proven by `P-01.03` through `P-01.05` where `disposable: true` instances automatically terminated with zero running instances remaining.
3. **Cryptographic Source Matching:** Proven by `P-01.04` where container git tree hash `aa54850bf7ddcd222539d3e0b6fe5059cb1d693d` perfectly matched local canonical tree hash.
4. **Execution Speed:** Proven average duration of 4.4s–5.1s per sandbox clone-install-test cycle on `astral/uv:python3.11-alpine`.

---

## 4. Research-Only Historical Bug/Fix Shortlist (for Future P-23.08 Replay)

*Note: `ResetVault` remains Basebreak's PRIMARY deterministic killer demo. The candidate pairs below are research-only shortlist candidates for eventual supplementary historical replay in P-23.08. At P-01.07: strictly NO code importing, NO replay implementation, and NO claiming upstream patch was produced by Basebreak.*

### Candidate 1: `urllib3/urllib3` — Cookie Header Stripping on Cross-Origin Redirect
- **Repository:** `https://github.com/urllib3/urllib3`
- **Root License:** MIT (verified in `LICENSE.txt` at fix revision)
- **Buggy Base SHA:** `740380c59ca2a7c2dceca19e5dba99f6b7060e62` (immediate parent of fix commit; also tag 2.0.5 resolves to `d9f85a749488188c286cd50606d159874db94d5f`)
- **Fixed SHA:** `644124ecd0b6e417c527191f866daa05a5a2056d` (commit merging GHSA-v845-jxx5-vc9f; included in release tag 2.0.6 commit `262e3e332209ee93ff70e2b13502c8f20c105ac8`)
- **Exact Upstream Evidence:** GitHub Security Advisory GHSA-v845-jxx5-vc9f (CVE-2023-43804); upstream `CHANGES.rst` entry for 2.0.6 release; commit `644124ecd0b6e417c527191f866daa05a5a2056d`.
- **Concise Behavioral Defect:** In `urllib3.util.retry.Retry`, `DEFAULT_REMOVE_HEADERS_ON_REDIRECT` only included `Authorization`. `Cookie` request headers were inadvertently preserved when following cross-origin redirects, potentially leaking sensitive session tokens to untrusted domains.
- **Likely Independent Witness:** Focused unit test checking `Retry().remove_headers_on_redirect` contains `"cookie"`, and/or functional test in `test/with_dummyserver/test_poolmanager.py` sending cross-host redirect asserting `Cookie` header is absent in redirected target request.
- **Dependency / Runtime Footprint:** Pure Python, lightweight dependencies, fast install via `uv` in < 2 seconds.
- **Nebius Linux Sandbox Feasibility:** High. Fully functional in `tag:astral/uv:python3.11-alpine`.
- **Verdict on Suitability:** **SUITABLE** (clean, self-contained, high security relevance, deterministic `BASE=FAIL, CANDIDATE=PASS` invariant).

### Candidate 2: `psf/requests` — .netrc Credential Leak on URLs with Embedded Userinfo
- **Repository:** `https://github.com/psf/requests`
- **Root License:** Apache-2.0 (verified in `LICENSE` at fix revision)
- **Buggy Base SHA:** `7341690e842a23cf18ded0abd9229765fa88c4e2` (immediate parent of fix commit)
- **Fixed SHA:** `96ba401c1296ab1dda74a2365ef36d88f7d144ef` (commit "Only use hostname to do netrc lookup instead of netloc")
- **Exact Upstream Evidence:** CVE-2024-47081 / GitHub Security Advisory GHSA-9wx4-h78v-56pm; commit `96ba401c1296ab1dda74a2365ef36d88f7d144ef`; regression test in commit `5b4b64c3467fd7a3c03f91ee641aaa348b6bed3b`.
- **Concise Behavioral Defect:** In `requests.utils.get_netrc_auth`, host parsing extracted the machine name via `ri.netloc.split(":")[0]` instead of `ri.hostname`. When requests targeted URLs with embedded userinfo (e.g., `http://example.com:@evil.com/`), credentials stored in `.netrc` for `example.com` were incorrectly sent to `evil.com`.
- **Likely Independent Witness:** Self-contained unit test creating a temporary `.netrc` entry for `example.com`, invoking `requests.utils.get_netrc_auth("http://example.com:@evil.com/")`, asserting returned auth is `None` (on base: returns `("user", "pass")` -> FAIL; on fixed: returns `None` -> PASS).
- **Dependency / Runtime Footprint:** Pure Python, standard requests dependencies (`urllib3`, `certifi`, `idna`, `charset-normalizer`).
- **Nebius Linux Sandbox Feasibility:** High. Completely offline, zero network access required during witness run, executes in milliseconds in `tag:astral/uv:python3.11-alpine`.
- **Verdict on Suitability:** **SUITABLE** (pure local unit test, no daemon/dummy server required, fast execution, zero network flakiness).

### Candidate 3: `encode/httpx` — NO_PROXY IPv4, IPv6 and Localhost Parsing
- **Repository:** `https://github.com/encode/httpx`
- **Root License:** BSD-3-Clause (verified in `LICENSE.md` at fix revision)
- **Buggy Base SHA:** `7d7c4f15b8784e4a550d974139acfa64193b32c2` (immediate parent of fix commit)
- **Fixed SHA:** `15d09a3bbc20372cd87e48f17f7c9381c8220a0f` (commit "fix: NO_PROXY should support IPv4, IPv6 and localhost (#2659)")
- **Exact Upstream Evidence:** Pull Request #2659; commit `15d09a3bbc20372cd87e48f17f7c9381c8220a0f`; unit tests in `tests/test_utils.py`.
- **Concise Behavioral Defect:** In `httpx._utils.get_environment_proxies`, all `NO_PROXY` entries were formatted as wildcard domain patterns `all://*<hostname>`, which broke exact IP and localhost matching (e.g., `127.0.0.1` improperly mapped to `all://*127.0.0.1` rather than `all://127.0.0.1`).
- **Likely Independent Witness:** Unit test invoking `get_environment_proxies()` with `no_proxy="127.0.0.1"` asserting `mounts["all://127.0.0.1"] is None`.
- **Dependency / Runtime Footprint:** Pure Python (`httpcore`, `anyio`, `certifi`, `idna`, `sniffio`).
- **Nebius Linux Sandbox Feasibility:** High. Installs in < 2 seconds in `tag:astral/uv:python3.11-alpine`.
- **Verdict on Suitability:** **SUITABLE** (deterministic unit test, pure Python, zero network dependency during test run).

### Audited & Disqualified Candidate: `pallets/werkzeug` — Safe Join Directory Traversal Edge Case
- **Repository:** `https://github.com/pallets/werkzeug`
- **Root License:** BSD-3-Clause (verified in `LICENSE.txt` at fix revision)
- **Buggy Base SHA:** `50cfeebcb0727e18cc52ffbeb125f4a66551179b` (immediate parent of fix; release tag 3.0.5 is `9caf72ac060181a3171d91fd12279e071df430ca`)
- **Fixed SHA:** `87cc78a25f782f8c59fbde786840a00cf0d09b3d` (commit "catch special absolute path on Windows Python < 3.11", merged in 3.0.6 release `5eaefc3996aa5cc8c5237d8b82f1b89eed6ea624`)
- **Exact Upstream Evidence:** GitHub Security Advisory GHSA-f9vj-2wh5-fj8j; Werkzeug 3.0.6 release notes in `CHANGES.rst`.
- **Concise Behavioral Defect:** `safe_join` did not catch certain leading slash path combinations (e.g., `//b/c`) on Windows when running on Python < 3.11 because `ntpath.isabs` did not treat them as absolute paths.
- **Likely Independent Witness:** Direct functional test invoking `werkzeug.security.safe_join("a", "//b/c")` asserting `None` is returned.
- **Dependency / Runtime Footprint:** Pure Python.
- **Nebius Linux Sandbox Feasibility:** **Infeasible / Non-discriminating in Linux container**. The proven Nebius sandbox runs LinuxKit Alpine with Python 3.11 (`tag:astral/uv:python3.11-alpine`). On POSIX systems, `posixpath.isabs` already identifies leading slashes as absolute, meaning the test passes even on the buggy base revision on Linux. It requires Windows and Python < 3.11 to exhibit the failure.
- **Verdict on Suitability:** **UNSUITABLE**
- **Reason for Disqualification:** Fails the causal verification invariant `BASE=FAIL` inside the proven Nebius Linux sandbox environment; platform-dependent bug that cannot be reliably witnessed on Linux Python 3.11.

---

## 5. Phase P-01 Completion Status & Independent QA Gate

With:
1. `P-01.01`: Official API and model catalog discovery complete (independently VERIFIED / PASS);
2. `P-01.02`: Real Nemotron inference verified live (independently VERIFIED / PASS);
3. `P-01.03`: Real sandbox beta access and execution primitives verified live (`EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE`);
4. `P-01.04`: Real repository materialization and cryptographic source identity verified live (`EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE`);
5. `P-01.05`: Two clean independent sandbox executions without mutable workspace sharing verified live (`EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE`);
6. `P-01.06`: Feasibility GO decision and architecture v0 frozen (`EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE`);
7. `P-01.07`: Judge-visible causal vertical-slice contract frozen (`EXECUTOR_COMPLETED / INDEPENDENT_QA_CANDIDATE`);

Phase `P-01` (Live Platform Discovery & Feasibility Proof) has proven all required real model, real sandbox, and two-clean-environment spine capabilities at executor level. Phase status is submitted as `CANDIDATE_FOR_INDEPENDENT_QA_CLOSURE` and remains open until independent QA verification is completed.
