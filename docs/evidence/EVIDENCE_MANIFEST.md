# Basebreak Canonical Evidence Manifest

This immutable manifest binds all deployment identities, repository commits, cryptographic digests, provider telemetry, and runtime facts for the competition-defining verification proof.

Competition: **Nebius x NVIDIA Global AI Hackathon**  
Track: **Coding and Agentic Engineering**  
Core Claim: **"Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green."**

---

## 1. Source Commit & Deployment Architecture Binding

> [!IMPORTANT]
> **Source Commit Distinction**: The Basebreak application implementation commit and the target repository scenario commit (`ResetVault`) are distinct and must never be conflated. The cryptographic receipt and verifier proof bind the target scenario source commit (`80b43b84...`), which represents the base repository under test.

| Boundary | Commit / Identity | Provenance / Role |
|---|---|---|
| **Basebreak Implementation (Head)** | `a24901b70c1f59724373fcdb595779b52e0f7740` | Application codebase and verifier implementation |
| **Fresh Live Run Execution SHA (P-29.03)** | `a24901b70c1f59724373fcdb595779b52e0f7740` | Exact commit under which the fresh live run was executed |
| **Historical 10th Run Execution SHA** | `78207c28772e090fc1e36890d98052c0393f7bfe` | Exact commit under which the historical tenth run was executed |
| **Deployed Oracle Bridge Code** | `a24901b70c1f59724373fcdb595779b52e0f7740` | Isolated Oracle Free Tier host (`basebreak-verifier`) loopback bridge |
| **Deployed Cloudflare Worker** | Version `5ac04fce-9572-41b9-9286-8ccb3a0aba24` | Cloudflare Workers Free Tier (`https://basebreak.zyganali.workers.dev`) |
| **Target Scenario Source Commit** | `80b43b84014fa61b941c7ebcd87836a56dcd7c92` | Immutable base tree of the `ResetVault` scenario being verified |
| **Frozen Contract Digest** | `93eeeb2cc7eb02a988da3c8a8543ad40b4816608c1452d048ff62ee93702f812` | Pre-execution frozen contract specifying `REQ-RESET-001` |

---

## 2. Canonical Reference Run Facts (`run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9`)

- **Run Identifier**: `run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9`
- **Execution Timestamp**: `2026-10-22T17:09:59.215580+00:00`
- **Evidence Provenance**: `LIVE_NEBIUS`
- **Overall Causal Verdict**: `VERIFIED` (Causal Triplet: BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL)
- **Grant Token**: `grant_c5b6ab9e-1cff-47f2-8fbe-7a5d5e14ddc8` (Single-use operator grant)
- **Idempotency Key**: `268728c6-e8f1-492d-8c8c-24edbc33141f`

### AI Model Generation Telemetry
- **Model Identifier**: `nvidia/Nemotron-3_5-Lightning`
- **Provider Request ID**: `chatcmpl-f5c5e28a90ae7b935630d6f9fe1683ae`
- **Model Call Count**: 1 call (no repair loops needed; passed AST syntax & class preservation checks)
- **Token Accounting**:
  - Prompt Tokens: 1,123
  - Completion Tokens: 693
  - Total Tokens: 1,816
  - Accounting Status: `model-usage:complete`
- **Candidate Origin**: `MODEL_GENERATED_NEBIUS`
- **Candidate Response Digest (SHA-256)**: `3153602c93d3dcbfe1802532bcb8ca731af5790b43109b840a3380db1906af7c`
- **Candidate Proposal Digest (SHA-256)**: `0d681d139cd5e71e82cb6d39a42223175fb3ee9556fdea5a30ab95633750da02`
- **Candidate Patch Digest (SHA-256)**: `5f3ac8d9dcef8b046c58f58f3d2c44a340b13191235637169b781cf54abe592e`
- **Candidate Tree Digest (Git Tree)**: `6c4f46cbb51119d8e93534a1e2ee922498ee450b`

### Differential Three-World Execution Facts

| World | Sandbox ID | Exit Code | Outcome | Execution Tree Digest | Diagnostic |
|---|---|---|---|---|---|
| **BASE** | `sbx-7da8ae8d855b45f1` | 1 | `FAIL` | `824fa2c69a222cc2204950bb6eb974abfd2abb7d` | `TEST` (Token replay assertion failed) |
| **CANDIDATE** | `sbx-c1057ebc4528465c` | 0 | `PASS` | `6c4f46cbb51119d8e93534a1e2ee922498ee450b` | `PASS` (1 sealed witness test passed in 0.04s) |
| **COUNTERFACTUAL** | `sbx-de5d5ca163034441` | 1 | `FAIL` | `824fa2c69a222cc2204950bb6eb974abfd2abb7d` | `TEST` (Delta reverted to base tree; replay failed) |

### Sealed Witness Information
- **Witness ID**: `wit-reset-vault-live-001`
- **Requirement Bound**: `REQ-RESET-001`
- **Execution Command**: `python -m pytest tests/fixtures/reset_vault/witness/test_single_use_witness.py -q`
- **Witness Digest (SHA-256)**: `a060f395818ad9b698de914d60f7a83763da088eb1d5f3a57ddd29df2fe2ff4a`
- **Witness Lock Digest (SHA-256)**: `3ed5aae3f757dd96ecca1c29eadc6ae04ba522359efee46d600ab1f06fff49a5`

### Cryptographic Proof & Receipt
- **Receipt Digest (SHA-256)**: `a7857896f3f701264bed995f3b0a70115a9ab007a84d5deece3ae8bcef876500`
- **Proof Digest (SHA-256)**: `e738d961e200f1df07af046d6a0adc56b7284b13b469249359ae0120e9a6cd2a`

---

## 3. Fresh Live Run Facts (`run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f`)

- **Run Identifier**: `run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f`
- **Execution Timestamp**: `2026-10-22T19:38:42.489554+00:00`
- **Evidence Provenance**: `LIVE_NEBIUS`
- **Overall Causal Verdict**: `VERIFIED` (Causal Triplet: BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL)
- **Grant Token**: `grant_f9dae5b3-c15b-4835-abfa-39c4a8cf82e9` (Single-use operator grant)
- **Idempotency Key**: Generated fresh UUID

### AI Model Generation Telemetry
- **Model Identifier**: `nvidia/Nemotron-3_5-Lightning`
- **Provider Request ID**: `chatcmpl-6f406c073cb413917bb3c4dea558d380`
- **Model Call Count**: 1 call (passed AST syntax & class preservation checks on turn 1)
- **Candidate Origin**: `MODEL_GENERATED_NEBIUS`
- **Candidate Response Digest (SHA-256)**: `3153602c93d3dcbfe1802532bcb8ca731af5790b43109b840a3380db1906af7c`
- **Candidate Proposal Digest (SHA-256)**: `0d681d139cd5e71e82cb6d39a42223175fb3ee9556fdea5a30ab95633750da02`
- **Candidate Patch Digest (SHA-256)**: `5f3ac8d9dcef8b046c58f58f3d2c44a340b13191235637169b781cf54abe592e`
- **Candidate Tree Digest (Git Tree)**: `6c4f46cbb51119d8e93534a1e2ee922498ee450b`

### Differential Three-World Execution Facts

| World | Sandbox ID | Exit Code | Outcome | Execution Tree Digest | Diagnostic |
|---|---|---|---|---|---|
| **BASE** | `sbx-c9e5c0e476fa4466` | 1 | `FAIL` | `824fa2c69a222cc2204950bb6eb974abfd2abb7d` | `TEST` (Token replay assertion failed) |
| **CANDIDATE** | `sbx-cd870e01d6d94bca` | 0 | `PASS` | `6c4f46cbb51119d8e93534a1e2ee922498ee450b` | `PASS` (1 sealed witness test passed in 0.04s) |
| **COUNTERFACTUAL** | `sbx-90d40f25758244d0` | 1 | `FAIL` | `824fa2c69a222cc2204950bb6eb974abfd2abb7d` | `TEST` (Delta reverted to base tree; replay failed) |

### Sealed Witness Information
- **Witness ID**: `wit-reset-vault-live-001`
- **Requirement Bound**: `REQ-RESET-001`
- **Execution Command**: `python -m pytest tests/fixtures/reset_vault/witness/test_single_use_witness.py -q`
- **Witness Digest (SHA-256)**: `1b2bdd3a42857dd1d22e1b3aec02a4594326c74dde5cf848fb883a6c7f3bcaeb`
- **Witness Lock Digest (SHA-256)**: `e27b1b160b206fb528bc25657793c4bd4978c7e8d9b9216803d997988ab8e3f1`

### Nebius Sandboxes Provider Operations (11 recorded)
- `01a1651b-c1b9-774c-a890-7f433337d28c`
- `01a1651c-a733-7638-a3e6-e53524928076`
- `01a1651c-af4f-733f-a26e-b5ab869495ab`
- `01a1651d-4bb3-72cc-be14-ef8b3ea05f58`
- `01a1651d-7594-7664-bf5e-3ee9146bdece`
- `01a1651d-876c-7350-886f-ef40cdc5249a`
- `01a1651d-9c43-7678-923d-a9afb9403d3c`
- `01a1651e-2f38-77bd-b2b9-e9a8ba3124d7`
- `01a1651e-6a0f-7058-9e80-f2a44f5bde3f`
- `01a1651e-ea00-7708-bb4b-e80369a279b9`
- `01a1651e-fbab-7666-9635-528786fdee8e`

### Cryptographic Proof & Receipt
- **Receipt Digest (SHA-256)**: `e2e833fd3aa9d69bdcbaad0805fd38167c680cb2f60a16209c27a80123a43708`
- **Proof Digest (SHA-256)**: `def59353ba1315979dead2544590b199ee66f966b479abf6b3496edb39e143b4`

---

## 4. Cryptographic Proof & Authority

- **Verifier Pinned Authority**:
  - Modulus SHA-256: `a13605cbf0b074300f56ee1cca01d53ef8bd9b7b998dca7c864502399a3917b2`
  - Public Exponent: `65537`
  - Signature Scheme: Custom Raw RSA-2048 Modular Exponentiation over double-SHA256 digest (`recovered_message == expected_message`).

### Public URLs
- **Canonical Reference Receipt Endpoint**:
  `https://basebreak.zyganali.workers.dev/v1/runs/run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9/receipt`
- **Canonical Reference Judge Route**:
  `https://basebreak.zyganali.workers.dev/judge/run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9`
- **Fresh Live Run Receipt Endpoint**:
  `https://basebreak.zyganali.workers.dev/v1/runs/run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f/receipt`
- **Fresh Live Run Judge Route**:
  `https://basebreak.zyganali.workers.dev/judge/run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f`

---

## 5. Security & Gate Status
- **Current Live Gate Status**: All three live gates safely shut down (`live_enabled=false`, `runtime_live_enabled=false`, `durable_live_enabled=false`).
- **In-Flight Concurrency**: Confirmed `0`.
- **Billing Safety**: Target personal spend remains `$0.00`; promotional balance safety floor `$5.00` strictly preserved.
- **Fail-Closed Gate Verification**: Anonymous public `POST /v1/runs` returns `403 BLOCKED` with `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`.

---

## 6. External Grounding & Tavily Evidence Binding (P-16.05)

- **Target Scenario**: `CVE-2024-21626` (Container escape file descriptor leak in runc)
- **Materiality Evaluation**: `GroundingMateriality.REQUIRED` (`GroundingCategory.CVE_SECURITY_ADVISORY`)
- **Integration Proof Document**: `docs/evidence/P16_05_TAVILY_GROUNDING_INTEGRATION.md`
- **Committed Evidence Packet**: `docs/evidence/p16_05_live_tavily_evidence_packet/tavily_cve_grounding_packet.json`
- **Executed Live Provider Event**:
  - Exactly one authorized real Tavily request executed under operator authorization and zero-cost confirmation (`search_depth='basic'`, `max_results=3`).
  - **Provider Request ID**: `cbb8a550-d334-4727-a715-1086799a73f9`
  - **Observation Timestamp (UTC)**: `2026-10-23T08:03:20.461092+00:00`
  - **Contract Digest**: `b882f0eac1e2bfcb3790fe5c80cf824bc6b1a8d7f6d97b0030d08d802ee1c8d9`
  - **Response Digest**: `e7727082b8735a7adc806398037b2fd3e281c0b04f8c37e11081bd0cdb66067d`
  - **Binding Digest**: `dff4c8589a24216329f6a7902d8dd3a0ac5c5ea22ddaeb5eb2b549807aef03cf`
  - **Returned Source URLs**:
    1. `https://github.com/yandex-cloud/docs/blob/master/en/_includes/security/security-bulletins/cve-2024-21626.md`
    2. `https://github.com/advisories/GHSA-xr7r-f8xq-vfvv`
    3. `https://security.snyk.io/vuln/SNYK-ALPINE324-RUNC-17303732`
  - **Provider-Observation Provenance**: `LOCAL_EXECUTION`
  - **Candidate Behavior**: `NOT_RUN` (no candidate witness executed)
  - **Grounding Firewall Decision**: `INSUFFICIENT_GROUNDING` / `BLOCKED` (fails closed on unverified temporal freshness and unsupported live observation boundary; external claims never certify code behavior)
  - **Credits Consumed**: `UNKNOWN` (omitted from provider API response payload; not fabricated)
  - **Zero Secrets**: verified clean of credentials or tokens.
- **Historical Preflight**: Previously observed missing-key status (`MISSING_KEY_BLOCKED`) retained as preflight history prior to operator key configuration.
- **Task Status Truth**: `LIVE_EXECUTED / INDEPENDENT_QA_PENDING` (held pending independent auditor QA).

---

## 7. Submission Preparation Package (P-30)

- **Status**: `PREPARATION_COMPLETE / SUBMISSION_ASSETS_FROZEN`
- **Execution Truth**: Human-led recording boundary strictly preserved: physical video recording, voiceover audio generation, screenshots, YouTube upload, and Devpost submission remain human-led operator tasks (NOT_RUN until captured).
- **Timed Storyboard (< 180s)**: `docs/submission/P30_STORYBOARD.md` (2:40 / 160s total duration)
- **Screen Recording Guide**: `docs/submission/P30_SCREEN_RECORDING_GUIDE.md` (Exact URLs, clicks, scroll actions)
- **English Narration Script**: `docs/submission/P30_NARRATION_SCRIPT.md` (360 words, scene-by-scene)
- **Accurate Subtitles (.srt)**: `docs/submission/basebreak_demo_subtitles.srt` (Full SubRip timecodes, ends at 02:39.5)
- **Screenshot & Asset Manifest**: `docs/submission/P30_SCREENSHOT_MANIFEST.md` (8 assets, source URLs, provenance)
- **Architecture Visual**: `docs/submission/P30_ARCHITECTURE_VISUAL.md` (Accurate verified components)
- **Devpost Story & 4 Criteria Mapping**: `docs/submission/P30_DEVPOST_SUBMISSION.md` (25% each criteria)
- **Video Safety Checklist**: `docs/submission/P30_VIDEO_SAFETY_CHECKLIST.md` (Credential, claim, evidence audits)
- **Operator Recording Checklist (TR)**: `docs/submission/P30_OPERATOR_RECORDING_CHECKLIST_TR.md` (Turkish step-by-step guidance)

