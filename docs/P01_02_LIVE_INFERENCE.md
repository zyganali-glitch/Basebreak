# P-01.02 — Live Token Factory Nemotron Inference Evidence

## Task Identification
- **Exact Task:** `P-01.02 — Execute first real Token Factory Nemotron inference call with sanitized minimal prompt`
- **Execution Timestamp (UTC):** `2026-09-24T08:38:27.536481+00:00` to `2026-09-24T08:38:28.254048+00:00` (Local time: `11:38:27` to `11:38:28+03:00`)
- **Elapsed Duration:** `0.717s`
- **Starting Canonical Remote SHA:** `c285379b3a453767db6434786c26ff0c6b6ec34b`
- **Evidence Provenance:** `LIVE_NEBIUS`

---

## Model Selection & Discovery Facts
- **Selected Model ID:** `nvidia/Nemotron-3_5-Lightning`
- **Provider Family:** NVIDIA Nemotron
- **Model Discovery Source:**
  - Account-authenticated discovery via `GET https://api.tokenfactory.nebius.com/v1/models` (confirmed live and available with `owned_by: system`).
  - Official documentation & cookbook verification: `https://github.com/nebius/token-factory-cookbook/tree/main/models/nemotron`.
- **Model Architecture/Characteristics:** 30B total / 3B active MoE architecture, serverless/token-based pricing, 1M context support.
- **API Base Host:** `api.tokenfactory.nebius.com`
- **API Endpoint:** `/v1/chat/completions`
- **Region:** `Global` (public serverless endpoint per official `public-serverless.md` specification).

---

## Sanitized Request Facts
- **Request Payload SHA-256:** `81c829a58db0a69225c2ddef827a577e3abb9449b6a69f58c8626af5aab5a187`
- **Digest Canonicalization & Reproducibility:**
  - Computed over the exact UTF-8 bytes of `json.dumps(payload, indent=2).encode('utf-8')` for the committed payload below.
  - Excludes transport-level headers (`Authorization`, `User-Agent`).
  - Independently recomputed and verified: `MATCH = True`.
- **Payload Structure:**
```json
{
  "model": "nvidia/Nemotron-3_5-Lightning",
  "messages": [
    {
      "role": "system",
      "content": "Return only the exact text BASEBREAK_LIVE_OK."
    },
    {
      "role": "user",
      "content": "Basebreak live connectivity check. Return only BASEBREAK_LIVE_OK."
    }
  ],
  "max_tokens": 16,
  "temperature": 0.0
}
```
- **Content Boundary:** No repository files, no secrets, no user personal data, and no hidden verifier assets.

---

## Runtime Execution & Response Facts
- **HTTP Status Code:** `200 OK`
- **Provider Request ID (`x-request-id`):** `85bd81c7e9d94a8be4d987cea57e6ba6`
- **Returned Model ID:** `nvidia/Nemotron-3_5-Lightning`
- **Response Content:**
```
Here's a thinking process:

1.  **Analyze User Input:**
```
- **Finish Reason:** `length` (promptly capped at `max_tokens: 16`).
- **Semantic Note on Model Response:** The exact requested text `BASEBREAK_LIVE_OK` was not returned because `nvidia/Nemotron-3_5-Lightning` emitted a reasoning/thinking preface that exhausted the constrained `16` token limit. This does not invalidate the P-01.02 connectivity proof, which requires proving real authenticated inference execution against NVIDIA Nemotron on Token Factory, not autonomous prompt compliance.
- **Token Usage:**
  - `prompt_tokens`: 45
  - `completion_tokens`: 16
  - `total_tokens`: 61
  - `reasoning_tokens`: 16
  - `prompt_cache_hit_tokens`: 0
  - `prompt_cache_miss_tokens`: 45
- **Response Digest Status & Integrity:**
  - The previously recorded response digest (`8658e0b3cf77c475d002ed6fdfe9c472e5db526047510f8d2b9d7dd83ed65c1c`) was computed over raw socket wire bytes from the HTTP response stream prior to JSON decoding. Because those raw wire bytes are not committed to git, this digest is formally classified as:
    `NOT_INDEPENDENTLY_REPRODUCIBLE_FROM_COMMITTED_RECORD`
  - In accordance with Defect 2 Repair Option B, it is not presented as independently verifiable evidence.
  - A reproducible post-hoc evidence record digest has been computed over the committed sanitized response fields:
    - **POST-HOC EVIDENCE RECORD DIGEST (SHA-256):** `eef88ed7209b444c779b3fdf314dd0870f6f57da633ff596474b0665fa01f866`
    - Canonicalization: `json.dumps(record, indent=2, sort_keys=True).encode('utf-8')` over fields `{"finish_reason": "length", "http_status": 200, "model": "nvidia/Nemotron-3_5-Lightning", "provider_request_id": "85bd81c7e9d94a8be4d987cea57e6ba6", "response_content": "Here's a thinking process:\n\n1.  **Analyze User Input:\n  ", "usage": {"completion_tokens": 16, "prompt_tokens": 45, "reasoning_tokens": 16, "total_tokens": 61}}`.

---

## Balance Observations & Monotonic Chronology
- **PRE_CALL_BALANCE_OBSERVATION:** `$25.00` promotional balance (Operator verified in Token Factory console at `2026-09-24T11:38:09+03:00`).
- **LIVE_INFERENCE_EXECUTION:** Completed between `11:38:27` and `11:38:28+03:00` (`2026-09-24T08:38:27.536481+00:00` to `2026-09-24T08:38:28.254048+00:00` UTC).
- **LATE_POST_CALL_BALANCE_OBSERVATION:** `$25.00` promotional balance (Operator verified via Token Factory web console `Settings -> Billing -> Usage` at `2026-09-24T12:01:48+03:00`).
  - Observed after inference during evidence repair.
  - Trial credit: `$1.00` (untouched, 24 days left).
  - Billing status: Active.
- **Chronology Monotonicity:** Strictly verified: `11:38:09 < 11:38:28 < 12:01:48`.
- **Chronology Audit Note:** The initial document recorded a post-call timestamp of `2026-09-24T11:37:00+03:00` derived from a desktop screenshot captured prior to the call. That timestamp was chronologically invalid (predating both PRE and call) and has been formally rejected and replaced with the late post-call observation at `2026-09-24T12:01:48+03:00`.
- **Cost Evidence & Balance Delta:**
  - Call cost from provider evidence: `NOT_OBSERVABLE / NOT_AVAILABLE` (Token Factory two-decimal balance view does not show sub-cent resolution; unverified micro-cent approximations are excluded).
  - `DISPLAYED_DELTA = NOT_OBSERVABLE_AT_UI_PRECISION` (Account balance remains displayed as `$25.00`).
  - Zero cost is NOT claimed.
  - Personal spend: `$0.00` (Zero-Cost Law preserved).
  - Safety floor: `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` satisfied (`$25.00 > $5.00`).

---

## Provider-Side Usage Corroboration (`LIVE_ACCOUNT`)
- **Corroborating Surface:** Token Factory Web Console `Settings -> Billing -> Usage` (`Organization: Basebreak-8pb`).
- **Observation Timestamp:** `2026-09-24T12:01:48+03:00` (screenshot `media_1790240505740.png`).
- **Filter Settings:** Date range `25.08.2026 — 24.09.2026`, Table view, Format `Rounded numbers`.
- **Observed Provider Content:**
  - Display: `No usage`
  - Text: `You did not use Nebius AI resources in the selected period.`
  - Billing: `Active`
  - Trial credits: `$1.00 / 24 days left`
  - Account balance: `$25.00`
- **Factual Corroboration Finding:** The provider console Usage view at this observation timestamp does not expose individual sub-cent request-level line items for public serverless inference. Stronger corroboration is not invented. Provider identity and runtime execution remain deterministically anchored by the authenticated HTTP 200 response, provider request ID `85bd81c7e9d94a8be4d987cea57e6ba6`, and returned model identity `nvidia/Nemotron-3_5-Lightning`.

---

## Security & Provenance Attestations
- **Secret Exclusion Statement:** Neither `NEBIUS_API_KEY` nor its prefix, suffix, length, hashes, nor Authorization headers are committed to git or stored in repository files. The credential was read exclusively from the Windows User environment in memory and discarded immediately.
- **No-Mock / No-Fallback Statement:** No mock, simulation, synthetic adapter, or non-NVIDIA fallback provider was used. Real, authenticated HTTPS traffic was sent to `api.tokenfactory.nebius.com` and answered by the NVIDIA Nemotron inference infrastructure.
- **Evidence Provenance Separation:**
  - `LIVE_NEBIUS`: Authenticated live inference request and response over the wire (`08:38:27–08:38:28 UTC`).
  - `LIVE_ACCOUNT`: Provider-side Token Factory UI observations (Balance and Usage tabs observed at `11:38:09` and `12:01:48`).
  - `OFFICIAL_DOC`: Official Nebius Token Factory documentation and cookbooks.

---

## Boundaries & NOT_RUN Scope
- **NOT_RUN:**
  - Second live model inference — explicitly FORBIDDEN and NOT RUN.
  - `P-01.03` (Token Factory Sandbox workflow) — explicitly NOT RUN.
  - `P-04.04` (Protected-surface manifest and diff checks) — explicitly NOT RUN.
  - `P-05` (Permanent provider adapter layer) — explicitly NOT RUN.
  - Batch inference, retry loops, and multiple comparative models — explicitly NOT RUN.
