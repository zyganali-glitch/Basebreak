# P-01.02 — Live Token Factory Nemotron Inference Evidence

## Task Identification
- **Exact Task:** `P-01.02 — Execute first real Token Factory Nemotron inference call with sanitized minimal prompt`
- **Document Role:** Live evidence record binding both the original Builder-executed API inference call (`RECORDED_LIVE`) and the independent operator manual Token Factory Playground reproduction (`LIVE_NEBIUS`).
- **Starting Canonical Remote SHA:** `c285379b3a453767db6434786c26ff0c6b6ec34b`
- **Evidence Provenance Separation:**
  - `RECORDED_LIVE`: Original Builder-executed API inference call (`2026-09-24T08:38:27.536481+00:00` to `2026-09-24T08:38:28.254048+00:00` UTC). Preserved as candidate evidence.
  - `LIVE_NEBIUS`: Independent operator manual reproduction executed directly in the Token Factory web Playground UI (`2026-09-24T12:33:40+03:00` local).
  - `LIVE_ACCOUNT`: Provider-side Token Factory UI observations (Balance confirmed at `$25.00` and Usage tab checked).
  - `OFFICIAL_DOC`: Official Nebius Token Factory documentation and cookbooks.

---

## Model Selection & Discovery Facts
- **Selected Model ID:** `nvidia/Nemotron-3_5-Lightning`
- **Provider Family:** NVIDIA Nemotron
- **Model Discovery Source:**
  - Account-authenticated discovery via `GET https://api.tokenfactory.nebius.com/v1/models` (confirmed live and available with `owned_by: system`).
  - Web UI Playground availability confirmation at `https://tokenfactory.nebius.com/playground?models=nvidia/Nemotron-3_5-Lightning`.
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

## Independent Operator Manual Playground Reproduction (`LIVE_NEBIUS`)
- **Execution Role & Governance Authority:** Independent operator manual reproduction in the official Nebius Token Factory web Playground.
  - *Governance Invariant:* **Builder cannot certify itself.** Because the initial API execution was conducted by the Builder and was not corroborated by the provider Usage view, an independent human-operator reproduction was executed directly in the provider web UI to satisfy the live-connectivity requirement.
- **Builder Invariant:** The Builder did NOT execute this call, did not invoke `/v1/chat/completions`, and did not automate or script the reproduction.
- **Observation Timestamp:** `2026-09-24T12:33:40+03:00` (Local time; browser session at `12:32–12:34`).
- **Provider Surface:** Token Factory Web Console Playground:
  `https://tokenfactory.nebius.com/playground?models=nvidia/Nemotron-3_5-Lightning`
- **Project & Organization:** Project `default-project` / Organization `Basebreak-8pb` (Billing Active).
- **Selected Model Identity in Provider UI:** `nvidia/Nemotron-3_5-Lightning` (UI display: `NVIDIA Nemotron-3.5-Lightning`).
- **Execution Settings:** Minimal/default safe parameters (`Temperature: 0.6`, `Response format: Text`).
- **Submitted User Prompt:**
```text
Return only BASEBREAK_QA_OK.
```
- **Observed Provider Response:**
  - The provider model generated an internal reasoning/thought sequence:
```text
Here's a thinking process:
1. Analyze User Input:
* User says: "Return only BASEBREAK_QA_OK."
* This looks like a specific keyword/phrase request.
* The instruction is very strict: return *only* that exact string.
2. Identify the Core Task:
* Output exactly: BASEBREAK_QA_OK
* No additional text, no reasoning, no formatting, just that string.
3. Check Constraints:
* "Return only BASEBREAK_QA_OK."
* Must adhere strictly.
4. Formulate Output:
5. Final Verification:
* Does it match exactly? Yes.
* Any extra characters? No.
* Ready.
```
  - Emitted final output text:
```text
BASEBREAK_QA_OK
```
- **Evidence Artifacts:**
  - `media_1790242384044.png`: Operator configuration of the Playground session showing model selection and initial state.
  - `media_1790242449780.png`: Operator execution and response generation in Token Factory Playground.
  - `media_1790242458649.png`: Operator full-screen capture showing model response and prompt in Token Factory Playground.
  - `media_1790242510670.png`: Operator confirmation of account balance ($25.00), trial credit ($1.00 untouched), and active billing status.
- **Sanitization & Secret Audit:** The operator provider UI session exposed no API keys, Authorization headers, credit card numbers, or unrelated personal identifiers.
- **Corroboration Verdict:** Independently confirms real live connectivity and response generation from `nvidia/Nemotron-3_5-Lightning` on Token Factory in a human-observed session.

---

## Original Builder API Execution Record (`RECORDED_LIVE`)
- **Record Role:** Historical candidate evidence from the initial Builder API execution. Preserved as `RECORDED_LIVE`.
- **Execution Timestamp (UTC):** `2026-09-24T08:38:27.536481+00:00` to `2026-09-24T08:38:28.254048+00:00` (Local time: `11:38:27` to `11:38:28+03:00`).
- **Elapsed Duration:** `0.717s`.
- **HTTP Status Code:** `200 OK`.
- **Provider Request ID (`x-request-id`):** `85bd81c7e9d94a8be4d987cea57e6ba6`.
- **Returned Model ID:** `nvidia/Nemotron-3_5-Lightning`.
- **Response Content:**
```
Here's a thinking process:

1.  **Analyze User Input:**
```
- **Finish Reason:** `length` (promptly capped at `max_tokens: 16`).
- **Semantic Note on Model Response:** The exact requested text `BASEBREAK_LIVE_OK` was not returned because `nvidia/Nemotron-3_5-Lightning` emitted a reasoning/thinking preface that exhausted the constrained `16` token limit.
- **Token Usage:**
  - `prompt_tokens`: 45
  - `completion_tokens`: 16
  - `total_tokens`: 61
  - `reasoning_tokens`: 16
  - `prompt_cache_hit_tokens`: 0
  - `prompt_cache_miss_tokens`: 45
- **Classification & Limits:** `RECORDED_LIVE` candidate evidence. In accordance with Basebreak causal invariants, Builder-recorded HTTP 200, request ID, and model fields alone cannot self-certify the Builder's live execution without independent verification.
- **Response Digest Status & Integrity:**
  - The original socket digest (`8658e0b3cf77c475d002ed6fdfe9c472e5db526047510f8d2b9d7dd83ed65c1c`) was computed over raw socket wire bytes from the HTTP response stream prior to JSON decoding. Because those raw wire bytes are not committed to git, this digest is formally classified as:
    `NOT_INDEPENDENTLY_REPRODUCIBLE_FROM_COMMITTED_RECORD`
  - In accordance with the response digest truth repair requirement, the post-hoc evidence record digest has been **REMOVED ENTIRELY** due to an internal byte-sequence mismatch between displayed content and post-hoc digest hashing. It is NOT replaced with any pseudo-authoritative digest.
  - The independently reproducible REQUEST digest (`81c829a58db0a69225c2ddef827a577e3abb9449b6a69f58c8626af5aab5a187`) remains intact and verified against the committed payload.

---

## Balance Observations & Monotonic Chronology (`LIVE_ACCOUNT`)
- **PRE_CALL_BALANCE_OBSERVATION:** `$25.00` promotional balance (Operator verified in Token Factory console at `2026-09-24T11:38:09+03:00`).
- **BUILDER_API_EXECUTION:** Completed between `11:38:27` and `11:38:28+03:00` (`2026-09-24T08:38:27.536481+00:00` to `2026-09-24T08:38:28.254048+00:00` UTC).
- **LATE_POST_CALL_BALANCE_OBSERVATION:** `$25.00` promotional balance (Operator verified via Token Factory web console `Settings -> Billing -> Usage` at `2026-09-24T12:01:48+03:00`).
  - Observed after inference during evidence repair.
  - Trial credit: `$1.00` (untouched, 24 days left).
  - Billing status: Active.
- **OPERATOR_PLAYGROUND_REPRODUCTION:** Completed at `2026-09-24T12:33:40+03:00`.
- **POST_REPRODUCTION_BALANCE_OBSERVATION:** `$25.00` account balance (Operator verified via Token Factory web console `Settings -> Billing -> Prices` at `2026-09-24T12:34:00+03:00`, screenshot `media_1790242510670.png`).
  - Trial credit: `$1.00` (untouched, 24 days left).
  - Billing status: Active.
- **Chronology Monotonicity:** Strictly verified: `11:38:09 < 11:38:28 < 12:01:48 < 12:33:40 < 12:34:00`.
- **Cost Evidence & Balance Delta:**
  - Call cost from provider evidence: `NOT_OBSERVABLE / NOT_AVAILABLE` (Token Factory two-decimal balance view does not show sub-cent resolution; unverified micro-cent approximations are excluded).
  - `DISPLAYED_DELTA = NOT_OBSERVABLE_AT_UI_PRECISION` (Account balance remains displayed as `$25.00`).
  - Zero cost is NOT claimed.
  - Personal spend: `$0.00` (Zero-Cost Law preserved).
  - Safety floor: `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` satisfied (`$25.00 > $5.00`).

---

## Provider-Side Usage UI Observation (`LIVE_ACCOUNT`)
- **Observed Surface:** Token Factory Web Console `Settings -> Billing -> Usage` (`Organization: Basebreak-8pb`).
- **Observation Timestamp:** `2026-09-24T12:01:48+03:00` (screenshot `media_1790240505740.png`).
- **Filter Settings:** Date range `25.08.2026 — 24.09.2026`, Table view, Format `Rounded numbers`.
- **Observed Provider Content:**
  - Display: `No usage`
  - Text: `You did not use Nebius AI resources in the selected period.`
  - Billing: `Active`
  - Trial credits: `$1.00 / 24 days left`
  - Account balance: `$25.00`
- **Factual Finding & Semantics:**
  - A `LIVE_ACCOUNT` observation was performed on the provider Usage UI.
  - The Usage UI showed no attributable usage entry at that observation time (`No usage`).
  - Therefore, the Usage UI provided **NO provider-side corroboration** for the original API request at that observation time.
  - This section is explicitly NOT titled or presented as provider corroboration.
  - Builder-recorded HTTP 200, provider request ID, and returned model identity are NOT claimed to be independently deterministic provider proof on their own; they are `RECORDED_LIVE` facts from the original execution record.
  - Independent provider-side corroboration is established by the operator manual Playground reproduction (`LIVE_NEBIUS`) detailed above.

---

## Security & Provenance Attestations
- **Secret Exclusion Statement:** Neither `NEBIUS_API_KEY` nor its prefix, suffix, length, hashes, nor Authorization headers are committed to git or stored in repository files. The credential used for the initial API call was read exclusively from the Windows User environment in memory and discarded immediately. The operator manual reproduction required no secret exposure in repository files or conversation.
- **No-Mock / No-Fallback Statement:** No mock, simulation, synthetic adapter, or non-NVIDIA fallback provider was used. Real, authenticated HTTPS traffic was sent to `api.tokenfactory.nebius.com` (Builder call) and the official Token Factory Playground UI (operator reproduction), answered by the NVIDIA Nemotron inference infrastructure.
- **Evidence Provenance Separation:**
  - `LIVE_NEBIUS`: Operator manual Token Factory Playground reproduction (`12:33:40+03:00`).
  - `RECORDED_LIVE`: Builder API inference record (`08:38:27–08:38:28 UTC`).
  - `LIVE_ACCOUNT`: Provider-side Token Factory UI observations (Balance and Usage tabs observed at `11:38:09`, `12:01:48`, and `12:34:00`).
  - `OFFICIAL_DOC`: Official Nebius Token Factory documentation and cookbooks.

---

## Boundaries & NOT_RUN Scope
- **NOT_RUN:**
  - Builder repetition of inference — explicitly FORBIDDEN and NOT RUN.
  - `P-01.03` (Token Factory Sandbox workflow) — explicitly NOT RUN.
  - `P-04.04` (Protected-surface manifest and diff checks) — explicitly NOT RUN.
  - `P-05` (Permanent provider adapter layer) — explicitly NOT RUN.
  - Batch inference, retry loops, and multiple comparative models — explicitly NOT RUN.
