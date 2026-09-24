# P-01.02 — Live Token Factory Nemotron Inference Evidence

## Task Identification
- **Exact Task:** `P-01.02 — Execute first real Token Factory Nemotron inference call with sanitized minimal prompt`
- **Execution Timestamp (UTC):** `2026-09-24T08:38:27.536481+00:00` to `2026-09-24T08:38:28.254048+00:00`
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
- **Response Payload SHA-256:** `8658e0b3cf77c475d002ed6fdfe9c472e5db526047510f8d2b9d7dd83ed65c1c`
- **Returned Model ID:** `nvidia/Nemotron-3_5-Lightning`
- **Response Content:**
```
Here's a thinking process:

1.  **Analyze User Input:**
```
- **Finish Reason:** `length` (promptly capped at `max_tokens: 16`).
- **Token Usage:**
  - `prompt_tokens`: 45
  - `completion_tokens`: 16
  - `total_tokens`: 61
  - `reasoning_tokens`: 16
  - `prompt_cache_hit_tokens`: 0
  - `prompt_cache_miss_tokens`: 45

---

## Pre- and Post-Inference Balance Observations
- **PRE_BALANCE:** `$25.00` promotional balance (Operator verified at `2026-09-24T11:38:09+03:00`).
- **POST_BALANCE:** `$25.00` promotional balance (Operator verified via web console at `2026-09-24T11:37:00+03:00` / local time).
- **DISPLAYED_DELTA:** `NOT_OBSERVABLE_AT_UI_PRECISION` (61 total tokens at serverless pricing is ~`$0.000003`, which is below the `$0.01` UI display precision).
- **Separate Trial Credit:** `$1.00` (untouched, 24 days validity remaining).
- **Personal Spend:** `$0.00` (strict Zero-Cost Law compliance).
- **Safety Reserve Floor:** `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` satisfied (`$25.00 > $5.00`).

---

## Security & Provenance Attestations
- **Secret Exclusion Statement:** Neither `NEBIUS_API_KEY` nor its prefix, suffix, length, hashes, nor Authorization headers are committed to git or stored in repository files. The credential was read exclusively from the Windows User environment in memory and discarded immediately.
- **No-Mock / No-Fallback Statement:** No mock, simulation, synthetic adapter, or non-NVIDIA fallback provider was used. Real, authenticated HTTPS traffic was sent to `api.tokenfactory.nebius.com` and answered by the NVIDIA Nemotron inference infrastructure.
- **Evidence Provenance:** `LIVE_NEBIUS`.

---

## Boundaries & NOT_RUN Scope
- **NOT_RUN:**
  - `P-01.03` (Token Factory Sandbox workflow) — explicitly NOT RUN.
  - `P-04.04` (Protected-surface manifest and diff checks) — explicitly NOT RUN.
  - `P-05` (Permanent provider adapter layer) — explicitly NOT RUN.
  - Batch inference, retry loops, and multiple comparative models — explicitly NOT RUN.
- **Unresolved Uncertainties:**
  - `nvidia/Nemotron-3_5-Lightning` defaults to outputting reasoning tokens prior to final textual completion unless constrained or configured via specific system parameters. The 16-token limit was exhausted during the reasoning preface. Model integration in `P-05` will formalize parameters for direct answering or extraction.
