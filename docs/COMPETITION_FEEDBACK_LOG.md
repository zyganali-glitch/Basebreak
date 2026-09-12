# Competition Feedback Log — Basebreak

Append-only factual log for mandatory Nebius x NVIDIA hackathon feedback.
This log may also be used as source material for the "Most Valuable Feedback" prize submission.

## Rules

- Record only genuinely observed experiences of the operator or Basebreak runtime.
- Never invent or fabricate feedback.
- Never store credentials, secrets, or private identifiers.
- Distinguish platform issue from operator error and Basebreak bug when known.
- Append only; do not delete or rewrite past entries.
- Each entry must have deterministic evidence or a clear reference.
- Allowed provenance is strictly limited to:
  - `LIVE_OBSERVATION` — hands-on runtime, API, SDK, or sandbox execution by Basebreak/operator.
  - `DOCUMENTATION_REVIEW` — when Basebreak/operator actually reviewed official documentation and the feedback concerns that direct experience.
- Third-party or community reports are strictly excluded from this competition feedback ledger; external feedback must never be synthesized as the operator's own experience.

## Entry Template

```
### F-NNN — [SHORT TITLE]

- **Date/Time:** YYYY-MM-DD HH:MM UTC
- **Provider/Tool:** Nebius Token Factory | Nebius AI Cloud | NVIDIA Nemotron | Tavily | Other
- **Feature/API:** [specific feature, endpoint, SDK, or UI element]
- **Task/Run Context:** [which Basebreak task or run triggered this observation]
- **What Worked Well:** [positive observation, if any]
- **Friction/Bug/Limitation:** [negative observation, if any]
- **Deterministic Evidence:** [error message, status code, log excerpt, screenshot reference — no secrets]
- **Developer Impact:** [how this affected development velocity, architecture, or cost]
- **Workaround:** [if any was found]
- **Concrete Product Suggestion:** [actionable improvement suggestion for the provider]
- **Severity/Value:** LOW | MEDIUM | HIGH | CRITICAL
- **Provenance:** LIVE_OBSERVATION | DOCUMENTATION_REVIEW
- **Status:** RESOLVED | UNRESOLVED | WORKAROUND_APPLIED
```

## Entries

### F-001 — Nebius Builder Program landing URL 404 / broken redirect

- **Date/Time:** 2026-09-12 11:45 UTC
- **Provider/Tool:** Nebius Token Factory
- **Feature/API:** Builder Program application page / URL navigation
- **Task/Run Context:** P-00.02 (Verify competition eligibility and terms against official sources)
- **What Worked Well:** Once located, the developer portal page (`https://dev.nebius.com/builders`) provided explicit, unambiguous promotional credit figures ($25 Token Factory + $25 Tavily) and clear 90-day expiry terms.
- **Friction/Bug/Limitation:** The primary URL cited in external hackathon collateral and promotional material (`https://nebius.com/builder-program`) returned HTTP 404 (Not Found) rather than redirecting smoothly to the active developer portal application page.
- **Deterministic Evidence:** HTTP GET `https://nebius.com/builder-program` returned status 404 Not Found during research fetch on 2026-09-12; active application page was located at `https://dev.nebius.com/builders`.
- **Developer Impact:** Increases friction and creates confusion for new hackathon entrants attempting to verify promotional credit terms or apply for the Builder Program.
- **Workaround:** Located and documented the active URL `https://dev.nebius.com/builders` in project competition governance.
- **Concrete Product Suggestion:** Set up an HTTP 301 permanent redirect from `nebius.com/builder-program` to `dev.nebius.com/builders`.
- **Severity/Value:** LOW
- **Provenance:** DOCUMENTATION_REVIEW
- **Status:** WORKAROUND_APPLIED
