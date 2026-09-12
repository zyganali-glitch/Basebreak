# Competition Contract — Nebius x NVIDIA Global AI Hackathon

Snapshot date: 2026-09-12.
Authoritative source at submission time remains the official Devpost rules.

## Verified Official Sources (Snapshot: 2026-09-12)

| Resource | Official URL | Verified Status / Terms |
|---|---|---|
| Devpost Hackathon Page | `https://nebiusglobalaihackathon.devpost.com/` | Verified live |
| Devpost Official Rules | `https://nebiusglobalaihackathon.devpost.com/rules` | Verified live |
| Nebius Builder Program | `https://nebius.com/builder-program` (also `dev.nebius.com/builders`) | Free application, promotional credits |
| Tavily Pricing | `https://tavily.com/pricing` | Free plan: 1,000 credits/mo, no credit card |

## Verified Competition Requirements

### 1. Track Fit & Wording
- **Track:** Coding and Agentic Engineering Track.
- **Official Definition:** "Build coding agents and developer tools: agents that write, run, and test code in Token Factory Sandboxes."
- **Eligibility:** Must run on either Nebius Token Factory or Nebius AI Cloud and use at least one NVIDIA open-source model. A runtime inference call to Token Factory qualifies as running on Token Factory.

### 2. Submission Artifacts
- **Working Project:** Built with NVIDIA open-source models (e.g. Nemotron) on Nebius Token Factory or Nebius AI Cloud.
- **Working Demo URL:** URL to a working demo, hosted application, or test build.
- **Demo Video:** Public YouTube video, strictly **< 3 minutes**, with audio covering how Nebius Token Factory and NVIDIA models were used.
- **Public Code Repository:** Publicly accessible URL (GitHub, GitLab, Bitbucket) with an open-source license (e.g. Apache-2.0, MIT) visible at the top of the repository page.
- **README:** Setup instructions and clear guidance for running/inspecting the project.
- **Mandatory Feedback:** Feedback on Nebius Token Factory, AI Cloud, and NVIDIA tools/models used (separate submission field).
- **Language:** English (or English translation included).

### 3. Judging Criteria (Stage Two — Equal 25% Weight)
1. **Technological Implementation:** How well is the project built, and how effectively does it use Nebius Token Factory or AI Cloud and NVIDIA Nemotron?
2. **Design:** Does the project deliver a complete, coherent product experience, not just a technical proof of concept?
3. **Potential Impact:** Does the project make a credible, specific case for solving a real problem for a real audience, and does the solution actually address it?
4. **Quality of the Idea:** Is this a creative, non-obvious use of Nebius Token Factory or AI Cloud and NVIDIA Nemotron, and does the team show genuine understanding of the problem space?

### 4. Judging Period & Judge Access Terms
- **Official Judging Period:** December 1, 2026 9:00 AM PT through December 15, 2026 12:00 PM PT.
- **Evaluation Obligation:** Judges are not obligated to run or test the code; they may evaluate based solely on the video demo and text description.
- **Official Availability Rule:** The project must remain available free of charge and without restriction through the end of the judging period (December 15, 2026 12:00 PM PT). If the website/project is private, testing instructions may include login credentials.
- **Basebreak Product/Design Preference:** While official rules permit providing login credentials if private, Basebreak *prefers* a friction-free, signed-out, read-only judge access mode as a product/design goal to avoid judge drop-off.

### 5. Verified Platform & Credit Terms
- **Nebius Builder Program:** Currently described as free to apply. Service-specific terms state promotional credits of USD $25 Token Factory + USD $25 Tavily after successful registration/verification, expiring 90 days from issuance.
- **Credit Caution:** Nebius marketing mentions broader "$400+ in credits and discounts"; Basebreak does NOT treat that phrase as guaranteed cash-equivalent balance.
- **Standard Nebius AI Cloud Caution:** Standard promo-code documentation may involve payment details/card verification. Under Basebreak Zero-Cost Law, the operator must NOT be instructed into a card-charge or deposit path automatically.
- **Post-Quota Billing Caution:** Official Builder Program terms note customers may continue on pay-as-you-go after promotional credits are consumed. Basebreak must never assume automatic hard stops; accounts must deterministically prevent paid continuation.
- **Tavily Free Tier:** Researcher / Free plan offers 1,000 API credits/month with **no credit card required**. Hard stops when quota is exhausted.

### 6. Bonus Track Rules
- **Best Use of Tavily ($3,000):** Requires a genuine functional runtime Tavily API call as part of the demonstrated solution.
- **Prizes Stacking:** Track prize (NVIDIA Jetson Orin Nano) and Tavily bonus prize can be won concurrently.
- **Feedback Prize:** "Most Valuable Feedback" awards ($100 cash + NVIDIA swag) are available for detailed, actionable platform feedback.

## Unresolved Zero-Cost Planning Risks

### CREDIT_EXPIRY / JUDGING-COVERAGE RISK
- **Issue:** Promotional credits under the Builder Program expire 90 days from issuance. The competition judging period runs through **December 15, 2026 12:00 PM PT**.
- **Constraint:** Promotional-credit issuance timing must be carefully considered against the full judging period. Basebreak must not assume credits obtained early in development will remain valid through December 15.
- **Mandate for P-00.02:** P-00.02 must determine a verified zero-cost strategy for keeping the required judge/test path available through the final judging deadline without incurring paid charges.
- **Strict Guardrails:**
  - Do NOT recommend paid fallback.
  - Do NOT instruct the operator to enter a payment card.
  - Do NOT assume unused credits can be extended.
  - Do NOT assume promo-code redemption timing differs from issuance timing unless official terms/runtime explicitly support it.

## Basebreak Compliance Posture

- Basebreak is newly created during the submission period on canonical branch `main`.
- Product thesis remains exact: `If the patch matters, the base must break.`
- Canonical claim remains exact: `Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green.`
- Donor repos are inspiration/provenance sources only (`CONCEPT_ONLY`), not copied code.
- Zero personal spend: all development and judge access must operate strictly within verified free tiers and sponsor credits.

## Pre-Submit Revalidation Checklist

Before P-32 release freeze, re-check:
- [ ] Official Devpost dates and deadline (2026-10-30 10:00 PDT).
- [ ] Public repository visibility and Apache-2.0 license at root.
- [ ] Working demo URL accessible signed-out with zero cost.
- [ ] Public YouTube video < 3 minutes with English audio/captions.
- [ ] Factual feedback from `docs/COMPETITION_FEEDBACK_LOG.md` ready for submission field.
- [ ] Real runtime Nebius Token Factory and NVIDIA Nemotron usage proven.
- [ ] Real runtime Tavily usage proven if claiming bonus prize.
