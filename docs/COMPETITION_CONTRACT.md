# Competition Contract — Nebius x NVIDIA Global AI Hackathon

Snapshot date: 2026-09-12.
Authoritative source at submission time remains the official Devpost rules.

## 1. Verified Official Sources (Snapshot: 2026-09-12)

| Resource | Official URL | Verified Status / Terms |
|---|---|---|
| Devpost Hackathon Page | `https://nebiusglobalaihackathon.devpost.com/` | Verified live |
| Devpost Official Rules | `https://nebiusglobalaihackathon.devpost.com/rules` | Verified live |
| Nebius Builder Program | `https://dev.nebius.com/builders` (note: `nebius.com/builder-program` 404s) | Free application, $25 Token Factory + $25 Tavily credits, 90-day expiry |
| Tavily Pricing & Free Tier | `https://tavily.com/pricing` | Researcher/Free plan: 1,000 credits/mo, no credit card required, hard stops |

## 2. Competition Timeline

- **Submission Period:** Wednesday, August 26, 2026 (9:00 am PT / 16:00 UTC) – Friday, October 30, 2026 (10:00 am PT / 17:00 UTC).
- **Judging Period:** Tuesday, December 1, 2026 (9:00 am PT) – Tuesday, December 15, 2026 (12:00 pm PT).
- **Winners Announced:** On or around Monday, January 11, 2027 (12:00 pm PT).

## 3. Eligibility Verification

- **Eligible Entrants:** Individuals who have reached the legal age of majority in their jurisdiction of residence, teams of up to five (5) eligible individuals, and corporate/business entities.
- **Excluded Jurisdictions:** Brazil, Quebec, Russia, Crimea, Cuba, Iran, North Korea, Syria, and any other territory subject to comprehensive OFAC trade sanctions.
- **Operator Eligibility:** Türkiye is **fully eligible** (not listed in excluded countries/territories).
- **Conflict of Interest / Novelty:** Projects that received prior financial support or preferential assistance from Sponsor/Administrator before the contest are disqualified. Basebreak was newly created independently during the Submission Period (created 2026-09-12) with zero prior funding or sponsor influence.

## 4. Track Fit & Runtime Definition

- **Track:** Coding and Agentic Engineering Track.
- **Official Track Definition:** "Build coding agents and developer tools: agents that write, run, and test code in Token Factory Sandboxes."
- **Official Runtime Definition:** To qualify as "running on Nebius Token Factory or Nebius AI Cloud", a project must make a runtime call to the Token Factory inference API, OR be deployed/run using Nebius AI Cloud compute (Serverless Jobs, Serverless Endpoints, DevPods).
- **Token Factory Inference Fit:** A runtime call to Token Factory inference alone satisfies the runtime requirement. Token Factory Sandboxes provide the isolated execution environments for Basebreak's multi-world execution (Base, Candidate, Counterfactual).
- **Stage One Viability:** Stage One is a Pass/Fail screen designed to filter out superficial rebrands, empty wrappers, and non-functioning projects. Basebreak's core causal verification engine represents a genuine, substantive technical implementation aligned directly with the track's mandate.

## 5. Submission Artifacts

- **Working Project Application:** Built with NVIDIA open-source models (e.g. Nemotron) hosted on Nebius Token Factory or Nebius AI Cloud.
- **Working Demo URL:** Public URL pointing to a working demo, hosted web application, or test build.
- **Video Demonstration:** Public YouTube URL, strictly **< 3 minutes** (< 3:00) in length, demonstrating the functioning software with English audio or clear English captions.
- **Public Code Repository:** Publicly accessible URL on GitHub, GitLab, or Bitbucket with an open-source license file (Apache-2.0, MIT, MPL 2.0) clearly visible at the top/root of the repository. (Basebreak uses root Apache-2.0 `LICENSE`).
- **README Guidance:** Comprehensive README providing installation, configuration, and execution instructions, highlighting the role of Nemotron models and Token Factory.
- **Mandatory Platform Feedback:** Mandatory submission field providing detailed feedback on Nebius Token Factory, Nebius AI Cloud, and NVIDIA tools used.
- **Submission Timing Window:** Project must be newly developed during the official Submission Period (Aug 26 – Oct 30, 2026). Basebreak Git history deterministically establishes inception on September 12, 2026.

## 6. Judging Criteria (Stage Two — Equal 25% Weight) & Basebreak Mapping

Stage One is a Pass/Fail viability screen. Submissions passing Stage One are evaluated in Stage Two on four equally weighted criteria (25% each):

1. **Technological Implementation (25%):**
   - *Official Criteria:* How well is the project built, and how effectively does it use Nebius Token Factory or AI Cloud and NVIDIA Nemotron?
   - *Basebreak Mapping:* Deep API-native integration of NVIDIA Nemotron via Nebius Token Factory; Token Factory Sandboxes for isolated, multi-world execution; deterministic execution receipts, cryptographic hash chaining, and counterfactual run validation.
2. **Design (25%):**
   - *Official Criteria:* Does the project deliver a complete, coherent product experience, not just a technical proof of concept?
   - *Basebreak Mapping:* Coherent, end-to-end causal verification runtime; intuitive 3-way visual/audit state transitions (`BASE=FAIL`, `CANDIDATE=PASS`, `COUNTERFACTUAL=FAIL`); rich inspection receipts; zero-friction signed-out judge exploration.
3. **Potential Impact (25%):**
   - *Official Criteria:* Does the project make a credible, specific case for solving a real problem for a real audience, and does the solution actually address it?
   - *Basebreak Mapping:* Eliminates the silent hallucination, pre-existing passing tests, and test-weakening risks in AI coding agents (Copilot, Cursor, Codex, custom agents) by mathematically and experimentally proving that the patch — and only the patch — caused the behavior delta.
4. **Quality of the Idea (25%):**
   - *Official Criteria:* Is this a creative, non-obvious use of Nebius Token Factory or AI Cloud and NVIDIA Nemotron, and does the team show genuine understanding of the problem space?
   - *Basebreak Mapping:* Unorthodox scientific thesis (`If the patch matters, the base must break`); transforms AI coding from unverified generation into empirical causal science under independent witnesses.
- **Official Tie-Breaking Order:** In the event of a tie, winners are determined based on the highest score in Technological Implementation, followed by Design, then Potential Impact, then Quality of the Idea. If still tied, the Judges' collective vote decides.

## 7. Judging Period & Testing Access Rules

- **Official Judging Period:** December 1, 2026 (9:00 am PT) through December 15, 2026 (12:00 pm PT).
- **Judge Evaluation Discretion:** Official rules state: "Judges are not obligated to test the code. They may judge solely on the description, images, and video."
- **Judge Access Obligation:** Official rules state: "Access must be provided free of charge and without restriction through the end of the Judging Period (December 15, 2026 12:00 pm PT)."
- **Private Project Provision:** If the website or project is private, testing instructions may include login credentials for judges.
- **Basebreak Design Objective:** While official rules allow providing login credentials if private, Basebreak *prefers* a friction-free, signed-out, read-only judge access mode as a primary product/design goal to eliminate judge drop-off and eliminate live token drain.

## 8. Strategic Prizes & Stacking Rules

- **Strategic Prizes:**
  - **Grand Prize / Overall Awards:** 1st Place ($20,000), 2nd Place ($10,000), 3rd Place ($6,000).
  - **Coding and Agentic Engineering Track Winner:** 1 NVIDIA Jetson Orin Nano.
  - **Best Use of Tavily Bonus Award:** $3,000 (Requires a functional, runtime call to the Tavily API as part of the demonstrated solution).
  - **Most Valuable Feedback Awards:** $100 cash + NVIDIA swag bag (up to 10 winners).
- **Multiple Prize / Stacking Rule (Official Rules §8):**
  - "Each Project is eligible for one (1) Overall Award OR one (1) Track Award AND one (1) Bonus Award."
  - *Stacking Conclusion:* Basebreak is eligible to win either an Overall Award ($20k/$10k/$6k) OR the Coding Track Award (Jetson Orin Nano), AND simultaneously win the Best Use of Tavily Bonus Award ($3,000). Feedback awards are also independently eligible.

## 9. Verified Zero-Cost Platform Terms

### Nebius Builder Program
- **Application:** Free to apply via `https://dev.nebius.com/builders`.
- **Promotional Credits:** USD $25 Token Factory credits + USD $25 Tavily credits upon successful verification.
- **Validity:** Credits expire **90 days from issuance**.
- **Post-Quota / Post-Expiry Billing Caution:** Official terms state customers may continue on pay-as-you-go after promotional credits are consumed.
- **Zero-Cost Safeguard:** Basebreak's Zero-Cost Law strictly forbids pay-as-you-go enablement or personal card charges. Account setup in P-01 must verify that PAYG is disabled or hard-capped at $0.00 personal spend.

### Tavily Free Path
- **Plan:** Researcher / Free plan ($0/month).
- **Allowance:** 1,000 API credits/month.
- **Payment Method:** **No credit card required**.
- **Exhaustion Behavior:** API calls are rejected when the monthly limit is reached (hard stop, no automatic billing).
- **Reset Behavior:** Allowance renews monthly.
- **Zero-Cost Status:** Fully zero-cost and compliant with Zero-Cost Law.

## 10. CREDIT_EXPIRY / JUDGING-COVERAGE RISK Status

- **Status:** `PARTIALLY_RESOLVED`
- **Reasoning & Resolution Strategy:**
  1. *Timing Delta:* If Builder Program promotional credits are issued in mid-September 2026, a 90-day expiration window terminates in mid-December (~December 14, 2026), creating potential exposure on the final day of the judging period (December 15, 2026 12:00 pm PT).
  2. *Testing Rule vs Inspection:* While Devpost rules state judges may evaluate based solely on the video and text description, the project must remain accessible free of charge throughout the judging window.
  3. *Deterministic Inspection Architecture:* Basebreak's core verification assets (witness code, execution traces, diffs, cryptographic hashes, and verification receipts) are deterministic artifacts. The Basebreak web UI / inspector can serve signed-out, read-only verified runs hosted on standard free tiers (e.g. GitHub Pages or Vercel Free) with zero live model inference calls, ensuring 100% judge inspection availability indefinitely at zero cost.
  4. *Live Run Path:* For interactive live runs by judges, operator onboarding in P-01 will determine whether Token Factory accounts support non-billable hard stops. If live credits expire or exhaust, the live execution UI will cleanly display that promotional live credits are exhausted while providing immediate, full-fidelity access to verified recorded runs. Under Zero-Cost Law, paid fallback is strictly blocked.

## 11. Basebreak Compliance Posture

- Basebreak is newly created during the submission period on canonical branch `main`.
- Product thesis remains exact: `If the patch matters, the base must break.`
- Canonical claim remains exact: `Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green.`
- Donor repos are inspiration/provenance sources only (`CONCEPT_ONLY`), not copied code.
- Zero personal spend: all development and judge access must operate strictly within verified free tiers and sponsor credits.

## 12. Pre-Submit Revalidation Checklist

Before P-32 release freeze, re-check:
- [ ] Official Devpost dates and deadline (2026-10-30 10:00 PDT).
- [ ] Public repository visibility and Apache-2.0 license at root.
- [ ] Working demo URL accessible signed-out with zero cost.
- [ ] Public YouTube video < 3 minutes with English audio/captions.
- [ ] Factual feedback from `docs/COMPETITION_FEEDBACK_LOG.md` ready for submission field.
- [ ] Real runtime Nebius Token Factory and NVIDIA Nemotron usage proven.
- [ ] Real runtime Tavily usage proven if claiming bonus prize.
