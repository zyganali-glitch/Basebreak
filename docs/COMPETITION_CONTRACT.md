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

- **Eligible Entrants:** Individuals who have reached the legal age of majority in their jurisdiction of residence, Teams of Eligible Individuals, and corporate/business entities (the Official Rules do not specify a five-person team maximum).
- **Excluded Jurisdictions:** Brazil, Quebec, Russia, Crimea, Cuba, Iran, North Korea, and any other territory subject to comprehensive OFAC trade sanctions.
- **Operator Geographic Eligibility:** Türkiye is not among the jurisdictions expressly listed as excluded in the current Official Rules. Individual eligibility remains subject to age-of-majority, applicable local/U.S. law, conflict-of-interest, Promotion Entity/Judge affiliation, and the other eligibility conditions in the Official Rules.
- **Conflict of Interest / Prior Financial Support:** The Official Rules provide that a Project must not have been developed or derived from a project developed with prohibited financial or preferential support from Sponsor or Administrator (including prior commercial grants, incubators, or direct custom assistance). No prohibited Sponsor/Administrator support is evidenced in the canonical repository; entrant compliance with this rule remains an entrant representation to be rechecked before submission. Note that the Official Rules explicitly invite entrants to apply for the Nebius Builder Program for hackathon tooling/credits; Basebreak maintains the exact official-rule distinction without asserting an unverified legal conclusion regarding promotional credits, and flags any ambiguity for pre-submit revalidation.

## 4. Track Fit & Runtime Definition

- **Track:** Coding and Agentic Engineering Track.
- **Official Track Definition:** "Build coding agents and developer tools: agents that write, run, and test code in Token Factory Sandboxes."
- **Official Runtime Definition:** To qualify as "running on Nebius Token Factory or Nebius AI Cloud", a project must make a runtime call to the Token Factory inference API, OR be deployed/run using Nebius AI Cloud compute (Serverless Jobs, Serverless Endpoints, DevPods).
- **Token Factory Inference Fit:** A runtime call to Token Factory inference alone satisfies the runtime requirement.
- **Token Factory Sandboxes Planning Stance:** Basebreak intends to use Token Factory Sandboxes for Base/Candidate/Counterfactual execution; P-01 must verify the actual isolation, lifecycle, filesystem, execution, and other required runtime properties before this architecture is considered proven.
- **Stage One Viability:** Stage One is a Pass/Fail screen designed to filter out superficial rebrands, empty wrappers, and non-functioning projects. Basebreak's core causal verification engine represents a genuine, substantive technical implementation aligned directly with the track's mandate.

## 5. Submission Artifacts

- **Working Project Application:** Built with NVIDIA open-source models (e.g. Nemotron) hosted on Nebius Token Factory or Nebius AI Cloud.
- **Working Demo URL:** URL to a working demo, hosted application, or test build.
- **Video Demonstration:** Public YouTube URL, strictly **< 3 minutes** (< 3:00) in length, demonstrating the functioning software with English audio or clear English captions.
- **Public Code Repository:** Publicly accessible URL on GitHub, GitLab, or Bitbucket with an open-source license file (Apache-2.0, MIT, MPL 2.0) clearly visible at the top/root of the repository. (Basebreak uses root Apache-2.0 `LICENSE`).
- **README Guidance:** Comprehensive README providing installation, configuration, and execution instructions, highlighting the role of Nemotron models and Token Factory.
- **Mandatory Platform Feedback:** Mandatory submission field providing detailed feedback on Nebius Token Factory, Nebius AI Cloud, and NVIDIA tools used.
- **Project Inception & Update Rule:** Under current Official Rules, submissions may be either newly created during the Submission Period OR pre-existing projects that are significantly updated after the Submission Period begins (August 26, 2026 9:00 am PT). Basebreak is newly created: canonical Git history deterministically establishes that its repository inception and initial commit occurred on September 12, 2026, well within the Submission Period.

## 6. Judging Criteria (Stage Two — Equal 25% Weight) & Basebreak Mapping

Stage One is a Pass/Fail viability screen. Submissions passing Stage One are evaluated in Stage Two on four equally weighted criteria (25% each):

1. **Technological Implementation (25%):**
   - *Official Criteria:* How well is the project built, and how effectively does it use Nebius Token Factory or AI Cloud and NVIDIA Nemotron?
   - *Basebreak Mapping [TARGET ARCHITECTURE / PLANNED]:* Planned API-native integration of NVIDIA Nemotron via Nebius Token Factory; intended use of Token Factory Sandboxes for isolated multi-world execution (Base, Candidate, Counterfactual), subject to P-01 live validation; planned deterministic execution receipts, cryptographic hash chaining, and counterfactual run validation.
2. **Design (25%):**
   - *Official Criteria:* Does the project deliver a complete, coherent product experience, not just a technical proof of concept?
   - *Basebreak Mapping [TARGET ARCHITECTURE / PLANNED]:* Planned end-to-end causal verification runtime; target 3-way visual/audit state transitions (`BASE=FAIL`, `CANDIDATE=PASS`, `COUNTERFACTUAL=FAIL`); intended inspection receipts; planned signed-out judge exploration mode to minimize evaluation friction.
3. **Potential Impact (25%):**
   - *Official Criteria:* Does the project make a credible, specific case for solving a real problem for a real audience, and does the solution actually address it?
   - *Basebreak Mapping [TARGET ARCHITECTURE / PLANNED]:* Aims to address silent hallucination, pre-existing passing tests, and test-weakening risks in AI coding agents (Copilot, Cursor, Codex, custom agents) by demonstrating that the exact candidate produced the required observed transition under an independently executed witness; where a valid counterfactual is available, removing the tested patch delta removes that observed transition.
4. **Quality of the Idea (25%):**
   - *Official Criteria:* Is this a creative, non-obvious use of Nebius Token Factory or AI Cloud and NVIDIA Nemotron, and does the team show genuine understanding of the problem space?
   - *Basebreak Mapping [TARGET ARCHITECTURE / PLANNED]:* Unorthodox causal thesis (`If the patch matters, the base must break`); reframes AI code evaluation from ungrounded confidence in model prose into empirical causal verification under an independently executed witness.
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
  - **Bonus Awards Group:** Best Use of Tavily ($3,000), City Winner Awards, and Most Valuable Feedback ($100 cash + NVIDIA swag bag, up to 10 winners) are categorized under Bonus Awards in the Official Rules.
- **Multiple Prize / Stacking Rule (Official Rules §8):**
  - "Each Project is eligible for one (1) Overall Award OR one (1) Track Award and one (1) Bonus Award."
  - **Conservative Basebreak Interpretation:** A Project may receive one Overall Award OR one Track Award, plus at most one Bonus Award. Basebreak therefore must not assume that Best Use of Tavily and Most Valuable Feedback can both be awarded to the same Project. If official clarification later confirms separate eligibility for feedback awards, current official reality may supersede this.

## 9. Verified Zero-Cost Platform Terms

### Nebius Builder Program
- **Application:** Free to apply via `https://dev.nebius.com/builders`.
- **Promotional Credits:** USD $25 Token Factory credits + USD $25 Tavily credits upon successful verification.
- **Validity:** Credits expire **90 days from issuance**.
- **Post-Quota / Post-Expiry Billing Caution:** Official terms state customers may continue on pay-as-you-go after promotional credits are consumed.
- **Zero-Cost Safeguard:** Basebreak's Zero-Cost Law strictly forbids personal spending or unmetered paid continuation. Under the operator-approved `TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION`, a payment card was attached solely to activate Builder Program promotional credits, while target personal spend remains strictly $0.00, post-promotional paid usage is strictly forbidden, and an operator policy safety reserve floor (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`) is enforced.

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
  3. *Read-Only Inspection Architecture:* Basebreak plans a zero-cost read-only evidence inspection path where feasible. Completed verification runs (witness code, execution traces, diffs, cryptographic hashes, and verification receipts) can be inspected with zero live model inference calls. Read-only inspection of verified evidence is a planned cost-control and judge-comprehension mitigation; it is not currently treated as proven satisfaction of the Official Rules' working-Project access/testing requirement.
  4. *Live Run Path & Risk Accounting:* First-party discovery in P-01 is complete: Nebius Support directly confirmed that Token Factory does not provide a guaranteed $0 post-promo hard spending cap, automatic card charging cannot be disabled on an active card-backed account, removing the card suspends Token Factory, and continued usage after promo exhaustion may charge the attached card. Basebreak uses operator-controlled pre/post balance checks and an operator policy safety reserve floor (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`). While these controls reduce development-spend risk during internal execution, they are not equivalent to a platform billing guarantee. Consequently, if live promotional credits expire or exhaust before December 15, or if unmetered public access could drain credits, a guaranteed zero-personal-spend working-project path through the full judging period remains unproven. Judging and deployment architecture must still solve this later (e.g. via read-only evidence inspection, strict budgeting, or bounded judge pathways). Under Zero-Cost Law, paid fallback remains strictly forbidden.

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
