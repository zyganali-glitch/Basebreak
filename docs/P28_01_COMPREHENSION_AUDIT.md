# 30-Second Judge Comprehension Audit (P-28.01)

> **Methodology:** Reproducible heuristic usability review evaluated against the 30-second first-impression cognitive budget of an expert or first-time judge.

---

## 1. Audit Framework & Cognitive Time Budget

A hackathon judge typically spends 20 to 60 seconds scanning a project dashboard to decide whether the product solves a real problem or is merely marketing theater.

| Second Window | Target Judge Question | Product Design Response in Basebreak | Result |
| :--- | :--- | :--- | :--- |
| **0 – 5s** | *What is this product and what is its thesis?* | Large header: **BASEBREAK VERIFICATION RUNTIME**.<br>Memorable core thesis in bright cyan: *“If the patch matters, the base must break.”* | **PASS** |
| **5 – 12s** | *What is the outcome of this run?* | Two prominent badges in the top right: Verdict badge (`VERIFIED` / `CONTRADICTED`) and Provenance badge (`LIVE_NEBIUS` / `LOCAL_EXECUTION`). Cryptographic integrity badge (`AUTHENTIC SHA-256`). | **PASS** |
| **12 – 20s** | *What does it actually prove that CI doesn't?* | Immediate 3-World Causal Transition Grid:<br>1. Base: `FAIL` (Defect reproduced)<br>2. Candidate: `PASS` (Defect fixed)<br>3. Counterfactual: `FAIL` (Patch delta proved necessary).<br>Explainer card: "Why Green CI Lies vs. What Basebreak Proves". | **PASS** |
| **20 – 30s** | *Can I trust this evidence? Where are the facts?* | Cryptographic receipt digest, candidate tree SHA, source commit SHA, and honest `NOT_RUN` obligation banner. | **PASS** |

---

## 2. Heuristic Findings & Scoring Matrix

| Heuristic Dimension | Criteria | Evaluation / Evidence | Status |
| :--- | :--- | :--- | :--- |
| **1. Visual Hierarchy** | Eye tracks Thesis $\rightarrow$ Verdict $\rightarrow$ 3-World Grid $\rightarrow$ Evidence Facts. | Top-to-bottom card structure leads with causal proof before technical hashes or execution logs. | **EXCELLENT** |
| **2. Jargon Minimization** | Eliminates confusing internal abstractions; uses clear plain English. | Distinguishes ordinary green CI from causal verification without requiring knowledge of formal methods or internal compiler state. | **EXCELLENT** |
| **3. Honesty & Transparency** | Non-executed items and contradictions are clearly visible. | Missing steps are explicitly badged as `NOT_RUN`. Contradictions and blockers have dedicated high-visibility warning panels. | **EXCELLENT** |
| **4. Scannability** | Critical numbers and outcomes visible without scrolling. | All core facts (World outcomes, verdict, provenance, receipt digest) fit within standard 1080p single-screen viewport. | **EXCELLENT** |
| **5. Cognitive Load** | Does not overwhelm judge with walls of unparsed json. | JSON data is collapsible/downloadable; dashboard surfaces formatted semantic cards. | **EXCELLENT** |

---

## 3. Heuristic Recommendations Implemented in P-28

1. **Thesis Front-and-Center:** *“If the patch matters, the base must break.”* is the primary visual anchor.
2. **Comparison Table Above Timeline:** Moved the 3-World comparison grid directly below the header so the causal story is seen before implementation timelines.
3. **Green CI Explainer Card:** Added an explicit comparison panel explaining why green tests can be misleading (vacuous assertions, tests that never failed on the buggy base) and how Basebreak's 3-world engine solves this.
4. **Honest Contradiction Views:** Contradictions and blocked runs are rendered with rich, explanatory status panels rather than generic errors.
