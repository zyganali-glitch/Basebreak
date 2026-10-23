# P-30 Storyboard: Basebreak Causal Verification Demo

- **Target Total Duration**: 2 minutes 40 seconds (160 seconds)
- **Hard Maximum Duration**: Strictly under 3 minutes (< 180 seconds)
- **Core Tagline**: *"If the patch matters, the base must break."*
- **Primary Causal Triplet**: `BASE = FAIL` $\rightarrow$ `CANDIDATE = PASS` $\rightarrow$ `COUNTERFACTUAL = FAIL`
- **Replay & Evidence Label**: `RECORDED_LIVE` (binding genuine provider run `run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f`)

---

## Timed Scene-by-Scene Breakdown

```
0:00        0:25               0:50                    1:20                   1:50               2:15        2:40
|-----------|------------------|-----------------------|----------------------|------------------|-----------|
  Scene 1        Scene 2                Scene 3                Scene 4              Scene 5        Scene 6
 The Dilemma   The Causal Engine      Live Verification      Cryptographic Proof    Tavily Grounding   Conclusion
 (Green CI)   (3-World Triplet)     (Nebius & Nemotron)     (Judge Dashboard)      (Advisory Invariant)
```

---

### Scene 1: The Core Dilemma — Why Green CI Lies
- **Timing**: `0:00 – 0:25` (Duration: 25 seconds)
- **Target Word Count**: ~55 words
- **Visual Display**:
  - Split screen: on the left, an AI agent generates code. On the right, traditional CI flashes an illustrative green badge: `ALL TESTS PASSING (ILLUSTRATIVE GREEN CI)`.
  - An animated red alert banner overlays: *"Did the AI fix the bug, or was the test already passing?"*
  - Cut to a diagram highlighting the three fatal flaws of green CI:
    1. Pre-existing passing tests (vacuous assertions).
    2. Overfitted tests that pass regardless of bug presence.
    3. Weakened assertions by the AI.
- **On-Screen Text**:
  - `GREEN CI CANNOT PROVE CAUSATION`
  - `If the patch matters, the base must break.`
- **Voiceover Narration**:
  *"Today, AI agents write code at superhuman speed, and CI systems dutifully flash green. But green tests alone cannot prove an AI patch actually fixed the intended problem. What if the test was already passing? What if assertions were weakened? To prove causation, you need more than green tests. If the patch matters, the base must break."*

---

### Scene 2: The Solution — The Three-World Causal Engine
- **Timing**: `0:25 – 0:50` (Duration: 25 seconds)
- **Target Word Count**: ~58 words
- **Visual Display**:
  - High-contrast visualization of Basebreak's Three-World Differential Architecture:
    1. **World 1 (BASE)**: Original repository $\rightarrow$ Run Sealed Witness $\rightarrow$ **FAIL** (Defect reproduced).
    2. **World 2 (CANDIDATE)**: AI-patched repository $\rightarrow$ Run Sealed Witness $\rightarrow$ **PASS** (Defect resolved).
    3. **World 3 (COUNTERFACTUAL)**: Revert candidate patch delta $\rightarrow$ Run Sealed Witness $\rightarrow$ **FAIL** (Proves the patch was strictly necessary).
  - Clear label in bold: `CAUSAL TRIPLET VERIFIED`.
- **On-Screen Text**:
  - `WORLD 1 (BASE): FAIL (Defect Reproduced)`
  - `WORLD 2 (CANDIDATE): PASS (Defect Resolved)`
  - `WORLD 3 (COUNTERFACTUAL): FAIL (Patch Was Necessary)`
- **Voiceover Narration**:
  *"Meet Basebreak: a causal verification runtime for AI-written code. Instead of trusting green CI, Basebreak evaluates the change across three isolated execution worlds: First, the Base world must fail under a sealed witness, reproducing the defect. Second, the Candidate world must pass. Third, reverting the patch delta in a counterfactual world must fail again, proving the patch was strictly necessary."*

---

### Scene 3: Live Verification in Action — Nebius Nemotron & Sandboxes
- **Timing**: `0:50 – 1:20` (Duration: 30 seconds)
- **Target Word Count**: ~70 words
- **Visual Display**:
  - Screen capture of Basebreak executing verified run `run_3ba7d1fd` against `ResetVault`, our synthetic security-sensitive scenario (`tests/fixtures/reset_vault/`).
  - Terminal and audit view showing:
    1. Nebius Token Factory candidate generation using `nvidia/Nemotron-3_5-Lightning` (request `chatcmpl-6f406c07...`).
    2. Static AST validation: verifying syntax and class preservation without executing untrusted code on the host.
    3. Token Factory Sandbox creation (`sbx-c9e5c0e4...`, `sbx-cd870e01...`, `sbx-90d40f25...`).
    4. Exact sandbox exit codes: `BASE exit 1`, `CANDIDATE exit 0 (1 test passed in 0.04s)`, `COUNTERFACTUAL exit 1`.
- **On-Screen Text**:
  - `Scenario: ResetVault (Synthetic Security-Sensitive Token Vault)`
  - `Model: nvidia/Nemotron-3_5-Lightning (Token Factory)`
  - `Sandboxes: 11 Isolated Nebius Sandbox Operations`
  - `Telemetry: BASE exit 1 | CAND exit 0 | CF exit 1`
  - `Provenance: RECORDED_LIVE (run_3ba7d1fd)`
- **Voiceover Narration**:
  *"Here is Basebreak verifying ResetVault, our synthetic security-sensitive scenario. The AI model—NVIDIA's Nemotron 3.5 Lightning hosted on Nebius Token Factory—generates the candidate fix. Basebreak parses the proposal via pure static AST inspection, then orchestrates eleven isolated operations across Nebius microVM sandboxes. Base fails with exit 1. The candidate passes exit 0 in forty milliseconds. And the counterfactual fails with exit 1."*

---

### Scene 4: Cryptographic Proof & The Public Judge Dashboard
- **Timing**: `1:20 – 1:50` (Duration: 30 seconds)
- **Target Word Count**: ~68 words
- **Visual Display**:
  - Screen capture of the live public Judge UI at:
    `https://basebreak.zyganali.workers.dev/judge/run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f`
  - Camera pans smoothly across:
    1. Top badges: `VERIFIED` verdict, `LIVE_NEBIUS` provenance, `AUTHENTIC SHA-256` integrity.
    2. The 3-World Comparison Grid showing all three exit codes and execution tree digests.
    3. The Cryptographic Receipt Card: showing Receipt Digest `e2e833fd...` and verifier-signed RSA-2048 Proof Digest `def59353...`.
    4. The Cloudflare Workers SQLite Durable Object audit trail.
- **On-Screen Text**:
  - `Public Judge UI: Signed-Out, Zero-Friction Inspection`
  - `Cryptographic Receipt: Verifier-Signed Custom RSA-2048 Proof`
  - `Durable Ledger: Cloudflare Workers SQLite DO`
- **Voiceover Narration**:
  *"Anyone can verify this outcome without logging in. Hosted globally on Cloudflare Workers, Basebreak's public Judge dashboard presents the complete causal receipt. Every run binds the exact source commit, candidate tree digest, and sandbox outputs into a cryptographic verification receipt, authenticated with a verifier-signed custom RSA-2048 proof and committed to an SQLite Durable Object ledger. Transparent, auditable, and independently reproducible."*

---

### Scene 5: Meaningful External Grounding with Tavily Search
- **Timing**: `1:50 – 2:15` (Duration: 25 seconds)
- **Target Word Count**: ~58 words
- **Visual Display**:
  - Transition to the External Grounding architecture for security fixes (`CVE-2024-21626`).
  - Visual separation of responsibilities:
    - **Tavily Search API**: grounds and binds authoritative advisory information from sources like GitHub Advisory Database to an already frozen contract (`GroundingMateriality.REQUIRED`).
    - **Grounding Authority Firewall**: binds facts to the frozen contract digest while guaranteeing that retrieved web claims **NEVER override code execution**.
    - **Evidence Honesty Disclosure**: genuine live provider observation executed (request ID `cbb8a550-d334-4727-a715-1086799a73f9`, 3 sources bound to frozen contract); deterministic firewall returned honest fail-closed `INSUFFICIENT_GROUNDING / BLOCKED` verdict; candidate execution strictly `NOT_RUN`; web evidence cannot override execution.
  - On-screen comparison: *"Tavily provides advisory context; Sandboxes score code behavior."*
- **On-Screen Text**:
  - `Tavily Search: Advisory Grounding for Frozen Contracts (CVE-2024-21626)`
  - `Binds: Authoritative Advisory Facts to Frozen Contract Digest`
  - `Firewall Primacy: Web Claims Never Override Sandbox Failure`
  - `Evidence Truth: Offline Pipeline Verified; Live Search Pending Key`
- **Voiceover Narration**:
  *"For advisory grounding on security fixes like CVE-2024-21626, Basebreak integrates Tavily Search. Tavily grounds and binds authoritative advisory information from sources like GitHub to an already frozen contract. Our deterministic firewall guarantees external web claims never override code execution. Web grounding provides advisory context; independent sandbox execution governs the verdict."*

---

### Scene 6: Conclusion & Impact — The Standard for Agentic Engineering
- **Timing**: `2:15 – 2:40` (Duration: 25 seconds)
- **Target Word Count**: ~55 words
- **Visual Display**:
  - Dynamic closing graphic showing the complete stack:
    `NVIDIA Nemotron` + `Nebius Token Factory` + `Tavily` + `Cloudflare Edge`.
  - Full-screen headline:
    **BASEBREAK**
    *Causal Verification Runtime for AI-Written Code*
  - Links displayed:
    - Public Judge: `https://basebreak.zyganali.workers.dev`
    - Open Source Code: `https://github.com/zyganali-glitch/Basebreak`
  - Final punchy audio fade-out.
- **On-Screen Text**:
  - `BASEBREAK: Beyond Green CI`
  - `If the patch matters, the base must break.`
  - `Open Source Apache-2.0 | zyganali-glitch/Basebreak`
- **Voiceover Narration**:
  *"Basebreak transforms AI code generation from probabilistic guessing into empirical causal verification under sealed witnesses. Powered by NVIDIA Nemotron, Nebius Token Factory Sandboxes, and Cloudflare Workers, it is the verification layer modern coding agents have been missing. Remember: If the patch matters, the base must break. Explore the proof yourself at Basebreak."*

---

## Storyboard Timing & Pacing Summary

| Scene | Section | Duration | Target Words | Cumulative Time |
|---|---|---|---|---|
| **Scene 1** | The Dilemma (Why Green CI Lies) | 25s | 55 words | 0:25 |
| **Scene 2** | The Solution (The 3-World Causal Engine) | 25s | 58 words | 0:50 |
| **Scene 3** | Live Verification (Nemotron & Sandboxes) | 30s | 70 words | 1:20 |
| **Scene 4** | Cryptographic Proof & Judge Dashboard | 30s | 68 words | 1:50 |
| **Scene 5** | External Grounding with Tavily | 25s | 58 words | 2:15 |
| **Scene 6** | Conclusion & Impact | 25s | 55 words | **2:40 (160s)** |

- **Total Spoken Words**: ~364 words
- **Runtime Bound**: 160 seconds (strictly < 180 seconds hard cap)
- **Execution Truth**: Storyboard is PREPARED; physical screen recordings and audio generation remain human-led operator tasks (NOT_RUN until captured).
