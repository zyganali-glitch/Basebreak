# P-30 Narration Script: Basebreak Causal Verification Demo

- **Target Audio Duration**: 2 minutes 40 seconds (160 seconds)
- **Target Word Count**: ~360 words
- **Target Pace**: ~135 words per minute (natural, confident, articulate technical cadence)
- **Voice Recommendation**: English (US or UK neutral), professional tech narrator (e.g. "Andrew Multilingual" or "Christopher" in Microsoft Edge / Clipchamp, or "Adam" in ElevenLabs/CapCut).
- **Execution Truth**: Script is PREPARED; physical audio recording/rendering remains human-led operator task (NOT_RUN until generated).

---

## Scene 1: The Core Dilemma — Why Green CI Lies
- **Timestamp**: `0:00 – 0:25` (25 seconds)
- **Word Count**: 55 words
- **Audio Cue**: Confident, deliberate opening tone; slight dramatic pause before the thesis.

> *"Today, AI agents write code at superhuman speed, and CI systems dutifully flash green. But green tests alone cannot prove an AI patch actually fixed the intended problem. What if the test was already passing? What if assertions were weakened? To prove causation, you need more than green tests. If the patch matters, the base must break."*

---

## Scene 2: The Solution — The Three-World Causal Engine
- **Timestamp**: `0:25 – 0:50` (25 seconds)
- **Word Count**: 58 words
- **Audio Cue**: Clear, explanatory cadence; emphasize the three numbered worlds.

> *"Meet Basebreak: a causal verification runtime for AI-written code. Instead of trusting green CI, Basebreak evaluates the change across three isolated execution worlds: First, the Base world must fail under a sealed witness, reproducing the defect. Second, the Candidate world must pass. Third, reverting the patch delta in a counterfactual world must fail again, proving the patch was strictly necessary."*

---

## Scene 3: Live Verification in Action — Nebius Nemotron & Sandboxes
- **Timestamp**: `0:50 – 1:20` (30 seconds)
- **Word Count**: 69 words
- **Audio Cue**: Fast-paced, concrete technical precision; enunciate telemetry details cleanly.

> *"Here is Basebreak verifying ResetVault, our synthetic security-sensitive scenario. The AI model—NVIDIA's Nemotron 3.5 Lightning hosted on Nebius Token Factory—generates the candidate fix. Basebreak parses the proposal via pure static AST inspection, then orchestrates eleven isolated operations across Nebius microVM sandboxes. Base fails with exit 1. The candidate passes exit 0 in forty milliseconds. And the counterfactual fails with exit 1."*

---

## Scene 4: Cryptographic Proof & The Public Judge Dashboard
- **Timestamp**: `1:20 – 1:50` (30 seconds)
- **Word Count**: 67 words
- **Audio Cue**: Authoritative and welcoming; highlight ease of inspection for judges.

> *"Anyone can verify this outcome without logging in. Hosted globally on Cloudflare Workers, Basebreak's public Judge dashboard presents the complete causal receipt. Every run binds the exact source commit, candidate tree digest, and sandbox outputs into a cryptographic verification receipt, authenticated with a verifier-signed custom RSA-2048 proof and committed to an SQLite Durable Object ledger. Transparent, auditable, and independently reproducible."*

---

## Scene 5: Meaningful External Grounding with Tavily Search
- **Timestamp**: `1:50 – 2:15` (25 seconds)
- **Word Count**: 56 words
- **Audio Cue**: Thoughtful architectural emphasis; stress the boundary between advisory grounding and code execution.

> *"For advisory grounding on security fixes like CVE-2024-21626, Basebreak integrates Tavily Search. Tavily grounds and binds authoritative advisory information from NIST and GitHub to an already frozen contract. Our deterministic firewall guarantees external web claims never override code execution. Web grounding provides advisory context; independent sandbox execution governs the verdict."*

---

## Scene 6: Conclusion & Impact — The Standard for Agentic Engineering
- **Timestamp**: `2:15 – 2:40` (25 seconds)
- **Word Count**: 55 words
- **Audio Cue**: Strong, inspiring conclusion; leave the core thesis lingering in memory.

> *"Basebreak transforms AI code generation from probabilistic guessing into empirical causal verification under sealed witnesses. Powered by NVIDIA Nemotron, Nebius Token Factory Sandboxes, and Cloudflare Workers, it is the verification layer modern coding agents have been missing. Remember: If the patch matters, the base must break. Explore the proof yourself at Basebreak."*

---

## Pronunciation Guide & Technical Terms

| Term | Pronunciation Note | Context |
|---|---|---|
| **Basebreak** | `BASE-break` | Product name |
| **Nemotron** | `NEM-oh-tron` | NVIDIA model family |
| **Nebius** | `NEH-bee-us` | Infrastructure platform |
| **Tavily** | `TAV-ih-lee` | Search API provider |
| **ResetVault** | `RESET-vault` | Synthetic security-sensitive demo scenario |
| **Counterfactual** | `kown-ter-FAK-choo-ul` | Third execution world |
| **AST** | Spell out: `A - S - T` | Abstract Syntax Tree |
| **CVE-2024-21626** | `C - V - E twenty-twenty-four, twenty-one-six-twenty-six` | Advisory grounding reference |
| **Durable Object** | `DUR-uh-bul OB-jekt` | Cloudflare persistence model |
| **SHA-256** | `SHAW two-fifty-six` | Cryptographic hash algorithm |
