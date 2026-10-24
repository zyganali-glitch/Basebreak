# P-30 Screen Recording Guide: Basebreak Demo

This guide provides concrete, click-by-click instructions for capturing the screen footage for the official 2-minute 40-second hackathon submission video.

- **Target Total Duration**: 2 minutes 40 seconds (160 seconds)
- **Hard Maximum Duration**: Strictly under 3 minutes (< 180 seconds)
- **Execution Truth**: Guide and capture instructions are PREPARED; physical screen footage capture remains a human-led operator task (NOT_RUN until captured).

---

## 1. Recording Setup & Standards

- **Video Resolution**: `1920 x 1080` (1080p Full HD)
- **Aspect Ratio**: `16:9`
- **Frame Rate**: `30 fps` or `60 fps`
- **Recommended Tools**: OBS Studio (free open-source), Windows Snipping Tool (built-in screen recorder: Win + Shift + R), or CapCut.
- **Browser**: Google Chrome, Edge, or Brave at **100% zoom level** (do not zoom in or out).
- **Audio Output**: No microphone recording needed from operator. Voiceover can be rendered using Windows Clipchamp or CapCut AI text-to-speech from `P30_NARRATION_SCRIPT.md`.

---

## 2. Scene-by-Scene Screen Capture Plan

### Scene 1: The Core Dilemma (0:00 – 0:25 / 25 seconds)
- **Source**: Split screen or slide presentation.
- **Left Side**: Visual of an AI coding agent generating code (or open VS Code showing `ResetVault`).
- **Right Side**: Browser or mockup showing traditional CI with `ALL TESTS PASSING (ILLUSTRATIVE GREEN CI)`.
- **Action**:
  - Show the illustrative green CI badge for 8 seconds.
  - Overlay or reveal the question: *"Did the AI fix the bug, or was the test already passing?"*
  - Transition to graphic showing vacuous test passes vs causal verification.
- **Duration**: Record 25 seconds.

---

### Scene 2: The Three-World Causal Engine (0:25 – 0:50 / 25 seconds)
- **Source**: Clean browser window or high-resolution architectural visual (`docs/submission/P30_ARCHITECTURE_VISUAL.md`).
- **Visible Elements**:
  - The 3-World Differential Execution flow:
    - `WORLD 1 (BASE): FAIL` $\rightarrow$ Sealed Witness proves bug was present.
    - `WORLD 2 (CANDIDATE): PASS` $\rightarrow$ AI patch fixes the bug under identical witness.
    - `WORLD 3 (COUNTERFACTUAL): FAIL` $\rightarrow$ Patch delta reverted; proves patch was causally necessary.
  - Tagline prominently displayed: *"If the patch matters, the base must break."*
- **Action**:
  - Step through each of the three worlds sequentially (approx. 7 seconds per world).
- **Duration**: Record 25 seconds.

---

### Scene 3: Live Verification in Action — Nebius Nemotron & Sandboxes (0:50 – 1:20 / 30 seconds)
- **Source**: Terminal window (PowerShell / Windows Terminal with dark theme, e.g. One Half Dark or Campbell) in repository root.
- **Action / Command**:
  1. Open terminal in the Basebreak repository root.
  2. Run the offline clean reproduction script demonstrating the three-world causal triplet (`LOCAL_EXECUTION` subprocess test replay):
     ```powershell
     python -m pytest tests/demo/test_p23_killer_demo.py -k test_p23_03_causal_triplet_subprocess_execution -v
     ```
  3. Show the three-world execution results:
     - `BASE exit 1` (Failure reproduced)
     - `CANDIDATE exit 0` (1 passed in 0.04s)
     - `COUNTERFACTUAL exit 1` (Delta reverted, failure reproduced)
  4. Display the Nebius Nemotron request ID (`chatcmpl-6f406c07...`) and 11 sandbox operations logged from the genuine live run (`RECORDED_LIVE` in `docs/evidence/p29_03_fresh_live_run_evidence_packet/VERIFICATION_AUDIT.md`).
- **Duration**: Record 30 seconds.

---

### Scene 4: Cryptographic Proof & The Public Judge Dashboard (1:20 – 1:50 / 30 seconds)
- **Source**: Browser window (Chrome/Edge in Incognito / Signed-out mode).
- **Primary URL**:
  `https://basebreak.zyganali.workers.dev/judge/run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f`
- **Action**:
  1. **Top Section (Seconds 0–8)**:
     - Highlight the header: `BASEBREAK VERIFICATION RUNTIME`.
     - Hover over top-right badges: `VERIFIED`, `LIVE_NEBIUS`, and `AUTHENTIC SHA-256`.
  2. **World Comparison Grid (Seconds 8–18)**:
     - Scroll down smoothly to the **Three-World Comparison Grid**.
     - Point cursor to `BASE: FAIL (exit 1)`, `CANDIDATE: PASS (exit 0)`, and `COUNTERFACTUAL: FAIL (exit 1)`.
     - Show the tree digests (`824fa2c6...` $\rightarrow$ `6c4f46cb...` $\rightarrow$ `824fa2c6...`).
  3. **Receipt & Proof Details (Seconds 18–30)**:
     - Scroll down to the **Cryptographic Verification Receipt** card.
     - Show Receipt Digest `e2e833fd...` and verifier-signed RSA-2048 Proof Digest `def59353...`.
     - Show Nebius request ID: `chatcmpl-6f406c073cb413917bb3c4dea558d380`.
     - Briefly navigate to the historical 10th run:
       `https://basebreak.zyganali.workers.dev/judge/run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9`
       to demonstrate audit trail consistency across runs.
- **Duration**: Record 30 seconds.

---

### Scene 5: Meaningful External Grounding with Tavily Search (1:50 – 2:15 / 25 seconds)
- **Source**: Browser or editor showing the Grounding Firewall architecture (`docs/evidence/P16_05_TAVILY_GROUNDING_INTEGRATION.md`) and preflight tooling.
- **Visible Elements**:
  - The deterministic advisory grounding flow for `CVE-2024-21626`:
    1. Tavily retrieves authoritative security advisories (e.g. GitHub Advisory Database) (`GroundingMateriality.REQUIRED`).
    2. Grounded facts bind into `GroundedContractBinding` bound to frozen contract digest.
    3. Grounding Authority Firewall enforces that retrieved web claims **NEVER override code execution**.
  - Show the passing test suite in terminal:
    ```powershell
    python -m pytest tests/grounding/test_p16_closure.py -q
    ```
    proving tamper detection and injection blocking.
  - Or show safe preflight status in terminal:
    ```powershell
    python -m basebreak.adapters.tavily.demo --check-preflight
    ```
- **Duration**: Record 25 seconds.

---

### Scene 6: Conclusion & Impact (2:15 – 2:40 / 25 seconds)
- **Source**: Clean browser window showing the public GitHub repository:
  `https://github.com/zyganali-glitch/Basebreak`
- **Action**:
  - Scroll past the README header showing the Apache-2.0 open-source badge, the competition track, and the one-command quickstart.
  - End on the full-screen title slide:
    **BASEBREAK**
    *If the patch matters, the base must break.*
    `https://basebreak.zyganali.workers.dev`
- **Duration**: Record 25 seconds.

---

## 3. Video Assembly Checklist

1. Place recorded clips onto timeline in CapCut, Clipchamp, or Premiere in scene order (Scenes 1 to 6).
2. Trim each clip to match the exact scene timing in `P30_STORYBOARD.md`.
3. Import the generated voiceover audio (`basebreak_voiceover.wav` or AI neural voice from `P30_NARRATION_SCRIPT.md`).
4. Import subtitles: `docs/submission/basebreak_demo_subtitles.srt`.
5. Verify total video duration: **2:40 (160 seconds)**.
6. Export at `1080p` MP4 (H.264 / AAC audio).
