# P-30 Video Safety & Truthfulness Checklist

Before publishing the final demo video to YouTube or embedding it in the Devpost submission, verify every item on this checklist.

---

## 1. Secrets & Privacy Boundary

- [ ] **No API Keys or Secrets Visible**: Ensure no `NEBIUS_API_KEY`, `TAVILY_API_KEY`, Cloudflare admin tokens, or SSH keys appear in any screen recording, terminal prompt, code editor, or environment dump.
- [ ] **No Personal Credentials or Billing Information**: Confirm no credit card numbers, billing addresses, or personal phone numbers are visible.
- [ ] **Sanitized Terminal Excerpts**: Any environment inspection in terminal recordings must use boolean masks (e.g. `bool(os.environ.get('KEY'))`), never printing raw token values.

---

## 2. Accurate Evidence & Provenance Labels

- [ ] **Truthful Provenance Labeling**: In video scenes displaying previous live executions (`run_3ba7d1fd` fresh run or `run_78fd00b7` tenth run), the display must be clearly identified as **`RECORDED_LIVE`**.
- [ ] **No Replay Masquerading as Live Invocations**: Playback of historical recordings must never imply that a live API call is taking place in real time during the video.
- [ ] **Authentic Provider Telemetry**: All displayed request IDs (`chatcmpl-6f406c07...`), token counts (1,123 prompt / 693 completion), and sandbox IDs (`sbx-c9e5c0e4...`) must match exact committed evidence in `docs/evidence/EVIDENCE_MANIFEST.md`.

---

## 3. Scope & Verification Honesty

- [ ] **Single Sealed Witness Honesty**: The live demonstration accurately verifies **one sealed behavioral witness** (`wit-reset-vault-live-001`, `test_single_use_witness.py`) under the canonical `ResetVault` scenario. The script and text must not claim a massive multi-witness suite for the live run.
- [ ] **Empirical Causal Verification, Not Global Proof**: Verification must be described as *empirical causal evidence under the executed witness*, proving that the patch caused the state transition for that test. Never claim mathematical proof of global correctness.
- [ ] **Raw RSA Signature Disclosure**: The cryptographic proof is generated using custom 2048-bit raw modular exponentiation RSA over SHA-256 digests. Do not claim standard PKCS#1 v1.5 or RSA-PSS padding.
- [ ] **Accurate Test Counts**: Production test counts must reflect exact repository reality (2,989+ Python pytest tests, 71 Node tests, 54 grounding/Tavily tests). Never inflate test numbers.

---

## 4. Scenario & External Grounding Separation

- [ ] **Distinct Scenario Identity**: The `ResetVault` scenario (internal invariant test, `GroundingMateriality.NOT_APPLICABLE`) and the `CVE-2024-21626` scenario (runc advisory grounding, `GroundingMateriality.REQUIRED`) must be presented as separate scenarios.
- [ ] **No False Grounding Attribution**: Never imply that the `ResetVault` receipt was generated using Tavily search.
- [ ] **Deterministic Firewall Primacy**: In the Tavily explanation, clearly state that external web search results **never override code execution failure** in the sandbox.

---

## 5. Technical Specifications & Accessibility

- [ ] **Duration**: Strictly under 3 minutes (< 180 seconds). Recommended: **2:30 – 2:40 (150–160 seconds)**.
- [ ] **Resolution**: 1080p Full HD (`1920x1080`), 16:9 aspect ratio.
- [ ] **Audio & Captions**: Clear English voiceover narration and complete, synchronized English subtitles (`.srt`).
- [ ] **YouTube Visibility**: Set to **Public** or **Unlisted** (never Private) so hackathon judges can view without permission requests.
