# P-30 Screenshot & Asset Manifest: Basebreak

This manifest catalogs all visual assets, source URLs, capture boundaries, provenance classifications, and operator selections for the Devpost gallery and video demonstration.

> [!NOTE]
> **Execution Status**: Screenshots CAPTURED & SELECTED by the human operator on October 24, 2026. All authentic image files are stored in `docs/submission/screenshots/`. IMG-05 was intentionally cancelled due to unreadable text scaling and was not submitted.

---

## Provenance Standard & Rules

In accordance with Basebreak's Evidence Model:
- **`RECORDED_LIVE`**: Screengrabs and data captured from the verified live executions (`run_3ba7d1fd` fresh run or `run_78fd00b7` tenth run). Retains genuine provider request IDs, sandbox IDs, and RSA signature digests. Never represented as fresh live invocations.
- **`LOCAL_EXECUTION`**: Terminal outputs captured from reproducible local pytest or verification commands (`tests/demo/test_p23_killer_demo.py`).
- **`FIXTURE`**: Diagrams illustrating system flows and firewall behavior.

---

## Operator Selected Assets (Devpost Submission)

The human operator selected the following five assets for the official Devpost submission:

1. **IMG-01** (`01_hero_judge_dashboard.png`) — **Devpost Thumbnail / Hero Image**
   - Provenance: `RECORDED_LIVE`
   - Source: `https://basebreak.zyganali.workers.dev/judge/run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f`
   - Description: Full-width public Judge dashboard displaying VERIFIED verdict, LIVE_NEBIUS badge, three-world comparison, and execution telemetry.
2. **IMG-04** (`04_nebius_telemetry_and_sandboxes.png`) — **Devpost Gallery #1**
   - Provenance: `RECORDED_LIVE`
   - Source: `docs/evidence/p29_03_fresh_live_run_evidence_packet/VERIFICATION_AUDIT.md`
   - Description: Terminal & JSON evidence showing NVIDIA Nemotron 3.5 request and 11 Nebius microVM sandbox operations.
3. **IMG-03** (`03_cryptographic_receipt_card.png`) — **Devpost Gallery #2**
   - Provenance: `RECORDED_LIVE`
   - Source: `https://basebreak.zyganali.workers.dev/judge/run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f`
   - Description: Cryptographic verification receipt card showing receipt digest `e2e833fd...`, verifier-signed RSA-2048 proof, and public auditability.
4. **IMG-11** (`11_tavily_live_observation_blocked.png`) — **Devpost Gallery #3**
   - Provenance: `RECORDED_LIVE`
   - Source: `docs/evidence/p16_05_live_tavily_evidence_packet/tavily_cve_grounding_packet.json`
   - Description: Deterministic authority firewall fail-closed state (`INSUFFICIENT_GROUNDING / BLOCKED`) for Tavily live observation on `CVE-2024-21626`.
5. **IMG-06** (`06_tavily_grounding_firewall_flow.png`) — **Devpost Gallery #4**
   - Provenance: `FIXTURE`
   - Source: `docs/evidence/P16_05_TAVILY_GROUNDING_INTEGRATION.md`
   - Description: Diagram illustrating Tavily search advisory integration, frozen contract binding, and deterministic authority firewall primacy.

---

## Complete Catalog of Captured Assets (`docs/submission/screenshots/`)

| Asset ID | File Name | Provenance | Status / Usage |
|---|---|---|---|
| **IMG-01** | `01_hero_judge_dashboard.png` | `RECORDED_LIVE` | Captured; Devpost Thumbnail; README Figure 1 |
| **IMG-02** | `02_three_world_comparison_grid.png` | `RECORDED_LIVE` | Captured; Three-world comparison close-up |
| **IMG-03** | `03_cryptographic_receipt_card.png` | `RECORDED_LIVE` | Captured; Devpost Gallery #2; README Figure 2 |
| **IMG-04** | `04_nebius_telemetry_and_sandboxes.png` | `RECORDED_LIVE` | Captured; Devpost Gallery #1 |
| **IMG-05** | `05_three_world_architecture_diagram.png` | `FIXTURE` | **CANCELLED** by operator (unreadable text scaling) |
| **IMG-06** | `06_tavily_grounding_firewall_flow.png` | `FIXTURE` | Captured; Devpost Gallery #4 |
| **IMG-07** | `07_terminal_local_verification.png` | `LOCAL_EXECUTION` | Captured; Local subprocess pytest replay |
| **IMG-08** | `08_historical_tenth_run_comparison.png` | `RECORDED_LIVE` | Captured; Canonical 10th run audit trail |
| **IMG-09** | `09_real_ci_success.png` | `RECORDED_LIVE` | Captured; GitHub Actions CI all green |
| **IMG-10** | `10_ci_test_steps.png` | `RECORDED_LIVE` | Captured; GitHub Actions CI step breakdown |
| **IMG-11** | `11_tavily_live_observation_blocked.png` | `RECORDED_LIVE` | Captured; Devpost Gallery #3 |
