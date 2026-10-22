# P-30 Screenshot & Asset Manifest: Basebreak

This manifest catalogs all visual assets, source URLs, capture boundaries, provenance classifications, and intended uses for the Devpost gallery and video demonstration.

---

## Provenance Standard & Rules

In accordance with Basebreak's Evidence Model:
- **`RECORDED_LIVE`**: Screengrabs and data captured from the verified live executions (`run_3ba7d1fd` fresh run or `run_78fd00b7` tenth run). Retains genuine provider request IDs, sandbox IDs, and RSA signature digests. Never represented as fresh live invocations.
- **`LOCAL_EXECUTION`**: Terminal outputs captured from reproducible local pytest or verification commands.
- **`FIXTURE`**: Mockups or diagrams illustrating conceptual flows (clearly designated as architectural diagrams).

---

## Asset Catalog

| Asset ID | File Name | Source / URL | Provenance | Description & Visual Content | Intended Placement |
|---|---|---|---|---|---|
| **IMG-01** | `01_hero_judge_dashboard.png` | `https://basebreak.zyganali.workers.dev/judge/run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f` | `RECORDED_LIVE` | Full-width viewport showing header, `VERIFIED` verdict badge, `LIVE_NEBIUS` badge, core tagline, and top summary cards. | Devpost Hero Image / Video Scene 4 |
| **IMG-02** | `02_three_world_comparison_grid.png` | `https://basebreak.zyganali.workers.dev/judge/run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f` | `RECORDED_LIVE` | Close-up of the Three-World Comparison Grid showing `BASE (FAIL)`, `CANDIDATE (PASS)`, and `COUNTERFACTUAL (FAIL)` with exit codes and tree digests. | Devpost Gallery #1 / Video Scene 2 & 4 |
| **IMG-03** | `03_cryptographic_receipt_card.png` | `https://basebreak.zyganali.workers.dev/judge/run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f` | `RECORDED_LIVE` | The Cryptographic Verification Receipt card showing SHA-256 Receipt Digest `e2e833fd...`, RSA-2048 Proof Digest `def59353...`, and signed-out public auditability. | Devpost Gallery #2 / Video Scene 4 |
| **IMG-04** | `04_nebius_telemetry_and_sandboxes.png` | `docs/evidence/p29_03_fresh_live_run_evidence_packet/VERIFICATION_AUDIT.md` | `RECORDED_LIVE` | Terminal / JSON showing `nvidia/Nemotron-3_5-Lightning` request `chatcmpl-6f406c07...` and 11 Nebius microVM sandbox operation IDs. | Devpost Gallery #3 / Video Scene 3 |
| **IMG-05** | `05_three_world_architecture_diagram.png` | `docs/submission/P30_ARCHITECTURE_VISUAL.md` | `FIXTURE` | High-contrast architecture diagram illustrating the Three-World verification pipeline, verifier bridge, and Cloudflare edge. | Devpost Gallery #4 / Video Scene 2 |
| **IMG-06** | `06_tavily_grounding_firewall_flow.png` | `docs/evidence/P16_05_TAVILY_GROUNDING_INTEGRATION.md` | `FIXTURE` | Diagram illustrating the Tavily search integration for `CVE-2024-21626`, contract binding, and deterministic authority firewall primacy. | Devpost Gallery #5 / Video Scene 5 |
| **IMG-07** | `07_terminal_local_verification.png` | Local execution of `tests/demo/test_p23_killer_demo.py` | `LOCAL_EXECUTION` | Windows Terminal showing clean pytest execution reproducing the exact three-world causal triplet in 0.04s. | Devpost Gallery #6 / Video Scene 3 |
| **IMG-08** | `08_historical_tenth_run_comparison.png` | `https://basebreak.zyganali.workers.dev/judge/run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9` | `RECORDED_LIVE` | Historical 10th run audit trail view proving audit reproducibility and immutable Durable Object ledger preservation. | Devpost Gallery #7 / Video Scene 4 |

---

## Recommended Devpost Gallery Sequence

1. **IMG-01** (`01_hero_judge_dashboard.png`): Primary cover image showing the live public Judge UI with `VERIFIED` and `LIVE_NEBIUS` badges.
2. **IMG-02** (`02_three_world_comparison_grid.png`): The Three-World Differential Execution Grid proving `BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL`.
3. **IMG-05** (`05_three_world_architecture_diagram.png`): Full end-to-end architecture showing Nemotron, Nebius Sandboxes, and Cloudflare Workers.
4. **IMG-03** (`03_cryptographic_receipt_card.png`): Tamper-proof cryptographic receipt with RSA-2048 verifier proof.
5. **IMG-04** (`04_nebius_telemetry_and_sandboxes.png`): NVIDIA Nemotron request and 11 Nebius microVM sandbox operations.
6. **IMG-06** (`06_tavily_grounding_firewall_flow.png`): Tavily external grounding workflow for `CVE-2024-21626` and authority firewall.
7. **IMG-07** (`07_terminal_local_verification.png`): Terminal verification showing one-command zero-dependency local reproduction.
