# Basebreak Causal Verification Proof Summary

> **Thesis:** *If the patch matters, the base must break.*
> **Judge Claim:** Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green.

## Verdict & Transition
- **Preliminary Verdict:** `VERIFIED` ([PASS] VERIFIED)
- **Causal Transition:** `CAUSAL_BUG_FIX_VERIFIED`
- **Evidence Provenance:** `LIVE_NEBIUS`
- **Verification Timestamp:** `2026-10-05T12:03:59.481078+00:00`

## Target / Product Identity Separation
| Identity Dimension | Value | Notes |
| :--- | :--- | :--- |
| **Basebreak Verifier Implementation SHA** | `15aeeb73d486f83795fe8431bd0403b354d18ff2` | Engine code running the verification |
| **Target Repository Locator** | `https://github.com/zyganali-glitch/basebreak-demo-target.git` | Isolated public demo repository |
| **Target BASE Commit** | `40ff923a134a21d8e357deb7a7988571cd396b56` | Root commit containing intentional defect |
| **Target BASE Tree** | `f81f6faa0c7572f9941570bbce376fadc10f39a3` | Materialized base tree in BASE sandbox |
| **Candidate Patch Digest** | `2d5dc4640352458323e973643e3a2215ec61d7a5a40996ba08a85516b625536e` | Exact captured patch fixing defect |
| **Expected Candidate Tree** | `31f7ab50a5e0da6da9160ce47bdc5daf71072216` | Pre-calculated clean candidate tree |
| **Actual Candidate Tree** | `31f7ab50a5e0da6da9160ce47bdc5daf71072216` | Materialized tree in CANDIDATE sandbox |
| **Tree Equality Match?** | **EXACT MATCH** | Bit-for-bit candidate reproduction verified |

## Two-World Behavioral Evidence
```
  BASE WORLD      [Outcome: FAIL] (Exit 1)
       |
       v
  CANDIDATE WORLD [Outcome: PASS] (Exit 0)
       |
       ===> CAUSAL TRANSITION: CAUSAL_BUG_FIX_VERIFIED
       ===> FINAL VERDICT:     VERIFIED
```

### World Execution Comparison
| Dimension | BASE World (Trusted Baseline) | CANDIDATE World (Reproduced Change) |
| :--- | :--- | :--- |
| **Outcome** | `FAIL` | `PASS` |
| **Exit Code** | `1` | `0` |
| **Sandbox ID** | `sbx-b607b89e2128481a` | `sbx-65e2598b2ee7497b` |
| **Target Commit** | `40ff923a134a` | `40ff923a134a` |
| **Tree Digest** | `f81f6faa0c75` | `31f7ab50a5e0` |
| **Duration** | 1.38s | 1.46s |

## Cryptographic Digest Chain (Unbroken Custody)
| Artifact / Entity | Identifier / Digest |
| :--- | :--- |
| Requirement ID | `REQ-6E7F6FF7` |
| Frozen Contract | `77b67a648b9f9d92a3af6e9c0203ef641a6a76618464e3c3d383c7d2b7a134c1` |
| Witness ID | `wit-req-6e7f6ff7` |
| Witness Seal | `a4cc1951f7e6394c8098f19856e0dcca12e2b350e9828d7f663fba1d2c95dc06` |
| Pre-Execution Lock | `e48444e6c7c65a65260b3496610d6a79158ccab93cdbcad69f8b5767d8ec76ba` |
| BASE Execution | `522e7fcffd0f73fcff8f176ea0d006f240b086ce712f53cb33fddf12ff1c7fa5` |
| CANDIDATE Execution | `75aee55363e9a6d556987a690c8cb23be24918b788a2813bd1d17327cedee7e9` |
| **Causal Receipt** | **`054da1affa5f060ad94ddf9ddcf213d787cdfa85b75ba15c94031a51cc40e4a2`** |

## Rationale
BASE broke (FAIL) and CANDIDATE passed (PASS) under identical witness: causal BUG_FIX verified.

---
*Generated deterministically by Basebreak Causal Two-World Engine.*
