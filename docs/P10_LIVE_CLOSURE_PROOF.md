# Basebreak Causal Verification Proof Summary

> **Thesis:** *If the patch matters, the base must break.*
> **Judge Claim:** Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green.

## Verdict & Transition
- **Preliminary Verdict:** `VERIFIED` ([PASS] VERIFIED)
- **Causal Transition:** `CAUSAL_BUG_FIX_VERIFIED`
- **Evidence Provenance:** `LIVE_NEBIUS`
- **Verification Timestamp:** `2026-10-15T09:21:26.107792+00:00`

## Target / Product Identity Separation
| Identity Dimension | Value | Notes |
| :--- | :--- | :--- |
| **Basebreak Verifier Implementation SHA** | `32235bce2ab31550406ca948f3111892765245df` | Engine code running |
| **Target Repository Locator** | `https://github.com/zyganali-glitch/basebreak-demo-target.git` | Isolated public demo repository |
| **Target BASE Commit** | `40ff923a134a21d8e357deb7a7988571cd396b56` | Root commit containing defect |
| **Target BASE Tree** | `f81f6faa0c7572f9941570bbce376fadc10f39a3` | Base tree in BASE sandbox |
| **Candidate Patch Digest** | `2d5dc4640352458323e973643e3a2215ec61d7a5a40996ba08a85516b625536e` | Captured patch fixing defect |
| **Expected Candidate Tree** | `31f7ab50a5e0da6da9160ce47bdc5daf71072216` | Pre-calculated candidate tree |
| **Actual Candidate Tree** | `31f7ab50a5e0da6da9160ce47bdc5daf71072216` | Materialized tree in CANDIDATE |
| **Tree Equality Match?** | **EXACT MATCH** | Bit-for-bit candidate verified |

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
| **Sandbox ID** | `sbx-dc75a9541e16408f` | `sbx-feddf5fdc89d4125` |
| **Target Commit** | `40ff923a134a` | `40ff923a134a` |
| **Tree Digest** | `f81f6faa0c75` | `31f7ab50a5e0` |
| **Duration** | 1.38s | 1.40s |

## Cryptographic Digest Chain (Unbroken Custody)
| Artifact / Entity | Identifier / Digest |
| :--- | :--- |
| Requirement ID | `REQ-6E7F6FF7` |
| Frozen Contract | `c22049489f5832b20087356ae3983f26e3c2bd869b6693b6d7ee981d6fb48e9b` |
| Witness ID | `wit-req-6e7f6ff7` |
| Witness Seal | `d4430f6e89dbf74f6fe250747b4225a7982872ef7ebe0e4261fd9f53cb587ae0` |
| Pre-Execution Lock | `56ff5425f448cd8a7a1f981cfc9849854cd4403673aafb2d0192a773f263024c` |
| BASE Execution | `3c792509042286d1bb9dc97876dfb33ff32fa6ea6e944cf822174a5a01252bf4` |
| CANDIDATE Execution | `658979c7e9648e1f03da208b7105b06a229f60a765a72923bbb80036f6ead740` |
| **Causal Receipt** | **`36e84ab513169748c5b0d38dcf82abd8a5c2d4fcc8577f0c6f8b4e74191c0fab`** |

## Rationale
BASE broke (FAIL) and CANDIDATE passed (PASS) under identical witness: causal BUG_FIX verified.

---
*Generated deterministically by Basebreak Causal Two-World Engine.*
