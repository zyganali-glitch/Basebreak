# Basebreak Causal Verification Proof Summary

> **Thesis:** *If the patch matters, the base must break.*
> **Judge Claim:** Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green.

## Verdict & Transition
- **Preliminary Verdict:** `VERIFIED` ([PASS] VERIFIED)
- **Causal Transition:** `CAUSAL_BUG_FIX_VERIFIED`
- **Evidence Provenance:** `LIVE_NEBIUS`
- **Verification Timestamp:** `2026-10-05T12:24:40.490858+00:00`

## Target / Product Identity Separation
| Identity Dimension | Value | Notes |
| :--- | :--- | :--- |
| **Basebreak Verifier Implementation SHA** | `6cdbe613eada838b31d8d97620f3f02bf19a8916` | Engine code running |
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
| **Sandbox ID** | `sbx-7f6f7a7008bd43ca` | `sbx-46191eab217f4a45` |
| **Target Commit** | `40ff923a134a` | `40ff923a134a` |
| **Tree Digest** | `f81f6faa0c75` | `31f7ab50a5e0` |
| **Duration** | 1.45s | 1.44s |

## Cryptographic Digest Chain (Unbroken Custody)
| Artifact / Entity | Identifier / Digest |
| :--- | :--- |
| Requirement ID | `REQ-6E7F6FF7` |
| Frozen Contract | `c22049489f5832b20087356ae3983f26e3c2bd869b6693b6d7ee981d6fb48e9b` |
| Witness ID | `wit-req-6e7f6ff7` |
| Witness Seal | `ca92d963f1e45c7581bdd25d230ef8019d75c242d078a0f069545cc8f456c866` |
| Pre-Execution Lock | `c788926f1b8e43d84aae9684ec07d98a1bcfe042972b6f3f326d5eb494e24459` |
| BASE Execution | `c251d40af60724503e96ecbde83ab0f8189fbc26ffc5fbb23b25f5307c42b424` |
| CANDIDATE Execution | `238bb5b3fed7bfd0a56d086741a31b65f6f8e83a27131f1a131aa22397a63f0a` |
| **Causal Receipt** | **`ebf2c14685be119a6476b9587e5702d379368d0fb9a5e1cf1d72deda81b0b676`** |

## Rationale
BASE broke (FAIL) and CANDIDATE passed (PASS) under identical witness: causal BUG_FIX verified.

---
*Generated deterministically by Basebreak Causal Two-World Engine.*
