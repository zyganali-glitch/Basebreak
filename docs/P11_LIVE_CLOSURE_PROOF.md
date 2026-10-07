# Basebreak Causal Verification Proof Summary

> **Thesis:** *If the patch matters, the base must break.*
> **Judge Claim:** Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green.

## Verdict & Transition
- **Preliminary Verdict:** `VERIFIED` ([PASS] VERIFIED)
- **Causal Transition:** `CAUSAL_TRIPLET_VERIFIED`
- **Evidence Provenance:** `LIVE_NEBIUS`
- **Verification Timestamp:** `2026-10-07T11:17:44.544669+00:00`

## Causal Triplet Behavioral Evidence
```
  BASE WORLD      [Outcome: FAIL] (Exit 1)
       |
       v
  CANDIDATE WORLD [Outcome: PASS] (Exit 0)
       |
       v
  COUNTERFACTUAL WORLD [Outcome: FAIL] (Exit 1)
       |
       ===> CAUSAL TRANSITION: CAUSAL_TRIPLET_VERIFIED
       ===> FINAL VERDICT:     VERIFIED
```

### World Execution Comparison
| Dimension | BASE | CANDIDATE | COUNTERFACTUAL World (Delta Subtraction) |
| :--- | :--- | :--- | :--- |
| **Outcome** | `FAIL` | `PASS` | `FAIL` |
| **Exit Code** | `1` | `0` | `1` |
| **Sandbox ID** | `sbx-02a2270ebd2a46c3` | `sbx-baf9bb9ac03b430b` | `sbx-ac9a975636054ed4` |
| **Source Commit** | `40ff923a134a` | `40ff923a134a` | `40ff923a134a` |
| **Tree Digest** | `f81f6faa0c75` | `31f7ab50a5e0` | `f81f6faa0c75` |
| **Duration** | 1.42s | 1.67s | 1.44s |

## Cryptographic Digest Chain (Unbroken Custody)
| Artifact / Entity | Identifier / Digest |
| :--- | :--- |
| Requirement ID | `REQ-6E7F6FF7` |
| Frozen Contract | `c22049489f5832b20087356ae3983f26e3c2bd869b6693b6d7ee981d6fb48e9b` |
| Witness ID | `wit-req-6e7f6ff7` |
| Witness Seal | `164d10c4a33527bfe5f47edceb347a652d727b3ad7530e79e367d882c8c02b85` |
| Pre-Execution Lock | `3c4bc9bceac444e33e19a33eb18fe204c287cc12f22dd7fecafb74742f22a215` |
| BASE Execution | `cc1289ab2e96a0541c62c8c4833c7e0a817235a98d282b088cf70a5e384b3404` |
| CANDIDATE Execution | `aa655a35cd3438f3cd220d637491130a7682444adc8704bc676e03f668b660c7` |
| COUNTERFACTUAL Execution | `b829547ea461338723e0802282b886a688a06e2a661d29849d43cce6502d7c7d` |
| Counterfactual ID | `cf-sub-full_pat-2d5dc46403524583` |
| Delta Digest | `2d5dc4640352458323e973643e3a2215ec61d7a5a40996ba08a85516b625536e` |
| **Causal Receipt** | **`08e0c9b916cace049b09edf34ec2f6d7a8bc9f19e5559a520b102e88f6f8aa85`** |

## Rationale
Causal triplet verified: BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL under identical witness. Patch delta proved causally necessary.

---
*Generated deterministically by Basebreak Causal Two-World Engine.*
