# Basebreak Causal Verification Proof Summary

> **Thesis:** *If the patch matters, the base must break.*
> **Judge Claim:** Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green.

## Verdict & Transition
- **Preliminary Verdict:** `VERIFIED` ([PASS] VERIFIED)
- **Causal Transition:** `CAUSAL_TRIPLET_VERIFIED`
- **Evidence Provenance:** `LIVE_NEBIUS`
- **Verification Timestamp:** `2026-10-07T16:38:30.378928+00:00`

## Verification Identity
- **Basebreak Implementation SHA:** `6bb8e0913d08b307ea4382833d4772380389ca78`

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
| **Sandbox ID** | `sbx-0d559eac1af648ce` | `sbx-4047f62bcebb4a3b` | `sbx-3ed738b2ce7d4ea7` |
| **Source Commit** | `40ff923a134a` | `40ff923a134a` | `40ff923a134a` |
| **Tree Digest** | `f81f6faa0c75` | `31f7ab50a5e0` | `f81f6faa0c75` |
| **Duration** | 1.46s | 1.45s | 1.40s |

## Cryptographic Digest Chain (Unbroken Custody)
| Artifact / Entity | Identifier / Digest |
| :--- | :--- |
| Requirement ID | `REQ-6E7F6FF7` |
| Frozen Contract | `c22049489f5832b20087356ae3983f26e3c2bd869b6693b6d7ee981d6fb48e9b` |
| Witness ID | `wit-req-6e7f6ff7` |
| Witness Seal | `755f9abd2323d255910b9ab41ce792e43b31cb2cb70f6f57a63275536b96b410` |
| Pre-Execution Lock | `d81ea48c1fab7a2920187d5ed81f86909aaf1f81c1cd0be4b771afacee3d3518` |
| BASE Execution | `b9b7bfcdd116920cbf5a9e5fc7bf495bec6bf55f1f08fa9b9f3ad4cd9f3a2d47` |
| CANDIDATE Execution | `88ed59064831f5b11c36597ea5142356daa7ed0c21c075621e3297cee651d1f3` |
| COUNTERFACTUAL Execution | `a1b863b4c1bbbca3d7258223052f63251d877b086f74633171623240b7575c90` |
| Counterfactual ID | `cf-sub-full_pat-2d5dc46403524583` |
| Delta Digest | `2d5dc4640352458323e973643e3a2215ec61d7a5a40996ba08a85516b625536e` |
| **Causal Receipt** | **`3b80457c7d1499fef1b160286bbc386fb6b16ae36921e65f775d338d905eb4a2`** |

## Rationale
Causal triplet verified: BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL under identical witness. Patch delta proved causally necessary.

---
*Generated deterministically by Basebreak Causal Two-World Engine.*
