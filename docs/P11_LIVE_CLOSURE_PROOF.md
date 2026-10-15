# Basebreak Causal Verification Proof Summary

> **Thesis:** *If the patch matters, the base must break.*
> **Judge Claim:** Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green.

## Verdict & Transition
- **Preliminary Verdict:** `VERIFIED` ([PASS] VERIFIED)
- **Causal Transition:** `CAUSAL_TRIPLET_VERIFIED`
- **Evidence Provenance:** `LIVE_NEBIUS`
- **Verification Timestamp:** `2026-10-15T09:22:25.451074+00:00`

## Verification Identity
- **Basebreak Implementation SHA:** `32235bce2ab31550406ca948f3111892765245df`

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
| **Sandbox ID** | `sbx-806dedc2c6e54945` | `sbx-b6b66b44f0434144` | `sbx-27ab2fc07cd54305` |
| **Source Commit** | `40ff923a134a` | `40ff923a134a` | `40ff923a134a` |
| **Tree Digest** | `f81f6faa0c75` | `31f7ab50a5e0` | `f81f6faa0c75` |
| **Duration** | 1.43s | 1.47s | 1.49s |

## Cryptographic Digest Chain (Unbroken Custody)
| Artifact / Entity | Identifier / Digest |
| :--- | :--- |
| Requirement ID | `REQ-6E7F6FF7` |
| Frozen Contract | `c22049489f5832b20087356ae3983f26e3c2bd869b6693b6d7ee981d6fb48e9b` |
| Witness ID | `wit-req-6e7f6ff7` |
| Witness Seal | `2c7fae394e4a1f7e4cc489b9798cd98c4d0cc6d6538e54226de860478be90a44` |
| Pre-Execution Lock | `4f37a62c8abf3be680cec340b9441df572f3771b14b5a813bc39ff397739ba58` |
| BASE Execution | `2adeb86c7720c8c6857337438f5c202ea5ef21a88e4e1a72fbd3bc72f167bbbc` |
| CANDIDATE Execution | `d7286b0c10cd3433ebdcea91495bbe4eba37df2d4de24c812370206097c0aee2` |
| COUNTERFACTUAL Execution | `833b6901dbfa976b8f8a94e79bf1cdd158312b267ea1265228de9d99e0ecc02f` |
| Counterfactual ID | `cf-sub-full_pat-2d5dc46403524583` |
| Delta Digest | `2d5dc4640352458323e973643e3a2215ec61d7a5a40996ba08a85516b625536e` |
| **Causal Receipt** | **`0f3f2bd3f2c297706ba1dd906b2e59605ea269ae5f3fca806696f250445c2b6e`** |

## Rationale
Causal triplet verified: BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL under identical witness. Patch delta proved causally necessary.

---
*Generated deterministically by Basebreak Causal Two-World Engine.*
