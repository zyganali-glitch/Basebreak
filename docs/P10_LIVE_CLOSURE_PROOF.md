# Basebreak Causal Verification Proof Summary

> **Thesis:** *If the patch matters, the base must break.*
> **Judge Claim:** Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green.

## Verdict & Transition
- **Preliminary Verdict:** `VERIFIED` ([PASS] VERIFIED)
- **Causal Transition:** `CAUSAL_BUG_FIX_VERIFIED`
- **Evidence Provenance:** `LIVE_NEBIUS`
- **Verification Timestamp:** `2026-10-05T10:36:24.768526+00:00`

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
| **Sandbox ID** | `sbx-d3000fd11079488d` | `sbx-e75edfab7b8c4d60` |
| **Source Commit** | `81ff638c14e5` | `81ff638c14e5` |
| **Tree Digest** | `5ca64f890757` | `3b8235197f5f` |
| **Duration** | 1.60s | 2.08s |

## Cryptographic Digest Chain (Unbroken Custody)
| Artifact / Entity | Identifier / Digest |
| :--- | :--- |
| Requirement ID | `REQ-A1B63A4A` |
| Frozen Contract | `d719a8af526ac5ef430c10a2e8b6291398686692b065ddaf582cfd56186f4ca5` |
| Witness ID | `wit-req-a1b63a4a` |
| Witness Seal | `76ce0cd8384ac9bcc966d3fe27e3eaa5f1ec8bfd9845796ddb283da27cac95dc` |
| Pre-Execution Lock | `2c5a8515050b7a799b05c48184895c60dbfdedc2778deb3031c67740fea6d331` |
| BASE Execution | `d359117ed12763d29b7107cdfb59eb70ca3723f63c10c224a7a9d5b8c93ecc92` |
| CANDIDATE Execution | `0b00d2f790f8e51829e29570cd57e1f6c1876c256ceb4656e36506dc0111bdf5` |
| **Causal Receipt** | **`6ba5502d0947e5825cb08a8dbe80cfd5772e7836dac52d664c5aa883dff66ded`** |

## Rationale
BASE broke (FAIL) and CANDIDATE passed (PASS) under identical witness: causal BUG_FIX verified.

---
*Generated deterministically by Basebreak Causal Two-World Engine.*
