# P-09 Live Witness Plan Proof

## Overview
This document records the live execution proof for **P-09 (Witness Generation)** using the real Nebius Token Factory API and `nvidia/Nemotron-3_5-Lightning` bound to the exact Basebreak implementation SHA.

- **Tested Basebreak Implementation SHA:** `81ff638c14e5a29938b457bc8f368efc490ae4c3`
- **Date:** 2026-10-05
- **Provenance:** `LIVE_NEBIUS`
- **Model Endpoint:** `https://api.tokenfactory.nebius.com/v1`
- **Model ID:** `nvidia/Nemotron-3_5-Lightning`
- **Target Repository Locator:** `https://github.com/zyganali-glitch/Basebreak.git`
- **Target Base Commit SHA:** `81ff638c14e5a29938b457bc8f368efc490ae4c3`
- **Witness Plan Digest:** `7387296c34508187aac006ef9838d0919f723bfc4a5c2a59949223eae7e8bde4`
- **Sealed Witness Seal Digest:** `76ce0cd8384ac9bcc966d3fe27e3eaa5f1ec8bfd9845796ddb283da27cac95dc`
- **Pre-Execution Witness Lock Digest:** `2c5a8515050b7a799b05c48184895c60dbfdedc2778deb3031c67740fea6d331`

## Protocol Execution Details

1. **Frozen Contract Context:**
   - Contract Task: `When user specifies --quiet flag, stdout must be empty.`
   - Change Semantics: `BUG_FIX` (DeterministicClassificationFact certainty: 1.0)
   - Requirement ID: `REQ-A1B63A4A`
   - Frozen Contract Digest: `d719a8af526ac5ef430c10a2e8b6291398686692b065ddaf582cfd56186f4ca5`

2. **Verifier Isolation & Zero Builder Leakage:**
   - Input provided to Nemotron was constructed strictly from `VerifierContextEnvelope` and trusted base source files (`src/basebreak/cli.py`).
   - Zero Builder context, reasoning, patches, or test names were included.
   - Non-authoritative model proposal was received.

3. **Deterministic Validation (P-09.02):**
   - Scope: strictly `BUG_FIX`.
   - Command: allowlisted executable (`pytest`).
   - Paths: normalized and checked against `ProtectedSurfaceManifest` and verifier boundaries.
   - Secrets: zero credentials detected.

4. **Authentic Sealing into TrustedWitnessVault (P-09.03):**
   - Sealed record generated with SHA-256 artifact digests and HMAC-SHA256 vault signature.
   - Integrity mechanically verified via `vault.verify_witness_integrity()`.

5. **Immutable Witness Lock (P-09.06):**
   - Immutable lock generated before candidate execution:
     `create_witness_lock(sealed_record, vault)`
   - Cryptographic chain binding:
     `requirement_id -> frozen_contract_digest -> witness_digest`
   - Verified that any mutated candidate witness fails closed.

## Deterministic Verification Invariants

- **Outcome anti-collapse (P-09.04):** TIMEOUT and ERROR never collapse into FAIL or PASS.
- **Vacuity defense (P-09.05):** Witnesses with zero assertions, trivial constant assertions (`assert True`), or 0 collected tests fail closed.
- **Billing safety:** Promotional credit safety floor ($5.00) strictly preserved.
