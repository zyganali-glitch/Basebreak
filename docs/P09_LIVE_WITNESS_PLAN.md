# P-09 Live Witness Plan Proof

## Overview
This document records the live execution proof for **P-09 (Witness Generation)** using the real Nebius Token Factory API and `nvidia/Nemotron-3_5-Lightning`.

- **Date:** 2026-10-05
- **Provenance:** `LIVE_NEBIUS`
- **Model Endpoint:** `https://api.tokenfactory.nebius.com/v1`
- **Model ID:** `nvidia/Nemotron-3_5-Lightning`
- **Tested Base Commit SHA:** `55abf808e9fc01d5003ef32d61557800942ceed8`

## Protocol Execution Details

1. **Frozen Contract Context:**
   - Contract Task: `When user specifies --quiet flag, stdout must be empty.`
   - Change Semantics: `BUG_FIX` (DeterministicClassificationFact certainty: 1.0)
   - Requirement ID: `REQ-F5ABFD4A`
   - Requirement Citation: `When user specifies --quiet flag, stdout must be empty.`

2. **Verifier Isolation & Zero Builder Leakage:**
   - Input provided to Nemotron was constructed strictly from `VerifierContextEnvelope` and trusted base source files (`src/cli.py`).
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
