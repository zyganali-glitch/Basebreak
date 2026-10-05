# P-09 Live Witness Plan Proof

## Overview
This document records the live execution proof for **P-09 (Witness Generation)** using the real Nebius Token Factory API and `nvidia/Nemotron-3_5-Lightning` bound to the exact Basebreak implementation SHA and isolated demo target.

- **Tested Basebreak Implementation SHA:** `15aeeb73d486f83795fe8431bd0403b354d18ff2`
- **Date:** 2026-10-05
- **Provenance:** `LIVE_NEBIUS`
- **Model Endpoint:** `https://api.tokenfactory.nebius.com/v1`
- **Model ID:** `nvidia/Nemotron-3_5-Lightning`
- **Target Repository Locator:** `https://github.com/zyganali-glitch/basebreak-demo-target.git`
- **Target Base Commit SHA:** `40ff923a134a21d8e357deb7a7988571cd396b56`
- **Target Base Tree SHA:** `f81f6faa0c7572f9941570bbce376fadc10f39a3`
- **Witness Plan Digest:** `d6f8329bcb52665aa86b4c334a1c9e3e0cfa2508f4306c70b25e32c4e554540b`
- **Sealed Witness Seal Digest:** `a4cc1951f7e6394c8098f19856e0dcca12e2b350e9828d7f663fba1d2c95dc06`
- **Pre-Execution Witness Lock Digest:** `e48444e6c7c65a65260b3496610d6a79158ccab93cdbcad69f8b5767d8ec76ba`

## Protocol Execution Details

1. **Frozen Contract Context:**
   - Contract Task: `When user specifies --quiet flag, stdout must be empty.`
   - Change Semantics: `BUG_FIX` (DeterministicClassificationFact certainty: 1.0)
   - Requirement ID: `REQ-6E7F6FF7`
   - Frozen Contract Digest: `77b67a648b9f9d92a3af6e9c0203ef641a6a76618464e3c3d383c7d2b7a134c1`

2. **Verifier Isolation & Zero Builder Leakage:**
   - Input provided to Nemotron was constructed strictly from `VerifierContextEnvelope` and isolated target repository source files (`src/demo_target/cli.py`).
   - Basebreak production code (`src/basebreak/`) contains zero planted defects and is completely isolated from the target.
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
- **Target / Product Identity Separation:** Basebreak verifier implementation SHA (`15aeeb73d486f83795fe8431bd0403b354d18ff2`) is explicitly distinguished from Target repository commit (`40ff923a134a21d8e357deb7a7988571cd396b56`).
- **Billing safety:** Promotional credit safety floor ($5.00) strictly preserved.
