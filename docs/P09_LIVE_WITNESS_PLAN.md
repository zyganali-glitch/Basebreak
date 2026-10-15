# P-09 Live Witness Plan Proof

## Overview
This document records the live execution proof for **P-09 (Witness Generation)**
using the real Nebius Token Factory API and `nvidia/Nemotron-3_5-Lightning` bound to
the exact Basebreak implementation SHA and isolated demo target.

- **Tested Basebreak Implementation SHA:** `32235bce2ab31550406ca948f3111892765245df`
- **Date:** 2026-10-05
- **Provenance:** `LIVE_NEBIUS`
- **Model Endpoint:** `https://api.tokenfactory.nebius.com/v1`
- **Model ID:** `nvidia/Nemotron-3_5-Lightning`
- **Target Repository Locator:** `https://github.com/zyganali-glitch/basebreak-demo-target.git`
- **Target BASE Commit SHA:** `40ff923a134a21d8e357deb7a7988571cd396b56`
- **Target BASE Tree SHA:** `f81f6faa0c7572f9941570bbce376fadc10f39a3`
- **Witness Plan Digest:** `250a358aead71434e8bc28fd5eb9d9ef7fe86bb79054fab3d6c703f4d5d4d74c`
- **Sealed Witness Seal Digest:** `d4430f6e89dbf74f6fe250747b4225a7982872ef7ebe0e4261fd9f53cb587ae0`
- **Pre-Execution Witness Lock Digest:** `56ff5425f448cd8a7a1f981cfc9849854cd4403673aafb2d0192a773f263024c`

## Protocol Execution Details

1. **Frozen Contract Context:**
   - Contract Task: `When user specifies --quiet flag, stdout must be empty.`
   - Change Semantics: `BUG_FIX` (DeterministicClassificationFact certainty: 1.0)
   - Requirement ID: `REQ-6E7F6FF7`
   - Frozen Contract Digest: `c22049489f5832b20087356ae3983f26e3c2bd869b6693b6d7ee981d6fb48e9b`

2. **Verifier Isolation & Zero Builder Leakage:**
   - Input provided to Nemotron was constructed strictly from `VerifierContextEnvelope`
     and isolated target repository source files (`src/demo_target/cli.py`).
   - Basebreak production code (`src/basebreak/`) contains zero planted defects and
     is completely isolated from the target.
   - Zero Builder context, reasoning, patches, or test names were included.
   - Non-authoritative model proposal was received.

3. **Deterministic Validation (P-09.02):**
   - Scope: strictly `BUG_FIX`.
   - Command: allowlisted executable (`pytest`).
   - Paths: normalized and checked against `ProtectedSurfaceManifest` and boundaries.
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
- **Vacuity defense (P-09.05):** Witnesses with zero assertions, trivial constant
  assertions (`assert True`), or 0 collected tests fail closed.
- **Target / Product Identity Separation:** Basebreak verifier implementation SHA
  (`32235bce2ab31550406ca948f3111892765245df`) is explicitly distinguished from Target repository commit
  (`40ff923a134a21d8e357deb7a7988571cd396b56`).
- **Billing safety:** Promotional credit safety floor ($5.00) strictly preserved.
