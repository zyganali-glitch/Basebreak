# Basebreak Reproducibility Guide & Clean Installation

This document provides complete, copyable, working instructions to reproduce Basebreak from a clean checkout on Linux, macOS, or Windows.

Competition: **Nebius x NVIDIA Global AI Hackathon**  
Track: **Coding and Agentic Engineering**  
Product Thesis: **"If the patch matters, the base must break."**

---

## 1. Public vs. Private Operator Architecture Separation

To guarantee zero personal spend and prevent credential leakage, Basebreak strictly separates public verification and local evaluation from private operator-only infrastructure:

| Component | Public Evaluator / Judge Path | Private Operator Infrastructure |
|---|---|---|
| **Python Runtime** | Pure standard library (`dependencies = []`), zero external runtime requirements. | Same clean Python codebase. |
| **Development Tooling** | `ruff`, `mypy`, `pytest`, `python-dotenv`. | Same developer tooling. |
| **Worker Edge & UI** | Cloudflare Workers Free Tier, Static Assets, SQLite Durable Object (`test:node`, `test:workerd-preflight`). | Deployed Worker at `https://basebreak.zyganali.workers.dev` (Fail-closed live gate). |
| **Causal Evidence** | Content-addressed cryptographic receipts and RSA-2048 verification proofs in `docs/evidence/`. | Authenticated Durable Object ledger records and diagnostic logs. |
| **Signing Authority** | Pinned public modulus and public exponent (65537) in source code. | Private signing key held exclusively on isolated root storage (`/etc/basebreak/verifier-signing-key.hex`, mode 0600). |
| **Provider Inference & Sandboxes** | Offline fixtures, simulated sandboxes, and recorded live receipts. Zero external credits required. | Nebius Token Factory (`nvidia/Nemotron-3_5-Lightning`) & Nebius Sandboxes under promotional credit bounds. |

---

## 2. Quickstart Clean-Install Instructions

### Prerequisites
- **Git** (2.30+)
- **Python** (3.11, 3.12, or 3.13)
- **Node.js** (20+ or 22+ recommended; 24 supported)

### Step 1: Clone Repository
```bash
git clone https://github.com/zyganali-glitch/Basebreak.git
cd Basebreak
```

### Step 2: Python Virtual Environment & Dependencies
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows (cmd):
.venv\Scripts\activate.bat
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Upgrade pip and install package in editable mode with development tools
python -m pip install --upgrade pip
python -m pip install -e ".[dev]" -c constraints.txt
```

### Step 3: Cloudflare Worker Testing Dependencies
```bash
cd cloudflare
npm ci
cd ..
```

---

## 3. Running Full Validation Gates

Every gate runs deterministically offline without requiring network access, API keys, or provider credits.

### A. Ruff Linter & Format Check
```bash
python -m ruff format --check .
python -m ruff check .
```
*Expected Output:* All files formatted, all checks passed.

### B. Mypy Strict Type Check
```bash
python -m mypy src tests
```
*Expected Output:* `Success: no issues found in 287 source files`.

### C. Full Python Pytest Suite
```bash
python -m pytest
```
*Expected Output:* `2989 passed, 12 skipped` (live-marked provider tests skipped offline).

### D. Cloudflare Worker Syntax & Node Test Suite
```bash
npm --prefix cloudflare run typecheck
npm --prefix cloudflare run test:node
```
*Expected Output:* 71 tests passing, 0 failures across admission ledger, HTTP interface, and cross-language canonicalization.

### E. Workerd / Miniflare Runtime Preflight
```bash
npm --prefix cloudflare run test:workerd-preflight
```
*Expected Output:* 7/7 checks passed (Durable Object SQLite transaction rollback, atomic admission, idempotency, kill switch).

### F. Deterministic Evidence Consistency Check
```bash
python -m pytest tests/evidence/test_p29_evidence_consistency.py -v
```
*Expected Output:* 5/5 passed (Verifies candidate tree digest `6c4f46cb...`, 1 witness test, non-PKCS#1 raw RSA proof, Python and Node verifications).

### G. Isolated Clean-Checkout Reproduction Test
```bash
python -m pytest tests/reproducibility/test_p29_clean_checkout.py -v
```
*Expected Output:* 3/3 passed (Verifies zero runtime dependencies, git archive extraction, and clean module imports).

---

## 4. Running the Local Judge Dashboard

Judges can launch the full visual judge dashboard locally:

```bash
basebreak serve --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080/judge` in any modern web browser to interact with the causal three-world verification timeline, inspect the "Why Green CI Lies" explainer, and view tamper detection.

Alternatively, run via rootless Docker:
```bash
docker build --build-arg BUILD_COMMIT_SHA=$(git rev-parse HEAD) -t basebreak .
docker run -p 8080:8080 -e BASEBREAK_BEARER_TOKEN=secret basebreak
```

---

## 5. Independent Verification of Canonical Production Run 10

To independently recompute the receipt digest and verify the RSA proof for the canonical production run (`run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9`):

### Python Verification
```bash
python -c "
import json
from basebreak.causal.public_receipt import PublicVerificationReceipt, verify_public_receipt_integrity
from basebreak.deployment.live_bridge import verify_receipt_proof

with open('docs/evidence/p27_06_live_run_10_evidence_packet/published_receipt.json', 'r', encoding='utf-8') as f:
    rcpt = PublicVerificationReceipt.from_dict(json.load(f))
verify_public_receipt_integrity(rcpt)
print('Receipt Integrity: PASS (Digest:', rcpt.receipt_digest, ')')

with open('docs/evidence/p27_06_live_run_10_evidence_packet/receipt_proof.json', 'r', encoding='utf-8') as f:
    proof = json.load(f)
assert verify_receipt_proof(rcpt, proof) is True
print('Verifier RSA Proof: PASS (Proof Digest:', proof['proof_digest'], ')')
"
```

### Node.js Verification
```bash
node -e "
const fs = require('fs');
const { computeReceiptDigest } = require('./cloudflare/src/crypto_utils');
const { verifyBridgeReceiptProof } = require('./cloudflare/src/provider_dispatcher');

const receipt = JSON.parse(fs.readFileSync('docs/evidence/p27_06_live_run_10_evidence_packet/published_receipt.json', 'utf8'));
if (computeReceiptDigest(receipt) !== receipt.receipt_digest) throw new Error('Digest mismatch');
console.log('Node Receipt Digest: PASS');

const proof = JSON.parse(fs.readFileSync('docs/evidence/p27_06_live_run_10_evidence_packet/receipt_proof.json', 'utf8'));
verifyBridgeReceiptProof({ receipt, proof, expectedSourceCommitId: receipt.source_commit_id, expectedProvenance: 'LIVE_NEBIUS' });
console.log('Node Verifier Proof: PASS');
"
```
