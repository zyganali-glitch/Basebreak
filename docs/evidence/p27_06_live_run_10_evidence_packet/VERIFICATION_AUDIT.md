# P-27.06 Live Run 10 Cryptographic Audit and Evidence Packet

This directory contains the independent, sanitized, portable evidence packet for the canonical production verification run:

- **Run ID**: `run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9`
- **Source Commit**: `80b43b84014fa61b941c7ebcd87836a56dcd7c92`
- **Candidate Patch Digest**: `5f3ac8d9dcef8b046c58f58f3d2c44a340b13191235637169b781cf54abe592e`
- **Candidate Tree Digest**: `8931eb6ea69b2d861ce1455bb59ee42b325244b7`
- **Causal Verdict**: `VERIFIED`
  - `BASE=FAIL` (exit code 1, assertion failure on token replay)
  - `CANDIDATE=PASS` (exit code 0, 5/5 tests passed in isolated Nebius sandbox)
  - `COUNTERFACTUAL=FAIL` (exit code 1, assertion failure on inverted token replay)
- **Evidence Provenance**: `LIVE_NEBIUS`
- **Receipt Digest**: `a7857896f3f701264bed995f3b0a70115a9ab007a84d5deece3ae8bcef876500`
- **Proof Digest**: `e738d961e200f1df07af046d6a0adc56b7284b13b469249359ae0120e9a6cd2a`
- **Signer**: RSA-2048 PKCS#1 v1.5 with SHA-256 (Pinned Verifier Authority)

---

## 1. Independent Python Verification

To independently verify the published receipt integrity and the verifier-signed proof:

```bash
python -c "
import json
from basebreak.causal.public_receipt import (
    PublicVerificationReceipt,
    compute_public_receipt_digest,
    verify_public_receipt_integrity,
)
from basebreak.deployment.live_bridge import verify_receipt_proof

with open('docs/evidence/p27_06_live_run_10_evidence_packet/published_receipt.json', 'r', encoding='utf-8') as f:
    rcpt_json = json.load(f)

rcpt = PublicVerificationReceipt.from_dict(rcpt_json)
verify_public_receipt_integrity(rcpt)
print('Receipt Integrity: PASS (Digest matches:', rcpt.receipt_digest, ')')

with open('docs/evidence/p27_06_live_run_10_evidence_packet/receipt_proof.json', 'r', encoding='utf-8') as f:
    proof = json.load(f)

assert verify_receipt_proof(rcpt, proof) is True
print('RSA-2048 Proof Signature: PASS (Proof Digest matches:', proof['proof_digest'], ')')
"
```

Expected output:
```text
Receipt Integrity: PASS (Digest matches: a7857896f3f701264bed995f3b0a70115a9ab007a84d5deece3ae8bcef876500 )
RSA-2048 Proof Signature: PASS (Proof Digest matches: e738d961e200f1df07af046d6a0adc56b7284b13b469249359ae0120e9a6cd2a )
```

---

## 2. Independent Node.js Verification

To independently verify using the Cloudflare Worker production cryptographic implementation:

```bash
node -e "
const fs = require('fs');
const { computeReceiptDigest } = require('./cloudflare/src/crypto_utils');
const { verifyBridgeReceiptProof } = require('./cloudflare/src/provider_dispatcher');

const receipt = JSON.parse(fs.readFileSync('docs/evidence/p27_06_live_run_10_evidence_packet/published_receipt.json', 'utf8'));
const computedReceiptDigest = computeReceiptDigest(receipt);
if (computedReceiptDigest !== receipt.receipt_digest) {
  throw new Error('Receipt digest mismatch: ' + computedReceiptDigest);
}
console.log('Node Receipt Digest: PASS (Matches:', computedReceiptDigest, ')');

const proof = JSON.parse(fs.readFileSync('docs/evidence/p27_06_live_run_10_evidence_packet/receipt_proof.json', 'utf8'));
verifyBridgeReceiptProof({
  receipt,
  proof,
  expectedSourceCommitId: receipt.source_commit_id,
  expectedProvenance: 'LIVE_NEBIUS',
});
console.log('Node RSA Proof Verification: PASS (Bound to source commit & live Nebius executions)');
"
```

Expected output:
```text
Node Receipt Digest: PASS (Matches: a7857896f3f701264bed995f3b0a70115a9ab007a84d5deece3ae8bcef876500 )
Node RSA Proof Verification: PASS (Bound to source commit & live Nebius executions)
```

---

## 3. Cryptographic Bounds and Pinned Public Key Authority

The RSA signature on `receipt_proof.json` is verified using the immutable pinned verifier authority:

- **Modulus (hex)**:
  `PINNED_VERIFIER_MODULUS_HEX`
- **Public Exponent**: `65537`
- **Signature Algorithm**: RSA PKCS#1 v1.5 with SHA-256.

The proof digest commits directly to:
- `receipt_digest`
- `source_commit_id`
- `candidate_tree_digest`
- `candidate_patch_digest`
- `overall_verdict`
- `provenance`
- `issued_at_utc`
- `issuer_id`
- `base_execution` stdout/stderr digests, exit code, and tree digest
- `candidate_execution` stdout/stderr digests, exit code, and tree digest
- `counterfactual_execution` stdout/stderr digests, exit code, and tree digest
