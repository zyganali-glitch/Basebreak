# P-29.03 Fresh Live Run Cryptographic Audit and Evidence Packet

This directory contains the independent, sanitized, portable evidence packet for the fresh P-29.03 competition verification run:

- **Run ID**: `run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f`
- **Execution Timestamp**: `2026-10-22T19:38:42.489554+00:00`
- **Source Commit**: `80b43b84014fa61b941c7ebcd87836a56dcd7c92`
- **Candidate Patch Digest**: `5f3ac8d9dcef8b046c58f58f3d2c44a340b13191235637169b781cf54abe592e`
- **Candidate Tree Digest**: `6c4f46cbb51119d8e93534a1e2ee922498ee450b`
- **Causal Verdict**: `VERIFIED`
  - `BASE=FAIL` (sandbox `sbx-c9e5c0e476fa4466`, exit code 1, assertion failure on token replay)
  - `CANDIDATE=PASS` (sandbox `sbx-cd870e01d6d94bca`, exit code 0, 1 sealed witness test passed in isolated Nebius sandbox: `1 passed in 0.04s`, witness `wit-reset-vault-live-001`)
  - `COUNTERFACTUAL=FAIL` (sandbox `sbx-90d40f25758244d0`, exit code 1, assertion failure on inverted token replay)
- **Evidence Provenance**: `LIVE_NEBIUS`
- **Provider Request ID**: `chatcmpl-6f406c073cb413917bb3c4dea558d380`
- **Model**: `nvidia/Nemotron-3_5-Lightning`
- **Receipt Digest**: `e2e833fd3aa9d69bdcbaad0805fd38167c680cb2f60a16209c27a80123a43708`
- **Proof Digest**: `def59353ba1315979dead2544590b199ee66f966b479abf6b3496edb39e143b4`
- **Signer**: Raw RSA-2048 Modular Exponentiation with SHA-256 (Pinned Verifier Authority; unpadded, non-PKCS#1)

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

with open('docs/evidence/p29_03_fresh_live_run_evidence_packet/published_receipt.json', 'r', encoding='utf-8') as f:
    rcpt_json = json.load(f)

rcpt = PublicVerificationReceipt.from_dict(rcpt_json)
verify_public_receipt_integrity(rcpt)
print('Receipt Integrity: PASS (Digest matches:', rcpt.receipt_digest, ')')

with open('docs/evidence/p29_03_fresh_live_run_evidence_packet/receipt_proof.json', 'r', encoding='utf-8') as f:
    proof = json.load(f)

assert verify_receipt_proof(rcpt, proof) is True
print('RSA-2048 Proof Signature: PASS (Proof Digest matches:', proof['proof_digest'], ')')
"
```

Expected output:
```text
Receipt Integrity: PASS (Digest matches: e2e833fd3aa9d69bdcbaad0805fd38167c680cb2f60a16209c27a80123a43708 )
RSA-2048 Proof Signature: PASS (Proof Digest matches: def59353ba1315979dead2544590b199ee66f966b479abf6b3496edb39e143b4 )
```

---

## 2. Independent Node.js Verification

To independently verify using the Cloudflare Worker production cryptographic implementation:

```bash
node -e "
const fs = require('fs');
const { computeReceiptDigest } = require('./cloudflare/src/crypto_utils');
const { verifyBridgeReceiptProof } = require('./cloudflare/src/provider_dispatcher');

const receipt = JSON.parse(fs.readFileSync('docs/evidence/p29_03_fresh_live_run_evidence_packet/published_receipt.json', 'utf8'));
const computedReceiptDigest = computeReceiptDigest(receipt);
if (computedReceiptDigest !== receipt.receipt_digest) {
  throw new Error('Receipt digest mismatch: ' + computedReceiptDigest);
}
console.log('Node Receipt Digest: PASS (Matches:', computedReceiptDigest, ')');

const proof = JSON.parse(fs.readFileSync('docs/evidence/p29_03_fresh_live_run_evidence_packet/receipt_proof.json', 'utf8'));
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
Node Receipt Digest: PASS (Matches: e2e833fd3aa9d69bdcbaad0805fd38167c680cb2f60a16209c27a80123a43708 )
Node RSA Proof Verification: PASS (Bound to source commit & live Nebius executions)
```

---

## 3. Cryptographic Bounds and Pinned Public Key Authority

The RSA signature on `receipt_proof.json` is verified using the immutable pinned verifier authority:

- **Modulus (hex)**:
  `PINNED_VERIFIER_MODULUS_HEX`
- **Public Exponent**: `65537`
- **Signature Algorithm**: Custom Raw Modular-Exponent RSA-2048 with SHA-256 (non-PKCS#1, unpadded).
  - Digest derivation: double-SHA256 (`SHA256(canonicalJson(proof_payload))`) converted to an integer and modularly exponentiated with the private key ($s = m^d \pmod n$).
  - Verification: $s^e \equiv m \pmod n$ checks that the recovered message integer equals the expected double-SHA256 digest integer.
  - Security Evaluation: The custom scheme directly checks mathematical authenticity under the pinned 2048-bit modulus without PKCS#1 v1.5 padding or PSS encoding. While non-standard, it deterministically binds the proof payload and prevents forgery in this verification pipeline.

---

## 4. Public Endpoints Verification

- **Public Receipt URL**:
  `https://basebreak.zyganali.workers.dev/v1/runs/run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f/receipt`
- **Public Judge Route**:
  `https://basebreak.zyganali.workers.dev/judge/run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f`
