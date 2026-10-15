/**
 * Cryptographic and serialization utilities for Basebreak Cloudflare Worker.
 *
 * Implements deterministic canonical JSON serialization, SHA-256 digest verification,
 * and secret redaction strictly matching Basebreak's Python causal receipt authority.
 */

import crypto from "node:crypto";

/**
 * Serialize an object into canonical JSON (recursively sorted keys, no whitespace).
 * Exactly matches Python: json.dumps(payload, sort_keys=True, separators=(",", ":"))
 *
 * @param {unknown} val
 * @returns {string}
 */
export function canonicalJson(val) {
  if (val === null || val === undefined) {
    return "null";
  }
  if (typeof val === "boolean" || typeof val === "number") {
    return JSON.stringify(val);
  }
  if (typeof val === "string") {
    return JSON.stringify(val);
  }
  if (Array.isArray(val)) {
    const elements = val.map((item) => canonicalJson(item));
    return "[" + elements.join(",") + "]";
  }
  if (typeof val === "object") {
    const keys = Object.keys(val).sort();
    const entries = [];
    for (const k of keys) {
      const v = val[k];
      if (v !== undefined && typeof v !== "function" && typeof v !== "symbol") {
        entries.push(JSON.stringify(k) + ":" + canonicalJson(v));
      }
    }
    return "{" + entries.join(",") + "}";
  }
  return JSON.stringify(val);
}

/**
 * Compute SHA-256 hex digest over a UTF-8 string or Buffer.
 *
 * @param {string | Buffer} input
 * @returns {string} 64-character lowercase hexadecimal digest
 */
export function computeSha256(input) {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex").toLowerCase();
}

/**
 * Compute the deterministic receipt digest from a receipt payload object.
 * Strips the 'receipt_digest' field if present before hashing.
 *
 * @param {Record<string, unknown>} receiptObj
 * @returns {string} 64-character lowercase hex digest
 */
export function computeReceiptDigest(receiptObj) {
  if (!receiptObj || typeof receiptObj !== "object") {
    throw new TypeError("Receipt payload must be a non-null object.");
  }
  const payloadCopy = {};
  for (const [k, v] of Object.entries(receiptObj)) {
    if (k !== "receipt_digest") {
      payloadCopy[k] = v;
    }
  }
  const canonicalBytes = canonicalJson(payloadCopy);
  return computeSha256(canonicalBytes);
}

/**
 * Verify cryptographic tamper integrity of a verification receipt.
 *
 * @param {Record<string, unknown>} receiptObj
 * @returns {boolean}
 */
export function verifyReceiptIntegrity(receiptObj) {
  if (!receiptObj || typeof receiptObj !== "object") {
    return false;
  }
  const statedDigest = receiptObj.receipt_digest;
  if (!statedDigest || typeof statedDigest !== "string" || statedDigest.length !== 64) {
    return false;
  }
  try {
    const recomputed = computeReceiptDigest(receiptObj);
    return recomputed.toLowerCase() === statedDigest.toLowerCase();
  } catch {
    return false;
  }
}

// Secret detection regular expressions matching Basebreak secret policy
const SECRET_PATTERNS = [
  /Bearer\s+[A-Za-z0-9_-]{12,}/i,
  /nb-[A-Za-z0-9_-]{20,}/i,
  /nvapi-[A-Za-z0-9_-]{20,}/i,
  /tvly-[A-Za-z0-9_-]{20,}/i,
  /sk-[A-Za-z0-9_-]{20,}/i,
  /ghp_[A-Za-z0-9]{30,}/i,
  /github_pat_[A-Za-z0-9_]{30,}/i,
  /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/i,
  /api[_-]?key\s*[:=]\s*["']?[A-Za-z0-9_-]{16,}["']?/i,
  /secret\s*[:=]\s*["']?[A-Za-z0-9_-]{16,}["']?/i,
];

/**
 * Detect if any sensitive secret credentials exist in the text or object.
 *
 * @param {string | Record<string, unknown>} input
 * @returns {{ hasSecret: boolean, matchedPattern?: string }}
 */
export function detectSecrets(input) {
  const text = typeof input === "string" ? input : JSON.stringify(input);
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(text)) {
      return { hasSecret: true, matchedPattern: pattern.source };
    }
  }
  return { hasSecret: false };
}

/**
 * Redact secret patterns from text.
 *
 * @param {string} text
 * @returns {string}
 */
export function redactSecrets(text) {
  if (typeof text !== "string") {
    return text;
  }
  let sanitized = text;
  for (const pattern of SECRET_PATTERNS) {
    sanitized = sanitized.replace(new RegExp(pattern, "g"), "[REDACTED_SECRET]");
  }
  return sanitized;
}
