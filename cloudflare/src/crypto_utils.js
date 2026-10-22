/**
 * Cryptographic and serialization utilities for Basebreak Cloudflare Worker.
 *
 * Implements deterministic canonical JSON serialization, SHA-256 digest verification,
 * and secret redaction strictly matching Basebreak's Python causal receipt authority.
 */

import crypto from "node:crypto";

/**
 * Serialize a string exactly like Python's json.dumps with ensure_ascii=True:
 * JSON.stringify already emits the short escapes (\n, \t, \r, \b, \f, \", \\)
 * and lowercase \uXXXX for other control characters, but leaves non-ASCII
 * characters raw. Python escapes every character >= U+007F as a lowercase
 * \uXXXX escape (astral characters as surrogate pairs), so the canonical
 * digest bytes remain identical across languages.
 *
 * @param {string} s
 * @returns {string}
 */
function pyAsciiJsonString(s) {
  return JSON.stringify(s).replace(/[\u007f-\uffff]/g, (ch) => {
    const code = ch.charCodeAt(0);
    return "\\u" + code.toString(16).padStart(4, "0");
  });
}

/**
 * Serialize an object into canonical JSON (recursively sorted keys, no whitespace).
 * Exactly matches Python's receipt canonical serializer
 * (basebreak.causal.public_receipt._canonical_receipt_json_bytes):
 * json.dumps(payload, sort_keys=True, separators=(",", ":")) with default
 * ensure_ascii=True semantics for BOTH strings and object keys, and ECMAScript
 * Number::toString for numbers (which Python mirrors via
 * _ecmascript_number_bytes). ASCII-only keys sort identically under Python
 * code-point ordering and ECMAScript UTF-16 code-unit ordering.
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
    return pyAsciiJsonString(val);
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
        // Keys are escaped with the same ensure_ascii semantics as values so
        // Python (json.dumps ensure_ascii=True) and this canonicalization
        // never hash different bytes for the same supported object.
        entries.push(pyAsciiJsonString(k) + ":" + canonicalJson(v));
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
 * Strips the 'receipt_digest' field if present before hashing and mirrors the
 * Python canonical payload normalization so genuine Python bridge receipts
 * verify cross-language.
 *
 * @param {Record<string, unknown>} receiptObj
 * @returns {string} 64-character lowercase hex digest
 */
/**
 * Mirror the Python-side canonical receipt payload normalization
 * (basebreak.causal.public_receipt.build_canonical_public_receipt_payload):
 * - the list fields `disclaimers`, `not_run_obligations`, and
 *   `runtime_identities` are sorted (strings trimmed),
 * - digest-like string fields are trimmed and lowercased,
 * - the remaining trimmed string fields match Python's .strip() normalization.
 * Python receipts serialize their wire form through the same canonical builder,
 * so a genuine Python receipt and this normalization produce identical bytes.
 *
 * @param {Record<string, unknown>} receiptObj
 * @returns {Record<string, unknown>}
 */
function normalizeReceiptDigestPayload(receiptObj) {
  const payloadCopy = {};
  for (const [k, v] of Object.entries(receiptObj)) {
    if (k !== "receipt_digest") {
      payloadCopy[k] = v;
    }
  }
  const sortedStringList = (v) =>
    Array.isArray(v) ? v.map((item) => String(item).trim()).sort() : v;
  for (const key of ["disclaimers", "not_run_obligations", "runtime_identities"]) {
    if (Array.isArray(payloadCopy[key])) {
      payloadCopy[key] = sortedStringList(payloadCopy[key]);
    }
  }
  const lowerTrim = (v) => (typeof v === "string" ? v.trim().toLowerCase() : v);
  for (const key of [
    "candidate_patch_digest",
    "candidate_tree_digest",
    "frozen_contract_digest",
    "source_commit_id",
  ]) {
    if (key in payloadCopy) {
      payloadCopy[key] = lowerTrim(payloadCopy[key]);
    }
  }
  const trim = (v) => (typeof v === "string" ? v.trim() : v);
  for (const key of ["task_id", "repo_locator", "schema_version", "signature_strategy"]) {
    if (key in payloadCopy) {
      payloadCopy[key] = trim(payloadCopy[key]);
    }
  }
  return payloadCopy;
}

export function computeReceiptDigest(receiptObj) {
  if (!receiptObj || typeof receiptObj !== "object") {
    throw new TypeError("Receipt payload must be a non-null object.");
  }
  const payloadCopy = normalizeReceiptDigestPayload(receiptObj);
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
