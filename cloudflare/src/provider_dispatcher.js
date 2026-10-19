/**
 * Genuine Provider Dispatcher & Remote Execution Boundary.
 *
 * This boundary is intentionally fail-closed unless the Cloudflare path is wired
 * to a trusted Python bridge that can authenticate the Worker request and return
 * a verifier-signed LIVE_NEBIUS receipt proof. The Worker never trusts caller-
 * supplied budget facts, provider claims, or self-certified verdicts.
 */

import crypto from "node:crypto";
import {
  canonicalJson,
  detectSecrets,
  verifyReceiptIntegrity,
} from "./crypto_utils.js";

export const CANONICAL_DEMO_SCENARIO = {
  task_id: "TASK-RESET-VAULT-001",
  target: "tests/fixtures/reset_vault",
  change_class: "BUG_FIX",
  source_commit_id: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
  frozen_contract_digest: "93eeeb2cc7eb02a988da3c8a8543ad40b4816608c1452d048ff62ee93702f812",
};

const BRIDGE_REQUEST_SCHEMA_VERSION = "1.0.0";
const BRIDGE_PROOF_SCHEMA_VERSION = "1.0.0";
const DEFAULT_BRIDGE_AUDIENCE = "cloudflare-worker";
export const DEFAULT_BRIDGE_TIMEOUT_MS = 180000;
const PINNED_VERIFIER_EXPONENT = 65537;
const PINNED_VERIFIER_MODULUS_HEX =
  "9f7dd01fb54c511cb50e01dcb27988345f4877632a1ae38819db17efb8751f1e2907963fce5ee20b" +
  "ee87ca1023e4ff87d97f6f01d46ed1e4473b3e1cd681d870d58cff4cb988d27a7674bf9b1a2e68af" +
  "14a28af332c785b9f6545c3a1c5b4576cc43c7327503aa1fc7b68a22a88984f50114e64f7c78d865" +
  "e58b0a8144577c3639bc921171d875484a3c426c4a6c5bc8f1aeee776671faf0ff740bccee51ef76" +
  "917812e54109c0616d21d99b03d309f7a98cf6b9abd75416b4f6f6ee08b3b617d71465d20ae06c50" +
  "e634898e161de69dcdf32d1121979a2f817f0036fb6b50eb2f9524e4f87c90f8293d2098616dce14" +
  "b580e70c3db2da0df108ac6ab497559d";

function normalizeOptionalString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function normalizeExecutionFact(fact) {
  if (!fact || typeof fact !== "object") {
    return null;
  }
  const sandboxId = normalizeOptionalString(fact.sandbox_id);
  const outcome = normalizeOptionalString(fact.outcome);
  if (!sandboxId || !outcome) {
    return null;
  }
  return {
    outcome,
    exit_code: typeof fact.exit_code === "number" ? fact.exit_code : null,
    sandbox_id: sandboxId,
    source_commit_id: normalizeOptionalString(fact.source_commit_id),
    tree_digest: normalizeOptionalString(fact.tree_digest),
    stdout_digest: normalizeOptionalString(fact.stdout_digest),
    stderr_digest: normalizeOptionalString(fact.stderr_digest),
  };
}

function buildBridgeReceiptProofPayload(proof) {
  return {
    base_execution: proof.base_execution,
    candidate_execution: proof.candidate_execution,
    candidate_patch_digest: proof.candidate_patch_digest,
    candidate_tree_digest: proof.candidate_tree_digest,
    counterfactual_execution: proof.counterfactual_execution,
    issued_at_utc: proof.issued_at_utc,
    issuer_id: proof.issuer_id,
    overall_verdict: proof.overall_verdict,
    provenance: proof.provenance,
    receipt_digest: proof.receipt_digest,
    schema_version: proof.schema_version,
    source_commit_id: proof.source_commit_id,
  };
}

function computeBridgeProofDigest(payload) {
  return crypto.createHash("sha256").update(canonicalJson(payload), "utf8").digest("hex").toLowerCase();
}

function buildRequestSignaturePayload({ method, path, timestamp, audience, body }) {
  return [
    String(method || "POST").toUpperCase(),
    String(path || "/internal/live-verifications"),
    String(timestamp || "").trim(),
    String(audience || DEFAULT_BRIDGE_AUDIENCE).trim(),
    canonicalJson(body),
  ].join("\n");
}

function computeRequestSignature({ sharedSecret, method, path, timestamp, audience, body }) {
  return crypto
    .createHmac("sha256", sharedSecret)
    .update(buildRequestSignaturePayload({ method, path, timestamp, audience, body }), "utf8")
    .digest("hex")
    .toLowerCase();
}

/**
 * Resolve the trusted-bridge fetch transport at the dispatcher seam.
 *
 * Preference order:
 *   1. explicit test override,
 *   2. a configured private Workers VPC Service binding (preferred production transport),
 *   3. a required-but-missing VPC binding => fail closed (null fetchImpl; never global fetch),
 *   4. the direct fetch fallback (backward-compatible default).
 *
 * When `mode` is "vpc" the private binding is REQUIRED: a missing binding returns a null
 * fetchImpl so the dispatcher fails closed and NEVER silently falls back to the untrusted
 * global fetch.
 *
 * @param {{ vpcBinding?: { fetch?: Function } | null, mode?: string, directFetch?: Function | null, overrideFetch?: Function | null }} [params]
 * @returns {{ fetchImpl: Function | null, transport: string, privateRequired: boolean }}
 */
export function resolveBridgeTransport({
  vpcBinding = null,
  mode = "",
  directFetch = globalThis.fetch,
  overrideFetch = null,
} = {}) {
  if (typeof overrideFetch === "function") {
    return { fetchImpl: overrideFetch, transport: "override", privateRequired: false };
  }
  if (vpcBinding && typeof vpcBinding.fetch === "function") {
    return {
      fetchImpl: vpcBinding.fetch.bind(vpcBinding),
      transport: "vpc_service_binding",
      privateRequired: true,
    };
  }
  const privateRequired = String(mode == null ? "" : mode).trim().toLowerCase() === "vpc";
  if (privateRequired) {
    return { fetchImpl: null, transport: "missing_required_vpc_binding", privateRequired: true };
  }
  return {
    fetchImpl: typeof directFetch === "function" ? directFetch : null,
    transport: "direct_fetch",
    privateRequired: false,
  };
}

function hexToBigInt(hex) {
  const clean = String(hex || "").trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean)) {
    throw new Error("Hex string is malformed.");
  }
  return BigInt("0x" + clean);
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let factor = base % modulus;
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) {
      result = (result * factor) % modulus;
    }
    factor = (factor * factor) % modulus;
    power >>= 1n;
  }
  return result;
}

function verifyDigestSignature({ digestHex, signatureHex, modulusHex, exponent }) {
  const expectedMessage = hexToBigInt(
    crypto.createHash("sha256").update(String(digestHex || ""), "utf8").digest("hex")
  );
  const recoveredMessage = modPow(
    hexToBigInt(signatureHex),
    BigInt(exponent),
    hexToBigInt(modulusHex)
  );
  return expectedMessage === recoveredMessage;
}

function extractExecutionMap(receipt) {
  const byWorld = {
    BASE: null,
    CANDIDATE: null,
    COUNTERFACTUAL: null,
  };
  const executions = Array.isArray(receipt?.executions) ? receipt.executions : [];
  for (const execution of executions) {
    const world = normalizeOptionalString(execution?.world);
    if (world && Object.prototype.hasOwnProperty.call(byWorld, world)) {
      byWorld[world] = normalizeExecutionFact(execution);
    }
  }
  const counterfactualExecution = normalizeExecutionFact(receipt?.counterfactual?.execution_fact);
  if (counterfactualExecution) {
    byWorld.COUNTERFACTUAL = counterfactualExecution;
  }
  return byWorld;
}

function compareExecutionFacts(receiptFact, proofFact, { requireTreeDigest = false } = {}) {
  if (!receiptFact || !proofFact) {
    return false;
  }
  if (receiptFact.outcome !== proofFact.outcome) {
    return false;
  }
  if (receiptFact.exit_code !== proofFact.exit_code) {
    return false;
  }
  if (receiptFact.sandbox_id !== proofFact.sandbox_id) {
    return false;
  }
  if (
    normalizeOptionalString(receiptFact.source_commit_id) !==
    normalizeOptionalString(proofFact.source_commit_id)
  ) {
    return false;
  }
  if (
    normalizeOptionalString(receiptFact.stdout_digest) !==
    normalizeOptionalString(proofFact.stdout_digest)
  ) {
    return false;
  }
  if (
    normalizeOptionalString(receiptFact.stderr_digest) !==
    normalizeOptionalString(proofFact.stderr_digest)
  ) {
    return false;
  }
  if (requireTreeDigest) {
    if (
      normalizeOptionalString(receiptFact.tree_digest) !==
      normalizeOptionalString(proofFact.tree_digest)
    ) {
      return false;
    }
  }
  return true;
}

export function buildBridgeRequestPayload({
  runId,
  target,
  sourceCommitId,
  estimatedCostUsd,
  audience = DEFAULT_BRIDGE_AUDIENCE,
  nowMs = Date.now(),
  timeoutMs = DEFAULT_BRIDGE_TIMEOUT_MS,
}) {
  if (!runId || typeof runId !== "string") {
    throw new TypeError("runId must be a non-empty string.");
  }
  if (!target || typeof target !== "string") {
    throw new TypeError("target must be a non-empty string.");
  }
  if (!sourceCommitId || typeof sourceCommitId !== "string") {
    throw new TypeError("sourceCommitId must be a non-empty string.");
  }
  if (!Number.isFinite(estimatedCostUsd) || estimatedCostUsd <= 0) {
    throw new TypeError("estimatedCostUsd must be a positive finite number.");
  }

  return {
    schema_version: BRIDGE_REQUEST_SCHEMA_VERSION,
    request_id: runId.trim(),
    issued_at_ms: Math.trunc(nowMs),
    deadline_ms: Math.trunc(nowMs + timeoutMs),
    receipt_audience: audience,
    task_id: CANONICAL_DEMO_SCENARIO.task_id,
    change_class: CANONICAL_DEMO_SCENARIO.change_class,
    target: target.trim(),
    source_commit_id: sourceCommitId.trim(),
    frozen_contract_digest: CANONICAL_DEMO_SCENARIO.frozen_contract_digest,
    max_estimated_cost_usd: Number(estimatedCostUsd),
  };
}

export function verifyBridgeReceiptProof({
  receipt,
  proof,
  expectedSourceCommitId,
  expectedProvenance = "LIVE_NEBIUS",
  authority = {
    modulusHex: PINNED_VERIFIER_MODULUS_HEX,
    exponent: PINNED_VERIFIER_EXPONENT,
  },
}) {
  if (!receipt || typeof receipt !== "object") {
    throw new Error("Bridge response is missing a receipt.");
  }
  if (!proof || typeof proof !== "object") {
    throw new Error("Bridge response is missing a verifier-signed receipt proof.");
  }
  if (!verifyReceiptIntegrity(receipt)) {
    throw new Error("Receipt digest verification failed.");
  }

  const proofPayload = buildBridgeReceiptProofPayload(proof);
  const computedProofDigest = computeBridgeProofDigest(proofPayload);
  if (normalizeOptionalString(proof.schema_version) !== BRIDGE_PROOF_SCHEMA_VERSION) {
    throw new Error("Receipt proof schema_version is unsupported.");
  }
  if (normalizeOptionalString(proof.proof_digest) !== computedProofDigest) {
    throw new Error("Receipt proof digest mismatch.");
  }
  if (!normalizeOptionalString(proof.signature)) {
    throw new Error("Receipt proof signature is required.");
  }
  if (
    !verifyDigestSignature({
      digestHex: computedProofDigest,
      signatureHex: proof.signature,
      modulusHex: authority.modulusHex,
      exponent: authority.exponent,
    })
  ) {
    throw new Error("Receipt proof signature verification failed.");
  }

  const receiptDigest = normalizeOptionalString(receipt.receipt_digest);
  const proofDigest = normalizeOptionalString(proof.receipt_digest);
  if (!receiptDigest || receiptDigest !== proofDigest) {
    throw new Error("Receipt proof does not bind to the returned receipt digest.");
  }

  const receiptProvenance = normalizeOptionalString(receipt.provenance);
  const proofProvenance = normalizeOptionalString(proof.provenance);
  if (receiptProvenance !== expectedProvenance || proofProvenance !== expectedProvenance) {
    throw new Error("Receipt provenance is not authenticated as LIVE_NEBIUS.");
  }

  const expectedSource = String(expectedSourceCommitId || "").trim().toLowerCase();
  const receiptSource = String(receipt.source_commit_id || "").trim().toLowerCase();
  const proofSource = String(proof.source_commit_id || "").trim().toLowerCase();
  if (!expectedSource || receiptSource !== expectedSource || proofSource !== expectedSource) {
    throw new Error("Receipt proof source_commit_id does not match the server-bound source.");
  }

  if (
    normalizeOptionalString(receipt.candidate_tree_digest)?.toLowerCase() !==
    normalizeOptionalString(proof.candidate_tree_digest)?.toLowerCase()
  ) {
    throw new Error("Receipt proof candidate_tree_digest mismatch.");
  }
  if (
    normalizeOptionalString(receipt.candidate_patch_digest)?.toLowerCase() !==
    normalizeOptionalString(proof.candidate_patch_digest)?.toLowerCase()
  ) {
    throw new Error("Receipt proof candidate_patch_digest mismatch.");
  }
  if (
    normalizeOptionalString(receipt.overall_verdict) !==
    normalizeOptionalString(proof.overall_verdict)
  ) {
    throw new Error("Receipt proof overall_verdict mismatch.");
  }

  const receiptExecutions = extractExecutionMap(receipt);
  const proofBase = normalizeExecutionFact(proof.base_execution);
  const proofCandidate = normalizeExecutionFact(proof.candidate_execution);
  const proofCounterfactual = normalizeExecutionFact(proof.counterfactual_execution);
  if (!compareExecutionFacts(receiptExecutions.BASE, proofBase, { requireTreeDigest: true })) {
    throw new Error("Receipt proof base execution binding mismatch.");
  }
  if (
    !compareExecutionFacts(receiptExecutions.CANDIDATE, proofCandidate, {
      requireTreeDigest: true,
    })
  ) {
    throw new Error("Receipt proof candidate execution binding mismatch.");
  }

  const receiptCounterfactual = receiptExecutions.COUNTERFACTUAL;
  if (receiptCounterfactual || proofCounterfactual) {
    if (
      !compareExecutionFacts(receiptCounterfactual, proofCounterfactual, {
        requireTreeDigest: true,
      })
    ) {
      throw new Error("Receipt proof counterfactual execution binding mismatch.");
    }
  }
}

async function parseBridgeResponse(response) {
  const contentType = response.headers.get("Content-Type") || "";
  if (/application\/json/i.test(contentType)) {
    return await response.json();
  }
  const text = await response.text();
  return {
    ok: false,
    status: "BRIDGE_INVALID_RESPONSE",
    error: text || `Bridge returned non-JSON content-type '${contentType}'.`,
  };
}

/**
 * Dispatch verification run through the trusted Python bridge.
 *
 * @param {object} params
 * @param {string} params.runId
 * @param {string} params.target
 * @param {string} params.sourceCommitId
 * @param {boolean} [params.allowLive=false]
 * @param {string} [params.bridgeUrl]
 * @param {string} [params.bridgeSharedSecret]
 * @param {string} [params.bridgeAudience]
 * @param {number} [params.estimatedCostUsd]
 * @param {(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>} [params.fetchImpl]
 * @param {{ modulusHex: string, exponent: number }} [params.verifierAuthorityOverride]
 * @returns {Promise<{ success: boolean, status: string, error: string, was_ambiguous: boolean, code?: number, receipt?: Record<string, unknown>, observed_cost_usd?: number, tokens_used?: number }>}
 */
export async function dispatchVerificationRun({
  runId,
  target,
  sourceCommitId,
  allowLive = false,
  bridgeUrl,
  bridgeSharedSecret,
  bridgeAudience = DEFAULT_BRIDGE_AUDIENCE,
  estimatedCostUsd,
  bridgeTimeoutMs = DEFAULT_BRIDGE_TIMEOUT_MS,
  fetchImpl = globalThis.fetch,
  verifierAuthorityOverride,
}) {
  if (!allowLive) {
    return {
      success: false,
      status: "NOT_RUN",
      error:
        "BLOCKED: Live execution not requested. Status: OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN.",
      was_ambiguous: false,
      provider_may_have_dispatched: false,
      code: 403,
    };
  }

  if (!bridgeUrl || typeof bridgeUrl !== "string" || !bridgeUrl.trim()) {
    return {
      success: false,
      status: "NOT_READY_FOR_DEPLOYMENT",
      error:
        "BLOCKED: Trusted Python verifier bridge URL is not configured. No Nebius sandbox request or LIVE_NEBIUS receipt issuance was attempted.",
      was_ambiguous: false,
      provider_may_have_dispatched: false,
      code: 503,
    };
  }
  if (!bridgeSharedSecret || typeof bridgeSharedSecret !== "string" || !bridgeSharedSecret.trim()) {
    return {
      success: false,
      status: "NOT_READY_FOR_DEPLOYMENT",
      error:
        "BLOCKED: Trusted Python verifier bridge authentication secret is missing. No provider call was attempted.",
      was_ambiguous: false,
      provider_may_have_dispatched: false,
      code: 503,
    };
  }
  if (!Number.isFinite(estimatedCostUsd) || estimatedCostUsd <= 0) {
    return {
      success: false,
      status: "NOT_READY_FOR_DEPLOYMENT",
      error:
        "BLOCKED: Server-controlled maximum estimated live cost is missing or invalid. Uncertain-cost live execution is forbidden.",
      was_ambiguous: false,
      provider_may_have_dispatched: false,
      code: 503,
    };
  }
  if (typeof fetchImpl !== "function") {
    return {
      success: false,
      status: "NOT_READY_FOR_DEPLOYMENT",
      error:
        "BLOCKED: Fetch transport is unavailable for the trusted Python verifier bridge.",
      was_ambiguous: false,
      provider_may_have_dispatched: false,
      code: 503,
    };
  }

  const requestUrl = new URL(bridgeUrl);
  const nowMs = Date.now();
  const timeoutMs =
    Number.isFinite(bridgeTimeoutMs) && bridgeTimeoutMs > 0
      ? bridgeTimeoutMs
      : DEFAULT_BRIDGE_TIMEOUT_MS;
  const requestBody = buildBridgeRequestPayload({
    runId,
    target,
    sourceCommitId,
    estimatedCostUsd,
    audience: bridgeAudience,
    nowMs,
    timeoutMs,
  });
  const timestamp = String(nowMs);
  const signature = computeRequestSignature({
    sharedSecret: bridgeSharedSecret,
    method: "POST",
    path: requestUrl.pathname,
    timestamp,
    audience: bridgeAudience,
    body: requestBody,
  });

  let response;
  try {
    response = await fetchImpl(requestUrl.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Basebreak-Bridge-Timestamp": timestamp,
        "X-Basebreak-Bridge-Audience": bridgeAudience,
        "X-Basebreak-Bridge-Signature": signature,
      },
      body: JSON.stringify(requestBody),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      status: "UNKNOWN_OUTCOME",
      error:
        "AMBIGUOUS: Trusted Python verifier bridge request failed after dispatch boundary: " +
        message,
      was_ambiguous: true,
      // The request may have reached the bridge (and thus the provider) before the
      // transport failed, so a chargeable operation may have started.
      provider_may_have_dispatched: true,
      code: 502,
    };
  }

  const responseBody = await parseBridgeResponse(response);
  // The trusted bridge reports whether it actually started provider work. Absent
  // that explicit signal (older bridge / proxy error), assume the worst: the
  // bridge was contacted and a chargeable operation may have started.
  const providerMayHaveDispatched = responseBody?.provider_dispatched === false ? false : true;
  if (!response.ok) {
    return {
      success: false,
      status: normalizeOptionalString(responseBody?.status) || "FAILED",
      error:
        normalizeOptionalString(responseBody?.error) ||
        `Bridge returned HTTP ${response.status} without a structured error payload.`,
      was_ambiguous: responseBody?.ambiguous_outcome === true,
      provider_may_have_dispatched: providerMayHaveDispatched,
      code: response.status,
    };
  }

  if (responseBody?.ok !== true) {
    return {
      success: false,
      status: normalizeOptionalString(responseBody?.status) || "FAILED",
      error:
        normalizeOptionalString(responseBody?.error) ||
        "Bridge returned a non-success payload without an error message.",
      was_ambiguous: responseBody?.ambiguous_outcome === true,
      provider_may_have_dispatched: providerMayHaveDispatched,
      code: response.status,
    };
  }

  if (detectSecrets(responseBody).hasSecret) {
    return {
      success: false,
      status: "FAILED",
      error: "Bridge response contains secret material and was rejected.",
      was_ambiguous: false,
      provider_may_have_dispatched: providerMayHaveDispatched,
      code: 502,
    };
  }

  try {
    verifyBridgeReceiptProof({
      receipt: responseBody.receipt,
      proof: responseBody.receipt_proof,
      expectedSourceCommitId: sourceCommitId,
      authority: verifierAuthorityOverride || {
        modulusHex: PINNED_VERIFIER_MODULUS_HEX,
        exponent: PINNED_VERIFIER_EXPONENT,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      status: "FAILED",
      error: `Bridge receipt proof verification failed: ${message}`,
      was_ambiguous: false,
      // The bridge may have already performed successful inference before
      // returning a malformed/unverifiable receipt, so consumption is unknown.
      provider_may_have_dispatched: providerMayHaveDispatched,
      code: 502,
    };
  }

  const observedCost =
    typeof responseBody.observed_cost_usd === "number" &&
    Number.isFinite(responseBody.observed_cost_usd)
      ? responseBody.observed_cost_usd
      : null;
  const reservedExposure =
    typeof responseBody.reserved_exposure_usd === "number" &&
    Number.isFinite(responseBody.reserved_exposure_usd)
      ? responseBody.reserved_exposure_usd
      : null;
  const approvedEstimate =
    typeof responseBody.approved_estimate_usd === "number" &&
    Number.isFinite(responseBody.approved_estimate_usd)
      ? responseBody.approved_estimate_usd
      : null;

  return {
    success: true,
    status: "COMPLETED",
    error: "",
    was_ambiguous: false,
    provider_may_have_dispatched: providerMayHaveDispatched,
    code: 201,
    receipt: responseBody.receipt,
    observed_cost_usd: observedCost,
    reserved_exposure_usd: reservedExposure,
    approved_estimate_usd: approvedEstimate,
    cost_provenance:
      observedCost === null
        ? "UNKNOWN"
        : normalizeOptionalString(responseBody.cost_provenance) || "PROVIDER_OBSERVED",
    tokens_used: typeof responseBody.tokens_used === "number" ? responseBody.tokens_used : 0,
  };
}
