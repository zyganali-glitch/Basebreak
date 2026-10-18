/**
 * Cloudflare Worker Entry Point for Basebreak Causal Verification.
 *
 * Implements Section B & C:
 * - Serves judge UI and static assets on a single public URL.
 * - Read-only inspection of authentic public receipts.
 * - Protected API for initiating pre-audited verification scenario.
 * - Single canonical SQLite-backed Durable Object for global admission ledger.
 * - Same-origin routing and durable state recovery.
 */

import { redactSecrets } from "./crypto_utils.js";
import { AdmissionLedgerDO, ReconciliationStateError, ReconciliationValidationError } from "./ledger.js";
import {
  CANONICAL_DEMO_SCENARIO,
  dispatchVerificationRun,
  resolveBridgeTransport,
} from "./provider_dispatcher.js";

// Re-export Durable Object class for Cloudflare Workers runtime
export { AdmissionLedgerDO };

// Embedded Judge UI HTML fallback when ASSETS binding is unavailable
import { readFileSync } from "node:fs";
import path from "node:path";

const FALLBACK_INDEX_HTML =
  "<!DOCTYPE html><html><body><h1>Basebreak Causal Verification</h1></body></html>";

let cachedIndexHtml = null;
function readLocalIndexHtml() {
  try {
    return readFileSync(new URL("../public/index.html", import.meta.url), "utf-8");
  } catch {}

  if (typeof import.meta.url === "string" && import.meta.url.trim()) {
    try {
      const candidatePath = path.resolve(path.dirname(import.meta.url), "../public/index.html");
      return readFileSync(candidatePath, "utf-8");
    } catch {}
  }

  try {
    return readFileSync(path.resolve("public/index.html"), "utf-8");
  } catch {}

  return null;
}

function getFallbackIndexHtml() {
  if (cachedIndexHtml !== null) {
    return cachedIndexHtml;
  }
  try {
    cachedIndexHtml = readLocalIndexHtml() || FALLBACK_INDEX_HTML;
  } catch {
    cachedIndexHtml = FALLBACK_INDEX_HTML;
  }
  return cachedIndexHtml;
}

/**
 * Standard helper to build secure JSON response with secret redaction and headers.
 *
 * @param {number} status
 * @param {any} data
 * @returns {Response}
 */
function jsonResponse(status, data) {
  const jsonStr = JSON.stringify(data);
  const safeStr = redactSecrets(jsonStr);
  return new Response(safeStr, {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
    },
  });
}

/**
 * Standard helper to build HTML response with headers.
 *
 * @param {number} status
 * @param {string} htmlContent
 * @returns {Response}
 */
function htmlResponse(status, htmlContent) {
  const safeHtml = redactSecrets(htmlContent);
  return new Response(safeHtml, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
    },
  });
}

async function serveJudgeUi(request, env) {
  if (env.ASSETS && typeof env.ASSETS.fetch === "function") {
    const pathname = new URL(request.url).pathname;
    const assetRequest =
      pathname === "/"
        ? request
        : new Request(new URL("/", request.url).toString(), request);

    const assetResponse = await env.ASSETS.fetch(assetRequest);
    if (assetResponse.status !== 404) {
      return assetResponse;
    }
  }

  return htmlResponse(200, getFallbackIndexHtml());
}

/**
 * Get or initialize the singleton global AdmissionLedgerDO instance.
 *
 * @param {any} env
 * @returns {AdmissionLedgerDO}
 */
function getGlobalLedger(env) {
  if (env.ADMISSION_LEDGER?.idFromName) {
    const id = env.ADMISSION_LEDGER.idFromName("canonical_global_ledger");
    return env.ADMISSION_LEDGER.get(id);
  }
  // Explicit in-process fallback for local Node tests only.
  if (env.__allowInProcessLedgerForTests === true) {
    if (!env.__ledgerInstance) {
      env.__ledgerInstance = new AdmissionLedgerDO(env.__sqliteBackend || {}, env);
    }
    return env.__ledgerInstance;
  }
  return null;
}

function buildMissingLedgerResponse() {
  return jsonResponse(503, {
    status: "NOT_READY_FOR_DEPLOYMENT",
    deployment_readiness: "NOT_READY_FOR_DEPLOYMENT",
    error:
      "ADMISSION_LEDGER Durable Object binding is missing. Production in-process fallback is disabled; Cloudflare runtime configuration must fail closed.",
  });
}

function requireLedger(env) {
  const ledger = getGlobalLedger(env);
  if (!ledger) {
    return { ledger: null, response: buildMissingLedgerResponse() };
  }
  return { ledger, response: null };
}

const UNKNOWN_BUILD_SHA = "UNKNOWN_BUILD_SHA";
const CANONICAL_PUBLIC_IDS = ["canonical-demo", "reset_vault"];
const DEFAULT_BRIDGE_AUDIENCE = "cloudflare-worker";
const NON_AUTHORITATIVE_CLIENT_FIELDS = [
  "balance_timestamp",
  "estimated_cost",
  "estimated_cost_usd",
  "live_enabled",
  "provider_facts",
  "provider_model_id",
  "provider_operation_ids",
  "receipt",
  "receipt_digest",
  "verified_balance",
];

function getDeclaredSourceCommit(env) {
  if (typeof env.EXPECTED_SOURCE_COMMIT === "string" && env.EXPECTED_SOURCE_COMMIT.trim()) {
    return env.EXPECTED_SOURCE_COMMIT.trim();
  }
  return UNKNOWN_BUILD_SHA;
}

function getConfiguredEstimatedLiveCost(env) {
  const raw = typeof env.LIVE_RUN_ESTIMATED_COST_USD === "string" ? env.LIVE_RUN_ESTIMATED_COST_USD : "";
  const parsed = Number.parseFloat(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function findForbiddenClientAuthorityField(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return null;
  }
  for (const fieldName of NON_AUTHORITATIVE_CLIENT_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(body, fieldName)) {
      return fieldName;
    }
  }
  if (
    Object.prototype.hasOwnProperty.call(body, "source_commit_id") &&
    typeof body.source_commit_id === "string" &&
    body.source_commit_id.trim()
  ) {
    return "source_commit_id";
  }
  return null;
}

function getRequestIdempotencyKey(request, body) {
  const headerValue = request.headers.get("Idempotency-Key");
  if (headerValue && headerValue.trim()) {
    return headerValue.trim();
  }
  if (body && typeof body.idempotency_key === "string" && body.idempotency_key.trim()) {
    return body.idempotency_key.trim();
  }
  return null;
}

function buildUnavailableRunPayload(runId, error) {
  return {
    run_id: runId,
    status: "NOT_RUN",
    outcome: "NOT_RUN",
    provenance: "NOT_RUN",
    is_published: false,
    error,
  };
}

async function getCanonicalStoredReceipt(ledger) {
  if (typeof ledger.getReceipt !== "function") {
    return null;
  }

  for (const candidateId of CANONICAL_PUBLIC_IDS) {
    const stored = await ledger.getReceipt(candidateId);
    if (stored) {
      return stored;
    }
  }

  return null;
}

function buildCanonicalRunSummary(runId, stored) {
  return {
    run_id: runId,
    status: "COMPLETED",
    outcome: stored.receipt.overall_verdict,
    provenance: stored.receipt.provenance,
    source_commit_id: stored.receipt.source_commit_id,
    receipt_available: true,
    receipt_digest: stored.receipt_digest,
    is_published: true,
  };
}

/**
 * Check admin bearer authorization.
 *
 * @param {Request} request
 * @param {any} env
 * @returns {boolean}
 */
function isAdminAuthorized(request, env) {
  const authHdr = request.headers.get("Authorization");
  if (!authHdr || !authHdr.startsWith("Bearer ")) {
    return false;
  }
  const token = authHdr.slice(7).trim();
  const expectedKey = env.BASEBREAK_ADMIN_KEY || env.BASEBREAK_BEARER_TOKEN;
  if (!expectedKey) {
    return false;
  }
  return token === expectedKey;
}

export default {
  /**
   * Main Worker fetch handler.
   *
   * @param {Request} request
   * @param {any} env
   * @param {any} ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // 1. Root and Judge Dashboard UI (Read-Only Public Access)
    if (method === "GET" && (path === "/" || path === "/judge" || path.startsWith("/judge/"))) {
      return serveJudgeUi(request, env);
    }

    const { ledger, response: missingLedgerResponse } = requireLedger(env);
    if (missingLedgerResponse) {
      return missingLedgerResponse;
    }

    // 2. Health & Source SHA Parity Endpoint (P-27.04)
    if (method === "GET" && (path === "/health" || path === "/v1/health")) {
      const expectedCommit =
        getDeclaredSourceCommit(env);
      const accounting =
        typeof ledger.getAccounting === "function" ? await ledger.getAccounting() : {};
      const runtimeLiveEnabled =
        typeof accounting.runtime_live_enabled === "boolean"
          ? accounting.runtime_live_enabled
          : env.LIVE_ENABLED === "true";
      const durableLiveEnabled =
        typeof accounting.durable_live_enabled === "boolean"
          ? accounting.durable_live_enabled
          : false;

      return jsonResponse(200, {
        status: "ok",
        platform: "cloudflare_workers",
        version: "1.0.0",
        source_commit_id: expectedCommit,
        source_commit_status:
          expectedCommit === UNKNOWN_BUILD_SHA ? "UNKNOWN_BUILD_SHA" : "CONFIGURED_UNVERIFIED",
        deployment_readiness: "NOT_READY_FOR_DEPLOYMENT",
        // Effective live execution requires BOTH the independent durable operator
        // gate and the runtime environment authorization.
        live_enabled: runtimeLiveEnabled && durableLiveEnabled,
        runtime_live_enabled: runtimeLiveEnabled,
        durable_live_enabled: durableLiveEnabled,
        durable_expected_source_commit: accounting.durable_expected_source_commit ?? null,
        source_commit_consistent: accounting.source_commit_consistent === true,
        kill_switch_engaged: accounting.kill_switch_engaged ?? false,
        total_runs: accounting.total_runs ?? 0,
        in_flight_count: accounting.in_flight_count ?? 0,
        timestamp: new Date().toISOString(),
      });
    }

    // 3. Read-Only Public Receipt Retrieval (P-27.05)
    const receiptMatch = path.match(/^\/v1\/runs\/([A-Za-z0-9_.-]+)\/receipt\/?$/);
    if (method === "GET" && receiptMatch) {
      const runId = receiptMatch[1];

      if (CANONICAL_PUBLIC_IDS.includes(runId)) {
        const storedCanonical = await getCanonicalStoredReceipt(ledger);
        if (!storedCanonical) {
          return jsonResponse(
            404,
            buildUnavailableRunPayload(
              runId,
              "No independently validated historical public receipt has been supplied for this route."
            )
          );
        }
        if (!storedCanonical.is_verified) {
          return jsonResponse(422, {
            error: "Public receipt integrity failure: recomputed digest mismatch or tampered payload.",
            tampered: true,
          });
        }
        return jsonResponse(200, storedCanonical.receipt);
      }

      let stored = null;
      if (typeof ledger.getReceipt === "function") {
        stored = await ledger.getReceipt(runId);
      }

      if (!stored) {
        return jsonResponse(404, { error: `Receipt for run '${runId}' not found.` });
      }

      if (!stored.is_verified) {
        return jsonResponse(422, {
          error: "Public receipt integrity failure: recomputed digest mismatch or tampered payload.",
          tampered: true,
        });
      }

      return jsonResponse(200, stored.receipt);
    }

    // 4. Run Details & Telemetry (Read-Only)
    const runMatch = path.match(/^\/v1\/runs\/([A-Za-z0-9_.-]+)\/?$/);
    if (method === "GET" && runMatch) {
      const runId = runMatch[1];
      if (CANONICAL_PUBLIC_IDS.includes(runId)) {
        const storedCanonical = await getCanonicalStoredReceipt(ledger);
        if (!storedCanonical || !storedCanonical.is_verified) {
          return jsonResponse(
            404,
            buildUnavailableRunPayload(
              runId,
              "No independently validated historical public run has been supplied for this route."
            )
          );
        }
        return jsonResponse(200, buildCanonicalRunSummary(runId, storedCanonical));
      }

      const publicRun =
        typeof ledger.getPublicRun === "function" ? await ledger.getPublicRun(runId) : null;

      if (!publicRun) {
        return jsonResponse(404, { error: `Run '${runId}' not found.` });
      }
      return jsonResponse(200, publicRun);
    }

    // 5. Initiate Pre-Audited Verification Scenario (Protected Admission)
    if (method === "POST" && path === "/v1/runs") {
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse(400, { error: "Malformed JSON body." });
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return jsonResponse(400, { error: "Run request body must be a JSON object." });
      }

      const allowLive =
        body.allow_live === true ||
        request.headers.get("X-Allow-Live") === "true";

      if (!allowLive) {
        return jsonResponse(403, {
          status: "NOT_RUN",
          error:
            "Offline synthesized causal results are disabled. No independently validated historical receipt has been supplied for anonymous execution.",
        });
      }

      const forbiddenField = findForbiddenClientAuthorityField(body);
      if (forbiddenField) {
        return jsonResponse(400, {
          status: "INVALID_INPUT",
          error:
            `Client-controlled authority field '${forbiddenField}' is forbidden. ` +
            "Budget facts, provider facts, and exact source binding are established only by trusted server-side configuration and operator-issued grants.",
        });
      }

      const expectedCommit = getDeclaredSourceCommit(env);
      if (expectedCommit === UNKNOWN_BUILD_SHA) {
        return jsonResponse(503, {
          status: "NOT_READY_FOR_DEPLOYMENT",
          error:
            "Live execution is blocked because EXPECTED_SOURCE_COMMIT is not configured. Exact source binding is mandatory before any provider call.",
        });
      }

      const estimatedCostUsd = getConfiguredEstimatedLiveCost(env);
      if (estimatedCostUsd === null) {
        return jsonResponse(503, {
          status: "NOT_READY_FOR_DEPLOYMENT",
          error:
            "Live execution is blocked because the server-controlled maximum estimated live cost is not configured. Uncertain-cost execution is forbidden.",
        });
      }

      const requestedTarget =
        typeof body.target === "string" && body.target.trim()
          ? body.target.trim()
          : CANONICAL_DEMO_SCENARIO.target;

      const reservation = await ledger.reserveAdmission({
        grant_token: request.headers.get("X-Judge-Grant") || "",
        target: requestedTarget,
        source_commit_id: expectedCommit,
        idempotency_key: getRequestIdempotencyKey(request, body),
        estimated_cost: estimatedCostUsd,
        live_enabled: env.LIVE_ENABLED === "true",
      });

      if (!reservation.admitted) {
        return jsonResponse(reservation.code || 503, {
          status: reservation.status,
          error: reservation.error,
        });
      }

      const runId = reservation.run_id;
      if (!runId) {
        return jsonResponse(500, {
          status: "FAILED",
          error: "Admission ledger admitted a run without a run_id.",
        });
      }

      if (reservation.is_replay) {
        const replayRun =
          typeof ledger.getPublicRun === "function" ? await ledger.getPublicRun(runId) : null;
        if (replayRun) {
          return jsonResponse(200, replayRun);
        }
      }

      await ledger.markInFlight(runId);

      // Resolve the trusted-bridge transport at the existing fetchImpl seam. A required
      // private Workers VPC Service binding (TRUSTED_VERIFIER_BRIDGE_MODE=vpc) must NEVER
      // silently fall back to the global fetch; when the binding is missing the resolved
      // fetchImpl is null and the dispatcher fails closed with NOT_READY_FOR_DEPLOYMENT.
      const bridgeTransport = resolveBridgeTransport({
        vpcBinding: env.TRUSTED_VERIFIER_BRIDGE,
        mode: env.TRUSTED_VERIFIER_BRIDGE_MODE,
        directFetch: globalThis.fetch,
        overrideFetch: env.__bridgeFetchForTests,
      });

      const dispatch = await dispatchVerificationRun({
        runId,
        target: requestedTarget,
        sourceCommitId: expectedCommit,
        allowLive: true,
        bridgeUrl: env.TRUSTED_VERIFIER_BRIDGE_URL,
        bridgeSharedSecret: env.TRUSTED_VERIFIER_BRIDGE_SHARED_SECRET,
        bridgeAudience:
          typeof env.TRUSTED_VERIFIER_BRIDGE_AUDIENCE === "string" &&
          env.TRUSTED_VERIFIER_BRIDGE_AUDIENCE.trim()
            ? env.TRUSTED_VERIFIER_BRIDGE_AUDIENCE.trim()
            : DEFAULT_BRIDGE_AUDIENCE,
        estimatedCostUsd,
        fetchImpl: bridgeTransport.fetchImpl,
        verifierAuthorityOverride: env.__testVerifierAuthority,
      });

      if (!dispatch.success) {
        await ledger.recordExecutionFailure(runId, {
          error_message: dispatch.error,
          outcome: dispatch.status,
          was_ambiguous: dispatch.was_ambiguous,
          provider_may_have_dispatched: dispatch.provider_may_have_dispatched === true,
          observed_cost:
            typeof dispatch.observed_cost_usd === "number" ? dispatch.observed_cost_usd : null,
        });
        return jsonResponse(dispatch.code || 503, {
          run_id: runId,
          status: dispatch.status,
          error: dispatch.error,
          ambiguous_outcome: dispatch.was_ambiguous,
        });
      }

      await ledger.recordExecutionSuccess(runId, {
        observed_cost:
          typeof dispatch.observed_cost_usd === "number" ? dispatch.observed_cost_usd : null,
        cost_provenance: dispatch.cost_provenance,
        tokens_used: dispatch.tokens_used || 0,
        receipt: dispatch.receipt,
        allowAuthoritativeProvenance: true,
      });

      const completedRun =
        typeof ledger.getPublicRun === "function" ? await ledger.getPublicRun(runId) : null;
      return jsonResponse(201, completedRun || { run_id: runId, status: "COMPLETED" });
    }

    // 6. Admin API: Issue Single-Use Access Grant
    if (method === "POST" && path === "/admin/grants") {
      if (!isAdminAuthorized(request, env)) {
        return jsonResponse(401, { error: "Unauthorized: Invalid operator admin key." });
      }

      let grantBody = {};
      try {
        grantBody = await request.json();
      } catch {
        // Optional body
      }

      const grant = await ledger.issueGrant({
        token: grantBody.token,
        ttlSeconds: grantBody.ttl_seconds || 3600,
        maxUses: 1, // Strictly single-use
        clientInfo: grantBody.client_info || "judge",
        verifiedBalance: grantBody.verified_balance,
        balanceTimestamp: grantBody.balance_timestamp,
        estimatedCostCap: grantBody.estimated_cost_cap,
      });

      return jsonResponse(201, grant);
    }

    // 7. Admin API: Kill Switch Control
    if (method === "POST" && path === "/admin/killswitch") {
      if (!isAdminAuthorized(request, env)) {
        return jsonResponse(401, { error: "Unauthorized: Invalid operator admin key." });
      }

      let body = {};
      try {
        body = await request.json();
      } catch {
        // Optional body
      }

      const engage = body.engage !== false;
      if (engage) {
        await ledger.engageKillSwitch(body.reason || "Operator engaged kill switch.");
        return jsonResponse(200, { kill_switch_engaged: true });
      } else {
        await ledger.disengageKillSwitch();
        return jsonResponse(200, { kill_switch_engaged: false });
      }
    }

    // 8. Admin API: Ledger Accounting & Audit Inspection
    if (method === "GET" && path === "/admin/ledger") {
      if (!isAdminAuthorized(request, env)) {
        return jsonResponse(401, { error: "Unauthorized: Invalid operator admin key." });
      }

      const accounting = await ledger.getAccounting();
      return jsonResponse(200, accounting);
    }

    // 9. Admin API: Explicit Operator Reconciliation of Unknown Cost (evidence required)
    if (method === "POST" && path === "/admin/reconcile-unknown-cost") {
      if (!isAdminAuthorized(request, env)) {
        return jsonResponse(401, { error: "Unauthorized: Invalid operator admin key." });
      }

      let reconcileBody = {};
      try {
        reconcileBody = await request.json();
      } catch {
        return jsonResponse(400, { error: "Malformed JSON body." });
      }
      if (!reconcileBody || typeof reconcileBody !== "object" || Array.isArray(reconcileBody)) {
        return jsonResponse(400, { error: "Reconciliation body must be a JSON object." });
      }
      if (
        typeof reconcileBody.run_id !== "string" ||
        !reconcileBody.run_id.trim()
      ) {
        return jsonResponse(400, { error: "Reconciliation requires a non-empty run_id." });
      }

      try {
        const result = await ledger.reconcileUnknownCost(reconcileBody.run_id.trim(), {
          attestation_type: reconcileBody.attestation_type,
          operator_decision: reconcileBody.operator_decision,
          provider_billing_observation: reconcileBody.provider_billing_observation,
          evidence_reference: reconcileBody.evidence_reference,
          observed_cost_usd: reconcileBody.observed_cost_usd,
          verification_timestamp: reconcileBody.verification_timestamp,
          release_amount_usd:
            reconcileBody.release_amount_usd === undefined
              ? null
              : reconcileBody.release_amount_usd,
          reconciled_by: reconcileBody.reconciled_by,
          note: reconcileBody.note,
        });
        return jsonResponse(200, result);
      } catch (error) {
        if (error instanceof ReconciliationValidationError) {
          return jsonResponse(400, { error: error.message, hold_preserved: true });
        }
        if (error instanceof ReconciliationStateError) {
          return jsonResponse(409, { error: error.message, hold_preserved: true });
        }
        const message = error instanceof Error ? error.message : String(error);
        return jsonResponse(409, { error: message, hold_preserved: true });
      }
    }

    // 10. Admin API: Explicit operator alignment of the durable expected source commit.
    if (method === "POST" && path === "/admin/configure-source-commit") {
      if (!isAdminAuthorized(request, env)) {
        return jsonResponse(401, { error: "Unauthorized: Invalid operator admin key." });
      }

      let body = {};
      try {
        body = await request.json();
      } catch {
        return jsonResponse(400, { error: "Malformed JSON body." });
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return jsonResponse(400, { error: "Body must be a JSON object." });
      }

      try {
        const result = await ledger.configureSourceCommit(body.source_commit_id, {
          configuredBy: body.configured_by,
          note: body.note,
        });
        return jsonResponse(200, result);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return jsonResponse(400, { error: message });
      }
    }

    // 11. Admin API: Explicit operator change of the durable live gate. Never
    //     triggered by deployment/environment configuration.
    if (method === "POST" && path === "/admin/configure-live-gate") {
      if (!isAdminAuthorized(request, env)) {
        return jsonResponse(401, { error: "Unauthorized: Invalid operator admin key." });
      }

      let body = {};
      try {
        body = await request.json();
      } catch {
        return jsonResponse(400, { error: "Malformed JSON body." });
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return jsonResponse(400, { error: "Body must be a JSON object." });
      }

      try {
        const result = await ledger.configureLiveGate(body.enabled, {
          configuredBy: body.configured_by,
          reason: body.reason,
        });
        return jsonResponse(200, result);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return jsonResponse(400, { error: message });
      }
    }

    // 12. Admin API: Issue a single-use one-time unknown-cost-hold exception.
    //     This is the smallest explicit, auditable exception to the unknown-cost
    //     admission hold. It is bound to exactly one existing single-use grant,
    //     records the historical unknown exposure, requires the promotional-budget
    //     calculation to include both the historical exposure and the new estimated
    //     run exposure, preserves the $5.00 reserve, and is consumed exactly once.
    if (method === "POST" && path === "/admin/cost-hold-exception") {
      if (!isAdminAuthorized(request, env)) {
        return jsonResponse(401, { error: "Unauthorized: Invalid operator admin key." });
      }

      let body = {};
      try {
        body = await request.json();
      } catch {
        return jsonResponse(400, { error: "Malformed JSON body." });
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return jsonResponse(400, { error: "Body must be a JSON object." });
      }

      try {
        const result = await ledger.authorizeCostHoldException({
          grantToken: body.grant_token,
          authorizedBy: body.authorized_by,
          reason: body.reason,
          note: body.note,
        });
        return jsonResponse(201, result);
      } catch (error) {
        if (error instanceof ReconciliationValidationError) {
          return jsonResponse(400, { error: error.message, exception_issued: false });
        }
        if (error instanceof ReconciliationStateError) {
          return jsonResponse(409, { error: error.message, exception_issued: false });
        }
        const message = error instanceof Error ? error.message : String(error);
        return jsonResponse(409, { error: message, exception_issued: false });
      }
    }

    return jsonResponse(404, { error: "Not Found", path });
  },
};
