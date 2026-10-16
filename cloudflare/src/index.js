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
import { AdmissionLedgerDO } from "./ledger.js";

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
    const assetResponse = await env.ASSETS.fetch(request);
    if (assetResponse.status !== 404) {
      return assetResponse;
    }

    const indexUrl = new URL("/index.html", request.url);
    const indexRequest = new Request(indexUrl.toString(), request);
    const indexResponse = await env.ASSETS.fetch(indexRequest);
    if (indexResponse.status !== 404) {
      return indexResponse;
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

function getDeclaredSourceCommit(env) {
  if (typeof env.EXPECTED_SOURCE_COMMIT === "string" && env.EXPECTED_SOURCE_COMMIT.trim()) {
    return env.EXPECTED_SOURCE_COMMIT.trim();
  }
  return UNKNOWN_BUILD_SHA;
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

      return jsonResponse(200, {
        status: "ok",
        platform: "cloudflare_workers",
        version: "1.0.0",
        source_commit_id: expectedCommit,
        source_commit_status:
          expectedCommit === UNKNOWN_BUILD_SHA ? "UNKNOWN_BUILD_SHA" : "CONFIGURED_UNVERIFIED",
        deployment_readiness: "NOT_READY_FOR_DEPLOYMENT",
        live_enabled: env.LIVE_ENABLED === "true",
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

      return jsonResponse(503, {
        status: "NOT_RUN",
        error:
          "Live execution is NOT_READY_FOR_DEPLOYMENT. Trusted server-controlled budget authority and independently validated remote Python verification integration are unavailable, so no provider call was attempted.",
      });
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

    return jsonResponse(404, { error: "Not Found", path });
  },
};
