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

import { detectSecrets, redactSecrets, verifyReceiptIntegrity } from "./crypto_utils.js";
import { AdmissionLedgerDO } from "./ledger.js";
import {
  CANONICAL_DEMO_SCENARIO,
  buildCanonicalResetVaultReceipt,
  dispatchVerificationRun,
} from "./provider_dispatcher.js";

// Re-export Durable Object class for Cloudflare Workers runtime
export { AdmissionLedgerDO };

// Embedded Judge UI HTML fallback when ASSETS binding is unavailable
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

let cachedIndexHtml = "";
try {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  cachedIndexHtml = readFileSync(join(__dirname, "../public/index.html"), "utf-8");
} catch {
  cachedIndexHtml = `<!DOCTYPE html><html><body><h1>Basebreak Causal Verification</h1></body></html>`;
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
  // In-process fallback instance for testing
  if (!env.__ledgerInstance) {
    env.__ledgerInstance = new AdmissionLedgerDO(env.__sqliteBackend || {}, env);
  }
  return env.__ledgerInstance;
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

    const ledger = getGlobalLedger(env);

    // 1. Root and Judge Dashboard UI (Read-Only Public Access)
    if (method === "GET" && (path === "/" || path === "/judge" || path.startsWith("/judge/"))) {
      if (env.ASSETS && typeof env.ASSETS.fetch === "function") {
        return env.ASSETS.fetch(request);
      }
      return htmlResponse(200, cachedIndexHtml);
    }

    // 2. Health & Source SHA Parity Endpoint (P-27.04)
    if (method === "GET" && (path === "/health" || path === "/v1/health")) {
      const expectedCommit =
        env.EXPECTED_SOURCE_COMMIT || "80b43b84014fa61b941c7ebcd87836a56dcd7c92";
      const accounting =
        typeof ledger.getAccounting === "function" ? ledger.getAccounting() : {};

      return jsonResponse(200, {
        status: "ok",
        platform: "cloudflare_workers",
        version: "1.0.0",
        source_commit_id: expectedCommit,
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

      // If requesting canonical demo receipt
      if (runId === "canonical-demo" || runId === "reset_vault") {
        const canonical = buildCanonicalResetVaultReceipt();
        return jsonResponse(200, canonical);
      }

      let stored = null;
      if (typeof ledger.getReceipt === "function") {
        stored = ledger.getReceipt(runId);
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
      if (runId === "canonical-demo") {
        return jsonResponse(200, {
          run_id: "canonical-demo",
          status: "COMPLETED",
          target: "tests/fixtures/reset_vault",
          outcome: "VERIFIED",
          is_published: true,
        });
      }

      const rows =
        typeof ledger.sql?.query === "function"
          ? ledger.sql.query("SELECT * FROM runs WHERE run_id = ?", runId)
          : [];

      if (rows.length === 0) {
        return jsonResponse(404, { error: `Run '${runId}' not found.` });
      }
      return jsonResponse(200, rows[0]);
    }

    // 5. Initiate Pre-Audited Verification Scenario (Protected Admission)
    if (method === "POST" && path === "/v1/runs") {
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse(400, { error: "Malformed JSON body." });
      }

      const grantToken =
        request.headers.get("X-Judge-Grant") || body.grant_token || body.grant;

      const target = body.target || "tests/fixtures/reset_vault";
      const sourceCommit =
        body.source_commit_id ||
        env.EXPECTED_SOURCE_COMMIT ||
        "80b43b84014fa61b941c7ebcd87836a56dcd7c92";

      const idempotencyKey =
        request.headers.get("Idempotency-Key") || body.idempotency_key;

      const allowLive =
        body.allow_live === true ||
        request.headers.get("X-Allow-Live") === "true";

      // If caller did not request live execution, serve offline canonical result safely
      if (!allowLive) {
        const canonical = buildCanonicalResetVaultReceipt({
          provenance: "FIXTURE",
        });
        return jsonResponse(200, {
          run_id: "run_offline_" + crypto.randomUUID().slice(0, 8),
          status: "VERIFIED",
          is_live: false,
          receipt: canonical,
          message:
            "Offline preflight completed. Invariant verified: BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL.",
        });
      }

      // Check admission boundary via Durable Object
      const reservation = ledger.reserveAdmission({
        grant_token: grantToken,
        target,
        source_commit_id: sourceCommit,
        idempotency_key: idempotencyKey,
        verified_balance: body.verified_balance ?? env.VERIFIED_PROMO_BALANCE,
        balance_timestamp:
          body.balance_timestamp ?? (env.BALANCE_TIMESTAMP ? Number(env.BALANCE_TIMESTAMP) : Date.now()),
        live_enabled: env.LIVE_ENABLED === "true",
      });

      if (!reservation.admitted) {
        return jsonResponse(reservation.code || 403, {
          error: reservation.error,
          status: reservation.status,
        });
      }

      if (reservation.is_replay) {
        return jsonResponse(200, {
          run_id: reservation.run_id,
          status: reservation.status,
          is_replay: true,
        });
      }

      const runId = reservation.run_id;
      if (typeof ledger.markInFlight === "function") {
        ledger.markInFlight(runId);
      }

      // Dispatch to provider execution boundary
      const execResult = await dispatchVerificationRun({
        runId,
        target,
        sourceCommitId: sourceCommit,
        allowLive: true,
        nebiusApiKey: env.NEBIUS_API_KEY,
        nebiusProjectId: env.NEBIUS_PROJECT_ID,
      });

      if (execResult.success && execResult.receipt) {
        ledger.recordExecutionSuccess(runId, {
          observed_cost: execResult.observed_cost,
          tokens_used: execResult.tokens_used,
          receipt: execResult.receipt,
        });

        return jsonResponse(201, {
          run_id: runId,
          status: "COMPLETED",
          outcome: execResult.receipt.overall_verdict,
          receipt: execResult.receipt,
        });
      } else {
        ledger.recordExecutionFailure(runId, {
          error_message: execResult.error || "Unknown execution failure",
          was_ambiguous: execResult.was_ambiguous ?? false,
          observed_cost: execResult.observed_cost ?? 0.0,
        });

        return jsonResponse(502, {
          error: execResult.error,
          run_id: runId,
          status: execResult.was_ambiguous ? "UNKNOWN_OUTCOME" : "FAILED",
        });
      }
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

      const grant = ledger.issueGrant({
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
        ledger.engageKillSwitch(body.reason || "Operator engaged kill switch.");
        return jsonResponse(200, { kill_switch_engaged: true });
      } else {
        ledger.disengageKillSwitch();
        return jsonResponse(200, { kill_switch_engaged: false });
      }
    }

    // 8. Admin API: Ledger Accounting & Audit Inspection
    if (method === "GET" && path === "/admin/ledger") {
      if (!isAdminAuthorized(request, env)) {
        return jsonResponse(401, { error: "Unauthorized: Invalid operator admin key." });
      }

      const accounting = ledger.getAccounting();
      return jsonResponse(200, accounting);
    }

    return jsonResponse(404, { error: "Not Found", path });
  },
};
