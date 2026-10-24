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
  DEFAULT_BRIDGE_TIMEOUT_MS,
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

/**
 * Normalize the trusted Worker runtime live-execution flag from env.
 * Accepts ONLY boolean true or exact string "true". All other values are disabled.
 *
 * @param {any} env
 * @returns {boolean}
 */
export function isTrustedRuntimeLiveEnabled(env) {
  return env?.LIVE_ENABLED === true || env?.LIVE_ENABLED === "true";
}

function getConfiguredEstimatedLiveCost(env) {
  const raw =
    typeof env.LIVE_RUN_ESTIMATED_COST_USD === "string" && env.LIVE_RUN_ESTIMATED_COST_USD.trim()
      ? env.LIVE_RUN_ESTIMATED_COST_USD.trim()
      : "0.50";
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
 * Safely escape HTML special characters to prevent injection attacks.
 *
 * @param {any} value
 * @returns {string}
 */
export function escapeHtml(value) {
  if (value === null || value === undefined) {
    return "";
  }
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function replaceRegion(html, startComment, endComment, newInnerContent) {
  const pattern = new RegExp(`<!--\\s*${startComment}\\s*-->[\\s\\S]*?<!--\\s*${endComment}\\s*-->`, "i");
  if (pattern.test(html)) {
    return html.replace(pattern, `<!-- ${startComment} -->\n${newInnerContent}\n<!-- ${endComment} -->`);
  }
  return html;
}

/**
 * Render the judge dashboard HTML binding against a verified stored receipt.
 *
 * @param {string} templateHtml
 * @param {{ runId?: string, stored?: { receipt: Record<string, any>, is_verified: boolean, receipt_digest?: string } | null, error?: string | null }} options
 * @returns {string}
 */
export function renderJudgeHtml(templateHtml, { runId, stored, error = null } = {}) {
  if (!runId || runId === "NOT_SPECIFIED") {
    return templateHtml;
  }

  const safeRunId = escapeHtml(runId);

  // Case 1: Unknown run ID or missing receipt
  if (!stored || !stored.receipt) {
    const errorMsg = error ? escapeHtml(error) : `Receipt for run &#39;${safeRunId}&#39; not found in ledger. Public state remains NOT_RUN.`;

    const badgesHtml = `      <div class="header-badges" id="header-badges">
        <span class="badge badge-prov" id="integrity-badge">PUBLIC RECEIPT: NOT_RUN</span>
        <span class="badge badge-prov" id="prov-badge">PROVENANCE: NOT_RUN</span>
        <span class="badge badge-prov" id="run-badge">RUN: ${safeRunId}</span>
        <span class="badge badge-live">CLOUDFLARE WORKERS EDGE</span>
      </div>`;

    const tripletHtml = `      <div class="triplet-grid" id="triplet-grid">
        <div class="world-card" id="world-card-base">
          <h4><span>[1. Baseline World]</span> <span class="world-status" id="world-status-base">NOT_RUN</span></h4>
          <p id="world-desc-base" style="font-size: 0.88rem; color: var(--text-muted); margin: 0 0 0.5rem;">No independently validated BASE witness execution found for run &#39;${safeRunId}&#39;.</p>
          <div class="digest-box" id="world-digest-base">Historical receipt unavailable in current ledger.</div>
        </div>
        <div class="world-card" id="world-card-candidate">
          <h4><span>[2. Candidate World]</span> <span class="world-status" id="world-status-candidate">NOT_RUN</span></h4>
          <p id="world-desc-candidate" style="font-size: 0.88rem; color: var(--text-muted); margin: 0 0 0.5rem;">No independently validated CANDIDATE witness execution found for run &#39;${safeRunId}&#39;.</p>
          <div class="digest-box" id="world-digest-candidate">Live Cloudflare-to-Nebius verification remains NOT_READY_FOR_DEPLOYMENT.</div>
        </div>
        <div class="world-card" id="world-card-cf">
          <h4><span>[3. Counterfactual]</span> <span class="world-status" id="world-status-cf">NOT_RUN</span></h4>
          <p id="world-desc-cf" style="font-size: 0.88rem; color: var(--text-muted); margin: 0 0 0.5rem;">No independently validated COUNTERFACTUAL witness execution found for run &#39;${safeRunId}&#39;.</p>
          <div class="digest-box" id="world-digest-cf">Synthetic or inferred three-world outcomes are intentionally suppressed.</div>
        </div>
      </div>`;

    const demoResultHtml = `          <div id="demo-result" style="display: block;">
            <div id="result-notice" class="notice notice-warning" style="display: block;">
              ${errorMsg}
            </div>
            <div id="result-details" style="margin-top: 0.75rem; font-size: 0.85rem;">
              Historical receipts remain unavailable until an independently validated artifact is explicitly supplied for publication.
            </div>
          </div>`;

    const receiptInspectorHtml = `          <div style="font-size: 0.85rem; display: flex; flex-direction: column; gap: 0.6rem;">
            <div>
              <span style="color: var(--text-muted);">Receipt SHA-256 Digest:</span>
              <div class="digest-box" id="digest-val">UNAVAILABLE (NOT_RUN)</div>
            </div>
            <div>
              <span style="color: var(--text-muted);">Source Commit SHA:</span>
              <div class="digest-box" id="commit-val">UNKNOWN_BUILD_SHA</div>
            </div>
            <div>
              <span style="color: var(--text-muted);">Public Evidence Status:</span>
              <div class="digest-box" id="evidence-status-val">No independently validated historical receipt supplied for run &#39;${safeRunId}&#39;.</div>
            </div>
            <div style="display: flex; justify-content: space-between; border-top: 1px solid var(--border); padding-top: 0.5rem; margin-top: 0.5rem;">
              <span><strong>Overall Verdict:</strong> <span id="verdict-val">NOT_RUN</span></span>
              <span><strong>Telemetry:</strong> <span id="telemetry-val">UNAVAILABLE</span></span>
            </div>
          </div>
          <div class="notice notice-warning" id="receipt-notice" style="margin-top: 1rem;">
            No canonical public receipt is published for run &#39;${safeRunId}&#39;. Equivalent receipt routes truthfully return NOT_RUN until authentic evidence is explicitly supplied.
          </div>`;

    let out = templateHtml;
    out = replaceRegion(out, "BEGIN_HEADER_BADGES", "END_HEADER_BADGES", badgesHtml);
    out = replaceRegion(out, "BEGIN_TRIPLET_GRID", "END_TRIPLET_GRID", tripletHtml);
    out = replaceRegion(out, "BEGIN_DEMO_RESULT", "END_DEMO_RESULT", demoResultHtml);
    out = replaceRegion(out, "BEGIN_RECEIPT_INSPECTOR", "END_RECEIPT_INSPECTOR", receiptInspectorHtml);
    return out;
  }

  // Case 2: Tampered or unverified receipt
  const statedDigest = stored.receipt.receipt_digest;
  const isIntegrityVerified = Boolean(
    stored.is_verified &&
    statedDigest &&
    (!stored.receipt_digest || stored.receipt_digest === statedDigest)
  );

  if (!isIntegrityVerified) {
    const badgesHtml = `      <div class="header-badges" id="header-badges">
        <span class="badge badge-fail" id="integrity-badge">PUBLIC RECEIPT: BLOCKED</span>
        <span class="badge badge-prov" id="prov-badge">PROVENANCE: BLOCKED</span>
        <span class="badge badge-prov" id="run-badge">RUN: ${safeRunId}</span>
        <span class="badge badge-live">CLOUDFLARE WORKERS EDGE</span>
      </div>`;

    const tripletHtml = `      <div class="triplet-grid" id="triplet-grid">
        <div class="world-card fail" id="world-card-base">
          <h4><span>[1. Baseline World]</span> <span class="world-status status-fail" id="world-status-base">BLOCKED</span></h4>
          <p id="world-desc-base" style="font-size: 0.88rem; color: var(--text-muted); margin: 0 0 0.5rem;">Receipt integrity verification failed. Execution fact suppressed.</p>
          <div class="digest-box" id="world-digest-base">BLOCKED (TAMPERED_OR_UNVERIFIED)</div>
        </div>
        <div class="world-card fail" id="world-card-candidate">
          <h4><span>[2. Candidate World]</span> <span class="world-status status-fail" id="world-status-candidate">BLOCKED</span></h4>
          <p id="world-desc-candidate" style="font-size: 0.88rem; color: var(--text-muted); margin: 0 0 0.5rem;">Receipt integrity verification failed. Candidate execution suppressed.</p>
          <div class="digest-box" id="world-digest-candidate">BLOCKED (TAMPERED_OR_UNVERIFIED)</div>
        </div>
        <div class="world-card fail" id="world-card-cf">
          <h4><span>[3. Counterfactual]</span> <span class="world-status status-fail" id="world-status-cf">BLOCKED</span></h4>
          <p id="world-desc-cf" style="font-size: 0.88rem; color: var(--text-muted); margin: 0 0 0.5rem;">Receipt integrity verification failed. Counterfactual execution suppressed.</p>
          <div class="digest-box" id="world-digest-cf">BLOCKED (TAMPERED_OR_UNVERIFIED)</div>
        </div>
      </div>`;

    const demoResultHtml = `          <div id="demo-result" style="display: block;">
            <div id="result-notice" class="notice notice-fail" style="display: block;">
              Receipt for run &#39;${safeRunId}&#39; failed cryptographic integrity verification. Payload may have been tampered.
            </div>
            <div id="result-details" style="margin-top: 0.75rem; font-size: 0.85rem;">
              Execution facts and verdicts are fail-closed suppressed until receipt recomputed digest matches declared digest.
            </div>
          </div>`;

    const receiptInspectorHtml = `          <div style="font-size: 0.85rem; display: flex; flex-direction: column; gap: 0.6rem;">
            <div>
              <span style="color: var(--text-muted);">Receipt SHA-256 Digest:</span>
              <div class="digest-box" id="digest-val">BLOCKED (TAMPERED_OR_UNVERIFIED)</div>
            </div>
            <div>
              <span style="color: var(--text-muted);">Source Commit SHA:</span>
              <div class="digest-box" id="commit-val">BLOCKED</div>
            </div>
            <div>
              <span style="color: var(--text-muted);">Public Evidence Status:</span>
              <div class="digest-box" id="evidence-status-val">Public receipt integrity failure: recomputed digest mismatch or tampered payload.</div>
            </div>
            <div style="display: flex; justify-content: space-between; border-top: 1px solid var(--border); padding-top: 0.5rem; margin-top: 0.5rem;">
              <span><strong>Overall Verdict:</strong> <span class="status-fail" id="verdict-val">BLOCKED</span></span>
              <span><strong>Telemetry:</strong> <span id="telemetry-val">BLOCKED</span></span>
            </div>
          </div>
          <div class="notice notice-fail" id="receipt-notice" style="margin-top: 1rem;">
            Receipt integrity check failed: recomputed digest did not match stated digest. Result is suppressed.
          </div>`;

    let out = templateHtml;
    out = replaceRegion(out, "BEGIN_HEADER_BADGES", "END_HEADER_BADGES", badgesHtml);
    out = replaceRegion(out, "BEGIN_TRIPLET_GRID", "END_TRIPLET_GRID", tripletHtml);
    out = replaceRegion(out, "BEGIN_DEMO_RESULT", "END_DEMO_RESULT", demoResultHtml);
    out = replaceRegion(out, "BEGIN_RECEIPT_INSPECTOR", "END_RECEIPT_INSPECTOR", receiptInspectorHtml);
    return out;
  }

  // Case 3: Authentic verified receipt
  const receipt = stored.receipt;
  const overallVerdict = escapeHtml(
    typeof receipt.overall_verdict === "string" && receipt.overall_verdict.trim()
      ? receipt.overall_verdict.trim()
      : "UNAVAILABLE"
  );
  const provenance = escapeHtml(
    typeof receipt.provenance === "string" && receipt.provenance.trim()
      ? receipt.provenance.trim()
      : "UNAVAILABLE"
  );
  const receiptDigest = escapeHtml(
    stored.receipt_digest || receipt.receipt_digest || "UNAVAILABLE"
  );
  const sourceCommit = escapeHtml(
    typeof receipt.source_commit_id === "string" && receipt.source_commit_id.trim()
      ? receipt.source_commit_id.trim()
      : UNKNOWN_BUILD_SHA
  );
  const taskId = escapeHtml(
    typeof receipt.task_id === "string" && receipt.task_id.trim()
      ? receipt.task_id.trim()
      : "UNAVAILABLE"
  );

  const executions = Array.isArray(receipt.executions) ? receipt.executions : [];
  const baseExec = executions.find((e) => e && e.world === "BASE") || null;
  const candExec = executions.find((e) => e && e.world === "CANDIDATE") || null;
  const cfExec =
    executions.find((e) => e && e.world === "COUNTERFACTUAL") ||
    receipt.counterfactual?.execution_fact ||
    null;

  function formatWorldFact(exec, worldName, defaultPassDesc, defaultFailDesc) {
    if (!exec) {
      return {
        outcome: "UNAVAILABLE",
        exitCode: "N/A",
        statusText: "UNAVAILABLE",
        statusClass: "",
        cardClass: "",
        sandbox: "N/A",
        treeShort: "N/A",
        duration: "N/A",
        digestBox: `No ${worldName} world execution fact recorded in stored receipt.`,
        desc: `No independently validated ${worldName} execution fact recorded in stored receipt.`,
        hasOutcome: false,
        hasExit: false,
        rawOutcome: null,
        rawExit: null,
      };
    }

    const hasOutcome = typeof exec.outcome === "string" && exec.outcome.trim().length > 0;
    const outcome = hasOutcome ? escapeHtml(exec.outcome.trim()) : "UNAVAILABLE";
    const hasExit = exec.exit_code !== undefined && exec.exit_code !== null;
    const exitCode = hasExit ? escapeHtml(String(exec.exit_code)) : "N/A";

    const statusText = `${outcome} (Exit ${exitCode})`;

    let statusClass = "";
    let cardClass = "";
    if (outcome === "PASS") {
      statusClass = "status-pass";
      cardClass = "pass";
    } else if (outcome === "FAIL") {
      statusClass = "status-fail";
      cardClass = "fail";
    }

    const sandbox = escapeHtml(exec.sandbox_id ? String(exec.sandbox_id) : "N/A");
    const treeShort = escapeHtml(
      exec.tree_digest ? String(exec.tree_digest).slice(0, 16) : "N/A"
    );
    const duration = escapeHtml(
      exec.duration_seconds !== undefined && exec.duration_seconds !== null
        ? String(exec.duration_seconds) + "s"
        : "N/A"
    );

    let desc = "";
    if (outcome === "PASS") {
      desc = defaultPassDesc;
    } else if (outcome === "FAIL") {
      desc = defaultFailDesc;
    } else {
      desc = `${worldName} execution recorded outcome: ${outcome}.`;
    }

    const digestBox = `Sandbox: ${sandbox} | Tree: ${treeShort}... (${duration})`;

    return {
      outcome,
      exitCode,
      statusText,
      statusClass,
      cardClass,
      sandbox,
      treeShort,
      duration,
      digestBox,
      desc,
      hasOutcome,
      hasExit,
      rawOutcome: exec.outcome,
      rawExit: exec.exit_code,
    };
  }

  const baseFact = formatWorldFact(
    baseExec,
    "BASE",
    "Baseline execution unexpectedly PASSED on witness.",
    "Clean base materialization before candidate patch. Verified failure on single-use witness."
  );
  const candFact = formatWorldFact(
    candExec,
    "CANDIDATE",
    "Nemotron candidate patch applied. Verified pass on single-use witness.",
    "Candidate execution FAILED on witness."
  );
  const cfFact = formatWorldFact(
    cfExec,
    "COUNTERFACTUAL",
    "Counterfactual execution PASSED (patch delta was not causally necessary).",
    "Candidate delta subtracted/reverted under identical witness. Proves patch delta was causally necessary."
  );

  const allThreeWorldsPresent = Boolean(baseExec && candExec && cfExec);
  const allOutcomesPresent = Boolean(
    baseFact.hasOutcome && candFact.hasOutcome && cfFact.hasOutcome
  );
  const allExitsPresent = Boolean(
    baseFact.hasExit && candFact.hasExit && cfFact.hasExit
  );

  const outcomesFormTriplets = Boolean(
    baseFact.rawOutcome === "FAIL" &&
    candFact.rawOutcome === "PASS" &&
    cfFact.rawOutcome === "FAIL" &&
    candFact.rawExit === 0 &&
    baseFact.rawExit !== 0 &&
    cfFact.rawExit !== 0
  );

  const isCausalTripletVerified = Boolean(
    overallVerdict === "VERIFIED" &&
    allThreeWorldsPresent &&
    allOutcomesPresent &&
    allExitsPresent &&
    outcomesFormTriplets
  );

  let resultNoticeClass = "notice-info";
  let resultNoticeText = "";
  let resultDetailsText = "";

  if (isCausalTripletVerified) {
    resultNoticeClass = "notice-info";
    resultNoticeText = `Verified historical execution for run: ${safeRunId} (Task: ${taskId})`;
    resultDetailsText = `Causal Invariant: BASE=${baseFact.outcome} (Exit ${baseFact.exitCode}) &rarr; CANDIDATE=${candFact.outcome} (Exit ${candFact.exitCode}) &rarr; COUNTERFACTUAL=${cfFact.outcome} (Exit ${cfFact.exitCode}). Causal triplet verified.`;
  } else if (
    overallVerdict === "VERIFIED" &&
    (!allThreeWorldsPresent || !allOutcomesPresent || !allExitsPresent || !outcomesFormTriplets)
  ) {
    resultNoticeClass = "notice-fail";
    resultNoticeText = `Contradictory execution record for run: ${safeRunId} (Task: ${taskId})`;
    resultDetailsText = `Stored receipt claims VERIFIED but recorded three-world causal outcomes are incomplete or contradictory (BASE=${baseFact.outcome}, CANDIDATE=${candFact.outcome}, COUNTERFACTUAL=${cfFact.outcome}). Causal triplet NOT verified.`;
  } else if (overallVerdict === "FAIL") {
    resultNoticeClass = "notice-fail";
    resultNoticeText = `Execution failed causal verification for run: ${safeRunId} (Task: ${taskId})`;
    resultDetailsText = `Causal Invariant violated: BASE=${baseFact.outcome} (Exit ${baseFact.exitCode}) &rarr; CANDIDATE=${candFact.outcome} (Exit ${candFact.exitCode}) &rarr; COUNTERFACTUAL=${cfFact.outcome} (Exit ${cfFact.exitCode}). Stored verdict: FAIL.`;
  } else if (overallVerdict === "INCONCLUSIVE") {
    resultNoticeClass = "notice-warning";
    resultNoticeText = `Inconclusive execution record for run: ${safeRunId} (Task: ${taskId})`;
    resultDetailsText = `Execution was inconclusive: BASE=${baseFact.outcome} (Exit ${baseFact.exitCode}) &rarr; CANDIDATE=${candFact.outcome} (Exit ${candFact.exitCode}) &rarr; COUNTERFACTUAL=${cfFact.outcome} (Exit ${cfFact.exitCode}). Stored verdict: INCONCLUSIVE.`;
  } else if (overallVerdict === "BLOCKED") {
    resultNoticeClass = "notice-fail";
    resultNoticeText = `Execution blocked for run: ${safeRunId} (Task: ${taskId})`;
    resultDetailsText = `Stored receipt recorded verdict: BLOCKED.`;
  } else if (!allThreeWorldsPresent || !allOutcomesPresent) {
    resultNoticeClass = "notice-warning";
    resultNoticeText = `Incomplete execution record for run: ${safeRunId} (Task: ${taskId})`;
    resultDetailsText = `One or more required three-world execution facts are missing from stored receipt. Causal triplet cannot be verified.`;
  } else {
    resultNoticeClass = "notice-warning";
    resultNoticeText = `Stored execution record for run: ${safeRunId} (Task: ${taskId})`;
    resultDetailsText = `Overall verdict: ${overallVerdict}. Execution facts: BASE=${baseFact.outcome} (Exit ${baseFact.exitCode}) &rarr; CANDIDATE=${candFact.outcome} (Exit ${candFact.exitCode}) &rarr; COUNTERFACTUAL=${cfFact.outcome} (Exit ${cfFact.exitCode}).`;
  }

  const acct = receipt.accounting || {};
  const timing = receipt.timing || {};
  const identities = Array.isArray(receipt.runtime_identities) ? receipt.runtime_identities : [];
  const modelIdRaw =
    identities.find((id) => typeof id === "string" && id.startsWith("model:"))?.replace("model:", "") ||
    identities.find((id) => typeof id === "string" && id.startsWith("candidate-generation:model:"))?.replace("candidate-generation:model:", "") ||
    (typeof acct.model === "string" && acct.model.trim() ? acct.model.trim() : null) ||
    "N/A";
  const modelId = escapeHtml(modelIdRaw);

  const promptTokens = escapeHtml(
    typeof acct.prompt_tokens === "number" ? acct.prompt_tokens.toLocaleString("en-US") : "N/A"
  );
  const completionTokens = escapeHtml(
    typeof acct.completion_tokens === "number" ? acct.completion_tokens.toLocaleString("en-US") : "N/A"
  );
  const sandboxCount = escapeHtml(executions.length > 0 ? String(executions.length) : "N/A");
  const totalDuration = escapeHtml(
    typeof timing.total_duration_seconds === "number"
      ? timing.total_duration_seconds.toFixed(2) + "s"
      : (timing.total_duration_seconds !== undefined && timing.total_duration_seconds !== null ? String(timing.total_duration_seconds) : "N/A")
  );

  const telemetryStr = `Model: ${modelId} | Tokens: ${promptTokens} in / ${completionTokens} out | Sandboxes: ${sandboxCount} | Duration: ${totalDuration}`;

  let verdictBadgeClass = "badge-prov";
  let verdictTextClass = "status-fail";
  if (overallVerdict === "VERIFIED" && isCausalTripletVerified) {
    verdictBadgeClass = "badge-verified";
    verdictTextClass = "status-pass";
  } else if (overallVerdict === "FAIL" || overallVerdict === "BLOCKED") {
    verdictBadgeClass = "badge-fail";
    verdictTextClass = "status-fail";
  }

  const provBadgeClass = provenance === "LIVE_NEBIUS" ? "badge-live" : "badge-prov";

  const badgesHtml = `      <div class="header-badges" id="header-badges">
        <span class="badge ${verdictBadgeClass}" id="integrity-badge">PUBLIC RECEIPT: ${overallVerdict}</span>
        <span class="badge ${provBadgeClass}" id="prov-badge">PROVENANCE: ${provenance}</span>
        <span class="badge badge-prov" id="run-badge">RUN: ${safeRunId}</span>
        <span class="badge badge-live">CLOUDFLARE WORKERS EDGE</span>
      </div>`;

  const tripletHtml = `      <div class="triplet-grid" id="triplet-grid">
        <div class="world-card ${baseFact.cardClass}" id="world-card-base">
          <h4><span>[1. Baseline World]</span> <span class="world-status ${baseFact.statusClass}" id="world-status-base">${baseFact.statusText}</span></h4>
          <p id="world-desc-base" style="font-size: 0.88rem; color: var(--text-muted); margin: 0 0 0.5rem;">${baseFact.desc}</p>
          <div class="digest-box" id="world-digest-base">${baseFact.digestBox}</div>
        </div>
        <div class="world-card ${candFact.cardClass}" id="world-card-candidate">
          <h4><span>[2. Candidate World]</span> <span class="world-status ${candFact.statusClass}" id="world-status-candidate">${candFact.statusText}</span></h4>
          <p id="world-desc-candidate" style="font-size: 0.88rem; color: var(--text-muted); margin: 0 0 0.5rem;">${candFact.desc}</p>
          <div class="digest-box" id="world-digest-candidate">${candFact.digestBox}</div>
        </div>
        <div class="world-card ${cfFact.cardClass}" id="world-card-cf">
          <h4><span>[3. Counterfactual]</span> <span class="world-status ${cfFact.statusClass}" id="world-status-cf">${cfFact.statusText}</span></h4>
          <p id="world-desc-cf" style="font-size: 0.88rem; color: var(--text-muted); margin: 0 0 0.5rem;">${cfFact.desc}</p>
          <div class="digest-box" id="world-digest-cf">${cfFact.digestBox}</div>
        </div>
      </div>`;

  const demoResultHtml = `          <div id="demo-result" style="display: block;">
            <div id="result-notice" class="notice ${resultNoticeClass}" style="display: block;">
              ${resultNoticeText}
            </div>
            <div id="result-details" style="margin-top: 0.75rem; font-size: 0.85rem;">
              ${resultDetailsText}
            </div>
          </div>`;

  const receiptInspectorHtml = `          <div style="font-size: 0.85rem; display: flex; flex-direction: column; gap: 0.6rem;">
            <div>
              <span style="color: var(--text-muted);">Receipt SHA-256 Digest:</span>
              <div class="digest-box" id="digest-val">${receiptDigest}</div>
            </div>
            <div>
              <span style="color: var(--text-muted);">Source Commit SHA:</span>
              <div class="digest-box" id="commit-val">${sourceCommit}</div>
            </div>
            <div>
              <span style="color: var(--text-muted);">Public Evidence Status:</span>
              <div class="digest-box" id="evidence-status-val">Authentic record loaded from ledger (SHA-256 digest verified). Provenance: ${provenance}.</div>
            </div>
            <div style="display: flex; justify-content: space-between; border-top: 1px solid var(--border); padding-top: 0.5rem; margin-top: 0.5rem;">
              <span><strong>Overall Verdict:</strong> <span class="${verdictTextClass}" id="verdict-val">${overallVerdict}</span></span>
              <span><strong>Telemetry:</strong> <span id="telemetry-val">${telemetryStr}</span></span>
            </div>
          </div>
          <div class="notice notice-info" id="receipt-notice" style="margin-top: 1rem;">
            Authentic stored receipt loaded from ledger. SHA-256 digest integrity verified against canonical serialization.
          </div>`;

  let out = templateHtml;
  out = replaceRegion(out, "BEGIN_HEADER_BADGES", "END_HEADER_BADGES", badgesHtml);
  out = replaceRegion(out, "BEGIN_TRIPLET_GRID", "END_TRIPLET_GRID", tripletHtml);
  out = replaceRegion(out, "BEGIN_DEMO_RESULT", "END_DEMO_RESULT", demoResultHtml);
  out = replaceRegion(out, "BEGIN_RECEIPT_INSPECTOR", "END_RECEIPT_INSPECTOR", receiptInspectorHtml);
  return out;
}

async function serveJudgeUi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  let templateHtml = null;
  if (env.ASSETS && typeof env.ASSETS.fetch === "function") {
    try {
      const assetRequest =
        path === "/"
          ? request
          : new Request(new URL("/", request.url).toString(), request);
      const assetResponse = await env.ASSETS.fetch(assetRequest);
      if (assetResponse.status === 200) {
        templateHtml = await assetResponse.text();
      }
    } catch {}
  }

  if (!templateHtml) {
    templateHtml = getFallbackIndexHtml();
  }

  // Handle specific /judge/:run_id route
  let runId = null;
  const judgeMatch = path.match(/^\/judge\/([A-Za-z0-9_.-]+)\/?$/);
  if (judgeMatch) {
    runId = judgeMatch[1];
  } else if (path !== "/" && path !== "/judge" && path !== "/judge/") {
    // Malformed /judge/* path
    let attemptedId = "NOT_FOUND";
    try {
      attemptedId = decodeURIComponent(path.slice(7).replace(/\/$/, ""));
    } catch {}
    return htmlResponse(404, renderJudgeHtml(templateHtml, { runId: attemptedId, stored: null }));
  }

  if (!runId) {
    // Root or base /judge path: truthful public NOT_RUN state
    return htmlResponse(200, templateHtml);
  }

  // Look up receipt in global ledger
  const ledger = getGlobalLedger(env);
  if (!ledger) {
    return htmlResponse(
      200,
      renderJudgeHtml(templateHtml, {
        runId,
        stored: null,
        error: "Admission ledger unavailable. Public state remains NOT_RUN.",
      })
    );
  }

  let stored = null;
  if (CANONICAL_PUBLIC_IDS.includes(runId)) {
    stored = await getCanonicalStoredReceipt(ledger);
  } else if (typeof ledger.getReceipt === "function") {
    stored = await ledger.getReceipt(runId);
  }

  const renderedHtml = renderJudgeHtml(templateHtml, { runId, stored });
  return htmlResponse(200, renderedHtml);
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

    const trustedRuntimeLiveEnabled = isTrustedRuntimeLiveEnabled(env);

    // 2. Health & Source SHA Parity Endpoint (P-27.04)
    if (method === "GET" && (path === "/health" || path === "/v1/health")) {
      const expectedCommit =
        getDeclaredSourceCommit(env);
      const accounting =
        typeof ledger.getAccounting === "function" ? await ledger.getAccounting() : {};
      const runtimeLiveEnabled =
        env && Object.prototype.hasOwnProperty.call(env, "LIVE_ENABLED")
          ? trustedRuntimeLiveEnabled
          : typeof accounting.runtime_live_enabled === "boolean"
            ? accounting.runtime_live_enabled
            : trustedRuntimeLiveEnabled;
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

      const configuredEstimatedCost = getConfiguredEstimatedLiveCost(env);
      const estimatedCostUsd = configuredEstimatedCost !== null ? configuredEstimatedCost : 0.50;

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
        live_enabled: trustedRuntimeLiveEnabled,
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
        bridgeTimeoutMs:
          Number.parseInt(env.TRUSTED_VERIFIER_BRIDGE_TIMEOUT_MS || "", 10) ||
          DEFAULT_BRIDGE_TIMEOUT_MS,
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
          tokens_used: dispatch.tokens_used || 0,
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

    // 13. Admin API: Explicit operator change of the durable global invocation cap.
    if (method === "POST" && path === "/admin/configure-invocation-cap") {
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
        const result = await ledger.configureInvocationCap(body.global_cap, {
          configuredBy: body.configured_by,
          reason: body.reason,
        });
        return jsonResponse(200, result);
      } catch (error) {
        if (error instanceof ReconciliationValidationError) {
          return jsonResponse(400, { error: error.message, configured: false });
        }
        const message = error instanceof Error ? error.message : String(error);
        return jsonResponse(400, { error: message, configured: false });
      }
    }

    // 14. Admin API: List historical verification runs with exact identifiers.
    if (method === "GET" && path === "/admin/runs") {
      if (!isAdminAuthorized(request, env)) {
        return jsonResponse(401, { error: "Unauthorized: Invalid operator admin key." });
      }

      const runs =
        typeof ledger.getAllRuns === "function"
          ? await ledger.getAllRuns()
          : { total: 0, runs: [] };
      return jsonResponse(200, runs);
    }

    return jsonResponse(404, { error: "Not Found", path });
  },
};
