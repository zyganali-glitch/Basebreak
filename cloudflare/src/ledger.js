/**
 * Admission Ledger & Durable Object with SQLite backing.
 *
 * Enforces Section C Credit-Drain Prevention:
 * - Single canonical SQLite-backed ledger for globally metered demo.
 * - Default LIVE_ENABLED=false.
 * - Operator-issued, single-use, server-validated access grants.
 * - Fixed allowlisted demo target and immutable source identity.
 * - Global total invocation cap.
 * - Maximum one in-flight cost-consuming run.
 * - Atomic check-and-reserve BEFORE any provider call.
 * - Idempotency and replay prevention.
 * - Fail-closed recovery after restarts, network loss, and ambiguous outcomes.
 * - Per-run token limits, runtime deadlines, and verified maximum-cost admission.
 * - Administrative kill switch.
 * - Durable accounting distinguishing reserved, observed, and unknown costs.
 * - Rejection of missing, expired, or unverified promotional balance.
 * - Operator-policy $5.00 safety reserve.
 * - No automatic retries capable of repeating an uncertain cost-consuming operation.
 */

import crypto from "node:crypto";
import {
  canonicalJson,
  computeReceiptDigest,
  computeSha256,
  detectSecrets,
  verifyReceiptIntegrity,
} from "./crypto_utils.js";
import { SqlAdapter } from "./sql_adapter.js";

// Safe fallback base class for testing outside Cloudflare Workers
class SafeDurableObjectBase {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env || {};
  }
}

let CloudflareDurableObject = SafeDurableObjectBase;
try {
  // @ts-ignore
  const cf = await import("cloudflare:workers");
  if (cf?.DurableObject) {
    CloudflareDurableObject = cf.DurableObject;
  }
} catch {
  // Running outside Cloudflare Workers environment (e.g. Node test runner)
}

export class AdmissionLedgerDO extends CloudflareDurableObject {
  /**
   * @param {any} ctxOrState Durable Object state/ctx or raw database instance
   * @param {any} [env] Worker environment bindings
   */
  constructor(ctxOrState, env) {
    super(ctxOrState, env);
    this.ctx = ctxOrState;
    this.env = env || {};

    const rawBackend = ctxOrState?.storage?.sql || ctxOrState?.sql || ctxOrState;
    this.sql = new SqlAdapter(rawBackend);
    this.initSchema();
  }

  /**
   * Initialize all SQLite tables and default records.
   */
  initSchema() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS grants (
        grant_id TEXT PRIMARY KEY,
        grant_token TEXT UNIQUE NOT NULL,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        max_uses INTEGER NOT NULL DEFAULT 1,
        use_count INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL,
        client_info TEXT
      );

      CREATE TABLE IF NOT EXISTS runs (
        run_id TEXT PRIMARY KEY,
        idempotency_key TEXT UNIQUE,
        grant_token TEXT,
        target TEXT NOT NULL,
        source_commit_id TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at INTEGER NOT NULL,
        completed_at INTEGER,
        reserved_cost REAL NOT NULL DEFAULT 0.0,
        observed_cost REAL NOT NULL DEFAULT 0.0,
        unknown_cost REAL NOT NULL DEFAULT 0.0,
        tokens_used INTEGER NOT NULL DEFAULT 0,
        error_message TEXT,
        outcome TEXT,
        payload_fingerprint TEXT
      );

      CREATE TABLE IF NOT EXISTS receipts (
        run_id TEXT PRIMARY KEY,
        receipt_digest TEXT NOT NULL,
        receipt_json TEXT NOT NULL,
        source_commit_id TEXT NOT NULL,
        provenance TEXT NOT NULL,
        verdict TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        is_verified INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS costs (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        reserved_cost REAL NOT NULL DEFAULT 0.0,
        observed_cost REAL NOT NULL DEFAULT 0.0,
        unknown_cost REAL NOT NULL DEFAULT 0.0,
        total_metered_cost REAL NOT NULL DEFAULT 0.0
      );

      INSERT OR IGNORE INTO costs (id, reserved_cost, observed_cost, unknown_cost, total_metered_cost)
      VALUES (1, 0.0, 0.0, 0.0, 0.0);

      CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        details TEXT NOT NULL
      );
    `);

    // Initialize default configs from env
    this.setConfigIfNotExists("LIVE_ENABLED", String(this.env.LIVE_ENABLED ?? "false"));
    this.setConfigIfNotExists("GLOBAL_INVOCATION_CAP", String(this.env.GLOBAL_INVOCATION_CAP ?? "5"));
    this.setConfigIfNotExists(
      "TOKEN_FACTORY_PROMO_STOP_THRESHOLD",
      String(this.env.TOKEN_FACTORY_PROMO_STOP_THRESHOLD ?? "5.00")
    );
    this.setConfigIfNotExists(
      "ALLOWLISTED_TARGET",
      String(this.env.ALLOWLISTED_TARGET ?? "tests/fixtures/reset_vault")
    );
    this.setConfigIfNotExists(
      "EXPECTED_SOURCE_COMMIT",
      String(this.env.EXPECTED_SOURCE_COMMIT ?? "80b43b84014fa61b941c7ebcd87836a56dcd7c92")
    );
    this.setConfigIfNotExists("kill_switch_engaged", "false");
  }

  /**
   * Set configuration value if not already set.
   *
   * @param {string} key
   * @param {string} value
   */
  setConfigIfNotExists(key, value) {
    const existing = this.sql.query("SELECT value FROM config WHERE key = ?", key);
    if (existing.length === 0) {
      this.sql.execute("INSERT INTO config (key, value) VALUES (?, ?)", key, value);
    }
  }

  /**
   * Get config value.
   *
   * @param {string} key
   * @param {string} [fallback]
   * @returns {string}
   */
  getConfig(key, fallback = "") {
    const rows = this.sql.query("SELECT value FROM config WHERE key = ?", key);
    return rows.length > 0 ? rows[0].value : fallback;
  }

  /**
   * Set config value.
   *
   * @param {string} key
   * @param {string} value
   */
  setConfig(key, value) {
    this.sql.execute(
      "INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
      key,
      value
    );
  }

  /**
   * Issue an operator-authenticated, single-use access grant.
   *
   * @param {object} options
   * @param {string} [options.token] Optional specific token (otherwise generated)
   * @param {number} [options.ttlSeconds=3600] Time-to-live in seconds
   * @param {number} [options.maxUses=1] Allowed uses (strictly 1 for single-use)
   * @param {string} [options.clientInfo=""]
   * @returns {{ grant_id: string, grant_token: string, expires_at: number, max_uses: number }}
   */
  issueGrant({ token, ttlSeconds = 3600, maxUses = 1, clientInfo = "" } = {}) {
    const grantId = "grant_" + crypto.randomUUID();
    const grantToken = token || "bb_grant_" + crypto.randomBytes(16).toString("hex");
    const now = Date.now();
    const expiresAt = now + ttlSeconds * 1000;

    this.sql.execute(
      `INSERT INTO grants (grant_id, grant_token, issued_at, expires_at, max_uses, use_count, status, client_info)
       VALUES (?, ?, ?, ?, ?, 0, 'ISSUED', ?)`,
      grantId,
      grantToken,
      now,
      expiresAt,
      maxUses,
      clientInfo
    );

    this.sql.execute(
      "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'GRANT_ISSUED', ?)",
      now,
      JSON.stringify({ grant_id: grantId, expires_at: expiresAt, max_uses: maxUses })
    );

    return {
      grant_id: grantId,
      grant_token: grantToken,
      expires_at: expiresAt,
      max_uses: maxUses,
    };
  }

  /**
   * Atomic check-and-reserve admission boundary.
   * Evaluates all constraints and locks quota BEFORE calling external provider.
   *
   * @param {object} params
   * @param {string} params.grant_token Single-use access grant token
   * @param {string} params.target Requested target repository locator
   * @param {string} params.source_commit_id Expected source commit SHA
   * @param {string} [params.idempotency_key] Optional caller idempotency key
   * @param {number} [params.estimated_cost=0.05] Estimated worst-case cost
   * @param {number} [params.verified_balance] Fresh verified promotional balance
   * @param {number} [params.balance_timestamp] Timestamp (ms) when balance was checked
   * @param {boolean} [params.live_enabled] Explicit override or uses config
   * @returns {{ admitted: boolean, status: string, code?: number, error?: string, run_id?: string, reserved_cost?: number, is_replay?: boolean }}
   */
  reserveAdmission({
    grant_token,
    target,
    source_commit_id,
    idempotency_key,
    estimated_cost = 0.05,
    verified_balance,
    balance_timestamp,
    live_enabled,
  }) {
    // 1. Recover orphan runs first
    this.recoverDurableState();

    const now = Date.now();

    // 2. Kill switch check
    if (this.getConfig("kill_switch_engaged") === "true") {
      const reason = this.getConfig("kill_switch_reason", "Operator halted live execution.");
      return {
        admitted: false,
        status: "BLOCKED_KILL_SWITCH",
        code: 503,
        error: `Kill switch engaged by operator: ${reason}. All live runs halted.`,
      };
    }

    // 3. Live enabled check (default LIVE_ENABLED=false)
    const isLive =
      live_enabled !== undefined
        ? Boolean(live_enabled)
        : this.getConfig("LIVE_ENABLED", "false") === "true";

    if (!isLive) {
      return {
        admitted: false,
        status: "BLOCKED",
        code: 403,
        error:
          "Live execution is disabled by default. Status: OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN. Zero-Cost Law enforced.",
      };
    }

    // 4. Target repository allowlist check
    const allowlistedTarget = this.getConfig("ALLOWLISTED_TARGET", "tests/fixtures/reset_vault");
    if (!target || target.trim() !== allowlistedTarget) {
      return {
        admitted: false,
        status: "INVALID_TARGET",
        code: 400,
        error: `Target repository substitution rejected. Only allowlisted canonical demo '${allowlistedTarget}' is permitted.`,
      };
    }

    // 5. Source commit immutability check
    const expectedCommit = this.getConfig(
      "EXPECTED_SOURCE_COMMIT",
      "80b43b84014fa61b941c7ebcd87836a56dcd7c92"
    );
    if (!source_commit_id || source_commit_id.trim().toLowerCase() !== expectedCommit.toLowerCase()) {
      return {
        admitted: false,
        status: "INVALID_SOURCE",
        code: 400,
        error: `Source commit substitution rejected. Expected '${expectedCommit}', received '${source_commit_id}'.`,
      };
    }

    // 6. Idempotency check
    const payloadFp = computeSha256(
      canonicalJson({ target: target.trim(), source_commit_id: source_commit_id.trim() })
    );

    if (idempotency_key && typeof idempotency_key === "string" && idempotency_key.trim()) {
      const existingRuns = this.sql.query(
        "SELECT run_id, status, payload_fingerprint FROM runs WHERE idempotency_key = ?",
        idempotency_key.trim()
      );
      if (existingRuns.length > 0) {
        const existing = existingRuns[0];
        if (existing.payload_fingerprint === payloadFp) {
          return {
            admitted: true,
            is_replay: true,
            run_id: existing.run_id,
            status: existing.status,
          };
        } else {
          return {
            admitted: false,
            status: "IDEMPOTENCY_CONFLICT",
            code: 409,
            error: "Idempotency key reused with conflicting request payload.",
          };
        }
      }
    }

    // 6. Grant validation (exists, unexpired, unconsumed)
    if (!grant_token || typeof grant_token !== "string" || !grant_token.trim()) {
      return {
        admitted: false,
        status: "MISSING_GRANT",
        code: 401,
        error: "Access grant token required for live execution. Anonymous self-service execution is forbidden.",
      };
    }

    const grantRows = this.sql.query(
      "SELECT * FROM grants WHERE grant_token = ?",
      grant_token.trim()
    );
    if (grantRows.length === 0) {
      return {
        admitted: false,
        status: "INVALID_GRANT",
        code: 403,
        error: "Invalid or forged access grant token.",
      };
    }

    const grant = grantRows[0];
    if (grant.status === "EXPIRED" || grant.expires_at < now) {
      this.sql.execute("UPDATE grants SET status = 'EXPIRED' WHERE grant_id = ?", grant.grant_id);
      return {
        admitted: false,
        status: "EXPIRED_GRANT",
        code: 403,
        error: "Access grant has expired.",
      };
    }

    if (grant.status === "CONSUMED" || grant.use_count >= grant.max_uses) {
      return {
        admitted: false,
        status: "GRANT_ALREADY_USED",
        code: 409,
        error: "Access grant has already been consumed (single-use constraint).",
      };
    }

    if (grant.status !== "ISSUED") {
      return {
        admitted: false,
        status: "INVALID_GRANT",
        code: 403,
        error: `Access grant is not active (status: ${grant.status}).`,
      };
    }

    // 7. Global total invocation cap check
    const countRows = this.sql.query("SELECT COUNT(*) as count FROM runs WHERE status != 'REJECTED'");
    const totalRuns = countRows[0]?.count ?? 0;
    const globalCap = parseInt(this.getConfig("GLOBAL_INVOCATION_CAP", "5"), 10);
    if (totalRuns >= globalCap) {
      return {
        admitted: false,
        status: "CAP_EXHAUSTED",
        code: 429,
        error: `Global live invocation cap (${globalCap}) reached. Promotional live budget is exhausted. Read-only inspection remains available.`,
      };
    }

    // 8. Global in-flight concurrency check (Maximum 1 in-flight)
    const inFlightRows = this.sql.query(
      "SELECT COUNT(*) as count FROM runs WHERE status IN ('RESERVED', 'IN_FLIGHT')"
    );
    const inFlightCount = inFlightRows[0]?.count ?? 0;
    if (inFlightCount >= 1) {
      return {
        admitted: false,
        status: "CONCURRENCY_LIMIT",
        code: 429,
        error:
          "A verification run is currently in progress. Global concurrency limit: 1. Please retry after completion.",
      };
    }

    // 10. Promotional balance verification and $5.00 safety reserve floor
    const stopThreshold = parseFloat(this.getConfig("TOKEN_FACTORY_PROMO_STOP_THRESHOLD", "5.00"));
    if (verified_balance === undefined || verified_balance === null) {
      return {
        admitted: false,
        status: "BLOCKED_BALANCE_MISSING",
        code: 422,
        error:
          "Promotional balance verification is missing. Cannot verify safety floor. Preflight check required.",
      };
    }

    if (typeof balance_timestamp !== "number" || now - balance_timestamp > 15 * 60 * 1000) {
      return {
        admitted: false,
        status: "BLOCKED_BALANCE_STALE",
        code: 422,
        error:
          "Promotional balance verification is stale (>15 minutes old). Fresh operator preflight balance verification is mandatory.",
      };
    }

    const balanceNum = parseFloat(String(verified_balance));
    if (isNaN(balanceNum) || balanceNum <= stopThreshold) {
      return {
        admitted: false,
        status: "BLOCKED_BUDGET_FLOOR",
        code: 403,
        error: `Promotional balance ($${balanceNum.toFixed(2)}) is at or below the $${stopThreshold.toFixed(2)} safety reserve floor. Live execution prohibited under Zero-Cost Law.`,
      };
    }

    if (balanceNum - estimated_cost < stopThreshold) {
      return {
        admitted: false,
        status: "BLOCKED_BUDGET_FLOOR",
        code: 403,
        error: `Estimated run cost ($${estimated_cost.toFixed(2)}) would reduce promotional balance ($${(balanceNum - estimated_cost).toFixed(2)}) below the $${stopThreshold.toFixed(2)} safety floor.`,
      };
    }

    // 11. Atomic Reservation within Transaction
    return this.sql.transaction(() => {
      // Re-verify in-flight count under transaction
      const checkInFlight = this.sql.query(
        "SELECT COUNT(*) as count FROM runs WHERE status IN ('RESERVED', 'IN_FLIGHT')"
      )[0]?.count ?? 0;
      if (checkInFlight >= 1) {
        return {
          admitted: false,
          status: "CONCURRENCY_LIMIT",
          code: 429,
          error: "Race condition prevented: A verification run was admitted concurrently.",
        };
      }

      // Consume grant
      this.sql.execute(
        "UPDATE grants SET use_count = use_count + 1, status = 'CONSUMED' WHERE grant_id = ?",
        grant.grant_id
      );

      const runId = "run_" + crypto.randomUUID();

      // Insert run as RESERVED
      this.sql.execute(
        `INSERT INTO runs (run_id, idempotency_key, grant_token, target, source_commit_id, status, started_at, reserved_cost, payload_fingerprint)
         VALUES (?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?)`,
        runId,
        idempotency_key ? idempotency_key.trim() : null,
        grant.grant_token,
        target.trim(),
        source_commit_id.trim(),
        now,
        estimated_cost,
        payloadFp
      );

      // Update costs
      this.sql.execute(
        "UPDATE costs SET reserved_cost = reserved_cost + ? WHERE id = 1",
        estimated_cost
      );

      // Log audit
      this.sql.execute(
        "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'RUN_RESERVED', ?)",
        now,
        JSON.stringify({
          run_id: runId,
          grant_id: grant.grant_id,
          reserved_cost: estimated_cost,
        })
      );

      return {
        admitted: true,
        run_id: runId,
        status: "RESERVED",
        reserved_cost: estimated_cost,
      };
    });
  }

  /**
   * Transition run from RESERVED to IN_FLIGHT when provider call is dispatched.
   *
   * @param {string} runId
   */
  markInFlight(runId) {
    this.sql.execute(
      "UPDATE runs SET status = 'IN_FLIGHT' WHERE run_id = ? AND status = 'RESERVED'",
      runId
    );
  }

  /**
   * Record successful verification run execution and persist authenticated public receipt.
   *
   * @param {string} runId
   * @param {object} params
   * @param {number} [params.observed_cost=0.0]
   * @param {number} [params.tokens_used=0]
   * @param {Record<string, unknown>} params.receipt
   */
  recordExecutionSuccess(runId, { observed_cost = 0.0, tokens_used = 0, receipt }) {
    if (!receipt || typeof receipt !== "object") {
      throw new Error("A valid public verification receipt object is required.");
    }

    // Cryptographic receipt integrity verification
    if (!verifyReceiptIntegrity(receipt)) {
      throw new Error("Public receipt integrity verification failed: hash mismatch or tampered payload.");
    }

    // Secret safety check
    const secretFinding = detectSecrets(receipt);
    if (secretFinding.hasSecret) {
      throw new Error(`Public receipt contains secret pattern: ${secretFinding.matchedPattern}`);
    }

    const now = Date.now();

    return this.sql.transaction(() => {
      const runRows = this.sql.query("SELECT * FROM runs WHERE run_id = ?", runId);
      if (runRows.length === 0) {
        throw new Error(`Run '${runId}' not found in ledger.`);
      }
      const run = runRows[0];
      const previousReserved = run.reserved_cost || 0.0;

      // Update run
      this.sql.execute(
        `UPDATE runs
         SET status = 'COMPLETED',
             completed_at = ?,
             observed_cost = ?,
             tokens_used = ?,
             outcome = ?,
             reserved_cost = 0.0
         WHERE run_id = ?`,
        now,
        observed_cost,
        tokens_used,
        String(receipt.overall_verdict ?? "VERIFIED"),
        runId
      );

      // Update accounting: subtract reserved_cost, add observed_cost
      this.sql.execute(
        `UPDATE costs
         SET reserved_cost = MAX(0.0, reserved_cost - ?),
             observed_cost = observed_cost + ?,
             total_metered_cost = (observed_cost + ?) + unknown_cost
         WHERE id = 1`,
        previousReserved,
        observed_cost,
        observed_cost
      );

      // Store verified receipt
      const receiptJson = canonicalJson(receipt);
      this.sql.execute(
        `INSERT OR REPLACE INTO receipts (run_id, receipt_digest, receipt_json, source_commit_id, provenance, verdict, created_at, is_verified)
         VALUES (?, ?, ?, ?, ?, ?, ?, 1)`,
        runId,
        String(receipt.receipt_digest),
        receiptJson,
        String(receipt.source_commit_id),
        String(receipt.provenance),
        String(receipt.overall_verdict),
        now
      );

      this.sql.execute(
        "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'RUN_COMPLETED', ?)",
        now,
        JSON.stringify({ run_id: runId, observed_cost, digest: receipt.receipt_digest })
      );

      return { success: true, run_id: runId, receipt_digest: receipt.receipt_digest };
    });
  }

  /**
   * Record failure or ambiguous execution outcome.
   * Enforces Section C:
   * - If outcome was ambiguous (timeout/disconnect), cost shifts to unknown_cost.
   * - Strictly forbids automatic retries that could duplicate a cost-consuming action.
   *
   * @param {string} runId
   * @param {object} params
   * @param {string} params.error_message
   * @param {string} [params.outcome="FAILED"]
   * @param {boolean} [params.was_ambiguous=false] True if timeout/crash occurred mid-execution
   * @param {number} [params.observed_cost=0.0]
   */
  recordExecutionFailure(runId, { error_message, outcome = "FAILED", was_ambiguous = false, observed_cost = 0.0 }) {
    const now = Date.now();

    return this.sql.transaction(() => {
      const runRows = this.sql.query("SELECT * FROM runs WHERE run_id = ?", runId);
      if (runRows.length === 0) {
        throw new Error(`Run '${runId}' not found in ledger.`);
      }
      const run = runRows[0];
      const previousReserved = run.reserved_cost || 0.0;
      const finalStatus = was_ambiguous ? "UNKNOWN_OUTCOME" : "FAILED";

      this.sql.execute(
        `UPDATE runs
         SET status = ?,
             completed_at = ?,
             error_message = ?,
             outcome = ?,
             reserved_cost = 0.0,
             unknown_cost = ?,
             observed_cost = ?
         WHERE run_id = ?`,
        finalStatus,
        now,
        error_message,
        outcome,
        was_ambiguous ? previousReserved : 0.0,
        observed_cost,
        runId
      );

      if (was_ambiguous) {
        // Shift reserved cost into unknown_cost to prevent double-spending while retaining conservative accounting
        this.sql.execute(
          `UPDATE costs
           SET reserved_cost = MAX(0.0, reserved_cost - ?),
               unknown_cost = unknown_cost + ?,
               total_metered_cost = observed_cost + (unknown_cost + ?)
           WHERE id = 1`,
          previousReserved,
          previousReserved,
          previousReserved
        );
      } else {
        this.sql.execute(
          `UPDATE costs
           SET reserved_cost = MAX(0.0, reserved_cost - ?),
               observed_cost = observed_cost + ?,
               total_metered_cost = (observed_cost + ?) + unknown_cost
           WHERE id = 1`,
          previousReserved,
          observed_cost,
          observed_cost
        );
      }

      this.sql.execute(
        "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'RUN_FAILED', ?)",
        now,
        JSON.stringify({ run_id: runId, status: finalStatus, error_message, was_ambiguous })
      );

      return { recorded: true, run_id: runId, status: finalStatus };
    });
  }

  /**
   * Fail-closed recovery after restarts, worker crashes, or network loss.
   * Clears dead in-flight locks and permanently shifts costs to unknown_cost.
   *
   * @param {number} [deadlineSeconds=60] Execution deadline threshold
   * @returns {number} Count of recovered orphan runs
   */
  recoverDurableState(deadlineSeconds = 60) {
    const thresholdTime = Date.now() - deadlineSeconds * 1000;
    const orphans = this.sql.query(
      "SELECT run_id, reserved_cost FROM runs WHERE status IN ('RESERVED', 'IN_FLIGHT') AND started_at < ?",
      thresholdTime
    );

    if (orphans.length === 0) {
      return 0;
    }

    return this.sql.transaction(() => {
      let recoveredCount = 0;
      for (const orphan of orphans) {
        const reserved = orphan.reserved_cost || 0.0;
        this.sql.execute(
          `UPDATE runs
           SET status = 'TIMED_OUT',
               completed_at = ?,
               error_message = 'Execution deadline exceeded without provider completion. Fail-closed recovery enforced.',
               reserved_cost = 0.0,
               unknown_cost = ?
           WHERE run_id = ?`,
          Date.now(),
          reserved,
          orphan.run_id
        );

        this.sql.execute(
          `UPDATE costs
           SET reserved_cost = MAX(0.0, reserved_cost - ?),
               unknown_cost = unknown_cost + ?,
               total_metered_cost = observed_cost + (unknown_cost + ?)
           WHERE id = 1`,
          reserved,
          reserved,
          reserved
        );

        this.sql.execute(
          "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'ORPHAN_RUN_RECOVERED', ?)",
          Date.now(),
          JSON.stringify({ run_id: orphan.run_id, shifted_cost: reserved })
        );

        recoveredCount += 1;
      }
      return recoveredCount;
    });
  }

  /**
   * Engage operator administrative kill switch.
   *
   * @param {string} reason
   */
  engageKillSwitch(reason = "Halted by operator.") {
    this.setConfig("kill_switch_engaged", "true");
    this.setConfig("kill_switch_reason", reason);
    this.sql.execute(
      "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'KILL_SWITCH_ENGAGED', ?)",
      Date.now(),
      JSON.stringify({ reason })
    );
  }

  /**
   * Disengage kill switch.
   */
  disengageKillSwitch() {
    this.setConfig("kill_switch_engaged", "false");
    this.sql.execute(
      "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'KILL_SWITCH_DISENGAGED', ?)",
      Date.now(),
      "{}"
    );
  }

  /**
   * Store an authoritative or fixture public receipt directly into durable SQLite storage.
   *
   * @param {string} runId
   * @param {Record<string, unknown>} receiptObj
   */
  storeReceipt(runId, receiptObj) {
    if (!verifyReceiptIntegrity(receiptObj)) {
      throw new Error("Public receipt integrity verification failed: recomputed digest mismatch.");
    }
    const secretCheck = detectSecrets(receiptObj);
    if (secretCheck.hasSecret) {
      throw new Error("Receipt contains sensitive credentials or secrets.");
    }

    const receiptJson = canonicalJson(receiptObj);
    const now = Date.now();

    this.sql.execute(
      `INSERT OR REPLACE INTO receipts (run_id, receipt_digest, receipt_json, source_commit_id, provenance, verdict, created_at, is_verified)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1)`,
      runId,
      String(receiptObj.receipt_digest),
      receiptJson,
      String(receiptObj.source_commit_id || ""),
      String(receiptObj.provenance || "FIXTURE"),
      String(receiptObj.overall_verdict || "VERIFIED"),
      now
    );
  }

  /**
   * Retrieve a public verification receipt by run ID.
   * Validates cryptographic integrity before returning to callers.
   *
   * @param {string} runId
   * @returns {{ receipt: Record<string, unknown>, is_verified: boolean, receipt_digest: string } | null}
   */
  getReceipt(runId) {
    const rows = this.sql.query("SELECT * FROM receipts WHERE run_id = ?", runId);
    if (rows.length === 0) {
      return null;
    }
    const row = rows[0];
    let parsed;
    try {
      parsed = JSON.parse(row.receipt_json);
    } catch {
      return null;
    }

    const isAuthentic = verifyReceiptIntegrity(parsed);
    return {
      receipt: parsed,
      is_verified: isAuthentic,
      receipt_digest: row.receipt_digest,
    };
  }

  /**
   * Get complete durable accounting and metrics.
   *
   * @returns {object}
   */
  getAccounting() {
    const costRows = this.sql.query("SELECT * FROM costs WHERE id = 1");
    const costs = costRows[0] || {
      reserved_cost: 0.0,
      observed_cost: 0.0,
      unknown_cost: 0.0,
      total_metered_cost: 0.0,
    };

    const inFlightCount =
      this.sql.query(
        "SELECT COUNT(*) as count FROM runs WHERE status IN ('RESERVED', 'IN_FLIGHT')"
      )[0]?.count ?? 0;

    const totalRuns =
      this.sql.query("SELECT COUNT(*) as count FROM runs WHERE status != 'REJECTED'")[0]?.count ??
      0;

    const completedRuns =
      this.sql.query("SELECT COUNT(*) as count FROM runs WHERE status = 'COMPLETED'")[0]?.count ?? 0;

    return {
      reserved_cost: costs.reserved_cost,
      observed_cost: costs.observed_cost,
      unknown_cost: costs.unknown_cost,
      total_metered_cost: costs.total_metered_cost,
      in_flight_count: inFlightCount,
      total_runs: totalRuns,
      completed_runs: completedRuns,
      global_cap: parseInt(this.getConfig("GLOBAL_INVOCATION_CAP", "5"), 10),
      kill_switch_engaged: this.getConfig("kill_switch_engaged") === "true",
      live_enabled: this.getConfig("LIVE_ENABLED", "false") === "true",
      safety_reserve_floor: parseFloat(this.getConfig("TOKEN_FACTORY_PROMO_STOP_THRESHOLD", "5.00")),
    };
  }
}
