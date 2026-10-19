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

const AUTHORITATIVE_PUBLIC_PROVENANCES = new Set(["LIVE_NEBIUS", "RECORDED_LIVE"]);

const HEX_40_REGEX = /^[0-9a-f]{40}$/;
const ALLOWED_RECONCILIATION_DECISIONS = new Set([
  "NO_PROVIDER_CHARGE",
  "PROVIDER_CHARGE_OBSERVED",
]);
const ALLOWED_ATTESTATION_TYPES = new Set(["OPERATOR_ATTESTED"]);
const MAX_RECONCILIATION_TIMESTAMP_SKEW_MS = 24 * 60 * 60 * 1000;
const COST_HOLD_EXCEPTION_AUTHORIZED = "AUTHORIZED";
const COST_HOLD_EXCEPTION_CONSUMED = "CONSUMED";
const COST_HOLD_EXCEPTION_EXPIRED = "EXPIRED";

/** Raised when a reconciliation record is missing/invalid evidence. */
export class ReconciliationValidationError extends Error {}

/** Raised when a reconciliation record is well-formed but the ledger state forbids it. */
export class ReconciliationStateError extends Error {}

export class AdmissionLedgerDO extends CloudflareDurableObject {
  /**
   * @param {any} ctxOrState Durable Object state/ctx or raw database instance
   * @param {any} [env] Worker environment bindings
   */
  constructor(ctxOrState, env) {
    super(ctxOrState, env);
    this.ctx = ctxOrState;
    this.env = env || {};

    this.sql = new SqlAdapter(ctxOrState);
    this.initSchema();
  }

  /**
   * Enforce that cryptographic digest equality does not, by itself, grant live-evidence authority.
   *
   * @param {Record<string, unknown>} receiptObj
   * @param {{ allowAuthoritativeProvenance?: boolean }} [options]
   */
  assertReceiptAuthority(receiptObj, { allowAuthoritativeProvenance = false } = {}) {
    const provenance = String(receiptObj.provenance || "").trim().toUpperCase();
    if (AUTHORITATIVE_PUBLIC_PROVENANCES.has(provenance) && !allowAuthoritativeProvenance) {
      throw new Error(
        "Authoritative LIVE_NEBIUS/RECORDED_LIVE receipt import is blocked until independent trusted verification authority is configured."
      );
    }
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
        client_info TEXT,
        verified_balance REAL,
        balance_timestamp INTEGER,
        estimated_cost_cap REAL
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

      CREATE TABLE IF NOT EXISTS reconciliations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL,
        attestation_type TEXT NOT NULL,
        operator_decision TEXT NOT NULL,
        provider_billing_observation TEXT NOT NULL,
        evidence_reference TEXT NOT NULL,
        observed_cost_usd REAL NOT NULL,
        verification_timestamp INTEGER NOT NULL,
        released_amount_usd REAL NOT NULL,
        remaining_unknown_cost REAL NOT NULL,
        reconciled_by TEXT NOT NULL,
        recorded_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS cost_hold_exceptions (
        exception_id TEXT PRIMARY KEY,
        grant_id TEXT NOT NULL,
        grant_token TEXT NOT NULL,
        authorized_by TEXT NOT NULL,
        reason TEXT NOT NULL,
        authorized_at INTEGER NOT NULL,
        existing_unknown_cost_usd REAL NOT NULL,
        estimated_cost_cap_usd REAL NOT NULL,
        reserve_floor_usd REAL NOT NULL,
        total_budget_required_usd REAL NOT NULL,
        verified_balance_usd REAL NOT NULL,
        status TEXT NOT NULL,
        consumed_at INTEGER,
        consumed_run_id TEXT
      );
    `);

    this.ensureColumnExists("grants", "verified_balance", "REAL");
    this.ensureColumnExists("grants", "balance_timestamp", "INTEGER");
    this.ensureColumnExists("grants", "estimated_cost_cap", "REAL");

    // Initialize default configs.
    //
    // The durable live gate is NEVER seeded from the runtime environment. A new
    // Worker deployment supplying LIVE_ENABLED=true must not automatically switch
    // on the durable operator gate. It always starts disabled and can only be
    // changed through the explicit, operator-authenticated configureLiveGate()
    // action. The expected source commit is seeded once from the environment at
    // first initialization only; an existing Durable Object keeps its durable
    // value across deployments and must be re-aligned explicitly through
    // configureSourceCommit().
    this.setConfigIfNotExists("LIVE_ENABLED", "false");
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
   * Add a missing column to a table in place.
   *
   * @param {string} tableName
   * @param {string} columnName
   * @param {string} columnDefinition
   */
  ensureColumnExists(tableName, columnName, columnDefinition) {
    const columns = this.sql.query(`PRAGMA table_info(${tableName})`);
    const hasColumn = columns.some((column) => String(column.name || "").trim() === columnName);
    if (!hasColumn) {
      this.sql.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnDefinition}`);
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
   * Explicit, operator-controlled alignment of the durable expected source commit.
   *
   * A deployment that supplies a newer EXPECTED_SOURCE_COMMIT to the Worker does
   * NOT change this durable value. An authorized operator must explicitly align it
   * with the independently verified deployed commit. This method never touches the
   * durable live gate, invocation caps, accounting, runs, or grants.
   *
   * @param {string} sourceCommitId 40-character lowercase hex commit SHA
   * @param {{ configuredBy?: string, note?: string }} [options]
   * @returns {{ configured: boolean, expected_source_commit: string, previous_source_commit: string | null }}
   */
  configureSourceCommit(sourceCommitId, { configuredBy = "operator", note = "" } = {}) {
    const normalized = String(sourceCommitId || "").trim().toLowerCase();
    if (!HEX_40_REGEX.test(normalized)) {
      throw new ReconciliationValidationError(
        "Expected source commit must be a 40-character lowercase hex SHA."
      );
    }
    const operator = String(configuredBy || "").trim();
    if (!operator) {
      throw new ReconciliationValidationError(
        "configureSourceCommit requires an explicit operator identity (configuredBy)."
      );
    }

    const previous = this.getConfig("EXPECTED_SOURCE_COMMIT", "") || null;
    const now = Date.now();
    this.sql.transaction(() => {
      this.setConfig("EXPECTED_SOURCE_COMMIT", normalized);
      this.sql.execute(
        "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'SOURCE_COMMIT_CONFIGURED', ?)",
        now,
        JSON.stringify({
          previous_source_commit: previous,
          expected_source_commit: normalized,
          configured_by: operator,
          note: String(note || ""),
        })
      );
    });

    return {
      configured: true,
      expected_source_commit: normalized,
      previous_source_commit: previous,
    };
  }

  /**
   * Explicit, operator-controlled change of the durable live gate.
   *
   * This is the ONLY post-initialization writer of the durable LIVE_ENABLED value.
   * It is never invoked from environment configuration; it must be called through
   * an authenticated operator action. Enabling does not bypass any other control:
   * admission still requires the runtime live authorization and every existing
   * budget, grant, kill-switch, concurrency and idempotency constraint.
   *
   * @param {boolean} enabled
   * @param {{ configuredBy?: string, reason?: string }} [options]
   * @returns {{ configured: boolean, durable_live_enabled: boolean, previous_durable_live_enabled: boolean }}
   */
  configureLiveGate(enabled, { configuredBy = "operator", reason = "" } = {}) {
    if (typeof enabled !== "boolean") {
      throw new ReconciliationValidationError("configureLiveGate requires a boolean enabled value.");
    }
    const operator = String(configuredBy || "").trim();
    if (!operator) {
      throw new ReconciliationValidationError(
        "configureLiveGate requires an explicit operator identity (configuredBy)."
      );
    }

    const previous = this.getConfig("LIVE_ENABLED", "false") === "true";
    const now = Date.now();
    this.sql.transaction(() => {
      this.setConfig("LIVE_ENABLED", enabled ? "true" : "false");
      this.sql.execute(
        "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'DURABLE_LIVE_GATE_CONFIGURED', ?)",
        now,
        JSON.stringify({
          previous_durable_live_enabled: previous,
          durable_live_enabled: enabled,
          configured_by: operator,
          reason: String(reason || ""),
        })
      );
    });

    return {
      configured: true,
      durable_live_enabled: enabled,
      previous_durable_live_enabled: previous,
    };
  }

  /**
   * Explicit, operator-controlled change of the durable global invocation cap.
   *
   * Allows the operator to adjust the lifetime invocation cap to permit
   * additional explicitly authorized runs while promotional budget allows.
   * Updates the durable config in SQLite and records an audit event.
   * Never clears or alters run history, accounting, or billing exposure.
   *
   * @param {number} newCap Bounded integer (1 <= newCap <= 100)
   * @param {{ configuredBy?: string, reason?: string }} [options]
   * @returns {{ configured: boolean, global_cap: number, previous_global_cap: number }}
   */
  configureInvocationCap(newCap, { configuredBy = "operator", reason = "" } = {}) {
    const parsed =
      typeof newCap === "number" ? Math.trunc(newCap) : parseInt(String(newCap || ""), 10);
    if (!Number.isFinite(parsed) || parsed < 1 || parsed > 100) {
      throw new ReconciliationValidationError(
        "configureInvocationCap requires an integer cap between 1 and 100."
      );
    }
    const operator = String(configuredBy || "").trim();
    if (!operator) {
      throw new ReconciliationValidationError(
        "configureInvocationCap requires an explicit operator identity (configuredBy)."
      );
    }

    const previous = parseInt(this.getConfig("GLOBAL_INVOCATION_CAP", "5"), 10);
    const now = Date.now();
    this.sql.transaction(() => {
      this.setConfig("GLOBAL_INVOCATION_CAP", String(parsed));
      this.sql.execute(
        "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'INVOCATION_CAP_CONFIGURED', ?)",
        now,
        JSON.stringify({
          previous_global_cap: previous,
          global_cap: parsed,
          configured_by: operator,
          reason: String(reason || ""),
        })
      );
    });

    return {
      configured: true,
      global_cap: parsed,
      previous_global_cap: previous,
    };
  }

  /**
   * Return recent or all historical runs for operator inspection.
   *
   * @param {object} [options]
   * @param {number} [options.limit=50]
   * @returns {{ total: number, runs: Array<object> }}
   */
  getAllRuns({ limit = 50 } = {}) {
    const lim = Math.max(1, Math.min(limit, 200));
    const total = this.sql.query("SELECT COUNT(*) as count FROM runs")[0]?.count ?? 0;
    const runs = this.sql.query(
      `SELECT run_id, status, outcome, error_message, started_at, completed_at,
              reserved_cost, observed_cost, unknown_cost, tokens_used, payload_fingerprint
       FROM runs
       ORDER BY started_at DESC
       LIMIT ?`,
      lim
    );
    return {
      total,
      runs: runs.map((r) => ({
        run_id: r.run_id,
        status: r.status,
        outcome: r.outcome,
        error_message: r.error_message,
        started_at: r.started_at,
        completed_at: r.completed_at,
        reserved_cost: r.reserved_cost,
        observed_cost: r.observed_cost,
        unknown_cost: r.unknown_cost,
        tokens_used: r.tokens_used,
      })),
    };
  }

  /**
   * Report the durable operator gate and the runtime environment gate separately,
   * including expected-source-commit consistency. Uses the runtime bindings the
   * Durable Object received so the two authority sources are never conflated.
   *
   * @returns {object}
   */
  getConfigStatus() {
    const durableLiveEnabled = this.getConfig("LIVE_ENABLED", "false") === "true";
    const runtimeLiveEnabled =
      this.env?.LIVE_ENABLED === true || this.env?.LIVE_ENABLED === "true";
    const durableSource = String(this.getConfig("EXPECTED_SOURCE_COMMIT", "")).trim().toLowerCase();
    const runtimeSource = String(this.env?.EXPECTED_SOURCE_COMMIT ?? "").trim().toLowerCase();
    const durableSourceOrNull = HEX_40_REGEX.test(durableSource) ? durableSource : null;
    const runtimeSourceOrNull = HEX_40_REGEX.test(runtimeSource) ? runtimeSource : null;

    return {
      durable_live_enabled: durableLiveEnabled,
      runtime_live_enabled: runtimeLiveEnabled,
      effective_live_enabled: durableLiveEnabled && runtimeLiveEnabled,
      durable_expected_source_commit: durableSourceOrNull,
      runtime_expected_source_commit: runtimeSourceOrNull,
      source_commit_consistent:
        durableSourceOrNull !== null &&
        runtimeSourceOrNull !== null &&
        durableSourceOrNull === runtimeSourceOrNull,
    };
  }

  /**
   * Issue an operator-authenticated, single-use access grant.
   *
   * @param {object} options
   * @param {string} [options.token] Optional specific token (otherwise generated)
   * @param {number} [options.ttlSeconds=3600] Time-to-live in seconds
   * @param {number} [options.maxUses=1] Allowed uses (strictly 1 for single-use)
   * @param {string} [options.clientInfo=""]
   * @param {number | null} [options.verifiedBalance=null]
   * @param {number | null} [options.balanceTimestamp=null]
   * @param {number | null} [options.estimatedCostCap=null]
   * @returns {{ grant_id: string, grant_token: string, expires_at: number, max_uses: number, preflight_balance_bound: boolean, estimated_cost_cap: number | null }}
   */
  issueGrant({
    token,
    ttlSeconds = 3600,
    maxUses = 1,
    clientInfo = "",
    verifiedBalance = null,
    balanceTimestamp = null,
    estimatedCostCap = null,
  } = {}) {
    const grantId = "grant_" + crypto.randomUUID();
    const grantToken = token || "bb_grant_" + crypto.randomBytes(16).toString("hex");
    const now = Date.now();
    const expiresAt = now + ttlSeconds * 1000;

    this.sql.execute(
      `INSERT INTO grants (
         grant_id, grant_token, issued_at, expires_at, max_uses, use_count, status, client_info,
         verified_balance, balance_timestamp, estimated_cost_cap
       )
       VALUES (?, ?, ?, ?, ?, 0, 'ISSUED', ?, ?, ?, ?)`,
      grantId,
      grantToken,
      now,
      expiresAt,
      maxUses,
      clientInfo,
      Number.isFinite(verifiedBalance) ? Number(verifiedBalance) : null,
      typeof balanceTimestamp === "number" ? Math.trunc(balanceTimestamp) : null,
      Number.isFinite(estimatedCostCap) ? Number(estimatedCostCap) : null
    );

    this.sql.execute(
      "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'GRANT_ISSUED', ?)",
      now,
      JSON.stringify({
        grant_id: grantId,
        expires_at: expiresAt,
        max_uses: maxUses,
        preflight_balance_bound: Number.isFinite(verifiedBalance),
        estimated_cost_cap: Number.isFinite(estimatedCostCap) ? Number(estimatedCostCap) : null,
      })
    );

    return {
      grant_id: grantId,
      grant_token: grantToken,
      expires_at: expiresAt,
      max_uses: maxUses,
      preflight_balance_bound: Number.isFinite(verifiedBalance),
      estimated_cost_cap: Number.isFinite(estimatedCostCap) ? Number(estimatedCostCap) : null,
    };
  }

  probeTransactionRollback() {
    const before = this.sql.query("SELECT COUNT(*) AS count FROM audit_log")[0]?.count ?? 0;
    let rollbackTriggered = false;

    try {
      this.sql.transaction(() => {
        this.sql.execute(
          "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'TX_ROLLBACK_PROBE', ?)",
          Date.now(),
          "{}"
        );
        throw new Error("rollback probe");
      });
    } catch (error) {
      if (error instanceof Error && error.message === "rollback probe") {
        rollbackTriggered = true;
      } else {
        throw error;
      }
    }

    const after = this.sql.query("SELECT COUNT(*) AS count FROM audit_log")[0]?.count ?? 0;
    return {
      before,
      after,
      rollbackTriggered,
      transactionSyncType: typeof this.ctx?.storage?.transactionSync,
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
   * @param {number} [params.verified_balance] Trusted promotional balance snapshot fallback
   * @param {number} [params.balance_timestamp] Trusted snapshot timestamp (ms) fallback
   * @param {boolean} [params.live_enabled] Trusted runtime live authorization signal
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

    // 3. Live enabled checks: both the durable operator gate and trusted runtime
    // authorization must be true. A request flag can never override a disabled
    // durable gate.
    const operatorLiveGateEnabled = this.getConfig("LIVE_ENABLED", "false") === "true";
    if (!operatorLiveGateEnabled) {
      return {
        admitted: false,
        status: "BLOCKED",
        code: 403,
        error:
          "Live execution is disabled by the durable operator-controlled gate. Status: OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN. Zero-Cost Law enforced.",
      };
    }

    if (live_enabled !== true) {
      return {
        admitted: false,
        status: "BLOCKED",
        code: 403,
        error:
          "Trusted runtime live authorization is absent. Status: OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN. Zero-Cost Law enforced.",
      };
    }

    if (!Number.isFinite(estimated_cost) || estimated_cost <= 0) {
      return {
        admitted: false,
        status: "BLOCKED_ESTIMATED_COST_UNKNOWN",
        code: 422,
        error:
          "Maximum estimated cost is missing or invalid. Uncertain-cost live execution is forbidden.",
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

    const payloadFp = computeSha256(
      canonicalJson({ target: target.trim(), source_commit_id: source_commit_id.trim() })
    );

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
    const effectiveVerifiedBalance =
      Number.isFinite(grant.verified_balance) ? Number(grant.verified_balance) : verified_balance;
    const effectiveBalanceTimestamp =
      typeof grant.balance_timestamp === "number" ? grant.balance_timestamp : balance_timestamp;
    const effectiveEstimatedCostCap = Number.isFinite(grant.estimated_cost_cap)
      ? Number(grant.estimated_cost_cap)
      : null;

    if (idempotency_key && typeof idempotency_key === "string" && idempotency_key.trim()) {
      const existingRuns = this.sql.query(
        "SELECT run_id, status, payload_fingerprint, grant_token FROM runs WHERE idempotency_key = ?",
        idempotency_key.trim()
      );
      if (existingRuns.length > 0) {
        const existing = existingRuns[0];
        if (existing.grant_token !== grant.grant_token) {
          return {
            admitted: false,
            status: "IDEMPOTENCY_CONTEXT_MISMATCH",
            code: 409,
            error: "Idempotency key is bound to a different authorization context.",
          };
        }
        if (existing.payload_fingerprint === payloadFp) {
          return {
            admitted: true,
            is_replay: true,
            run_id: existing.run_id,
            status: existing.status,
          };
        }
        return {
          admitted: false,
          status: "IDEMPOTENCY_CONFLICT",
          code: 409,
          error: "Idempotency key reused with conflicting request payload.",
        };
      }
    }

    if (grant.status === "EXPIRED" || grant.expires_at < now) {
      this.sql.execute("UPDATE grants SET status = 'EXPIRED' WHERE grant_id = ?", grant.grant_id);
      this.expireStaleCostHoldExceptions(now);
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

    // 6b. Unreconciled unknown-cost hold. If provider consumption may have started
    // but the measured cost is unknown, live admission is held until an
    // independently verified operator reconciliation explicitly clears it.
    //
    // The ONLY exception is a single-use, operator-authorized cost-hold exception
    // bound to this exact grant. It is consumed atomically with the reservation and
    // never weakens the general hold for ordinary grants.
    const unknownCostRow = this.sql.query("SELECT unknown_cost FROM costs WHERE id = 1")[0];
    const unreconciledUnknownCost = Number(unknownCostRow?.unknown_cost ?? 0.0);
    let costHoldException = null;
    if (unreconciledUnknownCost > 0) {
      costHoldException = this.getAuthorizedCostHoldException(grant.grant_token);
      if (!costHoldException) {
        return {
          admitted: false,
          status: "BLOCKED_UNRECONCILED_UNKNOWN_COST",
          code: 409,
          error:
            `Unreconciled unknown provider cost exposure ($${unreconciledUnknownCost.toFixed(4)}) ` +
            "is outstanding. Live admission is held until an independently verified " +
            "operator reconciliation clears the hold.",
        };
      }
      if (Number(costHoldException.estimated_cost_cap_usd) < Number(estimated_cost)) {
        return {
          admitted: false,
          status: "BLOCKED_ESTIMATED_COST_CAP",
          code: 403,
          error:
            "The authorized one-time cost-hold exception does not cover the requested run cost.",
        };
      }
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
    if (!Number.isFinite(effectiveEstimatedCostCap) || effectiveEstimatedCostCap <= 0) {
      return {
        admitted: false,
        status: "BLOCKED_ESTIMATED_COST_CAP_MISSING",
        code: 422,
        error:
          "Grant-bound estimated cost authority is missing or invalid. Live admission requires an explicit positive estimated_cost_cap issued by the operator.",
      };
    }

    if (estimated_cost > effectiveEstimatedCostCap) {
      return {
        admitted: false,
        status: "BLOCKED_ESTIMATED_COST_CAP",
        code: 403,
        error:
          `Estimated run cost ($${estimated_cost.toFixed(2)}) exceeds the operator-approved grant cap ` +
          `($${effectiveEstimatedCostCap.toFixed(2)}).`,
      };
    }

    if (effectiveVerifiedBalance === undefined || effectiveVerifiedBalance === null) {
      return {
        admitted: false,
        status: "BLOCKED_BALANCE_MISSING",
        code: 422,
        error:
          "Promotional balance verification is missing. Cannot verify safety floor. Preflight check required.",
      };
    }

    if (
      typeof effectiveBalanceTimestamp !== "number" ||
      now - effectiveBalanceTimestamp > 15 * 60 * 1000
    ) {
      return {
        admitted: false,
        status: "BLOCKED_BALANCE_STALE",
        code: 422,
        error:
          "Promotional balance verification is stale (>15 minutes old). Fresh operator preflight balance verification is mandatory.",
      };
    }

    const balanceNum = parseFloat(String(effectiveVerifiedBalance));
    if (isNaN(balanceNum) || balanceNum <= stopThreshold) {
      return {
        admitted: false,
        status: "BLOCKED_BUDGET_FLOOR",
        code: 403,
        error: `Promotional balance ($${balanceNum.toFixed(2)}) is at or below the $${stopThreshold.toFixed(2)} safety reserve floor. Live execution prohibited under Zero-Cost Law.`,
      };
    }

    // The promotional-budget calculation MUST include any outstanding historical
    // unknown-cost exposure in addition to the new maximum estimated run exposure.
    if (balanceNum - unreconciledUnknownCost - estimated_cost < stopThreshold) {
      return {
        admitted: false,
        status: "BLOCKED_BUDGET_FLOOR",
        code: 403,
        error: `Estimated run cost ($${estimated_cost.toFixed(2)}) plus outstanding unknown exposure ($${unreconciledUnknownCost.toFixed(2)}) would reduce promotional balance ($${(balanceNum - unreconciledUnknownCost - estimated_cost).toFixed(2)}) below the $${stopThreshold.toFixed(2)} safety floor.`,
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

      // Atomically consume the one-time cost-hold exception (if any) as part of the
      // same reservation transaction. A duplicate/concurrent/replayed attempt can
      // never find an AUTHORIZED exception again once it has been consumed.
      if (costHoldException) {
        const consumeResult = this.sql.execute(
          `UPDATE cost_hold_exceptions
           SET status = ?, consumed_at = ?, consumed_run_id = ?
           WHERE exception_id = ? AND status = ?`,
          COST_HOLD_EXCEPTION_CONSUMED,
          now,
          runId,
          costHoldException.exception_id,
          COST_HOLD_EXCEPTION_AUTHORIZED
        );
        if (consumeResult.changes !== 1) {
          return {
            admitted: false,
            status: "COST_HOLD_EXCEPTION_UNAVAILABLE",
            code: 409,
            error:
              "The authorized one-time cost-hold exception is no longer available " +
              "(already consumed or replayed).",
          };
        }
        this.sql.execute(
          "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'COST_HOLD_EXCEPTION_CONSUMED', ?)",
          now,
          JSON.stringify({
            exception_id: costHoldException.exception_id,
            grant_id: grant.grant_id,
            run_id: runId,
          })
        );
      }

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
   * @param {boolean} [params.allowAuthoritativeProvenance=false]
   */
  recordExecutionSuccess(
    runId,
    {
      observed_cost = null,
      tokens_used = 0,
      receipt,
      allowAuthoritativeProvenance = false,
      cost_provenance = "UNKNOWN",
    }
  ) {
    if (!receipt || typeof receipt !== "object") {
      throw new Error("A valid public verification receipt object is required.");
    }
    if (typeof receipt.overall_verdict !== "string" || !receipt.overall_verdict.trim()) {
      throw new Error("Public receipt overall_verdict is required.");
    }
    if (typeof receipt.provenance !== "string" || !receipt.provenance.trim()) {
      throw new Error("Public receipt provenance is required.");
    }
    if (typeof receipt.source_commit_id !== "string" || !receipt.source_commit_id.trim()) {
      throw new Error("Public receipt source_commit_id is required.");
    }
    this.assertReceiptAuthority(receipt, { allowAuthoritativeProvenance });

    // Cryptographic receipt integrity verification
    if (!verifyReceiptIntegrity(receipt)) {
      throw new Error("Public receipt integrity verification failed: hash mismatch or tampered payload.");
    }

    // Secret safety check
    const secretFinding = detectSecrets(receipt);
    if (secretFinding.hasSecret) {
      throw new Error(`Public receipt contains secret pattern: ${secretFinding.matchedPattern}`);
    }

    // DEFECT B: an approved estimate or grant cap is NEVER genuine observed cost.
    // When the provider did not report a trustworthy measured cost, the run is
    // accounted conservatively as UNKNOWN: the reserved exposure is shifted into
    // unknown_cost (never released as zero) and spending authority stays closed.
    const hasKnownObservedCost =
      typeof observed_cost === "number" && Number.isFinite(observed_cost) && observed_cost >= 0;
    const effectiveObserved =
      hasKnownObservedCost === true ? observed_cost : 0.0;

    const now = Date.now();

    return this.sql.transaction(() => {
      const runRows = this.sql.query("SELECT * FROM runs WHERE run_id = ?", runId);
      if (runRows.length === 0) {
        throw new Error(`Run '${runId}' not found in ledger.`);
      }
      const run = runRows[0];
      const previousReserved = run.reserved_cost || 0.0;
      const unknownShift = hasKnownObservedCost === true ? 0.0 : previousReserved;

      // Update run
      this.sql.execute(
        `UPDATE runs
         SET status = 'COMPLETED',
             completed_at = ?,
             observed_cost = ?,
             unknown_cost = ?,
             tokens_used = ?,
             outcome = ?,
             reserved_cost = 0.0
         WHERE run_id = ?`,
        now,
        effectiveObserved,
        unknownShift,
        tokens_used,
        String(receipt.overall_verdict),
        runId
      );

      // Update accounting: subtract reserved_cost, add observed (or unknown) cost.
      this.sql.execute(
        `UPDATE costs
         SET reserved_cost = MAX(0.0, reserved_cost - ?),
             observed_cost = observed_cost + ?,
             unknown_cost = unknown_cost + ?,
             total_metered_cost = (observed_cost + ?) + (unknown_cost + ?)
         WHERE id = 1`,
        previousReserved,
        effectiveObserved,
        unknownShift,
        effectiveObserved,
        unknownShift
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
        JSON.stringify({
          run_id: runId,
          observed_cost: effectiveObserved,
          cost_provenance: hasKnownObservedCost === true ? "PROVIDER_OBSERVED" : String(cost_provenance || "UNKNOWN"),
          unknown_cost_shift: unknownShift,
          digest: receipt.receipt_digest,
        })
      );

      return { success: true, run_id: runId, receipt_digest: receipt.receipt_digest };
    });
  }

  /**
   * Record failure or ambiguous execution outcome.
   * Enforces Section C:
   * - Execution-outcome certainty is separated from billing certainty.
   * - If a chargeable provider operation may have started and the measured cost is
   *   unknown, the reserved exposure is shifted into unknown_cost and HELD; it is
   *   never released as zero. This holds even for a deterministic FAILED outcome.
   * - Only a pre-dispatch failure (no provider operation possible) releases the
   *   reservation.
   * - Strictly forbids automatic retries that could duplicate a cost-consuming action.
   *
   * @param {string} runId
   * @param {object} params
   * @param {string} params.error_message
   * @param {string} [params.outcome="FAILED"]
   * @param {boolean} [params.was_ambiguous=false] True if timeout/crash occurred mid-execution
   * @param {number | null} [params.observed_cost=null] Genuine provider-observed cost, or null when unknown
   * @param {boolean} [params.provider_may_have_dispatched=false] True when a chargeable
   *   provider operation may have started before the failure (unknown consumption)
   */
  recordExecutionFailure(
    runId,
    {
      error_message,
      outcome = "FAILED",
      was_ambiguous = false,
      observed_cost = null,
      provider_may_have_dispatched = false,
    }
  ) {
    const now = Date.now();
    const hasKnownObservedCost =
      typeof observed_cost === "number" && Number.isFinite(observed_cost) && observed_cost >= 0;
    const effectiveObserved = hasKnownObservedCost === true ? observed_cost : 0.0;
    const dispatched = provider_may_have_dispatched === true;
    // Unknown billing exposure is held whenever consumption may have occurred but
    // the actual cost is not measured. FAILED / missing receipt / missing usage
    // must never be inferred as zero cost.
    const retainUnknownExposure = hasKnownObservedCost !== true && (was_ambiguous || dispatched);

    return this.sql.transaction(() => {
      const runRows = this.sql.query("SELECT * FROM runs WHERE run_id = ?", runId);
      if (runRows.length === 0) {
        throw new Error(`Run '${runId}' not found in ledger.`);
      }
      const run = runRows[0];
      const previousReserved = run.reserved_cost || 0.0;
      const finalStatus = was_ambiguous
        ? "UNKNOWN_OUTCOME"
        : retainUnknownExposure
          ? "FAILED_UNRECONCILED_COST"
          : "FAILED";

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
        retainUnknownExposure ? previousReserved : 0.0,
        effectiveObserved,
        runId
      );

      if (retainUnknownExposure) {
        // Shift reserved cost into unknown_cost to prevent double-spending while
        // retaining conservative accounting pending operator reconciliation.
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
          effectiveObserved,
          effectiveObserved
        );
      }

      this.sql.execute(
        "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'RUN_FAILED', ?)",
        now,
        JSON.stringify({
          run_id: runId,
          status: finalStatus,
          error_message,
          was_ambiguous,
          provider_may_have_dispatched: dispatched,
          retained_unknown_cost: retainUnknownExposure ? previousReserved : 0.0,
        })
      );

      return { recorded: true, run_id: runId, status: finalStatus };
    });
  }

  /**
   * Explicit, auditable operator reconciliation of unreconciled unknown cost.
   *
   * Only an admin-authenticated operator path may call this. It requires a
   * complete reconciliation record: the operator's provider billing observation,
   * an evidence reference, the observed cost, a verification timestamp, an
   * operator decision, and the operator identity. A bare request or arbitrary
   * free-text note MUST NOT clear the hold.
   *
   * Attestation honesty: only `OPERATOR_ATTESTED` records are accepted here. An
   * operator billing observation is NOT independently verified provider fact, so
   * `PROVIDER_VERIFIED` is rejected while no independent provider verifier is
   * configured. This method releases held unknown exposure; it never records or
   * fabricates provider-observed metered cost, and never silently converts unknown
   * cost into zero measured spend.
   *
   * @param {string} runId
   * @param {object} record
   * @param {string} record.operator_decision One of NO_PROVIDER_CHARGE | PROVIDER_CHARGE_OBSERVED
   * @param {string} record.provider_billing_observation Operator's billing observation text
   * @param {string} record.evidence_reference Reference to the evidence (URL/ID/statement)
   * @param {number} record.observed_cost_usd Observed provider cost (>= 0)
   * @param {number} record.verification_timestamp When the observation was verified (ms)
   * @param {string} record.reconciled_by Operator identity
   * @param {string} [record.attestation_type="OPERATOR_ATTESTED"]
   * @param {number | null} [record.release_amount_usd=null] Portion of the hold to release (defaults to full)
   * @param {string} [record.note=""]
   * @returns {object}
   */
  reconcileUnknownCost(runId, record = {}) {
    const {
      attestation_type = "OPERATOR_ATTESTED",
      operator_decision,
      provider_billing_observation,
      evidence_reference,
      observed_cost_usd,
      verification_timestamp,
      release_amount_usd = null,
      reconciled_by,
      note = "",
    } = record || {};

    const normalizedRunId = String(runId || "").trim();
    if (!normalizedRunId) {
      throw new ReconciliationValidationError("A non-empty run_id is required.");
    }
    const attestationType = String(attestation_type || "").trim();
    if (!ALLOWED_ATTESTATION_TYPES.has(attestationType)) {
      throw new ReconciliationValidationError(
        `Unsupported attestation_type '${attestationType || "(missing)"}'. Only operator-attested billing ` +
          "observations are accepted; provider verification is never claimed unless independently performed."
      );
    }
    const decision = String(operator_decision || "").trim();
    if (!ALLOWED_RECONCILIATION_DECISIONS.has(decision)) {
      throw new ReconciliationValidationError(
        "operator_decision must be one of " +
          [...ALLOWED_RECONCILIATION_DECISIONS].join(" | ") +
          "."
      );
    }
    const observation = String(provider_billing_observation || "").trim();
    if (observation.length < 3) {
      throw new ReconciliationValidationError(
        "provider_billing_observation is required and must be meaningful evidence."
      );
    }
    const evidenceReference = String(evidence_reference || "").trim();
    if (evidenceReference.length < 3) {
      throw new ReconciliationValidationError("evidence_reference is required.");
    }
    if (!Number.isFinite(observed_cost_usd) || observed_cost_usd < 0) {
      throw new ReconciliationValidationError(
        "observed_cost_usd must be a finite non-negative number."
      );
    }
    const operator = String(reconciled_by || "").trim();
    if (!operator) {
      throw new ReconciliationValidationError("reconciled_by operator identity is required.");
    }
    const now = Date.now();
    if (!Number.isInteger(verification_timestamp) || verification_timestamp <= 0) {
      throw new ReconciliationValidationError(
        "verification_timestamp must be a positive integer epoch-millisecond value."
      );
    }
    if (verification_timestamp > now + MAX_RECONCILIATION_TIMESTAMP_SKEW_MS) {
      throw new ReconciliationValidationError(
        "verification_timestamp is implausibly in the future."
      );
    }

    if (decision === "NO_PROVIDER_CHARGE" && observed_cost_usd !== 0) {
      throw new ReconciliationValidationError(
        "Contradictory reconciliation: NO_PROVIDER_CHARGE requires observed_cost_usd of exactly 0."
      );
    }
    if (decision === "PROVIDER_CHARGE_OBSERVED" && observed_cost_usd <= 0) {
      throw new ReconciliationValidationError(
        "Contradictory reconciliation: PROVIDER_CHARGE_OBSERVED requires observed_cost_usd > 0."
      );
    }

    return this.sql.transaction(() => {
      const runRows = this.sql.query("SELECT * FROM runs WHERE run_id = ?", normalizedRunId);
      if (runRows.length === 0) {
        throw new ReconciliationStateError(`Run '${normalizedRunId}' not found in ledger.`);
      }
      const run = runRows[0];
      const runUnknown = run.unknown_cost || 0.0;
      if (runUnknown <= 0) {
        throw new ReconciliationStateError(
          `Run '${normalizedRunId}' has no unreconciled unknown cost to clear.`
        );
      }
      const releaseAmount =
        release_amount_usd === null || release_amount_usd === undefined
          ? runUnknown
          : Number(release_amount_usd);
      if (!Number.isFinite(releaseAmount) || releaseAmount <= 0) {
        throw new ReconciliationValidationError(
          "release_amount_usd must be a positive finite number."
        );
      }
      if (releaseAmount > runUnknown) {
        throw new ReconciliationValidationError(
          "release_amount_usd exceeds the run's unreconciled unknown cost."
        );
      }
      if (observed_cost_usd > releaseAmount) {
        throw new ReconciliationValidationError(
          "Contradictory reconciliation: attested observed cost exceeds the released exposure."
        );
      }
      const remaining = runUnknown - releaseAmount;

      this.sql.execute(
        "UPDATE runs SET unknown_cost = ? WHERE run_id = ?",
        remaining,
        normalizedRunId
      );
      // Release held unknown exposure only. Observed metered cost is NOT changed:
      // an operator attestation is not provider-verified metering.
      this.sql.execute(
        `UPDATE costs
         SET unknown_cost = MAX(0.0, unknown_cost - ?),
             total_metered_cost = observed_cost + MAX(0.0, unknown_cost - ?)
         WHERE id = 1`,
        releaseAmount,
        releaseAmount
      );
      this.sql.execute(
        `INSERT INTO reconciliations (
           run_id, attestation_type, operator_decision, provider_billing_observation,
           evidence_reference, observed_cost_usd, verification_timestamp,
           released_amount_usd, remaining_unknown_cost, reconciled_by, recorded_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        normalizedRunId,
        attestationType,
        decision,
        observation,
        evidenceReference,
        Number(observed_cost_usd),
        verification_timestamp,
        releaseAmount,
        remaining,
        operator,
        now
      );
      this.sql.execute(
        "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'UNKNOWN_COST_RECONCILED', ?)",
        now,
        JSON.stringify({
          run_id: normalizedRunId,
          attestation_type: attestationType,
          operator_decision: decision,
          provider_billing_observation: observation,
          evidence_reference: evidenceReference,
          observed_cost_usd: Number(observed_cost_usd),
          verification_timestamp,
          released_amount_usd: releaseAmount,
          remaining_unknown_cost: remaining,
          reconciled_by: operator,
          note: String(note || ""),
          provider_verification_claimed: false,
        })
      );

      return {
        reconciled: true,
        run_id: normalizedRunId,
        attestation_type: attestationType,
        operator_decision: decision,
        attested_observed_cost_usd: Number(observed_cost_usd),
        released_amount_usd: releaseAmount,
        remaining_unknown_cost: remaining,
        provider_verification_claimed: false,
      };
    });
  }

  /**
   * Atomically and idempotently transition any unconsumed AUTHORIZED cost-hold
   * exception whose bound grant has expired or become invalid into the terminal
   * EXPIRED state, recording an explicit audit event once per transition.
   *
   * Never modifies CONSUMED exceptions, never deletes historical rows or audit
   * entries, never revives expired grants, and never releases or reduces
   * historical unknown_cost exposure.
   *
   * @param {number} [now=Date.now()]
   * @returns {number} Count of newly expired cost-hold exceptions
   */
  expireStaleCostHoldExceptions(now = Date.now()) {
    const authorizedRows = this.sql.query(
      "SELECT * FROM cost_hold_exceptions WHERE status = ?",
      COST_HOLD_EXCEPTION_AUTHORIZED
    );
    if (authorizedRows.length === 0) {
      return 0;
    }

    return this.sql.transaction(() => {
      let expiredCount = 0;
      for (const exc of authorizedRows) {
        const grantRows = this.sql.query(
          "SELECT * FROM grants WHERE grant_id = ? AND grant_token = ?",
          exc.grant_id,
          exc.grant_token
        );
        const grant = grantRows[0] || null;

        let invalidReason = null;
        if (!grant) {
          invalidReason = "BOUND_GRANT_MISSING";
        } else if (grant.status === "EXPIRED" || Number(grant.expires_at) < now) {
          invalidReason = "BOUND_GRANT_EXPIRED";
        } else if (
          grant.status === "CONSUMED" ||
          Number(grant.use_count) >= Number(grant.max_uses)
        ) {
          invalidReason = "BOUND_GRANT_ALREADY_CONSUMED";
        } else if (grant.status !== "ISSUED" || Number(grant.max_uses) !== 1) {
          invalidReason = `BOUND_GRANT_INVALID_STATUS_${String(grant.status)}`;
        }

        if (!invalidReason) {
          continue;
        }

        if (grant && grant.status === "ISSUED" && Number(grant.expires_at) < now) {
          this.sql.execute(
            "UPDATE grants SET status = 'EXPIRED' WHERE grant_id = ? AND status = 'ISSUED'",
            grant.grant_id
          );
        }

        const updateResult = this.sql.execute(
          "UPDATE cost_hold_exceptions SET status = ? WHERE exception_id = ? AND status = ?",
          COST_HOLD_EXCEPTION_EXPIRED,
          exc.exception_id,
          COST_HOLD_EXCEPTION_AUTHORIZED
        );

        if (updateResult.changes === 1) {
          this.sql.execute(
            "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'COST_HOLD_EXCEPTION_EXPIRED', ?)",
            now,
            JSON.stringify({
              exception_id: exc.exception_id,
              grant_id: exc.grant_id,
              reason: invalidReason,
              grant_expires_at: grant ? grant.expires_at : null,
            })
          );
          expiredCount += 1;
        }
      }
      return expiredCount;
    });
  }

  /**
   * Look up an unconsumed, operator-authorized one-time unknown-cost-hold
   * exception bound to a specific single-use grant token.
   *
   * @param {string} grantToken
   * @returns {object | null}
   */
  getAuthorizedCostHoldException(grantToken) {
    this.expireStaleCostHoldExceptions();
    const normalized = String(grantToken || "").trim();
    if (!normalized) {
      return null;
    }
    const rows = this.sql.query(
      "SELECT * FROM cost_hold_exceptions WHERE grant_token = ? AND status = ?",
      normalized,
      COST_HOLD_EXCEPTION_AUTHORIZED
    );
    return rows.length > 0 ? rows[0] : null;
  }

  /**
   * Explicit, auditable, single-use operator authorization that allows exactly one
   * subsequent live admission to proceed while a known unreconciled unknown-cost
   * exposure remains outstanding.
   *
   * This is the SMALLEST possible exception to the unknown-cost admission hold. It
   * is NOT a bypass flag and NOT a ledger reset:
   * - it must be bound to an existing, unexpired, unconsumed single-use grant;
   * - it requires an explicit operator identity and a reason (audit record);
   * - it requires the grant's operator-bound estimated cost cap;
   * - it records the historical unknown exposure and requires the promotional-budget
   *   calculation to include BOTH the historical unknown exposure AND the new
   *   maximum estimated run exposure while preserving the $5.00 safety reserve;
   * - at most one exception may be active at a time and at most one ever exists per
   *   grant token (duplicates/replays are rejected);
   * - the historical unknown exposure is retained (never cleared, never reconciled,
   *   never reset) and the general hold remains in force for all ordinary grants.
   *
   * @param {object} params
   * @param {string} params.grantToken Single-use grant token the exception is bound to
   * @param {string} params.authorizedBy Explicit operator identity (audit)
   * @param {string} params.reason Explicit authorization reason (audit)
   * @param {string} [params.note=""]
   * @returns {object}
   */
  authorizeCostHoldException({ grantToken, authorizedBy, reason, note = "" } = {}) {
    const normalizedToken = String(grantToken || "").trim();
    if (!normalizedToken) {
      throw new ReconciliationValidationError(
        "authorizeCostHoldException requires a non-empty grant_token."
      );
    }
    const operator = String(authorizedBy || "").trim();
    if (!operator) {
      throw new ReconciliationValidationError(
        "authorizeCostHoldException requires an explicit operator identity (authorized_by)."
      );
    }
    const reasonText = String(reason || "").trim();
    if (reasonText.length < 3) {
      throw new ReconciliationValidationError(
        "authorizeCostHoldException requires an explicit authorization reason."
      );
    }

    const now = Date.now();
    this.expireStaleCostHoldExceptions(now);

    return this.sql.transaction(() => {
      const costRow = this.sql.query("SELECT unknown_cost FROM costs WHERE id = 1")[0];
      const existingUnknownCost = Number(costRow?.unknown_cost ?? 0.0);
      if (!(existingUnknownCost > 0)) {
        throw new ReconciliationStateError(
          "No unreconciled unknown-cost exposure is outstanding; a cost-hold exception is not required."
        );
      }

      const grantRows = this.sql.query(
        "SELECT * FROM grants WHERE grant_token = ?",
        normalizedToken
      );
      if (grantRows.length === 0) {
        throw new ReconciliationStateError(
          "The grant token bound to a cost-hold exception does not exist."
        );
      }
      const grant = grantRows[0];
      if (grant.status === "EXPIRED" || Number(grant.expires_at) < now) {
        this.sql.execute(
          "UPDATE grants SET status = 'EXPIRED' WHERE grant_id = ? AND status = 'ISSUED'",
          grant.grant_id
        );
        throw new ReconciliationStateError(
          "The grant bound to a cost-hold exception has expired; an unconsumed issued single-use grant is required."
        );
      }
      if (grant.status !== "ISSUED" || grant.use_count >= grant.max_uses) {
        throw new ReconciliationStateError(
          "The grant bound to a cost-hold exception must be an unconsumed issued single-use grant."
        );
      }
      if (Number(grant.max_uses) !== 1) {
        throw new ReconciliationValidationError(
          "A cost-hold exception may only be bound to a strictly single-use grant (max_uses = 1)."
        );
      }

      const estimatedCostCap = Number(grant.estimated_cost_cap);
      if (!Number.isFinite(estimatedCostCap) || estimatedCostCap <= 0) {
        throw new ReconciliationValidationError(
          "The grant bound to a cost-hold exception must carry a positive operator-approved estimated_cost_cap."
        );
      }
      const verifiedBalance = Number(grant.verified_balance);
      if (!Number.isFinite(verifiedBalance)) {
        throw new ReconciliationValidationError(
          "The grant bound to a cost-hold exception must carry an operator-verified promotional balance."
        );
      }

      const reserveFloor = parseFloat(
        this.getConfig("TOKEN_FACTORY_PROMO_STOP_THRESHOLD", "5.00")
      );

      // Budget authority MUST include BOTH the historical unknown exposure AND the
      // new maximum estimated run exposure, while preserving the safety reserve.
      const totalBudgetRequired = existingUnknownCost + estimatedCostCap;
      if (verifiedBalance - totalBudgetRequired < reserveFloor) {
        throw new ReconciliationValidationError(
          `Cost-hold exception denied: promotional balance ($${verifiedBalance.toFixed(2)}) minus ` +
            `historical unknown exposure ($${existingUnknownCost.toFixed(2)}) and maximum estimated run ` +
            `exposure ($${estimatedCostCap.toFixed(2)}) would breach the $${reserveFloor.toFixed(2)} safety reserve.`
        );
      }

      // Reject duplicate/replayed authorization: at most one active exception and at
      // most one exception ever per grant token.
      const activeRows = this.sql.query(
        "SELECT COUNT(*) AS count FROM cost_hold_exceptions WHERE status = ?",
        COST_HOLD_EXCEPTION_AUTHORIZED
      );
      if ((activeRows[0]?.count ?? 0) > 0) {
        throw new ReconciliationStateError(
          "An active cost-hold exception already exists. Only one may be active at a time."
        );
      }
      const existingForGrant = this.sql.query(
        "SELECT COUNT(*) AS count FROM cost_hold_exceptions WHERE grant_token = ?",
        normalizedToken
      );
      if ((existingForGrant[0]?.count ?? 0) > 0) {
        throw new ReconciliationStateError(
          "A cost-hold exception has already been issued for this grant token."
        );
      }

      const exceptionId = "chx_" + crypto.randomUUID();
      this.sql.execute(
        `INSERT INTO cost_hold_exceptions (
           exception_id, grant_id, grant_token, authorized_by, reason, authorized_at,
           existing_unknown_cost_usd, estimated_cost_cap_usd, reserve_floor_usd,
           total_budget_required_usd, verified_balance_usd, status
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        exceptionId,
        grant.grant_id,
        normalizedToken,
        operator,
        reasonText,
        now,
        existingUnknownCost,
        estimatedCostCap,
        reserveFloor,
        totalBudgetRequired,
        verifiedBalance,
        COST_HOLD_EXCEPTION_AUTHORIZED
      );

      this.sql.execute(
        "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'COST_HOLD_EXCEPTION_AUTHORIZED', ?)",
        now,
        JSON.stringify({
          exception_id: exceptionId,
          grant_id: grant.grant_id,
          authorized_by: operator,
          reason: reasonText,
          existing_unknown_cost_usd: existingUnknownCost,
          estimated_cost_cap_usd: estimatedCostCap,
          reserve_floor_usd: reserveFloor,
          total_budget_required_usd: totalBudgetRequired,
          verified_balance_usd: verifiedBalance,
          note: String(note || ""),
        })
      );

      return {
        authorized: true,
        exception_id: exceptionId,
        grant_id: grant.grant_id,
        status: COST_HOLD_EXCEPTION_AUTHORIZED,
        existing_unknown_cost_usd: existingUnknownCost,
        estimated_cost_cap_usd: estimatedCostCap,
        reserve_floor_usd: reserveFloor,
        total_budget_required_usd: totalBudgetRequired,
        verified_balance_usd: verifiedBalance,
        single_use: true,
      };
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
    this.expireStaleCostHoldExceptions();
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
   * Store a public receipt directly into durable SQLite storage.
   * Digest verification proves tamper integrity only; authoritative live provenance remains separately gated.
   *
   * @param {string} runId
   * @param {Record<string, unknown>} receiptObj
   * @param {{ allowAuthoritativeProvenance?: boolean }} [options]
   */
  storeReceipt(runId, receiptObj, { allowAuthoritativeProvenance = false } = {}) {
    if (typeof receiptObj.overall_verdict !== "string" || !receiptObj.overall_verdict.trim()) {
      throw new Error("Receipt overall_verdict is required.");
    }
    if (typeof receiptObj.provenance !== "string" || !receiptObj.provenance.trim()) {
      throw new Error("Receipt provenance is required.");
    }
    if (typeof receiptObj.source_commit_id !== "string" || !receiptObj.source_commit_id.trim()) {
      throw new Error("Receipt source_commit_id is required.");
    }
    this.assertReceiptAuthority(receiptObj, { allowAuthoritativeProvenance });
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
      String(receiptObj.source_commit_id),
      String(receiptObj.provenance),
      String(receiptObj.overall_verdict),
      now
    );
  }

  async storeReceiptRpc(runId, receiptObj, options = {}) {
    this.storeReceipt(runId, receiptObj, options);
    return { stored: true };
  }

  async probeStoreReceiptAuthority(runId, receiptObj, options = {}) {
    try {
      this.storeReceipt(runId, receiptObj, options);
      return { ok: true };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
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
   * Retrieve the sanitized public run summary.
   *
   * @param {string} runId
   * @returns {{ run_id: string, status: string, outcome: string | null, source_commit_id: string, completed_at: number | null, receipt_available: boolean, receipt_digest: string | null, provenance: string | null } | null}
   */
  getPublicRun(runId) {
    const runRows = this.sql.query(
      "SELECT run_id, status, outcome, source_commit_id, completed_at FROM runs WHERE run_id = ?",
      runId
    );
    if (runRows.length === 0) {
      return null;
    }

    const run = runRows[0];
    const receiptRows = this.sql.query(
      "SELECT receipt_digest, provenance FROM receipts WHERE run_id = ?",
      runId
    );
    const receiptRow = receiptRows[0] || null;

    return {
      run_id: run.run_id,
      status: run.status,
      outcome: run.outcome ?? null,
      source_commit_id: run.source_commit_id,
      completed_at: run.completed_at ?? null,
      receipt_available: receiptRow !== null,
      receipt_digest: receiptRow?.receipt_digest ?? null,
      provenance: receiptRow?.provenance ?? null,
    };
  }

  /**
   * Get complete durable accounting and metrics.
   *
   * @returns {object}
   */
  getAccounting() {
    this.expireStaleCostHoldExceptions();

    const costRows = this.sql.query("SELECT * FROM costs WHERE id = 1");
    const costs = costRows[0] || {
      reserved_cost: 0.0,
      observed_cost: 0.0,
      unknown_cost: 0.0,
      total_metered_cost: 0.0,
    };

    const configStatus = this.getConfigStatus();

    const inFlightCount =
      this.sql.query(
        "SELECT COUNT(*) as count FROM runs WHERE status IN ('RESERVED', 'IN_FLIGHT')"
      )[0]?.count ?? 0;

    const totalRuns =
      this.sql.query("SELECT COUNT(*) as count FROM runs WHERE status != 'REJECTED'")[0]?.count ??
      0;

    const completedRuns =
      this.sql.query("SELECT COUNT(*) as count FROM runs WHERE status = 'COMPLETED'")[0]?.count ?? 0;

    const activeExceptionRows = this.sql.query(
      "SELECT * FROM cost_hold_exceptions WHERE status = ?",
      COST_HOLD_EXCEPTION_AUTHORIZED
    );
    const activeException = activeExceptionRows[0] || null;

    const recentExceptions = this.sql.query(
      `SELECT exception_id, grant_id, authorized_by, reason, authorized_at,
              existing_unknown_cost_usd, estimated_cost_cap_usd, reserve_floor_usd,
              total_budget_required_usd, verified_balance_usd, status,
              consumed_at, consumed_run_id
       FROM cost_hold_exceptions
       ORDER BY authorized_at DESC
       LIMIT 10`
    );

    const recentRuns = this.sql.query(
      `SELECT run_id, status, outcome, error_message, started_at, completed_at,
              reserved_cost, observed_cost, unknown_cost, tokens_used
       FROM runs
       ORDER BY started_at DESC
       LIMIT 10`
    );

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
      live_enabled: configStatus.durable_live_enabled,
      safety_reserve_floor: parseFloat(this.getConfig("TOKEN_FACTORY_PROMO_STOP_THRESHOLD", "5.00")),
      // Separate durable operator gate vs runtime environment gate, plus
      // expected-source-commit consistency, for truthful preflight inspection.
      durable_live_enabled: configStatus.durable_live_enabled,
      runtime_live_enabled: configStatus.runtime_live_enabled,
      effective_live_enabled: configStatus.effective_live_enabled,
      durable_expected_source_commit: configStatus.durable_expected_source_commit,
      runtime_expected_source_commit: configStatus.runtime_expected_source_commit,
      source_commit_consistent: configStatus.source_commit_consistent,
      // The single active one-time cost-hold exception, if any. Historical unknown
      // exposure above remains recorded and is never cleared by an exception.
      active_cost_hold_exception: activeException
        ? {
            exception_id: activeException.exception_id,
            grant_id: activeException.grant_id,
            authorized_by: activeException.authorized_by,
            reason: activeException.reason,
            existing_unknown_cost_usd: activeException.existing_unknown_cost_usd,
            estimated_cost_cap_usd: activeException.estimated_cost_cap_usd,
            reserve_floor_usd: activeException.reserve_floor_usd,
            total_budget_required_usd: activeException.total_budget_required_usd,
            verified_balance_usd: activeException.verified_balance_usd,
            status: activeException.status,
          }
        : null,
      recent_cost_hold_exceptions: recentExceptions.map((exc) => ({
        exception_id: exc.exception_id,
        grant_id: exc.grant_id,
        authorized_by: exc.authorized_by,
        reason: exc.reason,
        authorized_at: exc.authorized_at,
        existing_unknown_cost_usd: exc.existing_unknown_cost_usd,
        estimated_cost_cap_usd: exc.estimated_cost_cap_usd,
        reserve_floor_usd: exc.reserve_floor_usd,
        total_budget_required_usd: exc.total_budget_required_usd,
        verified_balance_usd: exc.verified_balance_usd,
        status: exc.status,
        consumed_at: exc.consumed_at ?? null,
        consumed_run_id: exc.consumed_run_id ?? null,
      })),
      recent_runs: recentRuns.map((r) => ({
        run_id: r.run_id,
        status: r.status,
        outcome: r.outcome,
        error_message: r.error_message,
        started_at: r.started_at,
        completed_at: r.completed_at,
        reserved_cost: r.reserved_cost,
        observed_cost: r.observed_cost,
        unknown_cost: r.unknown_cost,
        tokens_used: r.tokens_used,
      })),
    };
  }
}
