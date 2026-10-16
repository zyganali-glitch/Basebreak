import { afterEach, describe, expect, it, vi } from "vitest";
import { env, exports } from "cloudflare:workers";
import { evictDurableObject, reset, runInDurableObject } from "cloudflare:test";
import { buildFixturePublicReceipt } from "./fixtures/public_receipt_fixture.js";

const DEFAULT_TARGET = "tests/fixtures/reset_vault";
const DEFAULT_SOURCE = "80b43b84014fa61b941c7ebcd87836a56dcd7c92";

function getLedgerStub() {
  const id = env.ADMISSION_LEDGER.idFromName("canonical_global_ledger");
  return env.ADMISSION_LEDGER.get(id);
}

function issueLiveGrant(stub, options = {}) {
  return stub.issueGrant({
    estimatedCostCap: 1.0,
    ...options,
  });
}

afterEach(async () => {
  vi.restoreAllMocks();
  await reset();
});

describe("Basebreak Cloudflare Worker runtime compatibility preflight", () => {
  it("serves static assets and truthful health in the real Workers runtime", async () => {
    expect(typeof env.ASSETS.fetch).toBe("function");

    const rootResponse = await exports.default.fetch(new Request("https://example.com/", { method: "GET" }));
    expect(rootResponse.status).toBe(200);
    expect(rootResponse.headers.get("Content-Type")).toMatch(/text\/html/);
    expect(await rootResponse.text()).toContain("PUBLIC RECEIPT: NOT_RUN");

    const healthResponse = await exports.default.fetch(
      new Request("https://example.com/health", { method: "GET" })
    );
    expect(healthResponse.status).toBe(200);
    expect(await healthResponse.json()).toMatchObject({
      status: "ok",
      platform: "cloudflare_workers",
      source_commit_id: "UNKNOWN_BUILD_SHA",
      source_commit_status: "UNKNOWN_BUILD_SHA",
      deployment_readiness: "NOT_READY_FOR_DEPLOYMENT",
      live_enabled: false,
    });
  });

  it("uses Durable Object transactionSync rollback instead of unsupported SQL BEGIN/COMMIT", async () => {
    const stub = getLedgerStub();

    const result = await runInDurableObject(stub, (instance, state) => {
      const before = instance.sql.query("SELECT COUNT(*) AS count FROM audit_log")[0].count;
      let rollbackTriggered = false;

      try {
        instance.sql.transaction(() => {
          instance.sql.execute(
            "INSERT INTO audit_log (timestamp, event_type, details) VALUES (?, 'TX_ROLLBACK_PROBE', ?)",
            Date.now(),
            "{}"
          );
          throw new Error("rollback probe");
        });
      } catch (error) {
        rollbackTriggered = error instanceof Error && error.message === "rollback probe";
      }

      const after = instance.sql.query("SELECT COUNT(*) AS count FROM audit_log")[0].count;
      return {
        before,
        after,
        rollbackTriggered,
        transactionSyncType: typeof state.storage.transactionSync,
      };
    });

    expect(result.transactionSyncType).toBe("function");
    expect(result.rollbackTriggered).toBe(true);
    expect(result.after).toBe(result.before);
  });

  it("preserves single in-flight quota and idempotency context across real Durable Object RPC calls", async () => {
    const stub = getLedgerStub();
    await stub.configureLiveGate(true, { configuredBy: "runtime-harness" });
    const grants = await Promise.all([
      issueLiveGrant(stub, { clientInfo: "judge-a" }),
      issueLiveGrant(stub, { clientInfo: "judge-b" }),
      issueLiveGrant(stub, { clientInfo: "judge-c" }),
    ]);

    const results = await Promise.all(
      grants.map((grant) =>
        stub.reserveAdmission({
          grant_token: grant.grant_token,
          target: DEFAULT_TARGET,
          source_commit_id: DEFAULT_SOURCE,
          estimated_cost: 0.05,
          verified_balance: 20.0,
          balance_timestamp: Date.now(),
          live_enabled: true,
        })
      )
    );

    const admitted = results.find((result) => result.admitted === true);

    expect(admitted).toBeTruthy();
    expect(results.filter((result) => result.status === "CONCURRENCY_LIMIT")).toHaveLength(2);

    await stub.recordExecutionFailure(admitted.run_id, { error_message: "runtime preflight cleanup" });

    const replayGrant = await issueLiveGrant(stub, { clientInfo: "judge-replay" });
    const first = await stub.reserveAdmission({
      grant_token: replayGrant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      idempotency_key: "idem-runtime-1",
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    const replay = await stub.reserveAdmission({
      grant_token: replayGrant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      idempotency_key: "idem-runtime-1",
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    const conflictingGrant = await issueLiveGrant(stub, { clientInfo: "judge-conflict" });
    const mismatch = await stub.reserveAdmission({
      grant_token: conflictingGrant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      idempotency_key: "idem-runtime-1",
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });

    expect(first.admitted).toBe(true);
    expect(replay).toMatchObject({
      admitted: true,
      is_replay: true,
      run_id: first.run_id,
    });
    expect(mismatch).toMatchObject({
      admitted: false,
      status: "IDEMPOTENCY_CONTEXT_MISMATCH",
    });
  });

  it("recovers orphaned reserved runs after Durable Object eviction and restart", async () => {
    const stub = getLedgerStub();
    await stub.configureLiveGate(true, { configuredBy: "runtime-harness" });
    const grant = await issueLiveGrant(stub, { clientInfo: "judge-recovery" });
    const reservation = await stub.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      estimated_cost: 0.05,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });

    await runInDurableObject(stub, (instance) => {
      instance.sql.execute(
        "UPDATE runs SET started_at = ? WHERE run_id = ?",
        Date.now() - 70_000,
        reservation.run_id
      );
    });

    await evictDurableObject(stub);

    const recovered = await stub.recoverDurableState(60);
    const accounting = await stub.getAccounting();

    expect(recovered).toBe(1);
    expect(accounting.in_flight_count).toBe(0);
    expect(accounting.reserved_cost).toBe(0);
    expect(accounting.unknown_cost).toBe(0.05);
  });

  it("enforces admin auth, anonymous public sanitization, and fail-closed non-live execution", async () => {
    const unauthorizedGrant = await exports.default.fetch(
      new Request("https://example.com/admin/grants", { method: "POST", body: "{}" })
    );
    expect(unauthorizedGrant.status).toBe(401);

    const authorizedGrant = await exports.default.fetch(
      new Request("https://example.com/admin/grants", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer test_admin_secret_key_123",
        },
        body: JSON.stringify({ ttl_seconds: 600, client_info: "runtime-judge" }),
      })
    );
    expect(authorizedGrant.status).toBe(201);

    const stub = getLedgerStub();
    await runInDurableObject(stub, (instance) => {
      instance.sql.execute(
        `INSERT INTO runs (run_id, idempotency_key, grant_token, target, source_commit_id, status, started_at, completed_at, reserved_cost, observed_cost, unknown_cost, tokens_used, error_message, outcome, payload_fingerprint)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        "runtime_private_run",
        "idem-secret",
        "bb_grant_secret",
        DEFAULT_TARGET,
        DEFAULT_SOURCE,
        "FAILED",
        Date.now(),
        Date.now(),
        0.01,
        0.02,
        0.03,
        42,
        "sensitive failure details",
        "FAILED",
        "payload-fingerprint-secret"
      );
    });

    const publicRun = await exports.default.fetch(
      new Request("https://example.com/v1/runs/runtime_private_run", { method: "GET" })
    );
    expect(publicRun.status).toBe(200);
    expect(Object.keys(await publicRun.json()).sort()).toEqual([
      "completed_at",
      "outcome",
      "provenance",
      "receipt_available",
      "receipt_digest",
      "run_id",
      "source_commit_id",
      "status",
    ]);

    const accountingBefore = await stub.getAccounting();
    const nonLiveResponse = await exports.default.fetch(
      new Request("https://example.com/v1/runs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: DEFAULT_TARGET, allow_live: false }),
      })
    );
    const liveDisabledResponse = await exports.default.fetch(
      new Request("https://example.com/v1/runs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: DEFAULT_TARGET,
          allow_live: true,
          verified_balance: 999999,
          balance_timestamp: Date.now(),
        }),
      })
    );
    const accountingAfter = await stub.getAccounting();

    expect(nonLiveResponse.status).toBe(403);
    expect(await nonLiveResponse.json()).toMatchObject({ status: "NOT_RUN" });
    expect(liveDisabledResponse.status).toBe(400);
    expect(await liveDisabledResponse.json()).toMatchObject({ status: "INVALID_INPUT" });
    expect(accountingAfter.total_runs).toBe(accountingBefore.total_runs);
    expect(accountingAfter.in_flight_count).toBe(accountingBefore.in_flight_count);
  });

  it("blocks fixture promotion to LIVE_NEBIUS and preserves kill-switch controls in the real runtime", async () => {
    const stub = getLedgerStub();
    const forgedLiveReceipt = buildFixturePublicReceipt({ provenance: "LIVE_NEBIUS" });

    await expect(stub.storeReceipt("runtime_forged_live", forgedLiveReceipt)).rejects.toThrow(
      /trusted verification authority/
    );

    const engage = await exports.default.fetch(
      new Request("https://example.com/admin/killswitch", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer test_admin_secret_key_123",
        },
        body: JSON.stringify({ engage: true, reason: "runtime preflight" }),
      })
    );
    expect(engage.status).toBe(200);
    expect(await engage.json()).toEqual({ kill_switch_engaged: true });

    const accounting = await stub.getAccounting();
    expect(accounting.kill_switch_engaged).toBe(true);
  });
});
