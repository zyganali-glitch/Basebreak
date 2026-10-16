import assert from "node:assert/strict";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { buildFixturePublicReceipt } from "./fixtures/public_receipt_fixture.js";

const TEST_ADMIN_KEY = "test_admin_secret_key_123";
const DEFAULT_TARGET = "tests/fixtures/reset_vault";
const DEFAULT_SOURCE = "80b43b84014fa61b941c7ebcd87836a56dcd7c92";
const LEDGER_OBJECT_NAME = "canonical_global_ledger";
const SCRIPT_NAME = "basebreak";
const DO_CLASS_NAME = "AdmissionLedgerDO";
const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC_DIR = path.join(PROJECT_ROOT, "src");

async function buildWorkerModules() {
  const dirents = await readdir(SRC_DIR, { withFileTypes: true });
  const entrypointPath = path.join(SRC_DIR, "index.js");
  return [
    { type: "ESModule", path: entrypointPath },
    ...dirents
      .filter((dirent) => dirent.isFile() && dirent.name.endsWith(".js"))
      .map((dirent) => path.join(SRC_DIR, dirent.name))
      .sort()
      .filter((modulePath) => modulePath !== entrypointPath)
      .map((modulePath) => ({ type: "ESModule", path: modulePath })),
  ];
}

const workerModules = await buildWorkerModules();

function createMiniflareOptions({
  liveEnabled = "false",
  persistencePath,
} = {}) {
  return convertV4MiniflareOptions({
    name: SCRIPT_NAME,
    rootPath: PROJECT_ROOT,
    modules: workerModules,
    modulesRoot: PROJECT_ROOT,
    compatibilityDate: "2026-10-15",
    compatibilityFlags: ["nodejs_compat"],
    durableObjects: {
      ADMISSION_LEDGER: {
        className: DO_CLASS_NAME,
        useSQLite: true,
      },
    },
    assets: {
      directory: "./public",
      binding: "ASSETS",
      routerConfig: {
        has_user_worker: true,
      },
    },
    bindings: {
      BASEBREAK_ADMIN_KEY: TEST_ADMIN_KEY,
      LIVE_ENABLED: liveEnabled,
      GLOBAL_INVOCATION_CAP: "5",
      TOKEN_FACTORY_PROMO_STOP_THRESHOLD: "5.00",
      ALLOWLISTED_TARGET: DEFAULT_TARGET,
    },
    resourcePersistencePath: persistencePath,
    unsafeInspectDurableObjects: true,
  });
}

function getLedgerStub(bindings) {
  const id = bindings.ADMISSION_LEDGER.idFromName(LEDGER_OBJECT_NAME);
  return bindings.ADMISSION_LEDGER.get(id);
}

async function getLedgerStorage(miniflare) {
  return miniflare.unsafeGetDurableObjectStorage(SCRIPT_NAME, DO_CLASS_NAME, {
    name: LEDGER_OBJECT_NAME,
  });
}

async function createHarness(options = {}) {
  const persistencePath = await mkdtemp(path.join(tmpdir(), "basebreak-miniflare-"));
  const miniflare = new Miniflare(
    createMiniflareOptions({
      persistencePath,
      ...options,
    })
  );
  const bindings = await miniflare.getBindings();
  return {
    miniflare,
    bindings,
    stub: getLedgerStub(bindings),
    async dispose() {
      await miniflare.dispose();
      await rm(persistencePath, { recursive: true, force: true });
    },
  };
}

async function withHarness(options, fn) {
  const harness = await createHarness(options);
  try {
    return await fn(harness);
  } finally {
    await harness.dispose();
  }
}

async function runCheck(name, fn) {
  process.stdout.write(`- ${name} ... `);
  try {
    await fn();
    console.log("PASS");
    return true;
  } catch (error) {
    console.log("FAIL");
    console.error(error instanceof Error ? error.stack : error);
    return false;
  }
}

const results = [];

results.push(
  await runCheck("serves static judge asset and truthful health", async () => {
    await withHarness({}, async ({ miniflare }) => {
      const rootResponse = await miniflare.dispatchFetch("http://localhost/", {
        redirect: "manual",
      });
      assert.equal(rootResponse.status, 200);
      assert.match(rootResponse.headers.get("Content-Type") || "", /text\/html/);
      assert.equal(rootResponse.headers.get("Location"), null);
      assert.match(await rootResponse.text(), /PUBLIC RECEIPT: NOT_RUN/);

      const judgeResponse = await miniflare.dispatchFetch("http://localhost/judge", {
        redirect: "manual",
      });
      assert.equal(judgeResponse.status, 200);
      assert.match(judgeResponse.headers.get("Content-Type") || "", /text\/html/);
      assert.equal(judgeResponse.headers.get("Location"), null);
      assert.match(await judgeResponse.text(), /PUBLIC RECEIPT: NOT_RUN/);

      const nestedJudgeResponse = await miniflare.dispatchFetch(
        "http://localhost/judge/demo-run",
        { redirect: "manual" }
      );
      assert.equal(nestedJudgeResponse.status, 200);
      assert.match(nestedJudgeResponse.headers.get("Content-Type") || "", /text\/html/);
      assert.equal(nestedJudgeResponse.headers.get("Location"), null);
      assert.match(await nestedJudgeResponse.text(), /PUBLIC RECEIPT: NOT_RUN/);

      const healthResponse = await miniflare.dispatchFetch("http://localhost/health", {
        redirect: "manual",
      });
      assert.equal(healthResponse.status, 200);
      const healthPayload = await healthResponse.json();
      assert.equal(healthPayload.status, "ok");
      assert.equal(healthPayload.platform, "cloudflare_workers");
      assert.equal(healthPayload.version, "1.0.0");
      assert.equal(healthPayload.source_commit_id, "UNKNOWN_BUILD_SHA");
      assert.equal(healthPayload.source_commit_status, "UNKNOWN_BUILD_SHA");
      assert.equal(healthPayload.deployment_readiness, "NOT_READY_FOR_DEPLOYMENT");
      assert.equal(healthPayload.live_enabled, false);
      assert.equal(healthPayload.kill_switch_engaged, false);
      assert.equal(healthPayload.total_runs, 0);
      assert.equal(healthPayload.in_flight_count, 0);
      assert.match(String(healthPayload.timestamp), /^\d{4}-\d{2}-\d{2}T/);
    });
  })
);

results.push(
  await runCheck("uses Durable Object SQLite transaction rollback", async () => {
    await withHarness({}, async ({ stub }) => {
      const result = await stub.probeTransactionRollback();
      assert.equal(result.transactionSyncType, "function");
      assert.equal(result.rollbackTriggered, true);
      assert.equal(result.after, result.before);
    });
  })
);

results.push(
  await runCheck("enforces atomic admission, contention, and idempotency", async () => {
    await withHarness({ liveEnabled: "true" }, async ({ stub }) => {
      const grants = await Promise.all([
        stub.issueGrant({ clientInfo: "judge-a" }),
        stub.issueGrant({ clientInfo: "judge-b" }),
        stub.issueGrant({ clientInfo: "judge-c" }),
      ]);

      const results2 = await Promise.all(
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

      const admitted = results2.find((result) => result.admitted === true);
      assert.ok(admitted);
      assert.equal(results2.filter((result) => result.status === "CONCURRENCY_LIMIT").length, 2);

      await stub.recordExecutionFailure(admitted.run_id, {
        error_message: "runtime preflight cleanup",
      });

      const replayGrant = await stub.issueGrant({ clientInfo: "judge-replay" });
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
      const conflictingGrant = await stub.issueGrant({ clientInfo: "judge-conflict" });
      const mismatch = await stub.reserveAdmission({
        grant_token: conflictingGrant.grant_token,
        target: DEFAULT_TARGET,
        source_commit_id: DEFAULT_SOURCE,
        idempotency_key: "idem-runtime-1",
        verified_balance: 20.0,
        balance_timestamp: Date.now(),
        live_enabled: true,
      });

      assert.equal(first.admitted, true);
      assert.deepEqual(
        {
          admitted: replay.admitted,
          is_replay: replay.is_replay,
          run_id: replay.run_id,
        },
        {
          admitted: true,
          is_replay: true,
          run_id: first.run_id,
        }
      );
      assert.deepEqual(
        {
          admitted: mismatch.admitted,
          status: mismatch.status,
        },
        {
          admitted: false,
          status: "IDEMPOTENCY_CONTEXT_MISMATCH",
        }
      );
    });
  })
);

results.push(
  await runCheck("requires admin auth, sanitizes public data, and blocks provider dispatch", async () => {
    await withHarness({}, async ({ miniflare, stub }) => {
      const storage = await getLedgerStorage(miniflare);

      const unauthorizedGrant = await miniflare.dispatchFetch("http://localhost/admin/grants", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      assert.equal(unauthorizedGrant.status, 401);

      const authorizedGrant = await miniflare.dispatchFetch("http://localhost/admin/grants", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${TEST_ADMIN_KEY}`,
        },
        body: JSON.stringify({ ttl_seconds: 600, client_info: "runtime-judge" }),
      });
      assert.equal(authorizedGrant.status, 201);
      const grantPayload = await authorizedGrant.json();
      assert.equal(typeof grantPayload.grant_token, "string");
      assert.equal(grantPayload.max_uses, 1);

      await storage.exec(
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

      const publicRun = await miniflare.dispatchFetch("http://localhost/v1/runs/runtime_private_run");
      assert.equal(publicRun.status, 200);
      assert.deepEqual(Object.keys(await publicRun.json()).sort(), [
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
      const nonLiveResponse = await miniflare.dispatchFetch("http://localhost/v1/runs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: DEFAULT_TARGET, allow_live: false }),
      });
      const liveDisabledResponse = await miniflare.dispatchFetch("http://localhost/v1/runs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: DEFAULT_TARGET,
          allow_live: true,
          verified_balance: 999999,
          balance_timestamp: Date.now(),
        }),
      });
      const accountingAfter = await stub.getAccounting();

      assert.equal(nonLiveResponse.status, 403);
      const nonLivePayload = await nonLiveResponse.json();
      assert.equal(nonLivePayload.status, "NOT_RUN");
      assert.match(nonLivePayload.error, /Offline synthesized causal results are disabled/);
      assert.equal(liveDisabledResponse.status, 503);
      const liveDisabledPayload = await liveDisabledResponse.json();
      assert.equal(liveDisabledPayload.status, "NOT_RUN");
      assert.match(liveDisabledPayload.error, /Trusted server-controlled budget authority/);
      assert.equal(accountingAfter.total_runs, accountingBefore.total_runs);
      assert.equal(accountingAfter.in_flight_count, accountingBefore.in_flight_count);
    });
  })
);

results.push(
  await runCheck("recovers durable state across object re-instantiation", async () => {
    const persistencePath = await mkdtemp(path.join(tmpdir(), "basebreak-recovery-"));
    let firstMiniflare;
    let secondMiniflare;

    try {
      firstMiniflare = new Miniflare(
        createMiniflareOptions({
          persistencePath,
          liveEnabled: "true",
        })
      );
      const firstBindings = await firstMiniflare.getBindings();
      const firstStub = getLedgerStub(firstBindings);
      const storage = await getLedgerStorage(firstMiniflare);
      const grant = await firstStub.issueGrant({ clientInfo: "judge-recovery" });
      const reservation = await firstStub.reserveAdmission({
        grant_token: grant.grant_token,
        target: DEFAULT_TARGET,
        source_commit_id: DEFAULT_SOURCE,
        estimated_cost: 0.05,
        verified_balance: 20.0,
        balance_timestamp: Date.now(),
        live_enabled: true,
      });

      await storage.exec(
        "UPDATE runs SET started_at = ? WHERE run_id = ?",
        Date.now() - 70_000,
        reservation.run_id
      );

      await firstMiniflare.dispose();
      firstMiniflare = null;

      secondMiniflare = new Miniflare(
        createMiniflareOptions({
          persistencePath,
          liveEnabled: "true",
        })
      );
      const secondBindings = await secondMiniflare.getBindings();
      const secondStub = getLedgerStub(secondBindings);
      const recovered = await secondStub.recoverDurableState(60);
      const accounting = await secondStub.getAccounting();

      assert.equal(recovered, 1);
      assert.equal(accounting.in_flight_count, 0);
      assert.equal(accounting.reserved_cost, 0);
      assert.equal(accounting.unknown_cost, 0.05);
    } finally {
      if (firstMiniflare) {
        await firstMiniflare.dispose();
      }
      if (secondMiniflare) {
        await secondMiniflare.dispose();
      }
      await rm(persistencePath, { recursive: true, force: true });
    }
  })
);

results.push(
  await runCheck("rejects forged live receipts and preserves kill switch", async () => {
    await withHarness({}, async ({ miniflare, stub }) => {
      const forgedLive = await stub.probeStoreReceiptAuthority(
        "runtime_forged_live",
        buildFixturePublicReceipt({ provenance: "LIVE_NEBIUS" })
      );
      const forgedRecorded = await stub.probeStoreReceiptAuthority(
        "runtime_forged_recorded",
        buildFixturePublicReceipt({ provenance: "RECORDED_LIVE" })
      );
      assert.equal(forgedLive.ok, false);
      assert.match(forgedLive.error, /trusted verification authority/i);
      assert.equal(forgedRecorded.ok, false);
      assert.match(forgedRecorded.error, /trusted verification authority/i);

      const engage = await miniflare.dispatchFetch("http://localhost/admin/killswitch", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${TEST_ADMIN_KEY}`,
        },
        body: JSON.stringify({ engage: true, reason: "runtime preflight" }),
      });
      assert.equal(engage.status, 200);
      assert.deepEqual(await engage.json(), { kill_switch_engaged: true });

      const accounting = await stub.getAccounting();
      assert.equal(accounting.kill_switch_engaged, true);
    });
  })
);

const passed = results.filter(Boolean).length;
const failed = results.length - passed;

console.log(`\nMiniflare workerd preflight summary: ${passed}/${results.length} checks passed.`);

if (failed > 0) {
  process.exitCode = 1;
  console.error(`Miniflare workerd preflight failed with ${failed} failing check(s).`);
} else {
  console.log("Miniflare workerd preflight passed.");
}

process.exit(process.exitCode ?? 0);
