/**
 * Worker HTTP Interface Integration Tests.
 *
 * Verifies same-origin HTTP routing, truthful public NOT_RUN surfaces,
 * sanitized read-only access, and protected admin endpoints.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import worker, { AdmissionLedgerDO } from "../src/index.js";
import { dispatchVerificationRun } from "../src/provider_dispatcher.js";
import { buildFixturePublicReceipt } from "./fixtures/public_receipt_fixture.js";

function createWorkerEnv(overrides = {}) {
  const db = new DatabaseSync(":memory:");
  const env = {
    BASEBREAK_ADMIN_KEY: "test_admin_secret_key_123",
    LIVE_ENABLED: "false",
    GLOBAL_INVOCATION_CAP: "5",
    TOKEN_FACTORY_PROMO_STOP_THRESHOLD: "5.00",
    __allowInProcessLedgerForTests: true,
    __sqliteBackend: db,
    ...overrides,
  };
  env.__ledgerInstance = new AdmissionLedgerDO(db, env);
  return { env, db };
}

describe("Basebreak Cloudflare Worker HTTP Interface Suite", () => {
  it("GET / returns 200 HTML with truthful NOT_RUN public state", async () => {
    const { env } = createWorkerEnv();
    const req = new Request("https://basebreak.workers.dev/", { method: "GET" });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 200);
    assert.match(res.headers.get("Content-Type") || "", /text\/html/);
    assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
    assert.equal(res.headers.get("X-Frame-Options"), "DENY");

    const html = await res.text();
    assert.match(html, /If the patch matters, the base must break/);
    assert.match(html, /PUBLIC RECEIPT: NOT_RUN/);
    assert.match(html, /Live Execution Not Available/);
  });

  it("GET /judge routes fall back to /index.html when assets do not map nested UI paths", async () => {
    const requestedPaths = [];
    const { env } = createWorkerEnv({
      ASSETS: {
        async fetch(request) {
          const pathname = new URL(request.url).pathname;
          requestedPaths.push(pathname);
          if (pathname === "/index.html") {
            return new Response("<!DOCTYPE html><html><body>BASEBREAK JUDGE UI</body></html>", {
              status: 200,
              headers: { "Content-Type": "text/html; charset=utf-8" },
            });
          }
          return new Response("Not Found", { status: 404 });
        },
      },
    });

    const req = new Request("https://basebreak.workers.dev/judge/demo-run", { method: "GET" });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 200);
    assert.match(res.headers.get("Content-Type") || "", /text\/html/);
    assert.deepEqual(requestedPaths, ["/judge/demo-run", "/index.html"]);
    assert.match(await res.text(), /BASEBREAK JUDGE UI/);
  });

  it("GET /health returns 200 JSON with unknown SHA default and not-ready deployment truth", async () => {
    const { env } = createWorkerEnv();
    const req = new Request("https://basebreak.workers.dev/health", { method: "GET" });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 200);
    assert.match(res.headers.get("Content-Type") || "", /application\/json/);
    assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");

    const data = await res.json();
    assert.equal(data.status, "ok");
    assert.equal(data.platform, "cloudflare_workers");
    assert.equal(data.source_commit_id, "UNKNOWN_BUILD_SHA");
    assert.equal(data.source_commit_status, "UNKNOWN_BUILD_SHA");
    assert.equal(data.deployment_readiness, "NOT_READY_FOR_DEPLOYMENT");
    assert.equal(data.live_enabled, false);
  });

  it("GET /health fails closed when the Durable Object binding is missing outside explicit test fallback", async () => {
    const req = new Request("https://basebreak.workers.dev/health", { method: "GET" });
    const res = await worker.fetch(req, {}, {});

    assert.equal(res.status, 503);
    const data = await res.json();
    assert.equal(data.status, "NOT_READY_FOR_DEPLOYMENT");
    assert.match(data.error, /ADMISSION_LEDGER Durable Object binding is missing/);
  });

  it("GET /v1/runs/canonical-demo/receipt returns truthful NOT_RUN when no historical receipt was supplied", async () => {
    const { env } = createWorkerEnv();
    const req = new Request("https://basebreak.workers.dev/v1/runs/canonical-demo/receipt", {
      method: "GET",
    });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 404);
    const data = await res.json();
    assert.equal(data.run_id, "canonical-demo");
    assert.equal(data.status, "NOT_RUN");
    assert.equal(data.provenance, "NOT_RUN");
  });

  it("GET /v1/runs/canonical-demo returns truthful NOT_RUN when no public run was supplied", async () => {
    const { env } = createWorkerEnv();
    const req = new Request("https://basebreak.workers.dev/v1/runs/canonical-demo", { method: "GET" });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 404);
    const data = await res.json();
    assert.equal(data.run_id, "canonical-demo");
    assert.equal(data.status, "NOT_RUN");
  });

  it("POST /v1/runs without allow_live fails closed with NOT_RUN instead of synthesizing a receipt", async () => {
    const { env } = createWorkerEnv();
    const req = new Request("https://basebreak.workers.dev/v1/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: "tests/fixtures/reset_vault",
        allow_live: false,
      }),
    });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 403);
    const data = await res.json();
    assert.equal(data.status, "NOT_RUN");
    assert.match(data.error, /Offline synthesized causal results are disabled/);
  });

  it("POST /v1/runs ignores client-supplied balance authority and fails closed before any provider call", async () => {
    const { env } = createWorkerEnv({ LIVE_ENABLED: "true" });
    const req = new Request("https://basebreak.workers.dev/v1/runs", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Judge-Grant": "bb_grant_user_supplied",
      },
      body: JSON.stringify({
        target: "tests/fixtures/reset_vault",
        allow_live: true,
        verified_balance: 999999,
        balance_timestamp: Date.now(),
      }),
    });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 503);
    const data = await res.json();
    assert.equal(data.status, "NOT_RUN");
    assert.match(data.error, /Trusted server-controlled budget authority/);
  });

  it("GET /v1/runs/:id returns only sanitized public fields", async () => {
    const { env } = createWorkerEnv();
    env.__ledgerInstance.sql.execute(
      `INSERT INTO runs (run_id, idempotency_key, grant_token, target, source_commit_id, status, started_at, completed_at, reserved_cost, observed_cost, unknown_cost, tokens_used, error_message, outcome, payload_fingerprint)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      "run_private_1",
      "idem-secret",
      "bb_grant_secret",
      "tests/fixtures/reset_vault",
      "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
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

    const req = new Request("https://basebreak.workers.dev/v1/runs/run_private_1", { method: "GET" });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.deepEqual(Object.keys(data).sort(), [
      "completed_at",
      "outcome",
      "provenance",
      "receipt_available",
      "receipt_digest",
      "run_id",
      "source_commit_id",
      "status",
    ]);
    assert.equal(data.run_id, "run_private_1");
    assert.equal(data.status, "FAILED");
    assert.equal(data.receipt_available, false);
  });

  it("Admin endpoints: /admin/grants strictly enforce operator authentication", async () => {
    const { env } = createWorkerEnv();

    const unauthReq = new Request("https://basebreak.workers.dev/admin/grants", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const unauthRes = await worker.fetch(unauthReq, env, {});
    assert.equal(unauthRes.status, 401);

    const authReq = new Request("https://basebreak.workers.dev/admin/grants", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${env.BASEBREAK_ADMIN_KEY}`,
      },
      body: JSON.stringify({ ttl_seconds: 1800, client_info: "official_judge_1" }),
    });
    const authRes = await worker.fetch(authReq, env, {});
    assert.equal(authRes.status, 201);
    const grantData = await authRes.json();
    assert.ok(grantData.grant_token);
    assert.equal(grantData.max_uses, 1);
  });

  it("Admin endpoints: /admin/killswitch and /admin/ledger", async () => {
    const { env } = createWorkerEnv();

    const ksReq = new Request("https://basebreak.workers.dev/admin/killswitch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${env.BASEBREAK_ADMIN_KEY}`,
      },
      body: JSON.stringify({ engage: true, reason: "Testing freeze" }),
    });
    const ksRes = await worker.fetch(ksReq, env, {});
    assert.equal(ksRes.status, 200);
    const ksData = await ksRes.json();
    assert.equal(ksData.kill_switch_engaged, true);

    const ledgerReq = new Request("https://basebreak.workers.dev/admin/ledger", {
      method: "GET",
      headers: { Authorization: `Bearer ${env.BASEBREAK_ADMIN_KEY}` },
    });
    const ledgerRes = await worker.fetch(ledgerReq, env, {});
    assert.equal(ledgerRes.status, 200);
    const ledgerData = await ledgerRes.json();
    assert.equal(ledgerData.kill_switch_engaged, true);
    assert.equal(ledgerData.global_cap, 5);
  });

  it("dispatchVerificationRun fails closed before sandbox provisioning even when credentials are present", async () => {
    let fetchCalled = false;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      fetchCalled = true;
      throw new Error("fetch should not be called");
    };

    try {
      const result = await dispatchVerificationRun({
        runId: "run_dispatch_blocked",
        target: "tests/fixtures/reset_vault",
        sourceCommitId: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
        allowLive: true,
      });

      assert.equal(fetchCalled, false);
      assert.equal(result.success, false);
      assert.equal(result.status, "NOT_RUN");
      assert.match(result.error, /NOT_READY_FOR_DEPLOYMENT/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("GET /v1/runs/:id/receipt serves only explicitly supplied receipts", async () => {
    const { env } = createWorkerEnv();
    const receipt = buildFixturePublicReceipt();
    env.__ledgerInstance.storeReceipt("run_fixture_public", receipt);

    const req = new Request("https://basebreak.workers.dev/v1/runs/run_fixture_public/receipt", {
      method: "GET",
    });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.provenance, "FIXTURE");
    assert.equal(data.receipt_digest, receipt.receipt_digest);
  });
});
