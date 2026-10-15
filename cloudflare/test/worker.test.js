/**
 * Worker HTTP Interface Integration Tests.
 *
 * Verifies same-origin HTTP routing, security headers, signed-out public access,
 * and protected admin endpoints.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import worker, { AdmissionLedgerDO } from "../src/index.js";
import { buildCanonicalResetVaultReceipt } from "../src/provider_dispatcher.js";

function createWorkerEnv(overrides = {}) {
  const db = new DatabaseSync(":memory:");
  const env = {
    BASEBREAK_ADMIN_KEY: "test_admin_secret_key_123",
    LIVE_ENABLED: "false",
    EXPECTED_SOURCE_COMMIT: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
    GLOBAL_INVOCATION_CAP: "5",
    TOKEN_FACTORY_PROMO_STOP_THRESHOLD: "5.00",
    __sqliteBackend: db,
    ...overrides,
  };
  // Pre-seed ledger instance
  env.__ledgerInstance = new AdmissionLedgerDO(db, env);
  return { env, db };
}

describe("Basebreak Cloudflare Worker HTTP Interface Suite", () => {
  it("GET / returns 200 HTML with thesis and security headers", async () => {
    const { env } = createWorkerEnv();
    const req = new Request("https://basebreak.workers.dev/", { method: "GET" });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 200);
    assert.match(res.headers.get("Content-Type") || "", /text\/html/);
    assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
    assert.equal(res.headers.get("X-Frame-Options"), "DENY");

    const html = await res.text();
    assert.match(html, /If the patch matters, the base must break/);
    assert.match(html, /BASE = FAIL &rarr; CANDIDATE = PASS &rarr; COUNTERFACTUAL = FAIL/);
  });

  it("GET /health returns 200 JSON with source SHA parity and platform truth", async () => {
    const { env } = createWorkerEnv();
    const req = new Request("https://basebreak.workers.dev/health", { method: "GET" });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 200);
    assert.match(res.headers.get("Content-Type") || "", /application\/json/);
    assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");

    const data = await res.json();
    assert.equal(data.status, "ok");
    assert.equal(data.platform, "cloudflare_workers");
    assert.equal(data.source_commit_id, "80b43b84014fa61b941c7ebcd87836a56dcd7c92");
    assert.equal(data.live_enabled, false);
  });

  it("GET /v1/runs/canonical-demo/receipt returns authentic pre-verified public receipt", async () => {
    const { env } = createWorkerEnv();
    const req = new Request("https://basebreak.workers.dev/v1/runs/canonical-demo/receipt", {
      method: "GET",
    });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 200);
    const receipt = await res.json();
    assert.equal(receipt.task_id, "TASK-RESET-VAULT-001");
    assert.equal(receipt.overall_verdict, "VERIFIED");
    assert.equal(receipt.provenance, "RECORDED_LIVE");
    assert.ok(receipt.receipt_digest);
    assert.equal(receipt.receipt_digest.length, 64);
  });

  it("GET /v1/runs/:id/receipt returns 404 for non-existent run", async () => {
    const { env } = createWorkerEnv();
    const req = new Request("https://basebreak.workers.dev/v1/runs/missing-run-xyz/receipt", {
      method: "GET",
    });
    const res = await worker.fetch(req, env, {});
    assert.equal(res.status, 404);
  });

  it("POST /v1/runs without allow_live performs offline preflight verification safely", async () => {
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

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, "VERIFIED");
    assert.equal(data.is_live, false);
    assert.equal(data.receipt.provenance, "FIXTURE");
  });

  it("POST /v1/runs with allow_live=true fails closed when LIVE_ENABLED=false", async () => {
    const { env } = createWorkerEnv({ LIVE_ENABLED: "false" });
    const req = new Request("https://basebreak.workers.dev/v1/runs", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Judge-Grant": "any_grant_token",
      },
      body: JSON.stringify({
        target: "tests/fixtures/reset_vault",
        allow_live: true,
      }),
    });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 403);
    const data = await res.json();
    assert.equal(data.status, "BLOCKED");
    assert.match(data.error, /Live execution is disabled by default/);
  });

  it("POST /v1/runs with allow_live=true and no grant returns 401 MISSING_GRANT", async () => {
    const { env } = createWorkerEnv({ LIVE_ENABLED: "true" });
    const req = new Request("https://basebreak.workers.dev/v1/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: "tests/fixtures/reset_vault",
        allow_live: true,
      }),
    });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 401);
    const data = await res.json();
    assert.equal(data.status, "MISSING_GRANT");
  });

  it("Admin endpoints: /admin/grants strictly enforces operator authentication", async () => {
    const { env } = createWorkerEnv();

    // 1. Unauthenticated request rejected
    const unauthReq = new Request("https://basebreak.workers.dev/admin/grants", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const unauthRes = await worker.fetch(unauthReq, env, {});
    assert.equal(unauthRes.status, 401);

    // 2. Authenticated operator request succeeds
    const authReq = new Request("https://basebreak.workers.dev/admin/grants", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer test_admin_secret_key_123",
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

    // Toggle killswitch ON
    const ksReq = new Request("https://basebreak.workers.dev/admin/killswitch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer test_admin_secret_key_123",
      },
      body: JSON.stringify({ engage: true, reason: "Testing freeze" }),
    });
    const ksRes = await worker.fetch(ksReq, env, {});
    assert.equal(ksRes.status, 200);
    const ksData = await ksRes.json();
    assert.equal(ksData.kill_switch_engaged, true);

    // Read ledger accounting
    const ledgerReq = new Request("https://basebreak.workers.dev/admin/ledger", {
      method: "GET",
      headers: { Authorization: "Bearer test_admin_secret_key_123" },
    });
    const ledgerRes = await worker.fetch(ledgerReq, env, {});
    assert.equal(ledgerRes.status, 200);
    const ledgerData = await ledgerRes.json();
    assert.equal(ledgerData.kill_switch_engaged, true);
    assert.equal(ledgerData.global_cap, 5);
  });
});
