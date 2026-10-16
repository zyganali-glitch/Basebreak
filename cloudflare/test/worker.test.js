/**
 * Worker HTTP Interface Integration Tests.
 *
 * Verifies same-origin HTTP routing, truthful public NOT_RUN surfaces,
 * sanitized read-only access, and protected admin endpoints.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import worker, { AdmissionLedgerDO } from "../src/index.js";
import { canonicalJson, computeReceiptDigest } from "../src/crypto_utils.js";
import {
  CANONICAL_DEMO_SCENARIO,
  buildBridgeRequestPayload,
  dispatchVerificationRun,
} from "../src/provider_dispatcher.js";
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
  // The durable operator live gate is never seeded from the environment; tests
  // that model an operator-enabled ledger configure it explicitly.
  if (String(env.LIVE_ENABLED).trim() === "true") {
    env.__ledgerInstance.configureLiveGate(true, { configuredBy: "test-harness" });
  }
  return { env, db };
}

function bufferToBase64UrlHex(value) {
  return Buffer.from(value, "base64url").toString("hex").toLowerCase();
}

function hexToBigInt(hex) {
  return BigInt("0x" + hex);
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let factor = base % modulus;
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) {
      result = (result * factor) % modulus;
    }
    factor = (factor * factor) % modulus;
    power >>= 1n;
  }
  return result;
}

function createTestVerifierAuthority() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 1024,
    publicExponent: 0x10001,
  });
  const privateJwk = privateKey.export({ format: "jwk" });
  const publicJwk = publicKey.export({ format: "jwk" });
  return {
    modulusHex: bufferToBase64UrlHex(publicJwk.n),
    exponent: parseInt(bufferToBase64UrlHex(publicJwk.e), 16),
    privateExponentHex: bufferToBase64UrlHex(privateJwk.d),
  };
}

function signProofDigest(digestHex, authority) {
  const hashedDigest = crypto.createHash("sha256").update(digestHex, "utf8").digest("hex");
  const message = hexToBigInt(hashedDigest);
  const modulus = hexToBigInt(authority.modulusHex);
  const privateExponent = hexToBigInt(authority.privateExponentHex);
  return modPow(message, privateExponent, modulus).toString(16).padStart(256, "0");
}

function buildSignedBridgeSuccess(receipt, authority) {
  const executions = Object.fromEntries(receipt.executions.map((execution) => [execution.world, execution]));
  const counterfactualExecution = receipt.counterfactual?.execution_fact || null;
  const proof = {
    schema_version: "1.0.0",
    receipt_digest: receipt.receipt_digest,
    source_commit_id: receipt.source_commit_id,
    candidate_tree_digest: receipt.candidate_tree_digest,
    candidate_patch_digest: receipt.candidate_patch_digest ?? null,
    overall_verdict: receipt.overall_verdict,
    provenance: receipt.provenance,
    issued_at_utc: receipt.timing?.created_at_utc || "2026-10-16T08:00:00+00:00",
    issuer_id: "basebreak:verifier:nebius:worker",
    base_execution: executions.BASE,
    candidate_execution: executions.CANDIDATE,
    counterfactual_execution: counterfactualExecution,
  };
  const proofDigest = crypto.createHash("sha256").update(canonicalJson(proof), "utf8").digest("hex").toLowerCase();

  return {
    ok: true,
    status: "COMPLETED",
    receipt,
    receipt_proof: {
      ...proof,
      proof_digest: proofDigest,
      signature: signProofDigest(proofDigest, authority),
    },
    observed_cost_usd: 0.042,
    tokens_used: 321,
  };
}

function buildVerifiedLiveReceiptFixture() {
  const receipt = {
    schema_version: "1.0.0",
    frozen_contract_digest: "a".repeat(64),
    task_id: "TASK-RESET-VAULT-001",
    repo_locator: "tests/fixtures/reset_vault",
    source_commit_id: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
    candidate_tree_digest: "b".repeat(64),
    candidate_patch_digest: "c".repeat(64),
    overall_verdict: "VERIFIED",
    provenance: "LIVE_NEBIUS",
    executions: [
      {
        world: "BASE",
        outcome: "FAIL",
        exit_code: 1,
        sandbox_id: "sbx-base-1",
        source_commit_id: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
        tree_digest: "a".repeat(64),
        stdout_digest: "1".repeat(64),
        stderr_digest: "2".repeat(64),
      },
      {
        world: "CANDIDATE",
        outcome: "PASS",
        exit_code: 0,
        sandbox_id: "sbx-candidate-1",
        source_commit_id: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
        tree_digest: "b".repeat(64),
        stdout_digest: "3".repeat(64),
        stderr_digest: "4".repeat(64),
      },
    ],
    counterfactual: {
      is_required: true,
      outcome: "FAIL",
      delta_digest: "d".repeat(64),
      execution_fact: {
        world: "COUNTERFACTUAL",
        outcome: "FAIL",
        exit_code: 1,
        sandbox_id: "sbx-counterfactual-1",
        source_commit_id: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
        tree_digest: "e".repeat(64),
        stdout_digest: "5".repeat(64),
        stderr_digest: "6".repeat(64),
      },
    },
    coverage_summary: {
      contract_digest: "a".repeat(64),
      total_requirements: 1,
      eligible_count: 1,
      excluded_count: 0,
      verified_count: 1,
      not_run_count: 0,
      inconclusive_count: 0,
      contradicted_count: 0,
      blocked_count: 0,
      coverage_ratio: 1,
      coverage_percentage: 100,
      is_fully_verified: true,
      overall_verdict: "VERIFIED",
      per_requirement_facts: [],
      coverage_digest: "f".repeat(64),
    },
    witnesses: [],
    runtime_identities: ["trusted-python-bridge"],
    timing: {
      created_at_utc: "2026-10-16T08:00:00+00:00",
      total_duration_seconds: 1.25,
    },
    accounting: {
      is_metered: true,
      input_tokens: 123,
      output_tokens: 198,
      total_tokens: 321,
      cost_usd: 0.042,
      sandbox_count: 3,
    },
    not_run_obligations: [],
    signature_strategy: "SHA256_DIGEST_ONLY",
    signature: null,
    is_authoritative: false,
    disclaimers: ["Verifier-signed LIVE_NEBIUS bridge fixture for unit testing."],
  };
  receipt.receipt_digest = computeReceiptDigest(receipt);
  return receipt;
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

  it("GET /judge routes serve the root judge asset while preserving nested judge URLs", async () => {
    const requestedPaths = [];
    const { env } = createWorkerEnv({
      ASSETS: {
        async fetch(request) {
          const pathname = new URL(request.url).pathname;
          requestedPaths.push(pathname);
          if (pathname === "/") {
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
    assert.deepEqual(requestedPaths, ["/"]);
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

  it("POST /v1/runs rejects client-controlled authority fields before any provider call", async () => {
    let fetchCalled = false;
    const { env } = createWorkerEnv({
      LIVE_ENABLED: "true",
      EXPECTED_SOURCE_COMMIT: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
      LIVE_RUN_ESTIMATED_COST_USD: "0.25",
      __bridgeFetchForTests: async () => {
        fetchCalled = true;
        throw new Error("bridge fetch must not be called");
      },
    });
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

    assert.equal(fetchCalled, false);
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.status, "INVALID_INPUT");
    assert.match(data.error, /Client-controlled authority field '.*' is forbidden/);
  });

  it("POST /v1/runs fails closed when the trusted bridge infrastructure is unavailable", async () => {
    const { env } = createWorkerEnv({
      LIVE_ENABLED: "true",
      EXPECTED_SOURCE_COMMIT: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
      LIVE_RUN_ESTIMATED_COST_USD: "0.25",
    });
    const grant = env.__ledgerInstance.issueGrant({
      verifiedBalance: 10.0,
      balanceTimestamp: Date.now(),
      estimatedCostCap: 0.30,
      clientInfo: "judge",
    });

    const req = new Request("https://basebreak.workers.dev/v1/runs", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Judge-Grant": grant.grant_token,
      },
      body: JSON.stringify({
        target: "tests/fixtures/reset_vault",
        allow_live: true,
      }),
    });
    const res = await worker.fetch(req, env, {});

    assert.equal(res.status, 503);
    const data = await res.json();
    assert.equal(data.status, "NOT_READY_FOR_DEPLOYMENT");
    assert.match(data.error, /Trusted Python verifier bridge URL is not configured/);

    const accounting = env.__ledgerInstance.getAccounting();
    assert.equal(accounting.total_runs, 1);
    assert.equal(accounting.in_flight_count, 0);
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
        estimatedCostUsd: 0.25,
      });

      assert.equal(fetchCalled, false);
      assert.equal(result.success, false);
      assert.equal(result.status, "NOT_READY_FOR_DEPLOYMENT");
      assert.match(result.error, /bridge URL is not configured/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("buildBridgeRequestPayload binds the canonical ResetVault contract digest", () => {
    const payload = buildBridgeRequestPayload({
      runId: "run_contract_bound",
      target: "tests/fixtures/reset_vault",
      sourceCommitId: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
      estimatedCostUsd: 0.25,
      nowMs: 1700000000000,
      timeoutMs: 12345,
    });

    assert.equal(payload.task_id, CANONICAL_DEMO_SCENARIO.task_id);
    assert.equal(payload.change_class, CANONICAL_DEMO_SCENARIO.change_class);
    assert.equal(payload.frozen_contract_digest, CANONICAL_DEMO_SCENARIO.frozen_contract_digest);
    assert.equal(
      payload.frozen_contract_digest,
      "93eeeb2cc7eb02a988da3c8a8543ad40b4816608c1452d048ff62ee93702f812"
    );
  });

  it("dispatchVerificationRun preserves ambiguous bridge network failures", async () => {
    const result = await dispatchVerificationRun({
      runId: "run_dispatch_ambiguous",
      target: "tests/fixtures/reset_vault",
      sourceCommitId: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
      allowLive: true,
      estimatedCostUsd: 0.25,
      bridgeUrl: "https://bridge.example/internal/live-verifications",
      bridgeSharedSecret: "bridge-secret",
      fetchImpl: async () => {
        throw new Error("dial tcp timeout");
      },
    });

    assert.equal(result.success, false);
    assert.equal(result.status, "UNKNOWN_OUTCOME");
    assert.equal(result.was_ambiguous, true);
    assert.match(result.error, /AMBIGUOUS/);
  });

  it("dispatchVerificationRun accepts verifier-signed live receipts and rejects forged witness mutations", async () => {
    const authority = createTestVerifierAuthority();
    const liveReceipt = buildVerifiedLiveReceiptFixture();
    const successPayload = buildSignedBridgeSuccess(liveReceipt, authority);

    const success = await dispatchVerificationRun({
      runId: "run_dispatch_success",
      target: "tests/fixtures/reset_vault",
      sourceCommitId: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
      allowLive: true,
      estimatedCostUsd: 0.25,
      bridgeUrl: "https://bridge.example/internal/live-verifications",
      bridgeSharedSecret: "bridge-secret",
      verifierAuthorityOverride: {
        modulusHex: authority.modulusHex,
        exponent: authority.exponent,
      },
      fetchImpl: async () =>
        new Response(JSON.stringify(successPayload), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    });

    assert.equal(success.success, true);
    assert.equal(success.status, "COMPLETED");
    assert.equal(success.tokens_used, 321);

    const forgedPayload = structuredClone(successPayload);
    forgedPayload.receipt_proof.candidate_tree_digest = "f".repeat(64);
    const forged = await dispatchVerificationRun({
      runId: "run_dispatch_forged",
      target: "tests/fixtures/reset_vault",
      sourceCommitId: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
      allowLive: true,
      estimatedCostUsd: 0.25,
      bridgeUrl: "https://bridge.example/internal/live-verifications",
      bridgeSharedSecret: "bridge-secret",
      verifierAuthorityOverride: {
        modulusHex: authority.modulusHex,
        exponent: authority.exponent,
      },
      fetchImpl: async () =>
        new Response(JSON.stringify(forgedPayload), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    });

    assert.equal(forged.success, false);
    assert.equal(forged.status, "FAILED");
    assert.match(forged.error, /receipt proof verification failed/i);
  });

  it("dispatchVerificationRun never substitutes the estimate for observed provider cost", async () => {
    const authority = createTestVerifierAuthority();
    const liveReceipt = buildVerifiedLiveReceiptFixture();
    const successPayload = buildSignedBridgeSuccess(liveReceipt, authority);
    delete successPayload.observed_cost_usd;
    successPayload.reserved_exposure_usd = 0.25;
    successPayload.approved_estimate_usd = 0.25;
    successPayload.cost_provenance = "UNKNOWN";

    const result = await dispatchVerificationRun({
      runId: "run_dispatch_unknown_cost",
      target: "tests/fixtures/reset_vault",
      sourceCommitId: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
      allowLive: true,
      estimatedCostUsd: 0.25,
      bridgeUrl: "https://bridge.example/internal/live-verifications",
      bridgeSharedSecret: "bridge-secret",
      verifierAuthorityOverride: {
        modulusHex: authority.modulusHex,
        exponent: authority.exponent,
      },
      fetchImpl: async () =>
        new Response(JSON.stringify(successPayload), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    });

    assert.equal(result.success, true);
    assert.equal(result.observed_cost_usd, null);
    assert.equal(result.cost_provenance, "UNKNOWN");
    assert.equal(result.reserved_exposure_usd, 0.25);
    assert.equal(result.approved_estimate_usd, 0.25);
    assert.notEqual(result.observed_cost_usd, result.approved_estimate_usd);
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

  it("dispatchVerificationRun reports chargeable-dispatch possibility conservatively", async () => {
    const base = {
      runId: "run_dispatch_flag",
      target: "tests/fixtures/reset_vault",
      sourceCommitId: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
      allowLive: true,
      estimatedCostUsd: 0.25,
    };

    // Local pre-flight block: no bridge contact, no dispatch.
    const noBridge = await dispatchVerificationRun({ ...base });
    assert.equal(noBridge.provider_may_have_dispatched, false);

    // Connection loss after the request boundary: dispatch possible.
    const connectionLoss = await dispatchVerificationRun({
      ...base,
      bridgeUrl: "https://bridge.example/internal/live-verifications",
      bridgeSharedSecret: "bridge-secret",
      fetchImpl: async () => {
        throw new Error("dial tcp: connection reset");
      },
    });
    assert.equal(connectionLoss.status, "UNKNOWN_OUTCOME");
    assert.equal(connectionLoss.was_ambiguous, true);
    assert.equal(connectionLoss.provider_may_have_dispatched, true);

    // Explicit bridge pre-dispatch rejection: no dispatch.
    const preDispatchReject = await dispatchVerificationRun({
      ...base,
      bridgeUrl: "https://bridge.example/internal/live-verifications",
      bridgeSharedSecret: "bridge-secret",
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            ok: false,
            status: "BLOCKED_MISSING_PROVIDER_CREDENTIALS",
            error: "credentials missing",
            ambiguous_outcome: false,
            provider_dispatched: false,
          }),
          { status: 503, headers: { "Content-Type": "application/json" } }
        ),
    });
    assert.equal(preDispatchReject.provider_may_have_dispatched, false);

    // Malformed receipt after successful inference: consumption unknown -> dispatched.
    const authority = createTestVerifierAuthority();
    const liveReceipt = buildVerifiedLiveReceiptFixture();
    const successPayload = buildSignedBridgeSuccess(liveReceipt, authority);
    delete successPayload.receipt_proof.signature;
    const malformed = await dispatchVerificationRun({
      ...base,
      bridgeUrl: "https://bridge.example/internal/live-verifications",
      bridgeSharedSecret: "bridge-secret",
      verifierAuthorityOverride: {
        modulusHex: authority.modulusHex,
        exponent: authority.exponent,
      },
      fetchImpl: async () =>
        new Response(JSON.stringify(successPayload), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    });
    assert.equal(malformed.success, false);
    assert.equal(malformed.status, "FAILED");
    assert.equal(malformed.provider_may_have_dispatched, true);
  });

  it("POST /v1/runs holds unknown cost after a dispatched deterministic failure and blocks admission until reconciliation", async () => {
    const estimatedCost = 0.25;
    const { env } = createWorkerEnv({
      LIVE_ENABLED: "true",
      EXPECTED_SOURCE_COMMIT: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
      LIVE_RUN_ESTIMATED_COST_USD: String(estimatedCost),
      TRUSTED_VERIFIER_BRIDGE_URL: "https://bridge.example/internal/live-verifications",
      TRUSTED_VERIFIER_BRIDGE_SHARED_SECRET: "bridge-secret",
      __bridgeFetchForTests: async () =>
        new Response(
          JSON.stringify({
            ok: false,
            status: "FAILED",
            error: "Model returned a malformed response after inference completed.",
            ambiguous_outcome: false,
            provider_dispatched: true,
          }),
          { status: 502, headers: { "Content-Type": "application/json" } }
        ),
    });

    const grant = env.__ledgerInstance.issueGrant({
      verifiedBalance: 10.0,
      balanceTimestamp: Date.now(),
      estimatedCostCap: 0.30,
      clientInfo: "judge",
    });

    const makeRequest = (grantToken) =>
      new Request("https://basebreak.workers.dev/v1/runs", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Judge-Grant": grantToken,
        },
        body: JSON.stringify({ target: "tests/fixtures/reset_vault", allow_live: true }),
      });

    const first = await worker.fetch(makeRequest(grant.grant_token), env, {});
    assert.equal(first.status, 502);
    const firstData = await first.json();
    assert.equal(firstData.status, "FAILED");
    assert.equal(firstData.ambiguous_outcome, false);

    const accounting = env.__ledgerInstance.getAccounting();
    assert.equal(accounting.unknown_cost, estimatedCost);
    assert.equal(accounting.observed_cost, 0.0);
    assert.equal(accounting.reserved_cost, 0.0);
    assert.equal(accounting.in_flight_count, 0);

    // A fresh grant must be held until an independently verified reconciliation.
    const heldGrant = env.__ledgerInstance.issueGrant({
      verifiedBalance: 10.0,
      balanceTimestamp: Date.now(),
      estimatedCostCap: 0.30,
      clientInfo: "judge-2",
    });
    const held = await worker.fetch(makeRequest(heldGrant.grant_token), env, {});
    assert.equal(held.status, 409);
    const heldData = await held.json();
    assert.equal(heldData.status, "BLOCKED_UNRECONCILED_UNKNOWN_COST");

    // Explicit, evidence-backed operator reconciliation clears the hold.
    const reconcileReq = new Request(
      "https://basebreak.workers.dev/admin/reconcile-unknown-cost",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${env.BASEBREAK_ADMIN_KEY}`,
        },
        body: JSON.stringify({
          run_id: firstData.run_id,
          operator_decision: "NO_PROVIDER_CHARGE",
          attestation_type: "OPERATOR_ATTESTED",
          provider_billing_observation: "Nebius usage dashboard showed no billed inference.",
          evidence_reference: "nebius-console://usage/2026-10-16",
          observed_cost_usd: 0,
          verification_timestamp: Date.now(),
          reconciled_by: "operator-independent-qa",
          note: "Provider dashboard confirmed no billed usage.",
        }),
      }
    );
    const reconcileRes = await worker.fetch(reconcileReq, env, {});
    assert.equal(reconcileRes.status, 200);
    const reconcileData = await reconcileRes.json();
    assert.equal(reconcileData.reconciled, true);
    assert.equal(reconcileData.attestation_type, "OPERATOR_ATTESTED");
    assert.equal(reconcileData.provider_verification_claimed, false);

    const cleared = env.__ledgerInstance.getAccounting();
    assert.equal(cleared.unknown_cost, 0.0);

    const afterGrant = env.__ledgerInstance.issueGrant({
      verifiedBalance: 10.0,
      balanceTimestamp: Date.now(),
      estimatedCostCap: 0.30,
      clientInfo: "judge-3",
    });
    const after = await worker.fetch(makeRequest(afterGrant.grant_token), env, {});
    // The second dispatch is again a dispatched deterministic failure (held again),
    // but admission itself is no longer blocked by an unreconciled hold.
    assert.equal(after.status, 502);
  });

  it("POST /admin/reconcile-unknown-cost cannot silently clear a hold with a bare request or note", async () => {
    const { env } = createWorkerEnv({
      LIVE_ENABLED: "true",
      EXPECTED_SOURCE_COMMIT: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
      LIVE_RUN_ESTIMATED_COST_USD: "0.25",
      TRUSTED_VERIFIER_BRIDGE_URL: "https://bridge.example/internal/live-verifications",
      TRUSTED_VERIFIER_BRIDGE_SHARED_SECRET: "bridge-secret",
      __bridgeFetchForTests: async () =>
        new Response(
          JSON.stringify({
            ok: false,
            status: "FAILED",
            error: "dispatched failure",
            ambiguous_outcome: false,
            provider_dispatched: true,
          }),
          { status: 502, headers: { "Content-Type": "application/json" } }
        ),
    });
    const grant = env.__ledgerInstance.issueGrant({
      verifiedBalance: 10.0,
      balanceTimestamp: Date.now(),
      estimatedCostCap: 0.30,
      clientInfo: "judge",
    });
    const run = await worker.fetch(
      new Request("https://basebreak.workers.dev/v1/runs", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Judge-Grant": grant.grant_token },
        body: JSON.stringify({ target: "tests/fixtures/reset_vault", allow_live: true }),
      }),
      env,
      {}
    );
    const runData = await run.json();
    assert.equal(env.__ledgerInstance.getAccounting().unknown_cost, 0.25);

    const reconcile = (payload) =>
      worker.fetch(
        new Request("https://basebreak.workers.dev/admin/reconcile-unknown-cost", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${env.BASEBREAK_ADMIN_KEY}`,
          },
          body: JSON.stringify(payload),
        }),
        env,
        {}
      );

    // Bare request.
    const bare = await reconcile({ run_id: runData.run_id });
    assert.equal(bare.status, 400);
    const bareData = await bare.json();
    assert.equal(bareData.hold_preserved, true);

    // Arbitrary free-text note with no structured evidence.
    const noteOnly = await reconcile({
      run_id: runData.run_id,
      reconciled_by: "operator",
      note: "I checked and it was fine, clear it.",
    });
    assert.equal(noteOnly.status, 400);
    assert.equal(env.__ledgerInstance.getAccounting().unknown_cost, 0.25);

    // Claiming provider verification that never occurred is rejected.
    const fakeVerified = await reconcile({
      run_id: runData.run_id,
      operator_decision: "NO_PROVIDER_CHARGE",
      attestation_type: "PROVIDER_VERIFIED",
      provider_billing_observation: "independent verifier says zero",
      evidence_reference: "ref-1",
      observed_cost_usd: 0,
      verification_timestamp: Date.now(),
      reconciled_by: "operator",
    });
    assert.equal(fakeVerified.status, 400);
    assert.equal(env.__ledgerInstance.getAccounting().unknown_cost, 0.25);
  });

  it("POST /admin/configure-source-commit and /admin/configure-live-gate require admin auth and explicit input", async () => {
    const { env } = createWorkerEnv({ LIVE_ENABLED: "true" });

    const unauth = await worker.fetch(
      new Request("https://basebreak.workers.dev/admin/configure-source-commit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source_commit_id: "a".repeat(40) }),
      }),
      env,
      {}
    );
    assert.equal(unauth.status, 401);

    const badSource = await worker.fetch(
      new Request("https://basebreak.workers.dev/admin/configure-source-commit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${env.BASEBREAK_ADMIN_KEY}`,
        },
        body: JSON.stringify({ source_commit_id: "not-a-sha", configured_by: "operator" }),
      }),
      env,
      {}
    );
    assert.equal(badSource.status, 400);

    const okSource = await worker.fetch(
      new Request("https://basebreak.workers.dev/admin/configure-source-commit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${env.BASEBREAK_ADMIN_KEY}`,
        },
        body: JSON.stringify({ source_commit_id: "c".repeat(40), configured_by: "operator" }),
      }),
      env,
      {}
    );
    assert.equal(okSource.status, 200);
    assert.equal((await okSource.json()).expected_source_commit, "c".repeat(40));

    const gate = await worker.fetch(
      new Request("https://basebreak.workers.dev/admin/configure-live-gate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${env.BASEBREAK_ADMIN_KEY}`,
        },
        body: JSON.stringify({ enabled: true, configured_by: "operator", reason: "authorized" }),
      }),
      env,
      {}
    );
    assert.equal(gate.status, 200);
    assert.equal((await gate.json()).durable_live_enabled, true);
  });

  it("deploying a newer Worker env does not implicitly authorize or re-align the durable ledger", async () => {
    const db = new DatabaseSync(":memory:");
    const OLD_SOURCE = "1".repeat(40);
    const NEW_SOURCE = "2".repeat(40);
    const baseEnv = {
      BASEBREAK_ADMIN_KEY: "test_admin_secret_key_123",
      GLOBAL_INVOCATION_CAP: "5",
      TOKEN_FACTORY_PROMO_STOP_THRESHOLD: "5.00",
      __allowInProcessLedgerForTests: true,
      __sqliteBackend: db,
    };
    // Existing Durable Object with durable gate off and older source.
    new AdmissionLedgerDO(db, {
      ...baseEnv,
      LIVE_ENABLED: "false",
      EXPECTED_SOURCE_COMMIT: OLD_SOURCE,
    });
    // New Worker deployment (same DO storage) with updated environment.
    const env = {
      ...baseEnv,
      LIVE_ENABLED: "true",
      EXPECTED_SOURCE_COMMIT: NEW_SOURCE,
      LIVE_RUN_ESTIMATED_COST_USD: "0.25",
    };
    env.__ledgerInstance = new AdmissionLedgerDO(db, env);

    const health = await worker.fetch(new Request("https://basebreak.workers.dev/health"), env, {});
    const healthData = await health.json();
    assert.equal(healthData.runtime_live_enabled, true);
    assert.equal(healthData.durable_live_enabled, false);
    assert.equal(healthData.live_enabled, false);
    assert.equal(healthData.source_commit_consistent, false);
    assert.equal(healthData.durable_expected_source_commit, OLD_SOURCE);

    // Live POST is refused because the durable operator gate is still off.
    const grant = env.__ledgerInstance.issueGrant({
      verifiedBalance: 10.0,
      balanceTimestamp: Date.now(),
      estimatedCostCap: 0.30,
      clientInfo: "judge",
    });
    const res = await worker.fetch(
      new Request("https://basebreak.workers.dev/v1/runs", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Judge-Grant": grant.grant_token },
        body: JSON.stringify({ target: "tests/fixtures/reset_vault", allow_live: true }),
      }),
      env,
      {}
    );
    assert.equal(res.status, 403);
    assert.equal((await res.json()).status, "BLOCKED");
  });

  it("POST /admin/reconcile-unknown-cost rejects unauthenticated callers", async () => {
    const { env } = createWorkerEnv();
    const req = new Request("https://basebreak.workers.dev/admin/reconcile-unknown-cost", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ run_id: "run_x" }),
    });
    const res = await worker.fetch(req, env, {});
    assert.equal(res.status, 401);
  });
});
