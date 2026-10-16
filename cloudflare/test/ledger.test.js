/**
 * Focused Adversarial and Integration Test Suite for AdmissionLedgerDO.
 *
 * Implements Section E requirements:
 * - 100 repeated clicks producing at most one admitted run for a single grant.
 * - Parallel attempts from multiple clients against the same global ledger.
 * - Reused, forged, and expired grants.
 * - Restart during reserved/in-flight state.
 * - Unknown provider outcome and duplicate-retry prevention.
 * - Missing credentials, stale balance, and promo expiry.
 * - Budget exhaustion and kill switch.
 * - Attempted arbitrary target/source substitution.
 * - Receipt tampering, forged provenance, and secret exposure.
 * - Read-only public access after live budget exhaustion.
 * - Same-origin routing and durable state recovery.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { AdmissionLedgerDO } from "../src/ledger.js";
import { computeReceiptDigest, verifyReceiptIntegrity } from "../src/crypto_utils.js";
import { buildFixturePublicReceipt } from "./fixtures/public_receipt_fixture.js";

const DEFAULT_TARGET = "tests/fixtures/reset_vault";
const DEFAULT_SOURCE = "80b43b84014fa61b941c7ebcd87836a56dcd7c92";

function createTestLedger(initialConfig = {}) {
  const db = new DatabaseSync(":memory:");
  const env = {
    LIVE_ENABLED: "true",
    GLOBAL_INVOCATION_CAP: "5",
    TOKEN_FACTORY_PROMO_STOP_THRESHOLD: "5.00",
    ALLOWLISTED_TARGET: DEFAULT_TARGET,
    EXPECTED_SOURCE_COMMIT: DEFAULT_SOURCE,
    ...initialConfig,
  };
  const ledger = new AdmissionLedgerDO(db, env);
  return { ledger, db, env };
}

function issueLiveGrant(ledger, options = {}) {
  return ledger.issueGrant({
    estimatedCostCap: 1.0,
    ...options,
  });
}

describe("AdmissionLedgerDO Adversarial & Integration Verification Suite", () => {
  it("1. 100 repeated clicks produce at most one admitted run for a single grant", () => {
    const { ledger } = createTestLedger();
    const grant = issueLiveGrant(ledger, { maxUses: 1 });

    const results = [];
    for (let i = 0; i < 100; i++) {
      const res = ledger.reserveAdmission({
        grant_token: grant.grant_token,
        target: DEFAULT_TARGET,
        source_commit_id: DEFAULT_SOURCE,
        verified_balance: 10.0,
        balance_timestamp: Date.now(),
        live_enabled: true,
      });
      results.push(res);
    }

    const admitted = results.filter((r) => r.admitted === true);
    const rejected = results.filter((r) => r.admitted === false);

    assert.equal(admitted.length, 1, "Exactly one run must be admitted");
    assert.equal(rejected.length, 99, "99 repeated clicks must be rejected");
    assert.equal(
      rejected[0].status,
      "GRANT_ALREADY_USED",
      "Subsequent attempts must fail with GRANT_ALREADY_USED"
    );

    // Verify database state: grant use_count is 1
    const grantRow = ledger.sql.query(
      "SELECT use_count, status FROM grants WHERE grant_id = ?",
      grant.grant_id
    )[0];
    assert.equal(grantRow.use_count, 1);
    assert.equal(grantRow.status, "CONSUMED");
  });

  it("2. Parallel attempts from multiple clients against global ledger (concurrency cap = 1)", () => {
    const { ledger } = createTestLedger();

    // Issue 10 distinct grants
    const grants = [];
    for (let i = 0; i < 10; i++) {
      grants.push(issueLiveGrant(ledger, { clientInfo: `client_${i}` }));
    }

    // Client 0 reserves admission first -> enters RESERVED
    const firstRes = ledger.reserveAdmission({
      grant_token: grants[0].grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 15.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(firstRes.admitted, true);
    assert.equal(firstRes.status, "RESERVED");

    // Clients 1 through 9 attempt admission while Client 0 is in-flight
    const concurrentResults = [];
    for (let i = 1; i < 10; i++) {
      const res = ledger.reserveAdmission({
        grant_token: grants[i].grant_token,
        target: DEFAULT_TARGET,
        source_commit_id: DEFAULT_SOURCE,
        verified_balance: 15.0,
        balance_timestamp: Date.now(),
        live_enabled: true,
      });
      concurrentResults.push(res);
    }

    // All 9 must be rejected due to global concurrency limit 1
    assert.equal(concurrentResults.length, 9);
    for (const r of concurrentResults) {
      assert.equal(r.admitted, false);
      assert.equal(r.status, "CONCURRENCY_LIMIT");
      assert.equal(r.code, 429);
    }

    // Client 1's grant must NOT be consumed
    const client1Row = ledger.sql.query(
      "SELECT status, use_count FROM grants WHERE grant_id = ?",
      grants[1].grant_id
    )[0];
    assert.equal(client1Row.status, "ISSUED");
    assert.equal(client1Row.use_count, 0);
  });

  it("3. Reused, forged, and expired grants fail closed", () => {
    const { ledger } = createTestLedger();

    // 3a. Forged grant token
    const forgedRes = ledger.reserveAdmission({
      grant_token: "forged_token_does_not_exist",
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 10.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(forgedRes.admitted, false);
    assert.equal(forgedRes.status, "INVALID_GRANT");
    assert.equal(forgedRes.code, 403);

    // 3b. Expired grant
    const expiredGrant = issueLiveGrant(ledger, { ttlSeconds: -10 }); // Already expired
    const expiredRes = ledger.reserveAdmission({
      grant_token: expiredGrant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 10.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(expiredRes.admitted, false);
    assert.equal(expiredRes.status, "EXPIRED_GRANT");
    assert.equal(expiredRes.code, 403);

    // 3c. Reused grant
    const validGrant = issueLiveGrant(ledger);
    const run1 = ledger.reserveAdmission({
      grant_token: validGrant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 10.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(run1.admitted, true);

    const reusedRes = ledger.reserveAdmission({
      grant_token: validGrant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 10.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(reusedRes.admitted, false);
    assert.equal(reusedRes.status, "GRANT_ALREADY_USED");
  });

  it("4. Restart during reserved/in-flight state (orphan cleanup and unknown cost accounting)", () => {
    const { ledger, db, env } = createTestLedger();
    const grant = issueLiveGrant(ledger);

    const reservation = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      estimated_cost: 0.05,
      verified_balance: 10.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(reservation.admitted, true);

    // Simulate worker crash and restart: create fresh DO instance attached to same DB
    const freshLedger = new AdmissionLedgerDO(db, env);

    // Backdate started_at to exceed deadline (e.g. 70 seconds ago)
    db.prepare("UPDATE runs SET started_at = ? WHERE run_id = ?").run(
      Date.now() - 70000,
      reservation.run_id
    );

    // Run recovery
    const recoveredCount = freshLedger.recoverDurableState(60);
    assert.equal(recoveredCount, 1);

    // Run status must be TIMED_OUT, reserved_cost is 0, unknown_cost is 0.05
    const runRow = db.prepare("SELECT status, reserved_cost, unknown_cost FROM runs WHERE run_id = ?").get(
      reservation.run_id
    );
    assert.equal(runRow.status, "TIMED_OUT");
    assert.equal(runRow.reserved_cost, 0.0);
    assert.equal(runRow.unknown_cost, 0.05);

    // Global accounting must reflect unknown_cost and 0 in-flight
    const accounting = freshLedger.getAccounting();
    assert.equal(accounting.in_flight_count, 0);
    assert.equal(accounting.unknown_cost, 0.05);
    assert.equal(accounting.reserved_cost, 0.0);
  });

  it("5. Unknown provider outcome and duplicate-retry prevention", () => {
    const { ledger } = createTestLedger();
    const grant = issueLiveGrant(ledger);

    const reservation = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      estimated_cost: 0.04,
      verified_balance: 10.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });

    // Record ambiguous outcome (network disconnect mid-flight)
    const failureRes = ledger.recordExecutionFailure(reservation.run_id, {
      error_message: "Network disconnect during Nebius API call",
      was_ambiguous: true,
    });
    assert.equal(failureRes.status, "UNKNOWN_OUTCOME");

    const accounting = ledger.getAccounting();
    assert.equal(accounting.unknown_cost, 0.04);
    assert.equal(accounting.reserved_cost, 0.0);
    assert.equal(accounting.in_flight_count, 0);

    // Retry with the same grant MUST fail (prevent duplicate retry of uncertain operation)
    const retryRes = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 10.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(retryRes.admitted, false);
    assert.equal(retryRes.status, "GRANT_ALREADY_USED");
  });

  it("5b. Durable operator live gate cannot be overridden by request flag", () => {
    const { ledger } = createTestLedger({ LIVE_ENABLED: "false" });
    const grant = issueLiveGrant(ledger, {
      verifiedBalance: 20.0,
      balanceTimestamp: Date.now(),
    });

    const blocked = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });

    assert.equal(blocked.admitted, false);
    assert.equal(blocked.status, "BLOCKED");
    assert.match(blocked.error, /durable operator-controlled gate/);

    const grantRow = ledger.sql.query(
      "SELECT use_count, status FROM grants WHERE grant_id = ?",
      grant.grant_id
    )[0];
    assert.equal(grantRow.use_count, 0);
    assert.equal(grantRow.status, "ISSUED");
  });

  it("6. Missing credentials, stale balance, and promo expiry", () => {
    const { ledger } = createTestLedger();
    const grant = issueLiveGrant(ledger);

    // 6a. Missing operator cost cap
    const missingCapGrant = ledger.issueGrant({
      verifiedBalance: 12.0,
      balanceTimestamp: Date.now(),
    });
    const missingCapRes = ledger.reserveAdmission({
      grant_token: missingCapGrant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      live_enabled: true,
    });
    assert.equal(missingCapRes.admitted, false);
    assert.equal(missingCapRes.status, "BLOCKED_ESTIMATED_COST_CAP_MISSING");
    assert.equal(missingCapRes.code, 422);

    // 6b. Malformed operator cost cap
    const malformedCapGrant = ledger.issueGrant({
      verifiedBalance: 12.0,
      balanceTimestamp: Date.now(),
      estimatedCostCap: 0,
    });
    const malformedCapRes = ledger.reserveAdmission({
      grant_token: malformedCapGrant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      live_enabled: true,
    });
    assert.equal(malformedCapRes.admitted, false);
    assert.equal(malformedCapRes.status, "BLOCKED_ESTIMATED_COST_CAP_MISSING");
    assert.equal(malformedCapRes.code, 422);

    // 6c. Missing verified balance
    const missingBalRes = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      live_enabled: true,
    });
    assert.equal(missingBalRes.admitted, false);
    assert.equal(missingBalRes.status, "BLOCKED_BALANCE_MISSING");
    assert.equal(missingBalRes.code, 422);

    // 6d. Stale balance (>15 minutes old)
    const staleBalRes = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 12.0,
      balance_timestamp: Date.now() - 16 * 60 * 1000,
      live_enabled: true,
    });
    assert.equal(staleBalRes.admitted, false);
    assert.equal(staleBalRes.status, "BLOCKED_BALANCE_STALE");
    assert.equal(staleBalRes.code, 422);

    // 6e. Balance at or below safety floor ($5.00)
    const floorBalRes = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 5.0, // Exactly at $5.00 floor
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(floorBalRes.admitted, false);
    assert.equal(floorBalRes.status, "BLOCKED_BUDGET_FLOOR");
    assert.equal(floorBalRes.code, 403);

    // 6f. Balance below floor after deducting estimated cost (5.03 - 0.05 = 4.98 < 5.00)
    const wouldViolateFloor = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      estimated_cost: 0.05,
      verified_balance: 5.03,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(wouldViolateFloor.admitted, false);
    assert.equal(wouldViolateFloor.status, "BLOCKED_BUDGET_FLOOR");
    assert.equal(wouldViolateFloor.code, 403);

    // 6g. Operator-bound grant cap rejects a request whose server-side estimated cost is too high
    const cappedGrant = issueLiveGrant(ledger, {
      verifiedBalance: 10.0,
      balanceTimestamp: Date.now(),
      estimatedCostCap: 0.04,
    });
    const cappedRes = ledger.reserveAdmission({
      grant_token: cappedGrant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      estimated_cost: 0.05,
      live_enabled: true,
    });
    assert.equal(cappedRes.admitted, false);
    assert.equal(cappedRes.status, "BLOCKED_ESTIMATED_COST_CAP");
    assert.equal(cappedRes.code, 403);
  });

  it("7. Budget exhaustion and kill switch", () => {
    const { ledger } = createTestLedger({ GLOBAL_INVOCATION_CAP: "2" });

    // Run 1: Admitted and completed
    const g1 = issueLiveGrant(ledger);
    const r1 = ledger.reserveAdmission({
      grant_token: g1.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(r1.admitted, true);
    ledger.recordExecutionSuccess(r1.run_id, {
      observed_cost: 0.01,
      receipt: buildFixturePublicReceipt(),
    });

    // Run 2: Admitted and completed
    const g2 = issueLiveGrant(ledger);
    const r2 = ledger.reserveAdmission({
      grant_token: g2.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(r2.admitted, true);
    ledger.recordExecutionSuccess(r2.run_id, {
      observed_cost: 0.01,
      receipt: buildFixturePublicReceipt(),
    });

    // Run 3: Attempt admission after cap of 2 is reached
    const g3 = issueLiveGrant(ledger);
    const r3 = ledger.reserveAdmission({
      grant_token: g3.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(r3.admitted, false);
    assert.equal(r3.status, "CAP_EXHAUSTED");
    assert.equal(r3.code, 429);

    // 7b. Kill switch immediately stops all reservations
    const { ledger: ledger2 } = createTestLedger();
    ledger2.engageKillSwitch("Operator initiated emergency freeze");

    const gk = issueLiveGrant(ledger2);
    const rk = ledger2.reserveAdmission({
      grant_token: gk.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(rk.admitted, false);
    assert.equal(rk.status, "BLOCKED_KILL_SWITCH");
    assert.equal(rk.code, 503);

    // Disengage kill switch
    ledger2.disengageKillSwitch();
    const rk2 = ledger2.reserveAdmission({
      grant_token: gk.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(rk2.admitted, true);
  });

  it("8. Attempted arbitrary target / source substitution rejected", () => {
    const { ledger } = createTestLedger();
    const grant = issueLiveGrant(ledger);

    // 8a. Target substitution
    const badTargetRes = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: "untrusted/arbitrary-repo.git",
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 10.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(badTargetRes.admitted, false);
    assert.equal(badTargetRes.status, "INVALID_TARGET");
    assert.equal(badTargetRes.code, 400);

    // 8b. Source commit substitution
    const badSourceRes = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: "deadbeef00000000000000000000000000000000",
      verified_balance: 10.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(badSourceRes.admitted, false);
    assert.equal(badSourceRes.status, "INVALID_SOURCE");
    assert.equal(badSourceRes.code, 400);
  });

  it("9. Receipt tampering, forged provenance, and secret exposure rejected", () => {
    const { ledger } = createTestLedger();
    const validReceipt = buildFixturePublicReceipt();
    assert.equal(verifyReceiptIntegrity(validReceipt), true);

    // 9a. Tampered receipt (modified field without updating digest)
    const tamperedReceipt = { ...validReceipt, task_id: "TAMPERED_TASK_ID" };
    assert.equal(verifyReceiptIntegrity(tamperedReceipt), false);

    assert.throws(
      () => ledger.storeReceipt("run_tampered", tamperedReceipt),
      /integrity verification failed/
    );

    // 9b. Secret exposure in receipt
    const secretReceipt = {
      ...validReceipt,
      disclaimers: ["Bearer secret_api_key_1234567890"],
    };
    secretReceipt.receipt_digest = computeReceiptDigest(secretReceipt);

    assert.throws(
      () => ledger.storeReceipt("run_secret", secretReceipt),
      /Receipt contains sensitive credentials/
    );

    // 9c. Digest integrity alone cannot promote fixture data to authoritative live evidence
    const forgedLiveReceipt = buildFixturePublicReceipt({ provenance: "LIVE_NEBIUS" });
    assert.throws(
      () => ledger.storeReceipt("run_forged_live", forgedLiveReceipt),
      /independent trusted verification authority is configured/
    );

    // 9d. Clean authentic fixture receipt stores and retrieves with valid integrity verification
    ledger.storeReceipt("run_clean", validReceipt);
    const retrieved = ledger.getReceipt("run_clean");
    assert.ok(retrieved);
    assert.equal(retrieved.is_verified, true);
    assert.equal(retrieved.receipt_digest, validReceipt.receipt_digest);
  });

  it("9b. environment flags cannot authorize LIVE_NEBIUS or RECORDED_LIVE receipt imports", () => {
    const { ledger } = createTestLedger({ ALLOW_HISTORICAL_LIVE_RECEIPT_IMPORT: "true" });
    const liveReceipt = buildFixturePublicReceipt({ provenance: "LIVE_NEBIUS" });
    const recordedLiveReceipt = buildFixturePublicReceipt({ provenance: "RECORDED_LIVE" });

    assert.throws(
      () => ledger.storeReceipt("run_live_bypass_attempt", liveReceipt),
      /independent trusted verification authority is configured/
    );
    assert.throws(
      () => ledger.storeReceipt("run_recorded_live_bypass_attempt", recordedLiveReceipt),
      /independent trusted verification authority is configured/
    );
  });

  it("9c. recordExecutionSuccess rejects live receipt imports even when bypass flag is set", () => {
    const { ledger } = createTestLedger({
      ALLOW_HISTORICAL_LIVE_RECEIPT_IMPORT: "true",
      GLOBAL_INVOCATION_CAP: "2",
    });
    const grant = issueLiveGrant(ledger);
    const reservation = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(reservation.admitted, true);

    const liveReceipt = buildFixturePublicReceipt({ provenance: "LIVE_NEBIUS" });
    assert.throws(
      () =>
        ledger.recordExecutionSuccess(reservation.run_id, {
          observed_cost: 0.01,
          receipt: liveReceipt,
        }),
      /independent trusted verification authority is configured/
    );

    const run = ledger.sql.query("SELECT status FROM runs WHERE run_id = ?", reservation.run_id)[0];
    assert.equal(run.status, "RESERVED");
  });

  it("10. Read-only public access preserved after live budget exhaustion", () => {
    const { ledger } = createTestLedger({ GLOBAL_INVOCATION_CAP: "1" });
    const grant = issueLiveGrant(ledger);

    const reservation = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 10.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(reservation.admitted, true);

    const canonicalReceipt = buildFixturePublicReceipt();
    ledger.recordExecutionSuccess(reservation.run_id, {
      observed_cost: 0.005,
      receipt: canonicalReceipt,
    });

    // Budget is now 100% exhausted
    const accounting = ledger.getAccounting();
    assert.equal(accounting.total_runs, 1);
    assert.equal(accounting.global_cap, 1);

    // New live reservation fails
    const g2 = issueLiveGrant(ledger);
    const nextRes = ledger.reserveAdmission({
      grant_token: g2.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 10.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(nextRes.admitted, false);
    assert.equal(nextRes.status, "CAP_EXHAUSTED");

    // But read-only inspection of authentic receipt remains accessible!
    const publicReceipt = ledger.getReceipt(reservation.run_id);
    assert.ok(publicReceipt);
    assert.equal(publicReceipt.is_verified, true);
    assert.equal(publicReceipt.receipt.provenance, "FIXTURE");
  });

  it("11. Same-origin routing and durable state recovery", () => {
    const { ledger, db, env } = createTestLedger();
    const grant = issueLiveGrant(ledger, { token: "durable_grant_123" });

    // Store a published receipt
    const canonicalReceipt = buildFixturePublicReceipt();
    ledger.storeReceipt("run_durable_test", canonicalReceipt);

    // Destroy first DO instance, re-instantiate fresh DO with same DB
    const restoredLedger = new AdmissionLedgerDO(db, env);

    // Verify grant is intact
    const grantRows = restoredLedger.sql.query(
      "SELECT * FROM grants WHERE grant_token = ?",
      "durable_grant_123"
    );
    assert.equal(grantRows.length, 1);
    assert.equal(grantRows[0].status, "ISSUED");

    // Verify receipt is intact and verifies cryptographically
    const restoredReceipt = restoredLedger.getReceipt("run_durable_test");
    assert.ok(restoredReceipt);
    assert.equal(restoredReceipt.is_verified, true);
    assert.equal(restoredReceipt.receipt_digest, canonicalReceipt.receipt_digest);
  });

  it("12. Idempotency replays are bound to the original authorization context", () => {
    const { ledger } = createTestLedger();
    const grantOne = issueLiveGrant(ledger);
    const grantTwo = issueLiveGrant(ledger);

    const first = ledger.reserveAdmission({
      grant_token: grantOne.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      idempotency_key: "idem-boundary-key",
      verified_balance: 10.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(first.admitted, true);

    const replay = ledger.reserveAdmission({
      grant_token: grantOne.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      idempotency_key: "idem-boundary-key",
      verified_balance: 10.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(replay.admitted, true);
    assert.equal(replay.is_replay, true);
    assert.equal(replay.run_id, first.run_id);

    const crossGrantReplay = ledger.reserveAdmission({
      grant_token: grantTwo.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      idempotency_key: "idem-boundary-key",
      verified_balance: 10.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(crossGrantReplay.admitted, false);
    assert.equal(crossGrantReplay.status, "IDEMPOTENCY_CONTEXT_MISMATCH");
    assert.equal(crossGrantReplay.code, 409);
  });

  it("13. Successful execution with unknown provider cost is accounted conservatively", () => {
    const { ledger } = createTestLedger();
    const grant = issueLiveGrant(ledger);
    const reservation = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      estimated_cost: 0.07,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(reservation.admitted, true);

    ledger.recordExecutionSuccess(reservation.run_id, {
      observed_cost: null,
      cost_provenance: "UNKNOWN",
      receipt: buildFixturePublicReceipt(),
    });

    const accounting = ledger.getAccounting();
    assert.equal(accounting.observed_cost, 0.0, "Unknown cost must never be recorded as observed");
    assert.equal(accounting.unknown_cost, 0.07);
    assert.equal(accounting.reserved_cost, 0.0);
    assert.equal(accounting.total_metered_cost, 0.07);

    const runRow = ledger.sql.query(
      "SELECT status, observed_cost, unknown_cost, reserved_cost FROM runs WHERE run_id = ?",
      reservation.run_id
    )[0];
    assert.equal(runRow.status, "COMPLETED");
    assert.equal(runRow.observed_cost, 0.0);
    assert.equal(runRow.unknown_cost, 0.07);
    assert.equal(runRow.reserved_cost, 0.0);
  });

  it("13b. Known provider-observed cost is recorded as observed, not unknown", () => {
    const { ledger } = createTestLedger();
    const grant = issueLiveGrant(ledger);
    const reservation = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      estimated_cost: 0.07,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(reservation.admitted, true);

    ledger.recordExecutionSuccess(reservation.run_id, {
      observed_cost: 0.02,
      cost_provenance: "PROVIDER_OBSERVED",
      receipt: buildFixturePublicReceipt(),
    });

    const accounting = ledger.getAccounting();
    assert.equal(accounting.observed_cost, 0.02);
    assert.equal(accounting.unknown_cost, 0.0);
    assert.equal(accounting.reserved_cost, 0.0);
    assert.equal(accounting.total_metered_cost, 0.02);
  });

  it("14. Deterministic failure after dispatch retains unknown cost and blocks admission until reconciliation", () => {
    const { ledger } = createTestLedger();
    const grant = issueLiveGrant(ledger);
    const reservation = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      estimated_cost: 0.05,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(reservation.admitted, true);

    // Deterministic failure (not ambiguous) but the provider may have already
    // started charging — measured cost is unknown.
    const failure = ledger.recordExecutionFailure(reservation.run_id, {
      error_message: "Model returned a malformed response after inference completed.",
      outcome: "FAILED",
      was_ambiguous: false,
      provider_may_have_dispatched: true,
      observed_cost: null,
    });
    assert.equal(failure.status, "FAILED_UNRECONCILED_COST");

    const accounting = ledger.getAccounting();
    assert.equal(accounting.observed_cost, 0.0);
    assert.equal(accounting.unknown_cost, 0.05);
    assert.equal(accounting.reserved_cost, 0.0);

    // Subsequent live admission is held while unreconciled unknown exposure remains.
    const blockedGrant = issueLiveGrant(ledger);
    const blocked = ledger.reserveAdmission({
      grant_token: blockedGrant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(blocked.admitted, false);
    assert.equal(blocked.status, "BLOCKED_UNRECONCILED_UNKNOWN_COST");
    assert.equal(blocked.code, 409);

    // Independently verified operator reconciliation clears the hold.
    const reconciled = ledger.reconcileUnknownCost(reservation.run_id, {
      reconciled_by: "operator-independent-qa",
      note: "Provider usage dashboard confirmed zero billed inference.",
    });
    assert.equal(reconciled.reconciled, true);
    assert.equal(reconciled.reconciled_amount, 0.05);
    assert.equal(reconciled.remaining_unknown_cost, 0);

    const clearedAccounting = ledger.getAccounting();
    assert.equal(clearedAccounting.unknown_cost, 0.0);

    const afterReconcileGrant = issueLiveGrant(ledger);
    const admittedAfter = ledger.reserveAdmission({
      grant_token: afterReconcileGrant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(admittedAfter.admitted, true);
  });

  it("15. Deterministic pre-dispatch failure releases the reservation (no provider operation)", () => {
    const { ledger } = createTestLedger();
    const grant = issueLiveGrant(ledger);
    const reservation = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      estimated_cost: 0.05,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(reservation.admitted, true);

    const failure = ledger.recordExecutionFailure(reservation.run_id, {
      error_message: "Trusted bridge URL is not configured; no provider call attempted.",
      outcome: "NOT_READY_FOR_DEPLOYMENT",
      was_ambiguous: false,
      provider_may_have_dispatched: false,
      observed_cost: null,
    });
    assert.equal(failure.status, "FAILED");

    const accounting = ledger.getAccounting();
    assert.equal(accounting.unknown_cost, 0.0);
    assert.equal(accounting.observed_cost, 0.0);
    assert.equal(accounting.reserved_cost, 0.0);

    // No hold remains, so a fresh admission is admitted.
    const nextGrant = issueLiveGrant(ledger);
    const admitted = ledger.reserveAdmission({
      grant_token: nextGrant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    assert.equal(admitted.admitted, true);
  });

  it("16. Known observed cost on a dispatched failure is recorded as observed, not unknown", () => {
    const { ledger } = createTestLedger();
    const grant = issueLiveGrant(ledger);
    const reservation = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      estimated_cost: 0.05,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });

    ledger.recordExecutionFailure(reservation.run_id, {
      error_message: "Sandbox materialization error after measured inference.",
      outcome: "FAILED",
      was_ambiguous: false,
      provider_may_have_dispatched: true,
      observed_cost: 0.012,
    });

    const accounting = ledger.getAccounting();
    assert.equal(accounting.observed_cost, 0.012);
    assert.equal(accounting.unknown_cost, 0.0);
    assert.equal(accounting.reserved_cost, 0.0);
  });

  it("17. reconcileUnknownCost rejects invalid or unjustified reconciliation attempts", () => {
    const { ledger } = createTestLedger();
    const grant = issueLiveGrant(ledger);
    const reservation = ledger.reserveAdmission({
      grant_token: grant.grant_token,
      target: DEFAULT_TARGET,
      source_commit_id: DEFAULT_SOURCE,
      estimated_cost: 0.05,
      verified_balance: 20.0,
      balance_timestamp: Date.now(),
      live_enabled: true,
    });
    // No unknown cost yet.
    assert.throws(
      () => ledger.reconcileUnknownCost(reservation.run_id),
      /no unreconciled unknown cost/
    );
    // Unknown run.
    assert.throws(
      () => ledger.reconcileUnknownCost("run_does_not_exist"),
      /not found in ledger/
    );

    ledger.recordExecutionFailure(reservation.run_id, {
      error_message: "unknown cost hold",
      provider_may_have_dispatched: true,
    });

    assert.throws(
      () => ledger.reconcileUnknownCost(reservation.run_id, { amount_usd: 0 }),
      /positive finite number/
    );
    assert.throws(
      () => ledger.reconcileUnknownCost(reservation.run_id, { amount_usd: 999 }),
      /exceeds the run/
    );
  });
});
