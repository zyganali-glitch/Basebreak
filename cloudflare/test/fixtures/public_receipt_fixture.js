import { computeReceiptDigest } from "../../src/crypto_utils.js";

const DEFAULT_SOURCE = "80b43b84014fa61b941c7ebcd87836a56dcd7c92";

export function buildFixturePublicReceipt(overrides = {}) {
  const receipt = {
    schema_version: "1.0.0",
    task_id: "TFX_RESET_VAULT_001",
    source_commit_id: DEFAULT_SOURCE,
    overall_verdict: "VERIFIED",
    provenance: "FIXTURE",
    executions: [
      { world: "BASE", outcome: "FAIL", exit_code: 1 },
      { world: "CANDIDATE", outcome: "PASS", exit_code: 0 },
      { world: "COUNTERFACTUAL", outcome: "FAIL", exit_code: 1 },
    ],
    not_run_obligations: [],
    disclaimers: [
      "FIXTURE ONLY: synthetic receipt for local tests.",
      "Not live evidence and not for deployment or public authenticity claims.",
    ],
    ...overrides,
  };

  receipt.receipt_digest = computeReceiptDigest(receipt);
  return receipt;
}
