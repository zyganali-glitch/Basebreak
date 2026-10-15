/**
 * Genuine Provider Dispatcher & Remote Execution Boundary.
 *
 * This boundary is intentionally fail-closed until the Cloudflare path is wired
 * to an independently validated remote Python verifier that produces authentic
 * BASE/CANDIDATE/COUNTERFACTUAL execution facts.
 */

export const CANONICAL_DEMO_SCENARIO = {
  task_id: "TASK-RESET-VAULT-001",
  target: "tests/fixtures/reset_vault",
  change_class: "BUG_FIX",
  source_commit_id: "80b43b84014fa61b941c7ebcd87836a56dcd7c92",
  frozen_contract_digest: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
};

/**
 * Dispatch verification run.
 *
 * Cloudflare deployment remains NOT_READY_FOR_DEPLOYMENT until a real remote
 * Python verification bridge exists. This function must never provision a
 * sandbox or synthesize LIVE_NEBIUS / VERIFIED evidence from incomplete facts.
 *
 * @param {object} params
 * @param {string} params.runId
 * @param {string} params.target
 * @param {string} params.sourceCommitId
 * @param {boolean} [params.allowLive=false]
 * @returns {Promise<{ success: boolean, status: string, error: string, was_ambiguous: boolean }>}
 */
export async function dispatchVerificationRun({
  runId,
  target,
  sourceCommitId,
  allowLive = false,
}) {
  void runId;
  void target;
  void sourceCommitId;

  if (!allowLive) {
    return {
      success: false,
      status: "NOT_RUN",
      error:
        "BLOCKED: Live execution not requested. Status: OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN.",
      was_ambiguous: false,
    };
  }

  return {
    success: false,
    status: "NOT_RUN",
    error:
      "BLOCKED: Cloudflare provider dispatch is NOT_READY_FOR_DEPLOYMENT. No trusted remote Python verification bridge is configured, so no Nebius sandbox request or LIVE_NEBIUS receipt issuance was attempted.",
    was_ambiguous: false,
  };
}
