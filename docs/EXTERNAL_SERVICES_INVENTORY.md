# Basebreak — External Services Cleanup Inventory

Purpose: post-competition cleanup reference. This document records Basebreak's actual
or possible external dependencies, their free/trial/credit/PAYG classification, billing
risk, and eventual cancellation/deletion steps. **No resource was deleted, no account or
payment setting was modified, and no secret is recorded here.**

Status legend: `VERIFIED` (observed in this repo/runtime), `OPERATOR_CONFIGURABLE`
(operator-controlled, not machine-verified here), `UNKNOWN` (not verified — do not assume).

> **Preserve shared/operator accounts.** The operator's personal subscriptions
> (including their **ChatGPT Plus** subscription) and any account shared with other
> projects must NOT be cancelled as part of Basebreak cleanup.

## 1. Nebius AI Cloud / Token Factory (models + sandboxes)

- **Purpose:** Genuine required provider for `LIVE_NEBIUS` inference (Nemotron) and Token Factory Sandboxes.
- **Account/resource presence:** `OPERATOR_CONFIGURABLE`. Credentials are **absent** from this repo and from the Oracle bridge (no `NEBIUS_API_KEY`/`NEBIUS_PROJECT_ID`). No live call has been executed in these batches.
- **Free/PAYG classification:** Builder-Program **promotional credits**; a payment card is attached under the operator-approved `TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION`. Target personal spend is `$0.00`.
- **Billing risk:** **PAYG-capable** — promotional credits are finite and provider APIs provide **no** automated hard stop. Basebreak enforces an operator-policy floor `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` (client-side only).
- **Expiry:** `UNKNOWN` (promo balance/expiry not verified).
- **Preservation needs:** Needed only for the (still `NOT_RUN`) deployed `LIVE_NEBIUS` proof and any authorized live demo.
- **Cleanup steps:** (1) confirm no metered usage will occur; (2) verify outstanding balance `$0.00`; (3) remove/suspend the attached payment card per the bounded-billing exception; (4) do not delete the account until submission/judging obligations end.

## 2. NVIDIA

- **Purpose:** Model provider (Nemotron models are consumed through Nebius Token Factory, not a separate NVIDIA account).
- **Account/resource presence:** `UNKNOWN` (no separate NVIDIA account or key observed).
- **Classification:** No direct Basebreak billing dependency observed.
- **Cleanup steps:** None expected; confirm no separate NVIDIA account/credential exists before closing.

## 3. Oracle Cloud (Always Free) — VM `basebreak-verifier`

- **Purpose:** 24/7 Oracle Linux ARM64 host running the private trusted Python verifier bridge (`127.0.0.1:8787`) and a Cloudflare Tunnel connector.
- **Account/resource presence:** `VERIFIED` (existing instance; operator-provisioned).
- **Free/PAYG classification:** **Always Free** tier (VM.Standard.A1.Flex). No billing change was made.
- **Billing risk:** Low, provided the Always Free shape/limits are not exceeded and no paid resource is created.
- **Expiry:** N/A (Always Free).
- **Preservation needs:** Required while the Worker→VPC→Tunnel→bridge path and any live demo are in use.
- **Cleanup steps:** After judging: stop the `cloudflared` and `basebreak-bridge` services, remove the Cloudflare Tunnel + VPC Service, then terminate the instance and delete the boot volume/network resources if no longer needed. Preserve the signing key/state only if evidence is still required.

## 4. Cloudflare (Workers / Durable Objects / Tunnel / Workers VPC / Zero Trust)

- **Purpose:** Public judge Worker (`basebreak.zyganali.workers.dev`), SQLite Durable Object admission ledger, Cloudflare Tunnel + Workers VPC Service for private bridge connectivity.
- **Account/resource presence:** `VERIFIED` — account `Zyganali@gmail.com's Account` (`ad7b5885568722e67877af65b7100785`); Worker `basebreak`; Tunnel `basebreak-verifier` (`c4977eda-…`); VPC Service `basebreak-bridge` (`01a14dbe-…`).
- **Free/PAYG classification:** Workers **Free**, Durable Objects (SQLite) free tier, Tunnel free (all plans), **Workers VPC free during open beta**. Live gates remain disabled; no paid add-on enabled.
- **Billing risk:** Low while on Free; **Zero Trust onboarding requests payment details** even on the free plan (not charged) — not onboarded here.
- **Expiry:** N/A (Free).
- **Preservation needs:** Worker + Durable Object state must persist through the judging window (to ~2026-12-15); **do not reset Durable Object state**.
- **Cleanup steps:** After judging: delete the VPC Service, delete the Tunnel, remove Worker secrets, and (if desired) delete the Worker. No billing change required.

## 5. Tailscale

- **Purpose:** Private operator access to the Oracle VM (`basebreak-verifier`).
- **Account/resource presence:** `VERIFIED` — tailnet `tailf709b5.ts.net`; node `basebreak-verifier` (`100.98.246.103`). Free **Personal** plan.
- **Free/PAYG classification:** Free forever (personal). Funnel is **not** used.
- **Billing risk:** None observed.
- **Expiry:** N/A.
- **Cleanup steps:** Remove the node from the tailnet; optionally delete the tailnet if unused.

## 6. Tavily

- **Purpose:** Optional research adapter (P-16.05).
- **Account/resource presence:** `UNKNOWN`. **No Tavily call has been executed** (P-16.05 remains `OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN`).
- **Classification:** `UNKNOWN` (possible free tier). No key stored in repo.
- **Cleanup steps:** None required unless a key was created; if so, revoke it.

## 7. GitHub

- **Purpose:** Canonical source (`zyganali-glitch/Basebreak`) and CI (`.github/workflows/ci.yml`).
- **Account/resource presence:** `VERIFIED` (public repository, `main`).
- **Free/PAYG classification:** Free (public repo; GitHub Actions free minutes).
- **Billing risk:** None observed.
- **Cleanup steps:** None for Basebreak; do not delete the repository while submission/judging requires it.

## 8. Antigravity (Google) — coding agent environment

- **Purpose:** Operator's AI coding-agent workspace used to execute these batches.
- **Account/resource presence:** `OPERATOR_CONFIGURABLE` (this environment).
- **Classification:** `UNKNOWN` (not verified here).
- **Cleanup steps:** Operator-managed; out of Basebreak's scope.

## 9. Devpost

- **Purpose:** Hackathon submission/judging platform (Nebius × NVIDIA Global AI Hackathon).
- **Account/resource presence:** `OPERATOR_CONFIGURABLE`.
- **Classification:** Free to use.
- **Cleanup steps:** None.

## Notes / cautions

- Do **not** enable PAYG, purchase domains, start paid trials, or add billing for any service.
- Do **not** delete shared accounts or the operator's **ChatGPT Plus** subscription.
- Provider-enforced hard spending stop for Nebius is `UNKNOWN`/`UNVERIFIED`; only the client-side `$5.00` floor is enforced by Basebreak.
- All "cleanup steps" are advisory and require separate operator authorization; nothing here is executed automatically.
