# P-01.01 — Platform Discovery Report

- **Execution Date/Time:** 2026-09-12 14:30 UTC
- **Starting Canonical SHA:** `08ebfc94a75954d79ee2613f935584de2a9d5900`
- **Active Micro-Task:** `P-01.01 — Discover current Nebius account/runtime/API/model reality from official docs and live account`
- **Execution Status:** IN_PROGRESS (Repair candidate committed; awaiting independent QA)
- **Zero-Cost Gate Verdict:** `BLOCKED_ZERO_COST / OPERATOR_DECISION_REQUIRED` (Nebius Support confirmed payment card is mandatory before promotional credit redemption; cardless activation not supported; Zero-Cost Law forbids payment card entry without operator decision)

---

## 1. Verified Official Sources Table

| Resource | Official URL | Verified Status / Terms | Provenance | Observed At |
|---|---|---|---|---|
| Token Factory Portal | `https://tokenfactory.nebius.com/` | Active production web console (`ai-studio-ui@1.1182.0+0300d191`) | `OFFICIAL_DOC` / `LIVE_NEBIUS` | 2026-09-12 |
| Token Factory Quickstart | `https://docs.tokenfactory.nebius.com/quickstart` | Base URL `https://api.tokenfactory.nebius.com/v1/`, env var `NEBIUS_API_KEY` | `OFFICIAL_DOC` | 2026-09-12 |
| Token Factory API Intro & Auth | `https://docs.tokenfactory.nebius.com/api-reference/introduction` | Bearer token auth (`Authorization: Bearer <token>`), OpenAI SDK compatible | `OFFICIAL_DOC` | 2026-09-12 |
| Token Factory List Models API | `https://docs.tokenfactory.nebius.com/api-reference/models/list-models` | `GET /v1/models`, query params `project_id`, `verbose` | `OFFICIAL_DOC` | 2026-09-12 |
| Token Factory Public Model Catalog | `https://tokenfactory.nebius.com/model-catalog.md` | Public markdown table of all models, context windows, regions, pricing | `OFFICIAL_DOC` / `LIVE_NEBIUS` | 2026-09-12 |
| Token Factory Machine-Readable Catalog | `https://tokenfactory.nebius.com/api/public/models_info` | Authoritative JSON endpoint with per-flavor status, quantization, licenses | `OFFICIAL_DOC` / `LIVE_NEBIUS` | 2026-09-12 |
| Nebius Builder Program Terms | `https://nebius.com/builders-terms-and-conditions` | $25 Token Factory + $25 Tavily credits, 90-day expiry; Section C.3 notes PAYG continuation | `OFFICIAL_DOC` | 2026-09-12 |
| Nebius Nemotron Family Page | `https://nebius.com/services/token-factory/nemotron` | Showcases Nemotron 3 Nano, Omni, Super 120B, Ultra 550B models | `OFFICIAL_DOC` | 2026-09-12 |
| Billing & Consumption Documentation | `https://docs.tokenfactory.nebius.com/other-capabilities/billing-new.md` | Mandatory bank card onboarding; real-time debit; automatic charge if negative | `OFFICIAL_DOC` | 2026-09-12 |
| Sandboxes Documentation | `https://docs.tokenfactory.nebius.com/sandboxes/overview` | Contree Python SDK, CLI, MCP server, REST API; 50 concurrent ops; 180d retention | `OFFICIAL_DOC` | 2026-09-12 |
| Devpost Hackathon Rules | `https://nebiusglobalaihackathon.devpost.com/rules` | NVIDIA open source models on Token Factory/AI Cloud; <3m video, open repo | `OFFICIAL_DOC` | 2026-09-12 |

---

## 2. Token Factory UI & Access Path Reality

- **Web Application URL:** `https://tokenfactory.nebius.com/`
- **Federated Authentication Providers:** Google (`federation-e00studio-google`) and GitHub (`federation-e00studio-github`).
- **OAuth Identity Endpoint:** `https://auth.tokenfactory.nebius.com`
- **API Key Generation Path:** Web Console → Navigation → [API keys](https://tokenfactory.nebius.com/project/api-keys) → "Create API key".
- **Playground Access:** Web Console → [Playground](https://tokenfactory.nebius.com/playground) (interactive testing with model selection, temperature, and code generator).

---

## 3. Endpoint, API & SDK Reality

- **Base URL:** `https://api.tokenfactory.nebius.com/v1/`
- **Sandboxes Base URL:** `https://api.tokenfactory.nebius.com/sandboxes/v1/`
- **Regional Inference Endpoints:**
  - `eu-north1`: `https://api.tokenfactory.nebius.com/v1/`
  - `us-central1`: `https://api.tokenfactory.us-central1.nebius.com/v1/`
  - `us-north1`: `https://api.tokenfactory.us-north1.nebius.com/v1/`
  - `uk-south1`: `https://api.tokenfactory.uk-south1.nebius.com/v1/`
  - `eu-west1`: `https://api.tokenfactory.eu-west1.nebius.com/v1/`
  - `eu-west2`: `https://api.tokenfactory.eu-west2.nebius.com/v1/`
  - `me-west1`: `https://api.tokenfactory.me-west1.nebius.com/v1/`
- **Authentication Header:** `Authorization: Bearer <token>`
- **Canonical Environment Variable:** `NEBIUS_API_KEY`
- **Supported Client Libraries:**
  - Standard OpenAI Python SDK: `OpenAI(base_url="https://api.tokenfactory.nebius.com/v1/", api_key=os.environ.get("NEBIUS_API_KEY"))`
  - Standard OpenAI Node.js / TypeScript SDK: `new OpenAI({ baseURL: "https://api.tokenfactory.nebius.com/v1/", apiKey: process.env.NEBIUS_API_KEY })`
  - Standard cURL / HTTP REST.
  - Sandboxes: `Contree SDK` (Python), `Contree CLI`, and `Contree MCP`.
- **Live Metadata Discovery Probe:**
  - Executed `GET https://api.tokenfactory.nebius.com/v1/models` without token.
  - Result: HTTP `401 Unauthorized`: `{"detail":"Couldn't authenticate. Reason: token is not present"}`.
  - Deterministic Fact: Proves endpoint is active, reachable, and enforces Bearer authentication.

---

## 4. Live Model-Catalog Findings (Sanitized & Exhaustive)

> [!IMPORTANT]
> **Model Availability Scope Boundary:**
> - **PUBLIC PLATFORM CATALOG AVAILABILITY:** The models below are globally listed and verified active (or error) in Nebius Token Factory's public machine-readable catalog (`/api/public/models_info`).
> - **ACCOUNT-ACCESSIBLE MODEL AVAILABILITY:** `NOT VERIFIED` for this specific account because Token Factory account activation is blocked before authenticated access by the mandatory payment card requirement.
> - In accordance with P-01.01 boundary rules, Builder and Verifier model routing is NOT frozen here (deferred to P-05 / P-07).

Discovered directly from official live machine-readable endpoint `https://tokenfactory.nebius.com/api/public/models_info` and Markdown catalog `https://tokenfactory.nebius.com/model-catalog.md`:

| Exact Model ID | Provider / Vendor | Status | Quantization | Context Window | Regions | Input Price ($/1M) | Output Price ($/1M) |
|---|---|:---:|---|:---:|:---:|:---:|:---:|
| `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` | `nvidia` | `active` | FP8 | 262K (262,144) | `eu-north1` | \$0.06 | \$0.24 |
| `nvidia/nemotron-3-super-120b-a12b` | `nvidia` | `active` | FP4 | 256K (262,144) | `us-central1` | \$0.30 | \$0.90 |
| `nvidia/Nemotron-3_5-Lightning` | `nvidia` | `active` | BF16 | 1,024K (1,048,576) | `eu-north1` | \$0.06 | \$0.24 |
| `nvidia/Nemotron-3-Ultra-550b-a55b` | `nvidia` | `error` | FP4 | 1,024K (1,048,576) | `us-central1` | \$1.00 | \$3.00 |
| `meta-llama/Llama-3.3-70B-Instruct` | `meta` | `active` | FP8 | 128K (131,072) | `eu-north1` | \$0.13 | \$0.40 |
| `openai/gpt-oss-120b` | `openai` | `active` | FP4 | 131K (131,072) | `eu-north1` | \$0.15 | \$0.60 |
| `deepseek-ai/DeepSeek-V4-Flash-0731` | `deepseek` | `active` | FP8 | 1,024K (1,024,000) | `us-central1` | \$0.14 | \$0.28 |
| `deepseek-ai/DeepSeek-V4-Pro` | `deepseek` | `active` | FP8 | 1,000K (1,048,576) | `uk-south1` | \$1.75 | \$3.50 |
| `Qwen/Qwen3-30B-A3B-Instruct-2507` | `Qwen` | `active` | FP8 | 262K (262,144) | `eu-north1` | \$0.10 | \$0.30 |
| `Qwen/Qwen3-235B-A22B-Instruct-2507` | `Qwen` | `active` | FP8 | 262K (262,144) | `eu-north1` | \$0.20 | \$0.60 |

---

## 5. NVIDIA Model Eligibility & Open-Source Status

The hackathon requires building with NVIDIA open-source models served on Nebius Token Factory or Nebius AI Cloud.

### Candidate Evaluation:

1. **`nvidia/Nemotron-3_5-Lightning` (Prime Candidate)**
   - **Catalog Identity:** `nvidia/Nemotron-3_5-Lightning`
   - **Provider:** NVIDIA
   - **Parameters:** 30B MoE (3B active per token)
   - **Context Window:** 1,048,576 tokens (1M context)
   - **Quantization:** BF16
   - **Pricing:** \$0.06 input / \$0.24 output per million tokens (extremely cost-effective for hackathon credit conservation)
   - **HuggingFace Repository:** `https://huggingface.co/nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16`
   - **License:** `OpenMDW v1.1` (`https://openmdw.ai/license/1-1/`) — permissive open model distribution and weights license allowing commercial, research, and modification.
   - **Status in Catalog:** `active`
   - **Hackathon Track Compliance:** FULLY COMPLIANT.

2. **`nvidia/nemotron-3-super-120b-a12b` (High-Capacity Reasoning Candidate)**
   - **Catalog Identity:** `nvidia/nemotron-3-super-120b-a12b`
   - **Provider:** NVIDIA
   - **Parameters:** 120B hybrid MoE
   - **Context Window:** 256K tokens
   - **Quantization:** FP4
   - **Pricing:** \$0.30 input / \$0.90 output per million tokens
   - **HuggingFace Repository:** `https://huggingface.co/nvidia/Nemotron-3-Super-120B`
   - **License:** `nvidia-open-model-license` (`https://www.nvidia.com/en-us/agreements/enterprise-software/nvidia-open-model-license/`) — first-party NVIDIA open model license permitting commercial use, fine-tuning, and inference.
   - **Status in Catalog:** `active`
   - **Hackathon Track Compliance:** FULLY COMPLIANT.

3. **`nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` (Fast Small-Footprint Candidate)**
   - **Catalog Identity:** `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`
   - **Provider:** NVIDIA
   - **Parameters:** 30B MoE (3B active per token)
   - **Context Window:** 262K tokens
   - **Quantization:** FP8
   - **Pricing:** \$0.06 input / \$0.24 output per million tokens
   - **HuggingFace Repository:** `https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-FP8`
   - **License:** `nvidia-open-model-license`
   - **Status in Catalog:** `active`
   - **Hackathon Track Compliance:** FULLY COMPLIANT.

4. **`nvidia/Nemotron-3-Ultra-550b-a55b` (DEGRADED / NOT ELIGIBLE FOR ACTIVE SELECTION)**
   - **Catalog Identity:** `nvidia/Nemotron-3-Ultra-550b-a55b`
   - **Provider:** NVIDIA
   - **Status in Catalog:** `error` (Flagged as non-operational in official JSON metadata).
   - **Recommendation:** DO NOT USE in initial phases.

*Note: In accordance with P-01.01 boundary rules, Builder and Verifier routing is NOT frozen here. Routing decisions belong in P-05 / P-07.*

---

## 6. Billing, PAYG & Zero-Cost Hard-Stop Investigation

### Official Documentation Truth (`billing-new.md` & Builder Terms):
1. **Mandatory Billing Setup:** Official onboarding documentation (`https://docs.tokenfactory.nebius.com/other-capabilities/billing-new.md`) states: *"When you sign up for Nebius Token Factory, you are prompted to create a billing account during onboarding. Billing setup is mandatory—you cannot complete onboarding without it. Setting up a billing account requires a bank card."*
2. **Automatic Debit Mechanism:** *"When using a bank card, Nebius Token Factory debits your balance in real time. Your card is automatically charged in either of the following cases: At the start of the month, if your balance is negative; When the configured billing threshold is reached. The charge amount is calculated to bring your balance back to zero."*
3. **Builder Terms & PAYG Continuation:** Section C.3 of `https://nebius.com/builders-terms-and-conditions` states: *"Upon expiration or full consumption of promotional credits, Customer may continue using the Services on a pay-as-you-go basis in accordance with the Service Rates published at https://nebius.com/prices..."*
4. **Auto-Pause vs Hard Stop:** Section H.4 states: *"Nebius reserves the right to auto-pause or suspend Customer's account if monthly resource consumption exceeds the credit allocation by more than 30%."* This is an anti-abuse reserve right, NOT a user-guaranteed hard spending stop.

### Account State Matrix:

| Dimension | Discovery Status | Evidence Provenance | Notes |
|---|:---:|:---:|---|
| Devpost Hackathon Registration | `CONFIRMED` | `LIVE_ACCOUNT` | Registered on Devpost (`zyganali@gmail.com`) on 2026-09-12 |
| Builder Program membership | `ACCEPTED` | `LIVE_ACCOUNT` | Welcome email received on 2026-09-19 |
| Token Factory promotional entitlement | `CONFIRMED_BY_PROGRAM` | `LIVE_ACCOUNT` | Confirmed by Builder Program welcome email ($25 Token Factory credit) |
| Promo delivery/status | `UNRESOLVED / SUPPORT_CAN_CHECK` | `LIVE_ACCOUNT / FIRST_PARTY_SUPPORT` | Promo code email not yet delivered; Nebius Support offered to check via internal account IDs |
| Promo redemption | `BLOCKED_BY_MANDATORY_BILLING_SETUP` | `LIVE_ACCOUNT / FIRST_PARTY_SUPPORT` | Nebius Support confirmed: billing setup and payment card are mandatory before promotional credits can be redeemed |
| Token Factory activation | `BLOCKED_BY_ZERO_COST_LAW` | `LOCAL_EXECUTION` | Cannot be activated only with Builder Program credit without payment card; card entry forbidden by Zero-Cost Law |
| Payment method | `NONE` | `LIVE_ACCOUNT` | Zero payment cards entered; onboarding stopped at card prompt |
| PAYG State | `NOT_ENTERED / NOT_ACTIVATED` | `LIVE_ACCOUNT` | Billing onboarding deliberately stopped before card entry; PAYG never activated |
| Platform hard spending cap | `NOT_VERIFIED / NO GUARANTEED $0 PLATFORM HARD STOP ESTABLISHED` | `OFFICIAL_DOC` / `LIVE_ACCOUNT / FIRST_PARTY_SUPPORT` | Official docs state negative balance triggers auto-debit; no user-configurable $0 hard stop exists |
| Operator policy | `NO_CARD / ZERO_PERSONAL_SPEND` | `LOCAL_EXECUTION` | Basebreak Zero-Cost Law strictly forbids adding payment card or enabling PAYG without explicit operator decision |
| Local `NEBIUS_API_KEY` present | `NO` | `LOCAL_EXECUTION` | Key generation blocked by unactivated account |
| Tavily Account Onboarding | `COMPLETED` | `LIVE_ACCOUNT` | Onboarded via Free/Researcher path; no bank card required; usage-based payment visibly disabled |
| Tavily Account Credits | `CONFIRMED` | `LIVE_ACCOUNT` | 1,000 monthly plan credits + 3,125 promotional credits visible in dashboard |
| Tavily API Key | `GENERATED_SAFELY` | `LIVE_ACCOUNT` | Key exists in dashboard; not copied to chat/repo; 0 calls executed; integration deferred to P-16 |

### Deterministic Zero-Cost Gate Decision:
**Verdict: `BLOCKED_ZERO_COST / OPERATOR_DECISION_REQUIRED`**
- **Reasoning:** 
  1. **First-Party Support Finding:** On 2026-09-19, Nebius Support directly confirmed to the operator:
     > *"Token Factory onboarding requires billing details and a payment card before promotional credits can be redeemed. Promotional credits can be applied after billing setup, but Token Factory cannot currently be activated only with the Builder Program credit and without a payment method."*
  2. **Cardless Activation Unavailable:** Token Factory cannot currently be activated using only Builder Program promotional credits without attaching a payment method. Promo-code arrival alone is NOT sufficient to unblock activation.
  3. **Zero-Cost Law Violation Risk:** Under Basebreak ZERO-COST LAW, entering a bank or credit card that is subject to automated pay-as-you-go debit upon negative balance is strictly forbidden without explicit operator approval.
  4. **Platform Spending Cap Reality:** The platform does NOT provide a verified, guaranteed $0 hard spending cap to prevent post-promotional charges. (Operator policy of refusing to enter a card must not be confused with a platform-enforced hard spending cap).
  5. **Task P-01.02 Status:** Task P-01.02 (first live inference call) remains strictly `PENDING / UNSTARTED` and CANNOT execute under current Zero-Cost Law unless a verified cardless activation path is provided or the operator explicitly changes the payment-card policy after informed review of billing risk.


---

## 7. Sandboxes Section & Access Gate Visibility

- **Official Product Name:** Token Factory Sandboxes
- **Official Documentation URL:** `https://docs.tokenfactory.nebius.com/sandboxes/overview`
- **Official API Endpoint:** `https://api.tokenfactory.nebius.com/sandboxes/v1/`
- **Supported Access Interfaces:**
  - `Contree SDK` (Python SDK for programmatic sandbox management)
  - `Contree CLI` (Terminal client for command execution)
  - `Contree MCP` (Model Context Protocol server for AI assistant integration)
  - REST API (`https://docs.tokenfactory.nebius.com/api-reference/sandboxes`)
- **Documented Platform Limits:**
  - Max 50 simultaneous running operations.
  - 180-day checkpoint image retention.
- **Account Visibility & Access Gate:**
  - Web console exposes `sandboxesURL` in frontend bundle.
  - Actual account-level enablement requires operator inspection in web console.
- **Strict Boundary Enforced:** NO sandboxes were created, NO commands were executed, NO branch/checkpoint/rollback tests were run during P-01.01. (Testing reserved for P-01.03).

---

## 8. Material Findings Ledger (Fact / Provenance / Source / Result)

| FACT | PROVENANCE | SOURCE | OBSERVED_AT | RESULT |
|---|---|---|---|---|
| Token Factory Base URL is `https://api.tokenfactory.nebius.com/v1/` | `OFFICIAL_DOC` | `https://docs.tokenfactory.nebius.com/quickstart` | 2026-09-12 | VERIFIED |
| Canonical API key environment variable is `NEBIUS_API_KEY` | `OFFICIAL_DOC` | `https://docs.tokenfactory.nebius.com/quickstart` | 2026-09-12 | VERIFIED |
| Authentication requires `Authorization: Bearer <token>` | `OFFICIAL_DOC` / `LIVE_NEBIUS` | `GET /v1/models` without token returned HTTP 401 | 2026-09-12 | VERIFIED |
| Model list API endpoint is `GET /v1/models` | `OFFICIAL_DOC` | `https://docs.tokenfactory.nebius.com/api-reference/models/list-models` | 2026-09-12 | VERIFIED |
| Sandboxes API base URL is `https://api.tokenfactory.nebius.com/sandboxes/v1/` | `OFFICIAL_DOC` | `https://tokenfactory.nebius.com/` frontend bundle | 2026-09-12 | VERIFIED |
| Public machine-readable catalog is at `/api/public/models_info` | `OFFICIAL_DOC` / `LIVE_NEBIUS` | `https://tokenfactory.nebius.com/api/public/models_info` | 2026-09-12 | VERIFIED |
| `nvidia/Nemotron-3_5-Lightning` is active with 1M context | `OFFICIAL_DOC` / `LIVE_NEBIUS` | `https://tokenfactory.nebius.com/api/public/models_info` | 2026-09-12 | VERIFIED |
| `nvidia/nemotron-3-super-120b-a12b` is active with 256K context | `OFFICIAL_DOC` / `LIVE_NEBIUS` | `https://tokenfactory.nebius.com/api/public/models_info` | 2026-09-12 | VERIFIED |
| `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` is active with 262K context | `OFFICIAL_DOC` / `LIVE_NEBIUS` | `https://tokenfactory.nebius.com/api/public/models_info` | 2026-09-12 | VERIFIED |
| `nvidia/Nemotron-3-Ultra-550b-a55b` is reported with `status: "error"` | `LIVE_NEBIUS` | `https://tokenfactory.nebius.com/api/public/models_info` | 2026-09-12 | VERIFIED (DEGRADED) |
| Onboarding billing policy states bank card is mandatory | `OFFICIAL_DOC` | `https://docs.tokenfactory.nebius.com/other-capabilities/billing-new.md` | 2026-09-12 | VERIFIED |
| Bank card accounts are automatically debited when balance is negative | `OFFICIAL_DOC` | `https://docs.tokenfactory.nebius.com/other-capabilities/billing-new.md` | 2026-09-12 | VERIFIED |
| Builder Program promotional credits expire 90 days from issuance | `OFFICIAL_DOC` | `https://nebius.com/builders-terms-and-conditions` | 2026-09-12 | VERIFIED |
| Local environment currently contains no `NEBIUS_API_KEY` | `LOCAL_EXECUTION` | Windows PowerShell process/user/machine env query | 2026-09-12 | VERIFIED |
| Tavily account onboarded via Free/Researcher path without payment card; 1,000 monthly + 3,125 promotional credits active; usage-based payment disabled | `LIVE_ACCOUNT` | Tavily Web Dashboard | 2026-09-19 | VERIFIED |
| Nebius Support confirms Token Factory requires payment card before promo credit redemption; cardless activation not supported | `LIVE_ACCOUNT / FIRST_PARTY_SUPPORT` | Direct first-party Nebius Support communication | 2026-09-19 | VERIFIED (BLOCKER) |
| Token Factory account-level model access | `LIVE_ACCOUNT` | Token Factory web console | 2026-09-19 | NOT VERIFIED (Account unactivated) |

---

## 9. Operator Guidance (Screen-by-Screen in Turkish)

### STOP KURALI (Sıfır Maliyet Güvenlik Sınırı)

> [!CAUTION]
> **TOKEN FACTORY ONBOARDING DURDURULDU — KART BİLGİSİ GİRMEYİN:**
> Nebius Destek Ekibi (First-Party Support) 2026-09-19 tarihinde operatöre resmi olarak şu teyidi vermiştir:
> *"Token Factory onboarding requires billing details and a payment card before promotional credits can be redeemed. Promotional credits can be applied after billing setup, but Token Factory cannot currently be activated only with the Builder Program credit and without a payment method."*
>
> **Mevcut Basebreak SIFIR-MALİYET KANUNU (ZERO-COST LAW) gereğince:**
> - Token Factory paneline kesinlikle kredi kartı veya banka kartı **EKLENMEYECEKTİR**.
> - Token Factory onboarding akışı zorunlu kart adımında **DURDURULMUŞTUR**.
> - Promosyon kodu gelse dahi kart girmeden kullanılamayacağı birinci elden doğrulanmıştır; bu nedenle promosyon e-postasının gelmesi tek başına Token Factory'yi aktif etmeye yetmez.
> - Operatör tarafından ileride bilinçli bir faturalandırma riski değerlendirmesiyle açık bir politika değişikliği (`OPERATOR_DECISION_REQUIRED`) yapılmadığı sürece bu aşamada hiçbir kart girilmeyecek, faturalandırma adımı tamamlanmayacak, `NEBIUS_API_KEY` oluşturulmayacak/depolanmayacak ve çıkarım (inference) yapılmayacaktır.

### Operatörün Güncel Eylem Rehberi:
1. **Token Factory Paneli:** Zorunlu kart ekranında durun. Kart bilgisi girmeyin.
2. **Hesap Tanımlayıcılarının Gizliliği:** Destek ekibinin promosyon durumunu incelemek için talep ettiği hesap numaralarını (Organization ID / aitenant ID, User ID / tenantuseraccount ID) **kesinlikle kamuya açık git reposuna veya belgelere işlemeyin**, sohbette güvenle tutun.
3. **Tavily Durumu:** Tavily hesabı Free/Researcher yolu ile kart gerektirmeden güvenle tamamlanmıştır (1.000 aylık + 3.125 promosyon kredisi, kullanım bazlı faturalandırma kapalı). Bu hesap güvenlidir; ancak P-16 aşamasına kadar API çağrısı yapılmayacaktır.

---

## 10. NOT_RUN Declarations & Explicit Boundaries

In strict compliance with the Basebreak constitution and P-01.01 task contract:
- `P-01.02 inference`: **NOT_RUN** (Zero inference calls, token generation, or chat completion requests executed).
- `Sandbox creation / execution`: **NOT_RUN** (No sandbox container spun up; no command executed).
- `Repository materialization in sandbox`: **NOT_RUN**.
- `Tavily API execution`: **NOT_RUN** (Account safely onboarded and verified with 1,000 monthly + 3,125 promotional credits, usage-based billing disabled, zero cards; API key generated but NOT called and NOT committed; runtime integration deferred to P-16 — External Grounding & Tavily).
- `Future-phase runtime implementation`: **NOT_RUN** (Zero adapter or causal engine code implemented).
- `Donor implementation code`: **0 bytes reused** (Clean-room documentation only).

---

## 11. P-01.02 Safety Gate

P-01.02 (first live inference call) remains `PENDING / UNSTARTED` and CANNOT execute under current Zero-Cost Law unless one of the following becomes true:

A. Nebius provides a verified cardless Token Factory activation path; OR
B. The operator explicitly changes the payment-card policy after informed review of billing risk (`OPERATOR_DECISION_REQUIRED`).

Promo-code arrival alone is NOT sufficient.
No inference, API-key creation, or sandbox use is authorized now.
