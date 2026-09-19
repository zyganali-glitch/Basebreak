# P-01.01 — Platform Discovery Report

- **Execution Date/Time:** 2026-09-12 14:30 UTC
- **Starting Canonical SHA:** `08ebfc94a75954d79ee2613f935584de2a9d5900`
- **Active Micro-Task:** `P-01.01 — Discover current Nebius account/runtime/API/model reality from official docs and live account`
- **Execution Status:** EXECUTOR_COMPLETED (Candidate documentation committed; awaiting independent QA)
- **Zero-Cost Gate Verdict:** `OPERATOR_EXCEPTION_APPROVED / PENDING_PROMO_REDEMPTION` (Operator approved `TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION`; card attached; billing currently Suspended; $25 promo email pending; P-01.02 blocked until promo redemption)

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
> - **ACCOUNT-ACCESSIBLE MODEL AVAILABILITY:** `ACCOUNT_AUTHENTICATED_INFERENCE_ACCESS = NOT_VERIFIED` because the Builder Program promotional credit has not yet been redeemed, billing currently displays Suspended, and no authenticated Token Factory inference call has been executed.
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

### Official Documentation & First-Party Support Truth:
1. **Mandatory Billing Setup:** Official onboarding documentation (`https://docs.tokenfactory.nebius.com/other-capabilities/billing-new.md`) states: *"When you sign up for Nebius Token Factory, you are prompted to create a billing account during onboarding. Billing setup is mandatory—you cannot complete onboarding without it. Setting up a billing account requires a bank card."*
2. **Automatic Debit Mechanism:** *"When using a bank card, Nebius Token Factory debits your balance in real time. Your card is automatically charged in either of the following cases: At the start of the month, if your balance is negative; When the configured billing threshold is reached. The charge amount is calculated to bring your balance back to zero."*
3. **Builder Terms & PAYG Continuation:** Section C.3 of `https://nebius.com/builders-terms-and-conditions` states: *"Upon expiration or full consumption of promotional credits, Customer may continue using the Services on a pay-as-you-go basis in accordance with the Service Rates published at https://nebius.com/prices..."*
4. **Auto-Pause vs Hard Stop:** Section H.4 states: *"Nebius reserves the right to auto-pause or suspend Customer's account if monthly resource consumption exceeds the credit allocation by more than 30%."* This is an anti-abuse reserve right, NOT a user-guaranteed hard spending stop.
5. **First-Party Nebius Support Findings (2026-09-19):**
   - Nebius Support confirmed: Token Factory onboarding requires billing details and a payment card before promotional credits can be redeemed.
   - Token Factory cannot currently be activated using only Builder Program promotional credit without a payment method.
   - There is NO guaranteed automatic stop when promotional credit is exhausted.
   - A hard spending limit of $0 after promo exhaustion is NOT currently available.
   - Automatic card charging cannot currently be disabled for an active card-backed Token Factory account.
   - If the payment card is removed, the Token Factory account is suspended; access does not continue using only remaining promo balance.
   - If usage continues after promotional credit exhaustion, the attached card may be charged.
   - Builder Program Token Factory credit is delivered through a promo-code/top-up flow.
   - The separate promo-code email must be redeemed via Token Factory billing approximately through `Top up → With promo code`.
   - The operator has NOT yet received this separate promo-code email.
   - Nebius Support advised waiting for the separate promo-code email. (The operator is also contacting Devpost/hackathon organizers for assistance).

### Account State Matrix:

| Dimension | Discovery Status | Evidence Provenance | Notes |
|---|:---:|:---:|---|
| Devpost Hackathon Registration | `CONFIRMED` | `LIVE_ACCOUNT` | Registered on Devpost (`zyganali@gmail.com`) on 2026-09-12 |
| Builder Program membership | `ACCEPTED` | `LIVE_ACCOUNT` | Welcome email received on 2026-09-19 |
| Token Factory promotional entitlement | `CONFIRMED_BY_PROGRAM` | `LIVE_ACCOUNT` | Confirmed by Builder Program welcome email ($25 Token Factory credit) |
| Promo delivery/status | `PENDING_EMAIL` | `LIVE_ACCOUNT / FIRST_PARTY_SUPPORT` | Separate promo code email en route; not yet delivered; Nebius Support advised waiting |
| Promo redemption flow | `CONFIRMED_BY_SUPPORT` | `LIVE_ACCOUNT / FIRST_PARTY_SUPPORT` | Redeemed via `Top up → With promo code` in Token Factory billing |
| Payment card attached | `ATTACHED_BOUNDED` | `LIVE_ACCOUNT` | Card attached under operator-approved `TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION` |
| Token Factory console access | `ACCESSIBLE` | `LIVE_ACCOUNT` | Web console accessible; Sandboxes navigation is visible |
| Token Factory billing status | `SUSPENDED` | `LIVE_ACCOUNT` | Current dashboard billing status displays `Suspended` |
| Trial credit | `$1.00 / 29 days` | `LIVE_ACCOUNT` | Visible in dashboard; MUST NOT be consumed as substitute for Builder Program promo |
| Account balance | `$0.00` | `LIVE_ACCOUNT` | Current balance displays $0.00; no personal funds loaded |
| Transaction history | `EMPTY` | `LIVE_ACCOUNT` | Zero transactions recorded |
| Builder Program $25 credit visible | `NO` | `LIVE_ACCOUNT` | Not yet redeemed / awaiting separate promo email |
| Target personal spend | `$0.00` | `LOCAL_EXECUTION` | Preserved under Zero-Cost Law |
| Operational safety reserve | `$5.00 FLOOR` | `LOCAL_EXECUTION` | `TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00` enforced by operator policy (not platform cap) |
| Platform hard spending cap | `NONE` | `LIVE_ACCOUNT / FIRST_PARTY_SUPPORT` | Support confirmed no $0 post-promo hard stop exists; auto-charging cannot be disabled |
| Mandatory balance checks | `REQUIRED` | `LOCAL_EXECUTION` | Pre/post balance inspection required for all future cost-consuming LIVE_NEBIUS batches |
| Tavily Account Onboarding | `COMPLETED` | `LIVE_ACCOUNT` | Onboarded via Free/Researcher path; no bank card required; usage-based payment visibly disabled |
| Tavily Account Credits | `CONFIRMED` | `LIVE_ACCOUNT` | 1,000 monthly plan credits + 3,125 promotional credits visible in dashboard |
| Tavily API Key | `GENERATED_SAFELY` | `LIVE_ACCOUNT` | Key exists in dashboard; not copied to chat/repo; 0 calls executed; integration deferred to P-16 |
| Local `NEBIUS_API_KEY` | `NOT_USED` | `LOCAL_EXECUTION` | 0 inference/sandbox calls executed |

### Deterministic Zero-Cost Gate Decision:
**Verdict: `OPERATOR_EXCEPTION_APPROVED / PENDING_PROMO_REDEMPTION`**
- **Reasoning:** 
  1. **Operator-Approved Bounded Billing Exception:** The operator explicitly approved `TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION`. Attaching a payment card was permitted solely because Token Factory requires it to activate and redeem Builder Program promotional credits.
  2. **Personal Spend Invariant:** Target personal spend remains strictly **$0.00**. No manual top-up with personal money, paid subscriptions, reserved capacity, or paid fallback after promo exhaustion is authorized.
  3. **Manual Safety Reserve (`$5.00` Floor):** Because Nebius provides no platform-enforced hard stop upon promo exhaustion, Basebreak enforces an operator policy floor (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`). Once promotional balance is `<= $5.00`, all Token Factory workloads must halt immediately.
  4. **Promo Activation Gate:** The current `$1.00` trial credit MUST NOT be intentionally consumed. P-01.02 remains strictly `PENDING / EXTERNAL_PREREQUISITE_WAIT` until the separate Builder Program promo code email arrives, is redeemed, and the promotional balance is visibly verified in the billing UI to be `> $5.00`.



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
| Payment card attached under operator-approved `TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION` | `LIVE_ACCOUNT` | Token Factory billing web console | 2026-09-19 | VERIFIED (BOUNDED_EXCEPTION) |
| Token Factory billing status currently Suspended; trial credit $1.00 / 29 days; account balance $0.00 | `LIVE_ACCOUNT` | Token Factory billing web console | 2026-09-19 | VERIFIED |
| Nebius Support confirms Token Factory requires payment card before promo credit redemption; cardless activation not supported | `LIVE_ACCOUNT / FIRST_PARTY_SUPPORT` | Direct first-party Nebius Support communication | 2026-09-19 | VERIFIED (BLOCKER_RESOLVED_BY_EXCEPTION) |
| Nebius Support confirms promo delivered separately and redeemed via Top up → With promo code | `LIVE_ACCOUNT / FIRST_PARTY_SUPPORT` | Direct first-party Nebius Support communication | 2026-09-19 | VERIFIED |
| Nebius Support confirms no $0 platform hard stop and automatic card charging cannot be disabled | `LIVE_ACCOUNT / FIRST_PARTY_SUPPORT` | Direct first-party Nebius Support communication | 2026-09-19 | VERIFIED |
| Operational safety reserve floor ($5.00) enforced by operator policy (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`) | `LOCAL_EXECUTION` | Basebreak governance / operator policy | 2026-09-19 | VERIFIED |
| Token Factory account-level authenticated inference access | `LIVE_ACCOUNT` | Token Factory web console | 2026-09-19 | NOT VERIFIED (Awaiting promo redemption) |

---

## 9. Operator Guidance (Screen-by-Screen in Turkish)

### Bounded Billing İstisnası ve Güvenlik Sınırları

> [!IMPORTANT]
> **TOKEN FACTORY KARTLI KURULUM TAMAMLANDI — PROMOSYON KODU BEKLENİYOR:**
> Operatörün açık onayıyla (`TOKEN_FACTORY_BOUNDED_BILLING_EXCEPTION`), yalnızca Nebius Builder Programı promosyon kredisini ($25) aktive edebilmek amacıyla fatura kurulumu tamamlanmış ve ödeme kartı tanımlanmıştır.
>
> **Güncel Durum ve Güvenlik Kuralları:**
> 1. **Mevcut Panel Durumu:** Fatura durumu `Suspended` olarak görünmektedir. Ekranda `$1.00 / 29 days` deneme kredisi ve `$0.00` bakiye mevcuttur.
> 2. **Deneme Kredisi Yasağı:** `$1.00` deneme kredisi KESİNLİKLE kullanılmayacaktır. Builder Programı promosyonunun yerini tutmaz.
> 3. **Hedef Kişisel Harcama:** Kesinlikle **$0.00**'dır. Kişisel parayla bakiye yükleme, ücretli abonelik veya promo bitimi sonrası karttan çekim yasaktır.
> 4. **$5.00 Güvenlik Rezervi:** Promosyon kredisi yüklendiğinde, kalan bakiye `<= $5.00` olduğu anda tüm Token Factory işlemleri derhal DURDURULACAKTIR (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`). Bu son $5 rezerv kasten tüketilmeyecektir.
> 5. **Zorunlu Bakiye Kontrolleri:** Gelecekteki her maliyetli `LIVE_NEBIUS` işlem grubundan **ÖNCE** ve **SONRA** bakiye ekrandan kontrol edilecektir.

### Operatörün Güncel Eylem Rehberi:

#### Adım 1: Ayrı Promosyon Kodu E-postasını Bekleyin
- Nebius Destek Ekibi, $25'lık Token Factory promosyon kodunun ayrı bir e-posta ile gönderileceğini ve beklenmesi gerektiğini teyit etmiştir.
- Bu e-posta gelene kadar Token Factory üzerinde hiçbir API çağrısı veya test çalıştırılmayacaktır.

#### Adım 2: Promosyon Kodu Geldiğinde Yükleme Adımı
1. `https://tokenfactory.nebius.com/` adresine giriş yapın.
2. Sağ üstten bakiye alanına veya sol menüden **Billing** sekmesine tıklayın.
3. **Top up** (Bakiye Yükle) butonuna tıklayın.
4. Menüden **"With promo code"** (Promosyon kodu ile) seçeneğini seçin.
5. Gelen e-postadaki promosyon kodunu yapıştırıp onaylayın.
6. Bakiyenin en az `$25.00` olduğunu teyit edin.
7. **DİKKAT:** Kredi kartınızdan çekim yapacak herhangi bir miktar onaylamayın!

#### Adım 3: Tavily ve Gizlilik Durumu
- Tavily hesabı Free/Researcher yolu ile kart gerektirmeden güvenle açılmıştır (1.000 aylık + 3.125 promosyon kredisi). P-16'ya kadar çağrı yapılmayacaktır.
- Destek ekibiyle iletişimde kullanılan hesap numaralarını (Organization ID, User ID vb.) veya kart numaralarını **kesinlikle kamuya açık belgelere veya depoya yazmayın**.

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

P-01.02 (first live inference call) remains `PENDING / EXTERNAL_PREREQUISITE_WAIT` and CANNOT execute until all of the following conditions are met:

1. **Promo Code Email Arrival:** The separate Builder Program promo-code email arrives from Nebius.
2. **Supported Redemption:** The operator redeems the promo code in Token Factory billing (`Top up → With promo code`).
3. **Billing UI Verification:** Token Factory billing UI visibly displays the promotional credit, and exact balance and expiry date are recorded as `LIVE_ACCOUNT` evidence.
4. **Safety Reserve Check:** Remaining promotional balance is confirmed to be `> $5.00` (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`).
5. **Trial Credit Prohibition:** The current `$1.00` trial credit is NOT intentionally consumed as a substitute for Builder Program credit.
6. **Billing Operational:** Billing status is operational enough to make the bounded call.
7. **Independent QA Authorization:** Independent QA reviews and awards PASS to P-01.01.

No inference, API-key execution, or sandbox creation is authorized prior to these conditions.
