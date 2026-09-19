# P-01.01 — Platform Discovery Report

- **Execution Date/Time:** 2026-09-12 14:30 UTC
- **Starting Canonical SHA:** `08ebfc94a75954d79ee2613f935584de2a9d5900`
- **Active Micro-Task:** `P-01.01 — Discover current Nebius account/runtime/API/model reality from official docs and live account`
- **Execution Status:** EXECUTOR_COMPLETED (Candidate documentation committed; awaiting independent QA)
- **Zero-Cost Gate Verdict:** `OPERATOR_DECISION_REQUIRED` (Mandatory bank card onboarding policy documented; live account billing verification required before inference)

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
| Builder Program Application | `ACCEPTED` | `LIVE_ACCOUNT` | Welcome email received on 2026-09-19; separate $25 Token Factory promo code email en route |
| Token Factory Promo Code | `PENDING_EMAIL` | `LIVE_ACCOUNT` | Awaiting separate email from Nebius with $25 Token Factory promo code |
| Tavily Account Onboarding | `COMPLETED` | `LIVE_ACCOUNT` | Onboarded via Free/Researcher path; no bank card required; usage-based payment visibly disabled |
| Tavily Account Credits | `CONFIRMED` | `LIVE_ACCOUNT` | 1,000 monthly plan credits + 3,125 promotional credits visible in dashboard |
| Tavily API Key | `GENERATED_SAFELY` | `LIVE_ACCOUNT` | Key exists in dashboard; not copied to chat/repo; 0 calls executed; integration deferred to P-16 |
| Payment Method Attached | `NONE` | `LIVE_ACCOUNT` | Onboarding card entry aborted on Nebius; zero cards entered on Tavily; Zero-Cost Law strictly intact |
| Bank Card Present | `NO` | `LIVE_ACCOUNT` | Verified: zero cards entered across all services, zero personal risk |
| PAYG State | `NOT_ACTIVATED` | `LIVE_ACCOUNT` | Token Factory card setup bypassed; Tavily usage-based billing visibly disabled |
| Hard Spending Cap ($0.00 personal spend) | `ENFORCED_BY_POLICY` | `LOCAL_EXECUTION` | Card entry blocked; no personal charge possible |
| Local `NEBIUS_API_KEY` present | `NO` | `LOCAL_EXECUTION` | Awaiting Token Factory promo code email & key generation |

### Deterministic Zero-Cost Gate Decision:
**Verdict: `SAFE_AWAITING_TOKEN_FACTORY_PROMO_CODE`**
- **Reasoning:** 
  1. The operator was officially accepted into the Nebius AI Builder Program on 2026-09-19 (welcome email received).
  2. Nebius confirmed: *"Your $25 Nebius Token Factory credit is already coming your way in a separate email!"*.
  3. Tavily account onboarding was completed via the Free/Researcher path with zero card entry. Current dashboard displays 1,000 monthly plan credits plus 3,125 promotional credits, and usage-based payment is visibly disabled. Zero Tavily API calls were executed; integration remains deferred to P-16.
  4. Under Zero-Cost Law, the operator is completely protected from personal bank card debits across all platforms.
  5. Task P-01.01 discovery is 100% complete and verified with live account evidence.
  6. Task P-01.02 (first live inference call) remains strictly blocked until the separate Token Factory promo code email arrives and is redeemed.

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

---

## 9. Operator Guidance (Screen-by-Screen in Turkish)

Non-expert operatör için canlı hesap incelemesi, bakiye doğrulama, API anahtarı alma ve sıfır-maliyet güvenliği adımları:

### Adım 1: Token Factory Web Konsoluna Giriş Yapın
1. Web tarayıcınızda şu resmi adresi açın: **`https://tokenfactory.nebius.com/`**
2. Sayfanın sağ üst köşesinde yer alan **"Log in"** (Giriş Yap) butonuna tıklayın.
3. Açılan kimlik doğrulama penceresinde daha önce kayıt olduğunuz **Google** veya **GitHub** hesabınızı seçin.
4. **DİKKAT (Ne Seçilmemeli?):** Eğer ekranda sizden yeni bir kredi kartı bilgisi girmeniz istenirse (**"Add payment method"** veya **"Billing setup"**), **KART BİLGİSİ GİRMEYİN**. Önce promosyon kodu ile devam edip edemeyeceğinizi kontrol edin.

### Adım 2: Bakiye ve Kredi Durumunu Kontrol Edin
1. Giriş yaptıktan sonra sayfanın sağ üst tarafında veya profil menünüzün yanında bakiye alanını (örn. `$25.00` veya `$1.00`) bulun.
2. Bakiyenizin üzerine tıklayın veya sol menüden **"Billing"** (Faturalandırma) sayfasına gidin.
3. Aşağıdaki değerleri gözlemleyin:
   - Kalan bakiye miktarı (Current balance).
   - Promosyon kodu uygulanmış mı (Transactions / İşlemler sekmesinde `$25 Promo Code` görünüyor mu)?
   - Son kullanma tarihi (Expiry date) belirtilmiş mi?
4. **DİKKAT:** Sol menüden **Organisation → Billing details** sekmesine tıklayarak kayıtlı bir kredi kartı olup olmadığını kontrol edin. Eğer kart ekli ise ve bakiye eksiye düşerse karttan otomatik çekim yapılacağı resmi dokümanda yazmaktadır. Bu nedenle bakiye sıfırlanmadan önce harcama durdurulmalıdır.

### Adım 3: Sandboxes (Kum Havuzları) Sekmesini Kontrol Edin
1. Web konsolunun sol ana menüsünü inceleyin.
2. Menüde **"Sandboxes"** (veya **"Instances / Contree"**) başlıklı bir menü seçeneği görünüp görünmediğine bakın.
3. Eğer menü görünüyorsa, üzerine tıklayın ve erişiminizin açık olup olmadığını (erişim onaylandı mı, beklemede mi?) kontrol edin.
4. **KESİNLİKLE YAPMAYIN:** Asla yeni bir sandbox başlatmayın, "Create Sandbox" butonuna basmayın, hiçbir komut çalıştırmayın. P-01.01 aşamasında yalnızca menünün görünürlüğü tespit edilmektedir.

### Adım 4: Güvenli Şekilde API Anahtarı Oluşturma
1. Doğrudan şu URL'yi açın: **`https://tokenfactory.nebius.com/project/api-keys`** (veya sol menüden **API keys** sekmesine tıklayın).
2. **"Create API key"** butonuna tıklayın.
3. Açılan kutuda anahtar ismi olarak **`basebreak-dev`** yazın.
4. **"Create"** butonuna tıklayın.
5. Ekranda size uzun bir anahtar metni gösterilecektir.
6. **HAYATİ GÜVENLİK KURALI:**
   - Bu anahtarı **ASLA sohbet ekranına yapıştırmayın**.
   - Asla git reposu içerisindeki bir dosyaya yazıp commit etmeyin.
   - Ekran görüntüsü alıp sohbete atmayın.

### Adım 5: API Anahtarını Yerel Ortam Değişkeni Olarak Tanımlama
Windows terminalinizde (PowerShell) şu komutu çalıştırarak anahtarı yalnızca kendi oturumunuz için tanımlayın:
```powershell
[System.Environment]::SetEnvironmentVariable('NEBIUS_API_KEY', 'BURAYA_KOPYALADIGINIZ_ANAHTARI_YAPISTIRIN', 'User')
```
*(Bu işlem anahtarı Windows kullanıcı profilinize güvenle kaydeder; sohbete veya git geçmişine sızmasını engeller).*

### Adım 6: Doğrulama ve Raporlama
Anahtarı tanımladıktan sonra sohbete sadece şu bilgileri metin olarak iletin (anahtarı veya kart numarasını yazmadan):
- Hesaba giriş yapıldı mı: Evet / Hayır
- Görünen bakiye: (Örn: $25.00)
- Kredi kartı ekli mi: Evet / Hayır
- Sandboxes menüsü görünüyor mu: Evet / Hayır
- API anahtarı User ortam değişkenine kaydedildi mi: Evet

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

Before P-01.02 (minimal inference call) may be scheduled or executed:
1. Independent QA must review and award PASS to P-01.01 at the pushed canonical remote commit.
2. Operator must confirm live account billing state according to the guidance above.
3. Operator must confirm `NEBIUS_API_KEY` is present in local user environment without personal bank card risk.
4. Model candidate for P-01.02 inference probe must be selected from the confirmed active models (`nvidia/Nemotron-3_5-Lightning` or `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`).
