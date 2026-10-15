# Operatör Kurulum ve Canlı Dağıtım Rehberi (P-27.03)

> **DİKKAT — SIFIR MALİYET YASASI (Zero-Cost Law):**  
> Bu rehberdeki adımlar **kesinlikle hiçbir kredi kartı, banka kartı, ödeme yöntemi veya ücretli abonelik gerektirmez**.  
> Hedeflenen kişisel harcama: **0.00 TL / $0.00**.  
> Kamuya açık canlı dağıtım adımı, operatörün açık onayı verilene kadar **OPERATOR_DECISION_REQUIRED / NOT_RUN** statüsündedir.

---

## 1. Dağıtım Hedefleri ve Platform Gerçeği

Yarışma kurallarına, Devpost SSS (FAQ) duyurularına ve operatörün ürün gereksinimlerine göre:
- **Tek Bir Canlı Adres:** Hakemlerin doğrudan tarayıcıdan girip inceleyebileceği tek bir web adresi gerekmektedir (`https://basebreak.<subdomain>.workers.dev`).
- **Sıfır Soğuk Başlangıç (0ms Cold Start):** Uyku moduna geçen container sunucularının aksine Cloudflare Workers uç ağda anında yanıt verir.
- **Kartsız ve $0.00:** Cloudflare Workers Free katmanı günde 100.000 istek sunar ve kredi kartı gerektirmez. Kota bittiğinde otomatik durur, fatura çıkarmaz.
- **Tekil SQLite Yetki Defteri (Durable Object):** Kredi tükenmesini engellemek için tek kullanımlık hakem erişim kodları, global 1 eşzamanlı çalışma sınırı ve 5.00$ promosyon güvenlik rezervi doğrudan SQLite defterinde denetlenir.

---

## 2. Birincil Dağıtım Yolu: Cloudflare Workers Free (Kartsız, Edge Uç Noktası)

### Adım 1: Cloudflare Hesabı (Kartsız)
1. Tarayıcınızda şu adrese gidin:  
   👉 **URL:** `https://dash.cloudflare.com/sign-up`
2. E-posta ve şifrenizi girerek ücretsiz hesap oluşturun.
3. **ÖNEMLİ:** Plan seçimi ekranında **Free ($0)** planını seçin. Kredi kartı ekleme ekranı çıkarsa **SKIP (ATLA)** butonuna tıklayın.

### Adım 2: Wrangler CLI ile Giriş Yapma
Bilgisayarınızda terminal açın ve şu komutu çalıştırın:
```bash
cd cloudflare
npx wrangler login
```
1. Tarayıcınızda Cloudflare onay penceresi açılacaktır.
2. **Allow** (İzin Ver) butonuna tıklayarak terminali yetkilendirin.

### Adım 3: Ortam Değişkenleri ve Gizli Anahtarları Tanımlama
Uygulamanın yönetici anahtarını güvenle tanımlamak için:
```bash
# 1. Operatör yönetici anahtarını gizli değişken (secret) olarak kaydedin:
npx wrangler secret put BASEBREAK_ADMIN_KEY
# (İstendiğinde güçlü bir şifre girin, örn: sec-basebreak-admin-2026)

# 2. (Canlı Nebius onayı verildiğinde eklenecek gizli anahtarlar):
# npx wrangler secret put NEBIUS_API_KEY
# npx wrangler secret put NEBIUS_PROJECT_ID
```

### Adım 4: Canlı Dağıtımı Başlatma (OPERATOR_APPROVAL_REQUIRED)
Operatör dağıtıma onay verdiğinde:
```bash
npx wrangler deploy
```
Bu komut sonucunda Cloudflare size şu formatta tek bir canlı adres verecektir:  
👉 `https://basebreak.<alt-alan-adiniz>.workers.dev`

---

## 3. Hakem Erişim Kodu (Single-Use Grant) Üretme Prosedürü

Hakemlerin canlı on-demand doğrulama çalıştırabilmesi için operatörün tek kullanımlık bir erişim kodu üretmesi gerekir:

```bash
# Canlı adresiniz üzerinden tek kullanımlık hakem kodu üretin:
curl -X POST "https://basebreak.<alt-alan-adiniz>.workers.dev/admin/grants" \
  -H "Authorization: Bearer <BASEBREAK_ADMIN_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "ttl_seconds": 86400,
    "client_info": "devpost_judge_1"
  }'
```

**Dönen Yanıt:**
```json
{
  "grant_id": "grant_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "grant_token": "bb_grant_xxxxxxxxxxxxxxxx",
  "expires_at": 1792100000000,
  "max_uses": 1
}
```

### Hakeme Teslim Yöntemi:
Hakeme özel bağlantı verilir:  
👉 `https://basebreak.<alt-alan-adiniz>.workers.dev/judge?grant=bb_grant_xxxxxxxxxxxxxxxx`

- Bu kod **yalnızca 1 kez** kullanılabilir.
- 100 kez art arda tıklansa bile defter yalnızca ilk isteği kabul eder; diğer 99 istek reddedilir.
- Hakem kodu olmadan veya kod tüketildikten sonra bile hakemler sayfadaki doğrulanmış kanıtları sınırsız ve ücretsiz olarak okuyabilir.

---

## 4. Statik Yedek / Afet Kurtarma Katmanı: GitHub Pages (Kesintisiz $0.00)

Eğer Cloudflare hizmetine alternatif statik bir kanıt arşivi sunmak isterseniz:
1. `basebreak ui <run_id> --output docs/index.html` ile HTML dışa aktarın.
2. `basebreak receipt <run_id> --format json --output docs/receipt.json` ile makbuzu dışa aktarın.
3. GitHub Settings -> Pages menüsünden `/docs` klasörünü yayınlayın.
4. Adres: `https://zyganali-glitch.github.io/Basebreak/` (Salt-okunur arşiv).

---

## 5. Değişkenler ve Güvenlik Sınırları Tablosu

| Değişken Adı | Açıklama | Varsayılan Değer | Güvenlik Kuralı |
| :--- | :--- | :--- | :--- |
| `LIVE_ENABLED` | Canlı Nebius çağrılarına izin ver | `false` | Operatör canlı kredi onayı verene kadar kesinlikle `false` kalır. |
| `BASEBREAK_ADMIN_KEY` | Operatör yönetici anahtarı | *(Gizli)* | Asla depoya işlenmez, `wrangler secret` ile saklanır. |
| `GLOBAL_INVOCATION_CAP` | Canlı çalışma üst limiti | `5` | Toplam canlı çalıştırma sayısı bu rakama ulaşınca yeni çalıştırma durur. |
| `TOKEN_FACTORY_PROMO_STOP_THRESHOLD` | Promosyon güvenlik rezervi | `5.00` | Kalan bakiye $\le 5.00\$$ ise canlı çalıştırma fail-closed durdurulur. |
| `ALLOWLISTED_TARGET` | İzin verilen demo deposu | `tests/fixtures/reset_vault` | Keyfi veya maliyetli başka depoların çalıştırılması reddedilir. |
