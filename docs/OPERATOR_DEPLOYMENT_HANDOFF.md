# Operatör Kurulum ve Canlı Dağıtım Rehberi (P-27.03)

> **DİKKAT — SIFIR MALİYET YASASI (Zero-Cost Law):**
> Bu rehberdeki adımlar **kesinlikle hiçbir kredi kartı, banka kartı, ödeme yöntemi veya ücretli abonelik gerektirmez**.
> Hedeflenen kişisel harcama: **0.00 TL / $0.00**.
> Kamuya açık canlı dağıtım adımı, operatörün açık onayı verilene kadar **OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN** statüsündedir.

---

## 1. Dağıtım Seçenekleri ve Platform Gerçeği

Yarışma kurallarına ve Devpost SSS (FAQ) duyurularına göre:
- Hakemlerin 15 Aralık 2026 tarihine kadar projeyi **ücretsiz ve giriş yapmadan (signed-out)** inceleyebilmesi gerekmektedir.
- Bütün uygulamanın Nebius üzerinde barındırılması zorunlu değildir; uygun bir NVIDIA açık kaynak modeliyle Nebius Token Factory çağrısı yapılması yeterlidir.

### Hugging Face Docker Uyarısı:
Hugging Face, yeni Docker Space oluşturulması için artık **kredi kartı veya PRO abonelik** talep etmektedir. Sıfır Maliyet Yasası gereğince **kesinlikle kart bilginizi girmeyiniz**. Bu nedenle birincil ve garantili sıfır maliyetli hakem erişim yolu **GitHub Pages** olarak seçilmiştir.

---

## 2. Birincil Dağıtım Yolu: GitHub Pages (Garantili $0.00, Kartsız)

GitHub Pages, `zyganali-glitch/Basebreak` deposuna doğrudan entegredir ve 15 Aralık 2026 hakemlik penceresi boyunca kesintisiz, 7/24 ücretsiz çalışır.

### Adım 1: Doğrulanmış Hakem Arayüzü Çıktısını Üretme
Terminalinizde şu komutları çalıştırarak yayınlanacak hakem arayüzünü ve makbuzu oluşturun:

```bash
# 1. Hakem arayüzü HTML çıktısını docs/index.html olarak dışa aktarın:
python -m basebreak.cli.main ui <run_id> --output docs/index.html

# 2. Doğrulanmış kriptografik makbuz JSON çıktısını docs/receipt.json olarak dışa aktarın:
python -m basebreak.cli.main receipt <run_id> --format json --output docs/receipt.json
```

### Adım 2: Değişiklikleri GitHub'a Gönderme
```bash
git add docs/index.html docs/receipt.json
git commit -m "docs(judge): publish verification dashboard for judge inspection"
git push origin main
```

### Adım 3: GitHub Pages'i Aktif Etme (Ekran Ekran Türkçe Kılavuz)
1. Tarayıcınızda GitHub deponuza gidin:  
   👉 **URL:** `https://github.com/zyganali-glitch/Basebreak`
2. Üst yatay menü çubuğunda **Settings** (Ayarlar) sekmesine tıklayın.
3. Sol menüde **Code and automation** başlığı altındaki **Pages** seçeneğine tıklayın.
4. **Build and deployment** başlığı altında:
   - **Source (Kaynak):** `Deploy from a branch` seçili olmalıdır.
   - **Branch:** Açılır menüden `main` dalını seçin.
   - Klasör olarak `/ (root)` yerine **`/docs`** klasörünü seçin.
   - Sağdaki **Save** butonuna tıklayın.
5. Birkaç dakika sonra sayfanın üstünde yeşil bir kutucuk belirecektir:  
   `Your site is live at https://zyganali-glitch.github.io/Basebreak/`
6. Bu bağlantı hakemlerin erişimine açılacak resmi, ücretsiz, kesintisiz doğrulama adresinizdir.

---

## 3. İsteğe Bağlı Konteyner Dağıtımı: Hugging Face Spaces Docker (Yalnızca Mevcut Üyeliği Olanlar İçin)

Eğer halihazırda kart doğrulaması yapılmış veya PRO statüsünde bir Hugging Face hesabınız varsa, Docker Space seçeneğini kullanabilirsiniz:

### Önemli Ayarlar:
- **Port:** Basebreak konteyneri 8080 portunu dinler. Space ayarlarında `README.md` başlığında `app_port: 8080` tanımlanmalıdır:
  ```yaml
  ---
  title: Basebreak Verification Runtime
  emoji: 🛡️
  colorFrom: blue
  colorTo: indigo
  sdk: docker
  app_port: 8080
  pinned: false
  ---
  ```
- **Gizli Değişkenler (Settings -> Variables and secrets):**
  - `BASEBREAK_BEARER_TOKEN` (veya `BASEBREAK_API_TOKEN`): Operatör yetkilendirme parolası.
  - `BASEBREAK_RUNS_DIR`: `/data/runs`
- **Kart Uyarısı:** Eğer Hugging Face sizden kart veya ödeme isterse, DERHAL DURUN ve kart bilgisi girmeyin; 2. Bölümdeki GitHub Pages yolunu kullanın.

---

## 4. Ortam Değişkenleri Tablosu

| Değişken Adı | Açıklama | Örnek Değer | Zorunlu mu? |
| :--- | :--- | :--- | :--- |
| `BASEBREAK_HOST` | API sunucusunun dinleyeceği adres | `0.0.0.0` veya `127.0.0.1` | Hayır (Varsayılan: 127.0.0.1) |
| `BASEBREAK_PORT` / `PORT` | API sunucusu HTTP portu | `8080` | Hayır (Varsayılan: 8080) |
| `BASEBREAK_BEARER_TOKEN` | Operatör yönetici belirteci | `sec-token-12345` | Evet (Çalıştırma/Yayınlama için) |
| `BASEBREAK_API_TOKEN` | Alternatif operatör belirteci takma adı | `sec-token-12345` | Hayır (`BEARER_TOKEN` alternatifi) |
| `BASEBREAK_RUNS_DIR` | Kalıcı koşu ve makbuz dizini | `.basebreak/runs` veya `/data/runs` | Hayır (Varsayılan: `.basebreak/runs`) |
| `BASEBREAK_BUILD_COMMIT_SHA` | Konteyner içine enjekte edilen kaynak SHA | `d8aa8c491501...` | Evet (Konteyner derlemesinde) |

---

## 5. Acil Durum / UI Değişikliği Durumunda
- Servis sağlayıcı web arayüzünü güncellerse daima **Free / Ücretsiz** ibaresini arayın.
- Kredi kartı veya fatura bilgisi soran hiçbir adımı onaylamayın.
- Beklenmedik bir durumda işlemi durdurup `docs/COMPETITION_FEEDBACK_LOG.md` dosyasına not düşün.
