# Operatör Kurulum ve Canlı Dağıtım Rehberi (P-27.03)

> **DİKKAT — SIFIR MALİYET YASASI (Zero-Cost Law):**  
> Bu rehberdeki adımlar **kesinlikle hiçbir kredi kartı, banka kartı, ödeme yöntemi veya ücretli abonelik gerektirmez**.  
> Hedeflenen kişisel harcama: **0.00 TL / $0.00**.  
> Kamuya açık canlı dağıtım adımı, operatörün açık onayı verilene kadar **OPERATOR_DECISION_REQUIRED / NOT_RUN** statüsündedir.

---

## 1. Dağıtım Hedefleri ve Platform Gerçeği

Yarışma kurallarına, Devpost SSS (FAQ) duyurularına ve operatörün ürün gereksinimlerine göre:
- **Tek Bir Canlı Adres:** Hakemlerin doğrudan tarayıcıdan girip inceleyebileceği tek bir web adresi gerekmektedir.
- **Canlı Çalışma İsteği:** Hakemlerin statik bir ekran görüntüsü yerine, gerçek Nebius/NVIDIA çalışma kanıtlarını ve gerektiğinde canlı doğrulama isteğini tetikleyebilmesi hedeflenmektedir.
- **Kartsız ve $0.00:** Hiçbir ücretli plan açılmayacak, kredi kartı girilmeyecektir.

### Seçenek Özeti:
1. **Render Free (Aday Birincil Canlı Site):** Kredi kartsız, ücretsiz Python Web Service barındırma (`https://basebreak.onrender.com`). Tek URL üzerinden hem hakem arayüzünü hem de canlı Python API motorunu çalıştırır.
2. **GitHub Pages (Kalıcı Statik Yedek / Arşiv):** Depoya doğrudan entegre, sıfır maliyetli statik HTML/JSON yedeği.

---

## 2. Aday Birincil Dağıtım Yolu: Render Free (Kartsız, Tam Yığın Python)

Render, GitHub hesabınızla doğrudan bağlanabilen ve **kredi kartı istemeyen** ücretsiz bir Python barındırma katmanı sunar.

### Adım 1: Render Hesabı Açma (Kartsız)
1. Tarayıcınızda şu adrese gidin:  
   👉 **URL:** `https://render.com`
2. Sağ üstteki **GET STARTED** butonuna tıklayın.
3. **GitHub** ile giriş yap seçeneğini seçin (`zyganali-glitch` hesabınızla yetkilendirin).
4. **ÖNEMLİ:** Kredi kartı ekleme ekranı çıkarsa **SKIP (ATLA)** deyin veya boş bırakın. Hobby / Free planında kart zorunlu değildir.

### Adım 2: Web Service Oluşturma
1. Render kontrol panelinde **New +** butonuna tıklayın ve **Web Service** seçin.
2. **Build and deploy from a Git repository** seçeneğini seçin.
3. Depolarınız arasından `zyganali-glitch/Basebreak` deposunu bulun ve **Connect** butonuna tıklayın.
4. Açılan yapılandırma formunu şu şekilde doldurun:
   - **Name:** `basebreak` (veya `basebreak-verifier`)
   - **Region:** `Frankfurt (EU Central)` (veya en yakın bölge)
   - **Branch:** `main`
   - **Root Directory:** *(Boş bırakın)*
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install .`
   - **Start Command:** `basebreak serve --host 0.0.0.0 --port $PORT`
   - **Instance Type:** **Free ($0/month)** seçeneğini işaretleyin. *(Kesinlikle ücretli Starter/Standard seçmeyin!)*

### Adım 3: Ortam Değişkenlerini (Environment Variables) Ekleme
Aynı sayfanın altındaki **Advanced** veya **Environment Variables** bölümüne şu değişkenleri ekleyin:
1. `BASEBREAK_BEARER_TOKEN`: Operatör yönetici şifreniz (örn. rastgele güçlü bir parola).
2. `BASEBREAK_RUNS_DIR`: `.basebreak/runs`
3. *(Canlı Nebius onayı verildiğinde)* `NEBIUS_API_KEY`: Nebius API anahtarınız.
4. *(Canlı Nebius onayı verildiğinde)* `NEBIUS_PROJECT_ID`: Nebius proje kimliğiniz.

### Adım 4: Dağıtımı Başlatma
1. Sayfanın en altındaki **Create Web Service** butonuna tıklayın.
2. Birkaç dakika içinde uygulamanız derlenecek ve `https://basebreak.onrender.com` benzeri canlı adresiniz aktif olacaktır.

### Render Free Hakkında Önemli Bilgiler:
- **15 Dakika Boşta Kalma (Sleep):** 15 dakika istek gelmezse sunucu uyku moduna geçer. Sonraki ilk istekte 30-60 saniyelik bir uyanma süresi (cold start) olur.
- **Geçici Dosya Sistemi (Ephemeral Disk):** Sunucu her uyandığında geçici diski sıfırlanır. Ancak Basebreak, depoya önceden işlenmiş (`baked-in`) kanıt makbuzlarını otomatik yüklediği için hakemler uyandıktan hemen sonra doğrulanmış sonuçları inceleyebilir.
- **Kişisel Harcama:** Kart tanımlı olmadığı için hiçbir fatura çıkarılamaz ($0.00 kesin güvence).

---

## 3. Statik Yedek / Afet Kurtarma Yolu: GitHub Pages (Kesintisiz $0.00)

Eğer Render sunucusunun uykuya geçmesini istemiyorsanız veya salt-okunur kalıcı bir kanıt arşivi sunmak isterseniz GitHub Pages hazır durumdadır:

### Adım 1: Hakem Arayüzü Çıktısını Üretme
```bash
# 1. Hakem arayüzünü docs/index.html olarak dışa aktarın:
python -m basebreak.cli.main ui <run_id> --output docs/index.html

# 2. Kriptografik makbuzu docs/receipt.json olarak dışa aktarın:
python -m basebreak.cli.main receipt <run_id> --format json --output docs/receipt.json
```

### Adım 2: Değişiklikleri Gönderme
```bash
git add docs/index.html docs/receipt.json
git commit -m "docs(judge): publish static verification dashboard"
git push origin main
```

### Adım 3: GitHub Pages'i Açma
1. GitHub deponuzda **Settings -> Pages** menüsüne gidin.
2. **Build and deployment -> Source** için `Deploy from a branch` seçin.
3. **Branch** olarak `main`, klasör olarak `/docs` seçip **Save** butonuna tıklayın.
4. Canlı adres: `https://zyganali-glitch.github.io/Basebreak/`

---

## 4. Ortam Değişkenleri Tablosu

| Değişken Adı | Açıklama | Örnek Değer | Zorunlu mu? |
| :--- | :--- | :--- | :--- |
| `BASEBREAK_HOST` | API sunucusunun dinleyeceği adres | `0.0.0.0` | Hayır (Varsayılan: 127.0.0.1) |
| `PORT` / `BASEBREAK_PORT` | HTTP bağlantı noktası | `$PORT` veya `8080` | Render ortamında Render belirler |
| `BASEBREAK_BEARER_TOKEN` | Operatör yönetici belirteci | `sec-token-xyz` | Evet (Çalıştırma/Yayınlama için) |
| `BASEBREAK_API_TOKEN` | Alternatif operatör belirteci takma adı | `sec-token-xyz` | Hayır (`BEARER_TOKEN` alternatifi) |
| `BASEBREAK_RUNS_DIR` | Koşu ve makbuz dizini | `.basebreak/runs` | Hayır (Varsayılan: `.basebreak/runs`) |
| `NEBIUS_API_KEY` | Nebius Token Factory anahtarı | `nb-sec-...` | Sadece canlı çağrı yetkilendirildiğinde |

---

## 5. Güvenlik ve Uyarılar
- Render veya başka bir platform kredi kartı isterse **İŞLEMİ DERHAL DURDURUN**.
- Asla API anahtarlarınızı sohbete veya git deposuna yapıştırmayın; sadece platformun gizli ortam değişkenleri alanına girin.
- Beklenmedik bir durumda işlemi durdurup `docs/COMPETITION_FEEDBACK_LOG.md` dosyasına not düşün.
