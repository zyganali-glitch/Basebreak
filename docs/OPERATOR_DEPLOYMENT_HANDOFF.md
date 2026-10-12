# Operatör Kurulum ve Canlı Dağıtım Rehberi (P-27.03)

> **DİKKAT — SIFIR MALİYET YASASI (Zero-Cost Law):**
> Bu rehberdeki adımlar **kesinlikle hiçbir kredi kartı, ödeme yöntemi veya ücretli abonelik gerektirmez**.
> Hedeflenen kişisel harcama: **0.00 TL / $0.00**.
> Kamuya açık canlı dağıtım adımı, operatörün açık onayı verilene kadar **OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN** statüsündedir.

---

## 1. Genel Bakış ve Dağıtım Hedefi

Hakemlerin ve yarışma jürisinin (15 Aralık 2026 tarihine kadar) Basebreak doğrulama arayüzüne **ücretsiz, giriş yapmadan (signed-out)** erişebilmesi için en güvenli ve maliyetsiz platform **Hugging Face Spaces (Docker)** veya **Render Free Web Service** platformudur.

- **Ücret:** $0.00 (Tamamen Ücretsiz).
- **Kredi Kartı Riski:** Yok (Kredi kartı bilgisi girilmez).
- **Rolü:** Web arayüzü ve salt okunur hakem incelemesi sunar. Canlı Nebius Token Factory çağrıları ise yalnızca yetkili operatör tarafından tetiklenir.

---

## 2. Hugging Face Spaces ile Canlı Dağıtım (Adım Adım Türkçe Rehber)

### Adım 1: Hugging Face Hesabına Giriş
1. Tarayıcınızda şu resmi adrese gidin:  
   👉 **URL:** `https://huggingface.co/login`
2. Mevcut ücretsiz hesabınızla giriş yapın (Hesabınız yoksa sağ üstteki **Sign Up** butonuna tıklayarak ücretsiz oluşturun).
3. **Kart Riski:** Hugging Face ücretsiz üyelik için hiçbir kart istemez. Kart bilgisi soran hiçbir ekrana kart girmeyiniz.

### Adım 2: Yeni Bir "Space" Oluşturma
1. Sağ üst köşedeki profil resminize tıklayın ve açılan menüden **"New Space"** seçeneğini seçin.  
   (Doğrudan adres: `https://huggingface.co/new-space`)
2. Karşınıza gelen formdaki alanları şu şekilde doldurun:
   - **Space name (Alan Adı):** `basebreak-verifier` (veya `basebreak-runtime`)
   - **License (Lisans):** Açılır menüden `apache-2.0` seçin.
   - **Select the Space SDK (SDK Seçimi):** Burası çok önemlidir! **`Docker`** seçeneğine tıklayın.
   - **Choose a Docker template:** **`Blank`** seçeneğini işaretleyin.
   - **Space Hardware (Donanım):** **`CPU basic • 2 vCPU • 16GB RAM • Free`** seçili olmalıdır. Asla ücretli GPU donanımı seçmeyin!
   - **Space visibility (Görünürlük):** **`Public`** seçeneğini işaretleyin (Jüri üyelerinin görebilmesi için).
3. Sayfanın en altındaki **"Create Space"** butonuna tıklayın.

### Adım 3: Depoyu Bağlama ve Dağıtımı Başlatma
1. Space oluştuktan sonra Space sayfanız açılacaktır.
2. Üst menüde **"Files and versions"** sekmesine tıklayın.
3. Projedeki şu dosyalar Space deposuna aktarılır (Git veya web arayüzü ile):
   - `Dockerfile`
   - `.dockerignore`
   - `pyproject.toml`
   - `README.md`
   - `LICENSE`
   - `src/` klasörünün tamamı
4. Alternatif olarak GitHub senkronizasyonu: Space ayarlarından (Settings -> GitHub Repository) GitHub deponuzu bağlayabilirsiniz.
5. Hugging Face Docker imajını otomatik olarak derleyecek (`Building...`) ve birkaç dakika içinde **`Running`** durumuna geçecektir.

### Adım 4: Güvenlik Değişkenlerini (Secrets) Tanımlama (İsteğe Bağlı)
1. Space sayfanızda **"Settings"** sekmesine tıklayın.
2. Aşağı kaydırarak **"Variables and secrets"** bölümünü bulun.
3. **"New secret"** butonuna tıklayın:
   - **Name:** `BASEBREAK_BEARER_TOKEN`
   - **Value:** Yalnızca sizin bildiğiniz rastgele güçlü bir parola/token (Örn: `bb-sec-xxxxxxxxxxxx`).
   - Bu token, dışarıdan kimsenin sizin adınıza yetkisiz çalıştırma yapamamasını garanti eder.
   - Hakemler token olmadan **salt okunur** olarak tüm yayınlanmış kanıtları inceleyebilir.
4. **ASLA** bu token'ı veya Nebius anahtarınızı sohbet penceresine yapıştırmayınız veya koda eklemeyiniz.

### Adım 5: Canlı Dağıtımı Doğrulama
1. Space adresinize tarayıcıdan gidin: `https://huggingface.co/spaces/<kullanici-adiniz>/basebreak-verifier`
2. Sayfada **"BASEBREAK VERIFICATION RUNTIME"** başlığını ve *“If the patch matters, the base must break.”* tezini görüyorsanız dağıtım başarıyla tamamlanmıştır.
3. Sağlık kontrolü için adresin sonuna `/health` ekleyin (Örn: `.../health`).
   - Yanıtta `"status": "healthy"` ve commit SHA değeri görünmelidir.

---

## 3. Acil Durum / UI Değişikliği Durumunda
- Hugging Face web sitesi tasarımını değiştirirse: Her zaman üst kısımdaki arama çubuğundan veya menüden **"Spaces" -> "Create New"** yolunu izleyin.
- Kart veya faturalandırma uyarısı görürseniz: İşlemi durdurun ve **Free** ibaresi olmayan hiçbir seçeneğe tıklamayın.
