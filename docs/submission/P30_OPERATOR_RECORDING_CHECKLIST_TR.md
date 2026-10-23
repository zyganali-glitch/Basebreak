# P-30 Operatör Video Kayıt ve Montaj Rehberi (Türkçe)

Bu rehber, hackathon demo videosunun operatör tarafından **hiç İngilizce konuşmaya gerek kalmadan**, tamamen Windows'un yerleşik araçları veya ücretsiz montaj programları (Clipchamp / CapCut) ile en yüksek kalitede nasıl kaydedileceğini ve birleştirileceğini adım adım anlatır.

> [!NOTE]
> **Uygulama Durumu**: Tüm senaryo, metinler, süreler ve talimatlar HAZIRLANMIŞTIR (PREPARED). Fiziksel video kaydı, seslendirme oluşturma, YouTube'a yükleme ve Devpost gönderimi insan operatörün bizzat yapacağı adımlardır (NOT_RUN).

---

## Genel Hedef ve Süre Sınırı

- **Maksimum Süre**: Kesinlikle **3 dakikanın altında** (< 180 saniye).
- **Hedef Süre**: **2 dakika 40 saniye (160 saniye)**.
- **Çözünürlük**: 1080p Full HD (`1920x1080`).
- **Dil**: Video içi seslendirme İngilizce AI sesi ile yapılacak; operatörün mikrofona konuşması gerekmez. Altyazılar `basebreak_demo_subtitles.srt` dosyasından otomatik yüklenecektir.

---

## 1. Hazırlık: Ekran Kaydı Programı Seçimi

Aşağıdaki iki ücretsiz yoldan birini seçin:
1. **Windows 11 Ekran Kaydedici (Önerilen En Basit Yol)**:
   - Klavyede **`Win + Shift + R`** tuşlarına basın.
   - Ekranın tamamını (1920x1080) seçin.
   - Mikrofon simgesinin kapalı olduğundan emin olun (arka plan sesi kaydetmesin).
2. **OBS Studio (Alternatif Profesyonel Yol)**:
   - OBS'i açın, "Ekran Yakalama" kaynağı ekleyin ve 1080p 60fps kaydı başlatın.

---

## 2. Adım Adım Ekran Kaydı Alma (Toplam 6 Sahne)

Her sahneyi ayrı birer video parçası olarak kaydedebilirsiniz:

### Sahne 1: Problem — Yeşil CI Yalanı (0:00 – 0:25 / 25 saniye)
- Tarayıcıda geleneksel bir CI çıktısı veya VS Code ekranı açın.
- Örnek bir yeşil "ALL TESTS PASSING (ILLUSTRATIVE GREEN CI)" rozetini gösterin.
- "Yapay zeka hatayı gerçekten düzeltti mi, yoksa test zaten geçiyor muydu?" sorusunu vurgulayın.
- 25 saniye kaydedin.

### Sahne 2: Çözüm — Üç Dünyalı Nedensel Motor (0:25 – 0:50 / 25 saniye)
- `docs/submission/P30_ARCHITECTURE_VISUAL.md` dosyasındaki mimari şemayı veya `https://basebreak.zyganali.workers.dev` ana sayfasını açın.
- Üç dünyayı gösterin:
  - `WORLD 1 (BASE): FAIL` (Hata yeniden üretildi)
  - `WORLD 2 (CANDIDATE): PASS` (Hata giderildi)
  - `WORLD 3 (COUNTERFACTUAL): FAIL` (Yamanın zorunlu olduğu kanıtlandı)
- 25 saniye kaydedin.

### Sahne 3: Canlı Çalıştırma — Nebius Nemotron & Sandbox'lar (0:50 – 1:20 / 30 saniye)
- PowerShell terminalini açın. Arka plan siyah/koyu tema olsun.
- Proje ana dizininde şu yerel üç dünyalı alt-süreç test tekrarı komutunu çalıştırın:
  ```powershell
  python -m pytest tests/demo/test_p23_killer_demo.py -k test_reset_vault_triplet -v
  ```
- Çıktıda `BASE exit 1`, `CANDIDATE exit 0 (1 passed in 0.04s)`, `COUNTERFACTUAL exit 1` satırlarını gösterin.
- Gerçek sağlayıcı çalıştırmasının (`run_3ba7d1fd`, Nebius mikroVM sandbox'ları) telemetri kayıtlarını (`docs/evidence/p29_03_fresh_live_run_evidence_packet/VERIFICATION_AUDIT.md`) gösterin.
- 30 saniye kaydedin.

### Sahne 4: Kriptografik Kanıt & Jüri Paneli (1:20 – 1:50 / 30 saniye)
- Tarayıcınızı açın (Gizli Sekme / Incognito önerilir, oturum açmadan).
- Şu adrese gidin:
  `https://basebreak.zyganali.workers.dev/judge/run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f`
- Sırasıyla yapın:
  1. En üstteki **`VERIFIED`**, **`LIVE_NEBIUS`** ve **`AUTHENTIC SHA-256`** rozetlerini fareyle gösterin (8 saniye).
  2. Aşağıya **Three-World Comparison Grid** tablosuna kaydırın. Base=FAIL, Candidate=PASS, Counterfactual=FAIL satırlarını gösterin (10 saniye).
  3. Daha aşağıya **Cryptographic Verification Receipt** kartına kaydırın. SHA-256 makbuz özetini ve doğrulayıcı imzalı RSA-2048 kanıt özetini gösterin (12 saniye).
- 30 saniye kaydedin.

### Sahne 5: Tavily Harici Doğrulama (1:50 – 2:15 / 25 saniye)
- `docs/evidence/P16_05_TAVILY_GROUNDING_INTEGRATION.md` dosyasındaki mimariyi veya terminalde Tavily testlerini / ön kontrol aracını gösterin:
  ```powershell
  python -m basebreak.adapters.tavily.demo --check-preflight
  python -m pytest tests/grounding/test_p16_closure.py -q
  ```
- "Tavily dondurulmuş sözleşmeye danışmanlık sağlar; Sandbox kodun bunu sağlayıp sağlamadığını test eder; Güvenlik duvarı web iddialarının kod sonucunu ezmesine asla izin vermez" mantığını gösterin.
- 25 saniye kaydedin.

### Sahne 6: Kapanış & GitHub Deposu (2:15 – 2:40 / 25 saniye)
- Tarayıcıda açık kaynak GitHub deposunu açın:
  `https://github.com/zyganali-glitch/Basebreak`
- README başlığını, Apache-2.0 lisans rozetini gösterin.
- Son slaytta sloganı gösterin: *"If the patch matters, the base must break."*
- 25 saniye kaydedin.

---

## 3. Seslendirme (Voiceover) Oluşturma — Sıfır Maliyet & İngilizce Konuşmadan

Windows 11'de yerleşik **Microsoft Clipchamp** veya ücretsiz **CapCut** kullanın:

### Microsoft Clipchamp ile Seslendirme:
1. Başlat menüsünden **Clipchamp**'ı açın (Windows 11'de yüklüdür, ücretsizdir).
2. "Yeni video oluştur" deyin.
3. Sol menüden **"Kayıt ve oluştur" (Record & create)** $\rightarrow$ **"Metin okuma" (Text to speech)** seçeneğine tıklayın.
4. Ayarlar:
   - **Dil**: `English (United States)`
   - **Ses**: `Andrew (Neural)` veya `Christopher (Neural)`
   - **Konuşma hızı**: Normal (`1.0x`)
5. `docs/submission/P30_NARRATION_SCRIPT.md` dosyasındaki 6 sahnelik metni sahne sahne kopyalayıp yapıştırın ve "Medyaya kaydet" butonuna basın.
6. Otomatik olarak kusursuz bir İngilizce seslendirme kanalı oluşacaktır.

---

## 4. Video Montajı ve Altyazı Ekleme

1. Kaydettiğiniz 6 video klibini Clipchamp veya CapCut zaman çizgisine (timeline) sırayla dizin:
   - Klip 1: 0:00 – 0:25
   - Klip 2: 0:25 – 0:50
   - Klip 3: 0:50 – 1:20
   - Klip 4: 1:20 – 1:50
   - Klip 5: 1:50 – 2:15
   - Klip 6: 2:15 – 2:40
2. Seslendirme kanalını videonun altına yerleştirin.
3. Altyazı ekleyin:
   - `docs/submission/basebreak_demo_subtitles.srt` dosyasını içe aktarın (veya CapCut'ta "Auto captions / Import SRT" seçin).
4. Toplam video süresini kontrol edin: **2 dakika 40 saniye civarında ve kesinlikle 3 dakikanın altında** olmalıdır.
5. Sağ üstten **Dışa Aktar (Export) $\rightarrow$ 1080p** seçeneğiyle MP4 olarak kaydedin.

---

## 5. YouTube Yükleme Ayarları

1. `https://studio.youtube.com` adresine gidin.
2. Videoyu yükleyin.
3. **Başlık**: `Basebreak — Causal Verification Runtime for AI-Written Code (Nebius x NVIDIA Global AI Hackathon)`
4. **Açıklama**:
   ```
   Basebreak proves that an AI-written patch caused the behavior it claims to change — not merely that its tests are green.

   Nebius x NVIDIA Global AI Hackathon (Coding and Agentic Engineering Track)
   Target: Best Use of Tavily Bonus

   Live Public Judge URL:
   https://basebreak.zyganali.workers.dev/judge/run_3ba7d1fd-6dca-40c8-a7bb-39447bc85f1f

   GitHub Repository:
   https://github.com/zyganali-glitch/Basebreak
   ```
5. **Görünürlük (Visibility)**: **Public** (Herkese Açık) veya **Unlisted** (Liste Dışı). Kesinlikle "Private" (Gizli) yapmayın; jüri izleyebilmelidir.
6. **Çocuklara Özel mi?**: "Hayır, çocuklara özel değil" seçin.
7. Altyazı sekmesinde `basebreak_demo_subtitles.srt` dosyasını İngilizce altyazı olarak yükleyin.
8. YouTube video linkini kopyalayıp Devpost başvuru formundaki "Demo Video" alanına yapıştırın.
