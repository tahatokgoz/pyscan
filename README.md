
# pyScan OOP — Asenkron Port Tarayıcı

**pyScan OOP**, Python ve `asyncio` kullanılarak geliştirilmiş, **nmap-benzeri** hızlı bir TCP port tarama aracıdır.  
Yetkili hedeflerde portların durumunu (OPEN/CLOSED/TIMEOUT) tespit eder, temel **banner/TLS** bilgilerini toplar ve sonuçları **JSON** ile **HTML** formatlarında raporlar.

> ⚠️ **Yasal Uyarı:** Bu aracı yalnızca *izinli* hedeflerde kullanın. İzinsiz tarama hukuki ve etik sorumluluk doğurur.

---

## 🚀 Özellikler
- **Asenkron tarama** (aynı anda yüzlerce port)
- Port profilleri:
  - `quick` — 1–1024
  - `web` — HTTP/HTTPS ve ilgili yaygın portlar
  - `db` — Veritabanı portları
  - `common` — Yaygın servis portları
- TCP port durumu tespiti (OPEN, CLOSED, TIMEOUT, ERROR)
- HTTP, SMTP, Redis, SSH, MySQL, MongoDB için **banner grabbing**
- 443/8443/9443 portlarında **TLS sertifika özeti**
- **JSON** ve **HTML** rapor formatı
- CIDR desteği (örn. `192.168.1.0/24`)

---

## 📦 Gereksinimler
- **Python 3.10+**
- Ekstra bağımlılık **yok** (yalnızca standart kütüphaneler kullanılır)
- (Opsiyonel) `jq` → JSON filtreleme

---

## 🔧 Kurulum
```bash
git clone https://github.com/kullaniciadi/pyscan_oop.git
cd pyscan_oop
Gerekirse sanal ortam oluşturun:
python -m venv venv
source venv/bin/activate
💻 Kullanım
1. Yardım Menüsü
python pyscan_oop.py --help
2. Tek Host & Port
python pyscan_oop.py 127.0.0.1 -p 8000 --json r1.json --html r1.html
3. Port Profili ile
python pyscan_oop.py scanme.nmap.org --profile web --json out.json --html out.html
4. CIDR Aralığı Taraması
python pyscan_oop.py 192.168.1.0/28 --profile quick --json local.json
5. Otomatik Demo Scripti (run_demo.sh)
# 1️⃣ Lokal demo çalıştır (varsayılan ayarlarla)
./run_demo.sh

# 2️⃣ scanme.nmap.org hedefini tara (lokal HTTP server başlatma)
./run_demo.sh --target scanme.nmap.org --no-server

# 3️⃣ Demo çalıştır, ancak tarama sonrası HTML raporunu otomatik açma
./run_demo.sh --no-open
Açıklamalar:
./run_demo.sh → Varsayılan olarak 127.0.0.1’de lokal bir HTTP server başlatır, tek port ve web profili taraması yapar, sonuçları results/ klasörüne kaydeder.
--target scanme.nmap.org → Farklı bir hedef belirler.
--no-server → Lokal test server açmaz (dış hedeflerde gereklidir).
--no-open → HTML raporları otomatik açmaz, yalnızca dosyaları oluşturur.
📁 Çıktı Örnekleri
JSON
[
  {
    "host": "127.0.0.1",
    "port": 8000,
    "state": "OPEN",
    "banner": "HTTP/1.0 200 OK Server: SimpleHTTP/0.6 Python/3.11.13 ...",
    "latency_ms": 1
  }
]
HTML
⚙️ Gelişmiş Parametreler
-c, --concurrency → Aynı anda kaç port taransın (default: 200)
-t, --timeout → Her bağlantı için zaman aşımı (default: 1.2s)
--jitter → Portlar arası rastgele bekleme (trafik gürültüsünü azaltır)
--retries → Timeout durumunda yeniden deneme sayısı
🛡️ Güvenlik ve Etik
Yalnızca izinli hedefleri tarayın.
Yüksek concurrency değerleri IDS/IPS sistemleri tetikleyebilir.
TLS doğrulama yapılmaz, yalnızca sertifika envanteri çıkarılır.
📜 Lisans
Bu proje MIT Lisansı ile lisanslanmıştır. Detaylar için LICENSE dosyasına bakın.