#!/usr/bin/env bash
set -euo pipefail

# --- Ayarlar / Varsayılanlar ---
TARGET="127.0.0.1"     # --target ile değiştirilebilir
PORT=8000              # lokal HTTP için
OUTDIR="results"
OPEN_HTML=1            # 1: HTML'yi açmayı dene, 0: açma
RUN_LOCAL_SERVER=1     # 1: lokal sunucu başlat, 0: başlatma (örn. dış hedef)

# --- Argümanlar ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2;;
    --no-open) OPEN_HTML=0; shift;;
    --no-server) RUN_LOCAL_SERVER=0; shift;;
    --port) PORT="$2"; shift 2;;
    *) echo "Bilinmeyen argüman: $1"; exit 1;;
  esac
done

# --- Kontroller ---
[[ -f pyscan_oop.py ]] || { echo "HATA: pyscan_oop.py bu klasörde yok."; exit 1; }
command -v python >/dev/null || { echo "HATA: python bulunamadı."; exit 1; }
mkdir -p "$OUTDIR"

ts() { date +%Y%m%d_%H%M%S; }

# --- Lokal HTTP sunucu yönetimi ---
HTTP_PID_FILE=".http_pid"
start_server() {
  [[ "$RUN_LOCAL_SERVER" -eq 1 ]] || return 0
  # yalnız 127.0.0.1 hedefinde mantıklı
  if [[ "$TARGET" != "127.0.0.1" && "$TARGET" != "localhost" ]]; then
    echo "[i] TARGET $TARGET, lokal sunucu başlatılmıyor (--no-server önerilir)."
    RUN_LOCAL_SERVER=0
    return 0
  fi
  # varsa eskiyi kapat
  [[ -f "$HTTP_PID_FILE" ]] && kill "$(cat "$HTTP_PID_FILE")" 2>/dev/null || true
  echo "[i] Lokal HTTP sunucusu başlıyor: http://127.0.0.1:$PORT"
  python -m http.server "$PORT" >/dev/null 2>&1 & echo $! > "$HTTP_PID_FILE"
  # hazır olana kadar bekle (2 sn'e kadar)
  for _ in {1..20}; do
    if curl -sI "http://127.0.0.1:$PORT" >/dev/null; then
      echo "[+] HTTP $PORT hazır."
      return 0
    fi
    sleep 0.1
  done
  echo "[-] Uyarı: HTTP $PORT doğrulanamadı ama devam ediyorum."
}
stop_server() {
  [[ -f "$HTTP_PID_FILE" ]] || return 0
  echo "[i] Lokal HTTP sunucusu kapatılıyor..."
  kill "$(cat "$HTTP_PID_FILE")" 2>/dev/null || true
  rm -f "$HTTP_PID_FILE"
}
trap stop_server EXIT

# --- Yardımcı: HTML aç ---
open_html() {
  local f="$1"
  [[ "$OPEN_HTML" -eq 1 ]] || return 0
  ( open "$f" 2>/dev/null || xdg-open "$f" 2>/dev/null ) && echo "[i] HTML açıldı: $f" || echo "[i] HTML'i açamadım; dosya hazır: $f"
}

# --- Çalışma ---
echo "=== pyScan demo başlıyor ==="
echo "[i] Target: $TARGET"

start_server

# 1) Tek port taraması
T1=$(ts)
JSON1="$OUTDIR/${T1}_local_${TARGET//\//-}_p${PORT}.json"
HTML1="$OUTDIR/${T1}_local_${TARGET//\//-}_p${PORT}.html"
echo "[i] Tek port taraması: $TARGET:$PORT"
python pyscan_oop.py "$TARGET" -p "$PORT" --json "$JSON1" --html "$HTML1"
echo "[+] JSON -> $JSON1"
echo "[+] HTML -> $HTML1"
open_html "$HTML1"

# 2) Web profili taraması
T2=$(ts)
JSON2="$OUTDIR/${T2}_web_${TARGET//\//-}.json"
HTML2="$OUTDIR/${T2}_web_${TARGET//\//-}.html"
echo "[i] Web profili taraması: $TARGET (22,80,443,8080,8081,8000,8443,8888,9000)"
python pyscan_oop.py "$TARGET" --profile web --json "$JSON2" --html "$HTML2"
echo "[+] JSON -> $JSON2"
echo "[+] HTML -> $HTML2"
open_html "$HTML2"

echo "=== Bitti ==="
echo "Özet:"
echo " - Tek port raporları: $JSON1 , $HTML1"
echo " - Web profili raporları: $JSON2 , $HTML2"
echo "Raporların tamamı '$OUTDIR/' klasöründe."
