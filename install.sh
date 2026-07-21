#!/usr/bin/env bash
#
# KaliRecon kurulum: sistem araçlarını (nmap, gobuster, ffuf, whatweb) + venv +
# Python bağımlılıklarını kurar. Kali / PEP 668 uyumlu.  Kullanım: ./install.sh
#
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

VENV_DIR=".venv"
PYTHON_BIN="python3"

echo "[*] KaliRecon kurulumu başlatılıyor..."

# --- 1) Sistem araçları -------------------------------------------------------
# Bunlar apt paketleridir. Root gerektirdiği için sudo ile kuruyoruz.
SYS_PKGS=(python3-venv python3-tk nmap gobuster ffuf whatweb wordlists)
MISSING=()

need_pkg() {
    # Paket kurulu mu diye dpkg üzerinden bakar.
    dpkg -s "$1" >/dev/null 2>&1 || MISSING+=("$1")
}

for pkg in "${SYS_PKGS[@]}"; do
    need_pkg "$pkg"
done

if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "[!] Eksik sistem paketleri: ${MISSING[*]}"
    echo "[*] Kurulmaya çalışılıyor (sudo gerekebilir)..."
    sudo apt update
    sudo apt install -y "${MISSING[@]}"
else
    echo "[+] Gerekli sistem paketleri zaten kurulu."
fi

# Gobuster bazı Kali sürümlerinde farklı gelebilir; yoksa uyar.
command -v gobuster >/dev/null 2>&1 || \
    echo "[!] gobuster bulunamadı. Manuel kurulum: sudo apt install gobuster"

# --- 2) Sanal ortam -----------------------------------------------------------
[ -d "$VENV_DIR" ] || "$PYTHON_BIN" -m venv "$VENV_DIR"

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# --- 3) Python bağımlılıkları (venv içinde -> PEP 668 engeli yok) --------------
echo "[*] Python bağımlılıkları yükleniyor..."
python -m pip install -q -r requirements.txt

echo "[+] Kurulum tamamlandı. Başlatmak için: ./run.sh"
echo "    Not: -sS/-A/-O taramaları root ister -> sudo setcap cap_net_raw,cap_net_admin+eip \$(command -v nmap)"
