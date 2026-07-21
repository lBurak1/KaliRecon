#!/usr/bin/env bash
#
# KaliRecon — Hızlı başlatıcı
# venv'i aktive eder ve uygulamayı çalıştırır. Root ile çalıştırmayın.
#
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

[ "$(id -u)" -eq 0 ] && echo "[!] Root ile çalıştırmayın (X11/DISPLAY sorunu çıkabilir)."

if [ ! -d ".venv" ]; then
    echo "[-] .venv yok. Önce ./install.sh çalıştırın."
    exit 1
fi

# shellcheck disable=SC1091
source ".venv/bin/activate"
exec python app.py
