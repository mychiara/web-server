#!/bin/bash

# Warna untuk output yang menarik
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}=================================================${NC}"
echo -e "${CYAN}     MASANDIGITAL DASHBOARD - UPDATE SCRIPT      ${NC}"
echo -e "${CYAN}=================================================${NC}"
echo ""

# Cek apakah dijalankan sebagai root (Sudo)
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}[ERROR] Mohon jalankan script ini dengan sudo!${NC}"
  echo "Usage: sudo bash update.sh"
  exit 1
fi

# Dapatkan direktori tempat script ini berada
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Tentukan folder instalasi
if [ -d "$SCRIPT_DIR/.git" ]; then
    INSTALL_DIR="$SCRIPT_DIR"
elif [ -d "$(pwd)/.git" ]; then
    INSTALL_DIR="$(pwd)"
elif [ -d "/root/masandigital_dashboard/.git" ]; then
    INSTALL_DIR="/root/masandigital_dashboard"
elif [ -d "/home/masandigital/masandigital_dashboard/.git" ]; then
    INSTALL_DIR="/home/masandigital/masandigital_dashboard"
else
    # Fallback terakhir
    INSTALL_DIR="/root/masandigital_dashboard"
    if [ ! -d "$INSTALL_DIR" ]; then
        echo -e "${RED}[ERROR] Folder instalasi dashboard dengan git tidak ditemukan!${NC}"
        exit 1
    fi
fi

cd "$INSTALL_DIR" || exit 1
echo -e "${BLUE}[1/3] Pindah ke direktori: $INSTALL_DIR${NC}"

# Simpan cadangan data (optional tapi aman)
if [ -d "data" ]; then
    echo -e "${BLUE}[INFO] Membuat cadangan folder data...${NC}"
    tar -czf "data_backup_$(date +%F_%H%M%S).tar.gz" data/ 2>/dev/null
fi

echo -e "${BLUE}[2/3] Mengunduh pembaruan dari GitHub...${NC}"
git fetch --all
# Reset hard jika ada perubahan lokal tak terduga, tapi simpan data via volume
git reset --hard origin/main
git pull origin main

echo -e "${BLUE}[3/3] Membangun ulang dan menyalakan kontainer Docker...${NC}"
docker compose down
docker compose up --build -d

echo ""
echo -e "${GREEN}=================================================${NC}"
echo -e "${GREEN} [SUKSES] Pembaruan Dashboard Selesai Dilakukan!  ${NC}"
echo -e "${GREEN}=================================================${NC}"
echo -e "Silakan tunggu 5-10 detik lalu buka kembali halaman dashboard."
