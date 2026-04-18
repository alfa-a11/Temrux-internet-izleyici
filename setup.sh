#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║         NetGuard - Termux Kurulum Betiği v1.0               ║
# ║         Askeri Düzey Ağ İzleme Sistemi                      ║
# ╚══════════════════════════════════════════════════════════════╝

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
cat << 'EOF'
 ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
EOF
    echo -e "${CYAN}               Askeri Düzey Ağ İzleme & Koruma Sistemi${NC}"
    echo -e "${RED}               [YASAL KULLANIM: SADECE KENDİ AĞINIZDA]${NC}"
    echo ""
}

banner

echo -e "${YELLOW}[*] Termux paketleri güncelleniyor...${NC}"
pkg update -y && pkg upgrade -y

echo -e "${YELLOW}[*] Gerekli sistem paketleri kuruluyor...${NC}"
pkg install -y python python-pip nmap net-tools iproute2 tsu root-repo tcpdump curl wget git openssh

echo -e "${YELLOW}[*] Python kütüphaneleri kuruluyor...${NC}"
pip install --upgrade pip
pip install scapy python-nmap fastapi "uvicorn[standard]" rich psutil \
    requests schedule mac-vendor-lookup pydantic websockets python-dotenv

echo -e "${YELLOW}[*] Dizin yapısı oluşturuluyor...${NC}"
mkdir -p netguard/{database,scanner,monitor,blocker,api/routes,cli,logs,data}
touch netguard/{database,scanner,monitor,blocker,api/routes,cli}/__init__.py

echo -e "${YELLOW}[*] Çalışma izinleri ayarlanıyor...${NC}"
chmod +x netguard/main.py 2>/dev/null || true

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     KURULUM TAMAMLANDI! ✓            ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Başlatmak için:${NC}"
echo -e "  ${YELLOW}cd netguard && sudo python main.py${NC}"
echo -e "${CYAN}Sadece API sunucusu için:${NC}"
echo -e "  ${YELLOW}sudo python main.py --api --port 8000${NC}"
echo ""
echo -e "${RED}[!] NOT: Ağ tarama ve engelleme için ROOT gereklidir.${NC}"
