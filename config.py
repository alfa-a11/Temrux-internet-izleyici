"""
NetGuard - Sistem Konfigürasyonu
Tüm ayarlar buradan yönetilir.
"""
import os
import json
from pathlib import Path

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR  = BASE_DIR / "logs"
DB_PATH  = DATA_DIR / "netguard.db"
CONFIG_FILE = DATA_DIR / "config.json"

DATA_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

DEFAULT_CONFIG = {
    "network": {
        "interface": "wlan0",          # Termux'ta genellikle wlan0
        "subnet": "192.168.1.0/24",   # Ağ alt ağı
        "gateway": "192.168.1.1",      # Ağ geçidi
        "scan_interval": 30,           # Saniye cinsinden tarama aralığı
        "deep_scan_interval": 300,     # Port tarama aralığı (saniye)
    },
    "security": {
        "auto_block_unknown": False,   # Bilinmeyen cihazları otomatik engelle
        "alert_new_device": True,      # Yeni cihaz uyarısı
        "whitelist_only_mode": False,  # Sadece whitelist modunu aktif et
        "block_method": "iptables",    # iptables veya arp
    },
    "api": {
        "host": "0.0.0.0",
        "port": 8000,
        "secret_key": os.urandom(32).hex(),
        "enable_auth": False,
    },
    "monitor": {
        "capture_packets": True,       # Paket yakalama aktif/pasif
        "packet_buffer": 1000,         # Bellekte tutulacak paket sayısı
        "log_connections": True,       # Bağlantıları logla
        "detect_apps": True,           # Uygulama tespiti
    }
}

# Bilinen port → uygulama eşlemeleri
PORT_APP_MAP = {
    80:   "HTTP Web",
    443:  "HTTPS Web",
    8080: "HTTP Proxy",
    53:   "DNS",
    22:   "SSH",
    21:   "FTP",
    25:   "SMTP E-posta",
    110:  "POP3 E-posta",
    143:  "IMAP E-posta",
    3306: "MySQL DB",
    5432: "PostgreSQL DB",
    27017:"MongoDB",
    6379: "Redis",
    3389: "RDP Uzak Masaüstü",
    5900: "VNC Uzak Masaüstü",
    1194: "OpenVPN",
    1723: "PPTP VPN",
    4500: "IPSec VPN",
    51820: "WireGuard VPN",
    5228: "Google Push / FCM",
    5222: "XMPP / WhatsApp",
    5223: "WhatsApp TLS",
    5242: "WhatsApp Media",
    1935: "RTMP Video Akışı",
    554:  "RTSP Video",
    8443: "HTTPS Alt",
    9090: "Prometheus",
    9200: "Elasticsearch",
    6881: "BitTorrent",
    6969: "BitTorrent Tracker",
    4444: "Metasploit",
    23:   "Telnet",
    161:  "SNMP",
    123:  "NTP Zaman",
    67:   "DHCP Sunucu",
    68:   "DHCP İstemci",
}

# Tehdit seviyesine göre portlar
SUSPICIOUS_PORTS = {4444, 1337, 31337, 12345, 54321, 6666, 6667, 7777}
VPN_PORTS = {1194, 1723, 4500, 51820, 500, 4501}

def load_config() -> dict:
    """Konfigürasyon dosyasını yükle, yoksa varsayılanı kullan."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                saved = json.load(f)
            # Deep merge
            config = DEFAULT_CONFIG.copy()
            for section, values in saved.items():
                if section in config:
                    config[section].update(values)
            return config
        except Exception:
            pass
    save_config(DEFAULT_CONFIG)
    return DEFAULT_CONFIG.copy()

def save_config(config: dict) -> None:
    """Konfigürasyonu dosyaya kaydet."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

CONFIG = load_config()
