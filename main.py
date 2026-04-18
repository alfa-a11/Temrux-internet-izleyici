"""
NetGuard - Ana Giriş Noktası
Askeri Düzey Ağ İzleme & Koruma Sistemi

Kullanım:
    sudo python main.py                    # CLI + API
    sudo python main.py --api              # Sadece API sunucusu
    sudo python main.py --no-monitor       # Paket yakalama olmadan
"""
import sys
import os
import argparse
import logging
import threading
import signal
from datetime import datetime
from pathlib import Path

# Proje kök dizinini path'e ekle
sys.path.insert(0, str(Path(__file__).parent))

# ── LOGGING ──────────────────────────────────────────────────────────────────

def setup_logging(level: str = "INFO"):
    from config import LOG_DIR
    log_file = LOG_DIR / f"netguard_{datetime.now().strftime('%Y%m%d')}.log"
    
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=fmt,
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stderr)
        ]
    )
    # Gürültülü kütüphaneleri sustur
    for lib in ("scapy", "uvicorn", "fastapi", "asyncio", "urllib3"):
        logging.getLogger(lib).setLevel(logging.WARNING)

# ── GLOBAL SINGLETON'LAR ────────────────────────────────────────────────────
_scanner       = None
_traffic_monitor = None

# ── ROOT KONTROLÜ ────────────────────────────────────────────────────────────

def check_root():
    if os.geteuid() != 0:
        print("\n[!] UYARI: NetGuard root yetkisi olmadan çalıştırılıyor.")
        print("    Ağ tarama ve engelleme özellikleri kısıtlı olacak.")
        print("    Tam özellik için: sudo python main.py\n")
        return False
    return True

# ── ANA PROGRAM ──────────────────────────────────────────────────────────────

def main():
    global _scanner, _traffic_monitor
    
    parser = argparse.ArgumentParser(
        description="NetGuard - Askeri Düzey Ağ İzleme & Koruma Sistemi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  sudo python main.py                     # Tam sistem (CLI + API)
  sudo python main.py --api               # Sadece REST API
  sudo python main.py --api --port 9000   # Farklı port
  sudo python main.py --no-monitor        # Paket yakalama kapalı
  sudo python main.py --log-level DEBUG   # Hata ayıklama modu
        """
    )
    parser.add_argument("--api",        action="store_true", help="Sadece API sunucusunu başlat")
    parser.add_argument("--host",       default="0.0.0.0",  help="API sunucu adresi")
    parser.add_argument("--port",       type=int, default=8000, help="API portu")
    parser.add_argument("--no-monitor", action="store_true", help="Paket yakalamayı devre dışı bırak")
    parser.add_argument("--no-scan",    action="store_true", help="Otomatik taramayı devre dışı bırak")
    parser.add_argument("--log-level",  default="INFO",     help="Log seviyesi (DEBUG/INFO/WARNING)")
    parser.add_argument("--interface",  default=None,       help="Ağ arayüzü (ör: wlan0, eth0)")
    args = parser.parse_args()
    
    setup_logging(args.log_level)
    logger = logging.getLogger("netguard.main")
    
    # Konfigürasyon
    from config import CONFIG, save_config
    if args.interface:
        CONFIG["network"]["interface"] = args.interface
        save_config(CONFIG)
    
    # Veritabanı başlat
    from database.db import Database
    db = Database()
    logger.info("NetGuard başlatılıyor — v1.0.0")
    
    # Root kontrolü
    is_root = check_root()
    
    # Tarayıcı
    if not args.no_scan:
        from scanner.network_scanner import NetworkScanner
        _scanner = NetworkScanner(CONFIG)
        _scanner.start()
        logger.info("Ağ tarayıcı başlatıldı.")
    
    # Trafik monitörü
    if not args.no_monitor and CONFIG["monitor"]["capture_packets"]:
        if is_root:
            from monitor.traffic_monitor import TrafficMonitor
            _traffic_monitor = TrafficMonitor(CONFIG["network"]["interface"])
            _traffic_monitor.start()
            logger.info("Trafik monitörü başlatıldı.")
        else:
            logger.warning("Paket yakalama için root gerekli — monitor atlandı.")
    
    # Sinyal yakalama (temiz kapanma)
    def _shutdown(sig, frame):
        print("\n[!] Kapatma sinyali alındı...")
        if _scanner:
            _scanner.stop()
        if _traffic_monitor:
            _traffic_monitor.stop()
        from blocker.device_blocker import DeviceBlocker
        blocker = DeviceBlocker()
        # İsteğe bağlı: blocker.flush_all()
        sys.exit(0)
    
    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    
    if args.api:
        # Sadece API modu
        print(f"\n[*] NetGuard API başlatılıyor: http://{args.host}:{args.port}")
        print(f"[*] API Docs: http://{args.host}:{args.port}/docs")
        print(f"[*] Durdurmak için CTRL+C\n")
        from api.server import start_api_server
        start_api_server(host=args.host, port=args.port)
    else:
        # CLI + API mod
        # API arka planda
        from api.server import start_api_server
        api_thread = threading.Thread(
            target=start_api_server,
            kwargs={"host": args.host, "port": args.port},
            daemon=True,
            name="APIServer"
        )
        api_thread.start()
        
        logger.info("API sunucusu arka planda başlatıldı: http://%s:%d", args.host, args.port)
        
        # CLI menü (ön plan)
        from cli.menu import MainMenu
        menu = MainMenu()
        menu.run()


if __name__ == "__main__":
    main()
