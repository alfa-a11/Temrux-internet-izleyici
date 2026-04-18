"""
NetGuard - Ağ Tarayıcı
ARP tarama + Nmap ile cihaz keşfi, port tarama ve OS tespiti.
"""
import logging
import socket
import subprocess
import json
import threading
import time
from datetime import datetime
from typing import Optional

logger = logging.getLogger("netguard.scanner")

try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    logger.warning("Scapy bulunamadı → ARP tarama devre dışı.")

try:
    import nmap
    NMAP_OK = True
except ImportError:
    NMAP_OK = False
    logger.warning("python-nmap bulunamadı → port tarama devre dışı.")

try:
    from mac_vendor_lookup import MacLookup, BaseMacLookup
    BaseMacLookup.cache_path = "/tmp/mac_vendors.txt"
    _mac_lookup = MacLookup()
    MAC_LOOKUP_OK = True
except Exception:
    MAC_LOOKUP_OK = False


def get_vendor(mac: str) -> str:
    """MAC adresinden üretici bilgisi al."""
    if not MAC_LOOKUP_OK:
        return "Bilinmiyor"
    try:
        return _mac_lookup.lookup(mac)
    except Exception:
        return "Bilinmiyor"


def get_hostname(ip: str) -> str:
    """IP'den hostname çözümle."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Bilinmiyor"


def _arp_scan_scapy(subnet: str, interface: str, timeout: int = 3) -> list[dict]:
    """Scapy ile ARP tarama — en güvenilir yöntem."""
    if not SCAPY_OK:
        return []
    try:
        scapy_conf.verb = 0
        arp_req = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_req
        answered, _ = srp(packet, iface=interface, timeout=timeout, retry=2)
        devices = []
        for sent, received in answered:
            mac = received.hwsrc.upper()
            ip  = received.psrc
            devices.append({
                "mac": mac,
                "ip":  ip,
                "hostname": get_hostname(ip),
                "vendor":   get_vendor(mac),
            })
        return devices
    except Exception as e:
        logger.error("Scapy ARP hata: %s", e)
        return []


def _arp_scan_system(subnet: str) -> list[dict]:
    """Sistem ARP tablosu üzerinden cihaz listesi."""
    devices = []
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                ip  = parts[1].strip("()")
                mac = parts[3].upper() if len(parts) > 3 else "UNKNOWN"
                if mac == "UNKNOWN" or len(mac) < 10:
                    continue
                devices.append({
                    "mac": mac,
                    "ip":  ip,
                    "hostname": get_hostname(ip),
                    "vendor":   get_vendor(mac),
                })
    except Exception as e:
        logger.error("Sistem ARP hata: %s", e)
    return devices


def _arp_scan_nmap(subnet: str) -> list[dict]:
    """nmap -sn ile ping tarama."""
    if not NMAP_OK:
        return []
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments="-sn -T4 --host-timeout 5s")
        devices = []
        for host in nm.all_hosts():
            try:
                mac = nm[host]["addresses"].get("mac", "").upper()
                ip  = nm[host]["addresses"].get("ipv4", host)
                vendor = nm[host].get("vendor", {}).get(mac, "Bilinmiyor") if mac else "Bilinmiyor"
                hostname = nm[host].hostname() or get_hostname(ip)
                if mac:
                    devices.append({"mac": mac, "ip": ip, "hostname": hostname, "vendor": vendor})
            except Exception:
                continue
        return devices
    except Exception as e:
        logger.error("nmap ARP hata: %s", e)
        return []


def scan_network(subnet: str, interface: str = "wlan0", timeout: int = 3) -> list[dict]:
    """
    Ağı tara — en iyi yöntemi otomatik seç.
    Öncelik: Scapy → nmap → Sistem ARP
    """
    logger.info("Ağ taranıyor: %s", subnet)
    
    # 1. Scapy (en hızlı ve doğru)
    if SCAPY_OK:
        devices = _arp_scan_scapy(subnet, interface, timeout)
        if devices:
            logger.info("Scapy: %d cihaz bulundu", len(devices))
            return devices
    
    # 2. nmap fallback
    if NMAP_OK:
        devices = _arp_scan_nmap(subnet)
        if devices:
            logger.info("nmap: %d cihaz bulundu", len(devices))
            return devices
    
    # 3. Sistem ARP tablosu
    devices = _arp_scan_system(subnet)
    logger.info("Sistem ARP: %d cihaz bulundu", len(devices))
    return devices


class PortScanner:
    """Nmap tabanlı port tarayıcı."""
    
    def __init__(self):
        self.nm = nmap.PortScanner() if NMAP_OK else None
    
    def scan_device(self, ip: str, port_range: str = "1-1024",
                    aggressive: bool = False) -> dict:
        """
        Bir cihazın portlarını ve OS'unu tara.
        Returns: {"ports": [...], "os": str, "services": {...}}
        """
        if not self.nm:
            return {"ports": [], "os": "nmap yok", "services": {}}
        
        args = "-sV -T4 --host-timeout 30s"
        if aggressive:
            args = "-A -T4 --host-timeout 60s"
        
        try:
            logger.info("Port tarama: %s [%s]", ip, port_range)
            self.nm.scan(hosts=ip, ports=port_range, arguments=args)
            
            if ip not in self.nm.all_hosts():
                return {"ports": [], "os": "erişilemiyor", "services": {}}
            
            host = self.nm[ip]
            open_ports = []
            services = {}
            
            for proto in host.all_protocols():
                for port, data in host[proto].items():
                    if data["state"] == "open":
                        svc = data.get("name", "?")
                        ver = data.get("version", "")
                        open_ports.append(port)
                        services[port] = f"{svc} {ver}".strip()
            
            os_guess = "Bilinmiyor"
            if "osmatch" in host and host["osmatch"]:
                os_guess = host["osmatch"][0].get("name", "Bilinmiyor")
            
            return {
                "ports": sorted(open_ports),
                "os": os_guess,
                "services": services
            }
        except Exception as e:
            logger.error("Port tarama hata (%s): %s", ip, e)
            return {"ports": [], "os": "hata", "services": {}}
    
    def quick_scan(self, ip: str) -> list[int]:
        """Sadece açık portları hızlıca döndür."""
        result = self.scan_device(ip, "21-23,25,53,80,110,143,443,1194,3306,3389,5900,8080,8443")
        return result.get("ports", [])


class NetworkScanner:
    """
    Ana ağ tarayıcı — sürekli çalışan tarama döngüsü.
    Yeni cihazları tespit eder, DB'ye kaydeder, uyarı oluşturur.
    """
    
    def __init__(self, config: dict):
        from database.db import Database
        self.db = Database()
        self.cfg = config
        self.port_scanner = PortScanner()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.known_devices: dict = {}   # mac → device_info
        self._load_known()
    
    def _load_known(self):
        """DB'den bilinen cihazları yükle."""
        for dev in self.db.get_all_devices():
            self.known_devices[dev["mac"]] = dev
    
    def scan_once(self) -> list[dict]:
        """Tek seferlik ağ taraması."""
        from config import CONFIG
        net_cfg = CONFIG["network"]
        devices = scan_network(
            net_cfg["subnet"],
            net_cfg["interface"],
            timeout=3
        )
        new_count = 0
        
        for dev in devices:
            mac = dev["mac"]
            is_new = self.db.upsert_device(
                mac=mac,
                ip=dev["ip"],
                hostname=dev["hostname"],
                vendor=dev["vendor"]
            )
            if is_new:
                new_count += 1
                logger.info("YENİ CİHAZ: %s (%s) - %s", mac, dev["ip"], dev["vendor"])
                self.db.add_alert(
                    alert_type="new_device",
                    severity="high",
                    message=f"Yeni cihaz tespit edildi: {dev['ip']} ({dev['vendor']}) MAC: {mac}",
                    device_mac=mac,
                    device_ip=dev["ip"]
                )
                # Otomatik engelle?
                from config import CONFIG as CFG
                if CFG["security"]["auto_block_unknown"]:
                    self._auto_block(mac, dev["ip"])
            
            self.known_devices[mac] = dev
        
        self.db.log_scan(
            devices_found=len(devices),
            new_devices=new_count,
            scan_type="arp"
        )
        return devices
    
    def _auto_block(self, mac: str, ip: str):
        """Whitelist'te olmayan cihazı otomatik engelle."""
        dev = self.db.get_device(mac)
        if dev and dev.get("is_whitelisted"):
            return
        logger.warning("Otomatik engelleme: %s (%s)", mac, ip)
        from blocker.device_blocker import DeviceBlocker
        blocker = DeviceBlocker()
        blocker.block(mac, ip)
        self.db.set_device_status(mac, "blocked")
        self.db.add_alert(
            alert_type="auto_blocked",
            severity="critical",
            message=f"Cihaz otomatik engellendi: {ip} ({mac})",
            device_mac=mac,
            device_ip=ip
        )
    
    def deep_scan_device(self, mac: str):
        """Belirli bir cihazı derinlemesine tara (portlar + OS)."""
        dev = self.db.get_device(mac)
        if not dev:
            return
        ip = dev["ip"]
        result = self.port_scanner.scan_device(ip)
        self.db.update_device_ports(mac, result["ports"], result["os"])
        
        # Şüpheli port uyarısı
        from config import SUSPICIOUS_PORTS
        suspicious = set(result["ports"]) & SUSPICIOUS_PORTS
        if suspicious:
            self.db.add_alert(
                alert_type="suspicious_port",
                severity="critical",
                message=f"ŞÜPHELİ PORTLAR: {ip} → {suspicious}",
                device_mac=mac,
                device_ip=ip
            )
        logger.info("Derin tarama tamamlandı: %s → port:%s os:%s",
                    ip, result["ports"], result["os"])
    
    def start(self):
        """Arka planda tarama döngüsünü başlat."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ScanLoop")
        self._thread.start()
        logger.info("Ağ tarayıcı başlatıldı.")
    
    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Ağ tarayıcı durduruldu.")
    
    def _loop(self):
        """Ana tarama döngüsü."""
        from config import CONFIG
        interval = CONFIG["network"]["scan_interval"]
        deep_interval = CONFIG["network"]["deep_scan_interval"]
        last_deep = 0
        
        while self._running:
            try:
                self.scan_once()
                now = time.time()
                if now - last_deep >= deep_interval:
                    # Tüm cihazları derin tara
                    for dev in self.db.get_all_devices():
                        if not self._running:
                            break
                        self.deep_scan_device(dev["mac"])
                    last_deep = now
            except Exception as e:
                logger.error("Tarama döngüsü hata: %s", e)
            
            for _ in range(interval):
                if not self._running:
                    return
                time.sleep(1)
