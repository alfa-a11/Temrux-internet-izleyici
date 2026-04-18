"""
NetGuard - Trafik İzleme Modülü
Scapy ile gerçek zamanlı paket yakalama, bağlantı takibi,
uygulama tespiti ve bant genişliği ölçümü.
"""
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional

logger = logging.getLogger("netguard.monitor")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, conf as scapy_conf
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    logger.warning("Scapy yok — paket yakalama devre dışı.")

from config import PORT_APP_MAP, VPN_PORTS, SUSPICIOUS_PORTS


def _resolve_app(port: int, protocol: str = "TCP") -> str:
    """Port numarasından uygulama adı belirle."""
    if port in PORT_APP_MAP:
        return PORT_APP_MAP[port]
    if port in SUSPICIOUS_PORTS:
        return f"⚠️ Şüpheli Port {port}"
    if port in VPN_PORTS:
        return f"🔒 VPN ({port})"
    if 49152 <= port <= 65535:
        return f"Dinamik/Ephemeral"
    return f"{protocol}:{port}"


class BandwidthTracker:
    """Cihaz başına bant genişliği takibi."""
    
    def __init__(self):
        # mac → {"in": bytes, "out": bytes, "last_reset": timestamp}
        self._stats: dict = defaultdict(lambda: {"in": 0, "out": 0, "last_reset": time.time()})
        self._lock = threading.Lock()
    
    def add_bytes(self, mac: str, direction: str, size: int):
        with self._lock:
            self._stats[mac][direction] += size
    
    def get_stats(self, mac: str = None) -> dict:
        with self._lock:
            if mac:
                return dict(self._stats.get(mac, {"in": 0, "out": 0}))
            return {k: dict(v) for k, v in self._stats.items()}
    
    def reset(self, mac: str = None):
        with self._lock:
            if mac:
                self._stats[mac] = {"in": 0, "out": 0, "last_reset": time.time()}
            else:
                self._stats.clear()
    
    def get_top_consumers(self, limit: int = 5) -> list:
        with self._lock:
            items = [
                (mac, data["in"] + data["out"])
                for mac, data in self._stats.items()
            ]
        return sorted(items, key=lambda x: x[1], reverse=True)[:limit]


class ConnectionTracker:
    """Aktif bağlantıları takip eder."""
    
    def __init__(self, max_size: int = 2000):
        self._conns: deque = deque(maxlen=max_size)
        self._lock = threading.Lock()
        # ip → mac haritalama
        self._ip_to_mac: dict = {}
    
    def register_device(self, ip: str, mac: str):
        self._ip_to_mac[ip] = mac
    
    def mac_for_ip(self, ip: str) -> Optional[str]:
        return self._ip_to_mac.get(ip)
    
    def add(self, conn: dict):
        with self._lock:
            self._conns.appendleft(conn)
    
    def get_all(self, limit: int = 100) -> list:
        with self._lock:
            return list(self._conns)[:limit]
    
    def get_by_mac(self, mac: str, limit: int = 50) -> list:
        with self._lock:
            return [c for c in self._conns if c.get("mac") == mac][:limit]
    
    def get_by_ip(self, ip: str, limit: int = 50) -> list:
        with self._lock:
            return [c for c in self._conns if c.get("src_ip") == ip][:limit]
    
    def active_ips(self) -> set:
        with self._lock:
            return {c["src_ip"] for c in self._conns}


class TrafficMonitor:
    """
    Ana trafik izleme motoru.
    Scapy ile arayüzü dinler, paketleri analiz eder,
    DB'ye kaydeder ve uyarılar oluşturur.
    """
    
    def __init__(self, interface: str = "wlan0"):
        from database.db import Database
        self.db = Database()
        self.interface = interface
        self.bw = BandwidthTracker()
        self.conn_tracker = ConnectionTracker()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._packet_count = 0
        self._start_time = None
        
        # IP → MAC'i DB'den yükle
        for dev in self.db.get_all_devices():
            self.conn_tracker.register_device(dev["ip"], dev["mac"])
    
    def _process_packet(self, pkt):
        """Her paketi işle."""
        try:
            if not pkt.haslayer(IP):
                return
            
            self._packet_count += 1
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            size = len(pkt)
            now = datetime.now().isoformat()
            
            src_mac = self.conn_tracker.mac_for_ip(src_ip)
            
            # Bant genişliği
            if src_mac:
                self.bw.add_bytes(src_mac, "out", size)
            dst_mac = self.conn_tracker.mac_for_ip(dst_ip)
            if dst_mac:
                self.bw.add_bytes(dst_mac, "in", size)
            
            # TCP / UDP analiz
            proto = "ICMP"
            src_port = dst_port = 0
            app_name = "Diğer"
            
            if pkt.haslayer(TCP):
                proto = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                app_name = _resolve_app(dst_port, "TCP")
            elif pkt.haslayer(UDP):
                proto = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                app_name = _resolve_app(dst_port, "UDP")
                
                # DNS sorgularını yakala
                if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                    try:
                        query = pkt[DNS].qd.qname.decode().rstrip(".")
                        app_name = f"DNS→{query}"
                    except Exception:
                        pass
            
            # Bağlantı kaydı
            conn = {
                "mac": src_mac or "unknown",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "app": app_name,
                "size": size,
                "ts": now,
            }
            self.conn_tracker.add(conn)
            
            # DB'ye kaydet (sadece bilinen cihazlar)
            if src_mac:
                from config import CONFIG
                if CONFIG["monitor"]["log_connections"]:
                    self.db.log_connection(
                        device_mac=src_mac,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=proto,
                        app_name=app_name,
                        bytes_sent=size
                    )
            
            # Güvenlik uyarıları
            self._check_threats(src_mac, src_ip, dst_ip, dst_port, proto, app_name)
            
        except Exception as e:
            logger.debug("Paket işleme hata: %s", e)
    
    def _check_threats(self, mac: Optional[str], src: str, dst: str,
                       dport: int, proto: str, app: str):
        """Tehdit tespiti."""
        # Engelli cihaz trafik tespiti
        if mac:
            dev = self.db.get_device(mac)
            if dev and dev.get("status") == "blocked":
                logger.warning("Engelli cihaz trafiği: %s → %s", src, dst)
                return
        
        # Şüpheli port
        if dport in SUSPICIOUS_PORTS:
            self.db.add_alert(
                alert_type="suspicious_traffic",
                severity="critical",
                message=f"Şüpheli port trafiği! {src} → {dst}:{dport} ({app})",
                device_mac=mac,
                device_ip=src
            )
        
        # VPN tespiti
        if dport in VPN_PORTS:
            self.db.add_alert(
                alert_type="vpn_detected",
                severity="medium",
                message=f"VPN bağlantısı tespit edildi: {src} → {dst}:{dport}",
                device_mac=mac,
                device_ip=src
            )
    
    def get_live_stats(self) -> dict:
        """Anlık istatistikler."""
        elapsed = time.time() - (self._start_time or time.time())
        pps = self._packet_count / max(elapsed, 1)
        
        conns = self.conn_tracker.get_all(50)
        top_apps: dict = defaultdict(int)
        for c in conns:
            top_apps[c["app"]] += 1
        
        return {
            "running": self._running,
            "packet_count": self._packet_count,
            "pps": round(pps, 2),
            "active_connections": len(conns),
            "top_apps": sorted(top_apps.items(), key=lambda x: x[1], reverse=True)[:10],
            "bandwidth": self.bw.get_stats(),
            "top_consumers": self.bw.get_top_consumers(),
        }
    
    def start(self):
        """Paket yakalamayı başlat."""
        if self._running:
            return
        if not SCAPY_OK:
            logger.error("Scapy yok — monitor başlatılamıyor.")
            return
        
        self._running = True
        self._start_time = time.time()
        self._thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="TrafficMonitor"
        )
        self._thread.start()
        logger.info("Trafik izleme başlatıldı: %s", self.interface)
    
    def stop(self):
        self._running = False
        logger.info("Trafik izleme durduruldu.")
    
    def _capture_loop(self):
        """Scapy sniff döngüsü."""
        scapy_conf.verb = 0
        while self._running:
            try:
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    store=False,
                    timeout=5,          # 5 saniyede bir döngü kontrol et
                    filter="ip"         # Sadece IP paketleri
                )
            except Exception as e:
                if self._running:
                    logger.error("Sniff hata: %s", e)
                    time.sleep(3)
