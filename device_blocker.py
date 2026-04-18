"""
NetGuard - Cihaz Engelleme Modülü
iptables (MAC bazlı) ve ARP zehirleme yöntemleriyle cihazları engeller.
"""
import subprocess
import logging
import threading
import time
from typing import Optional

logger = logging.getLogger("netguard.blocker")

try:
    from scapy.all import ARP, Ether, sendp, get_if_hwaddr, conf as scapy_conf
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


def _run(cmd: list, check: bool = False) -> tuple[int, str, str]:
    """Shell komutu çalıştır."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", f"komut bulunamadı: {cmd[0]}"


class IptablesBlocker:
    """iptables ile MAC adresi bazlı engelleme."""
    
    CHAIN = "NETGUARD_BLOCK"
    
    def __init__(self):
        self._ensure_chain()
    
    def _ensure_chain(self):
        """NETGUARD_BLOCK zincirini oluştur."""
        # Zincir var mı?
        rc, _, _ = _run(["iptables", "-L", self.CHAIN, "-n"])
        if rc != 0:
            _run(["iptables", "-N", self.CHAIN])
            # FORWARD ve INPUT'tan yönlendir
            _run(["iptables", "-I", "FORWARD", "-j", self.CHAIN])
            _run(["iptables", "-I", "INPUT",   "-j", self.CHAIN])
            logger.info("iptables zinciri oluşturuldu: %s", self.CHAIN)
    
    def block_mac(self, mac: str) -> bool:
        """MAC adresini engelle."""
        mac = mac.upper()
        # Zaten var mı?
        rc, out, _ = _run(["iptables", "-L", self.CHAIN, "-n"])
        if mac.lower() in out.lower():
            logger.debug("Zaten engelli: %s", mac)
            return True
        
        rc, _, err = _run([
            "iptables", "-A", self.CHAIN,
            "-m", "mac", "--mac-source", mac,
            "-j", "DROP"
        ])
        if rc == 0:
            logger.info("iptables engellendi: %s", mac)
            return True
        logger.error("iptables engelleme hata (%s): %s", mac, err)
        return False
    
    def unblock_mac(self, mac: str) -> bool:
        """MAC engelini kaldır."""
        mac = mac.upper()
        rc, _, err = _run([
            "iptables", "-D", self.CHAIN,
            "-m", "mac", "--mac-source", mac,
            "-j", "DROP"
        ])
        if rc == 0:
            logger.info("iptables engel kaldırıldı: %s", mac)
            return True
        logger.warning("iptables engel kaldırma hata (%s): %s", mac, err)
        return False
    
    def block_ip(self, ip: str) -> bool:
        """IP adresini engelle."""
        rc, _, err = _run([
            "iptables", "-A", self.CHAIN,
            "-s", ip, "-j", "DROP"
        ])
        if rc == 0:
            _run(["iptables", "-A", self.CHAIN, "-d", ip, "-j", "DROP"])
            logger.info("iptables IP engellendi: %s", ip)
            return True
        logger.error("iptables IP engelleme hata (%s): %s", ip, err)
        return False
    
    def unblock_ip(self, ip: str) -> bool:
        _run(["iptables", "-D", self.CHAIN, "-s", ip, "-j", "DROP"])
        _run(["iptables", "-D", self.CHAIN, "-d", ip, "-j", "DROP"])
        logger.info("iptables IP engel kaldırıldı: %s", ip)
        return True
    
    def list_blocked(self) -> list[str]:
        """Engelli MAC listesi."""
        rc, out, _ = _run(["iptables", "-L", self.CHAIN, "-n"])
        blocked = []
        for line in out.splitlines():
            if "MAC" in line:
                parts = line.split()
                for p in parts:
                    if ":" in p and len(p) == 17:
                        blocked.append(p.upper())
        return blocked
    
    def flush(self):
        """Tüm kuralları temizle."""
        _run(["iptables", "-F", self.CHAIN])
        logger.info("iptables kuralları temizlendi.")


class ARPBlocker:
    """
    ARP zehirleme ile internet bağlantısını kes.
    Cihaza yanlış gateway MAC'i göndererek interneti keser.
    """
    
    def __init__(self, interface: str = "wlan0", gateway_ip: str = "192.168.1.1"):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self._threads: dict[str, threading.Thread] = {}
        self._active: set[str] = set()
    
    def _get_our_mac(self) -> str:
        try:
            return get_if_hwaddr(self.interface)
        except Exception:
            return "00:00:00:00:00:00"
    
    def _poison_loop(self, target_ip: str, target_mac: str):
        """Sürekli ARP paketi gönder (cihaza gateway olarak kendimizi tanıt)."""
        if not SCAPY_OK:
            return
        
        our_mac = self._get_our_mac()
        scapy_conf.verb = 0
        
        # Cihaza: "Ben gateway'im"
        pkt_to_target = Ether(dst=target_mac) / ARP(
            op=2,                    # is-at
            pdst=target_ip,
            hwdst=target_mac,
            psrc=self.gateway_ip,
            hwsrc=our_mac
        )
        
        while target_ip in self._active:
            try:
                sendp(pkt_to_target, iface=self.interface, verbose=False)
            except Exception as e:
                logger.error("ARP zehir hata: %s", e)
            time.sleep(2)
        
        logger.info("ARP zehirleme durduruldu: %s", target_ip)
    
    def block(self, target_ip: str, target_mac: str) -> bool:
        """Hedef IP'nin internetini kes."""
        if target_ip in self._active:
            return True
        if not SCAPY_OK:
            logger.error("Scapy yok — ARP engelleme devre dışı.")
            return False
        
        self._active.add(target_ip)
        t = threading.Thread(
            target=self._poison_loop,
            args=(target_ip, target_mac),
            daemon=True,
            name=f"ARP-{target_ip}"
        )
        self._threads[target_ip] = t
        t.start()
        logger.info("ARP engelleme başlatıldı: %s (%s)", target_ip, target_mac)
        return True
    
    def unblock(self, target_ip: str, target_mac: str):
        """ARP zehirlemeyi durdur ve tabloyu düzelt."""
        self._active.discard(target_ip)
        if not SCAPY_OK:
            return
        
        # Gerçek gateway MAC'ini yeniden gönder
        try:
            from scapy.all import getmacbyip
            gw_mac = getmacbyip(self.gateway_ip)
            if gw_mac:
                restore_pkt = Ether(dst=target_mac) / ARP(
                    op=2,
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=self.gateway_ip,
                    hwsrc=gw_mac
                )
                sendp(restore_pkt, iface=self.interface, count=5, verbose=False)
        except Exception as e:
            logger.warning("ARP geri yükleme hata: %s", e)
        
        logger.info("ARP engel kaldırıldı: %s", target_ip)


class DeviceBlocker:
    """
    Üst düzey cihaz engelleme yöneticisi.
    iptables + ARP yöntemlerini birlikte kullanır.
    """
    
    def __init__(self):
        from config import CONFIG
        self.cfg = CONFIG
        self._ipt = IptablesBlocker()
        self._arp = ARPBlocker(
            interface=CONFIG["network"]["interface"],
            gateway_ip=CONFIG["network"]["gateway"]
        )
        self.method = CONFIG["security"]["block_method"]  # "iptables" | "arp" | "both"
    
    def block(self, mac: str, ip: str) -> bool:
        """Cihazı engelle (yapılandırılmış yönteme göre)."""
        success = False
        
        if self.method in ("iptables", "both"):
            ok = self._ipt.block_mac(mac)
            if ok:
                self._ipt.block_ip(ip)
            success = ok or success
        
        if self.method in ("arp", "both"):
            ok = self._arp.block(ip, mac)
            success = ok or success
        
        logger.info("Cihaz engellendi: %s (%s) yöntem=%s", mac, ip, self.method)
        return success
    
    def unblock(self, mac: str, ip: str) -> bool:
        """Cihazın engelini kaldır."""
        if self.method in ("iptables", "both"):
            self._ipt.unblock_mac(mac)
            self._ipt.unblock_ip(ip)
        
        if self.method in ("arp", "both"):
            self._arp.unblock(ip, mac)
        
        logger.info("Cihaz engeli kaldırıldı: %s (%s)", mac, ip)
        return True
    
    def list_blocked(self) -> list[str]:
        return self._ipt.list_blocked()
    
    def flush_all(self):
        """Tüm engelleri kaldır."""
        self._ipt.flush()
        self._arp._active.clear()
        logger.info("Tüm engeller kaldırıldı.")
