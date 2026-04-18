"""
NetGuard - SQLite Veritabanı Yöneticisi
Tüm cihaz, trafik ve uyarı verileri burada saklanır.
"""
import sqlite3
import threading
import time
import logging
from datetime import datetime
from pathlib import Path
from config import DB_PATH

logger = logging.getLogger("netguard.db")


class Database:
    """Thread-safe SQLite veritabanı yöneticisi."""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._local = threading.local()
        self.db_path = str(DB_PATH)
        self.initialize()
    
    def _get_conn(self) -> sqlite3.Connection:
        """Thread-local bağlantı döndür."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=10
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    @property
    def conn(self) -> sqlite3.Connection:
        return self._get_conn()

    def initialize(self):
        """Tablo yapısını oluştur."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS devices (
                mac         TEXT PRIMARY KEY,
                ip          TEXT,
                hostname    TEXT DEFAULT 'Bilinmiyor',
                vendor      TEXT DEFAULT 'Bilinmiyor',
                os_guess    TEXT,
                open_ports  TEXT DEFAULT '[]',
                status      TEXT DEFAULT 'unknown'
                    CHECK(status IN ('allowed','blocked','unknown')),
                is_whitelisted INTEGER DEFAULT 0,
                is_blacklisted INTEGER DEFAULT 0,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                notes       TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS connections (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac  TEXT REFERENCES devices(mac),
                src_ip      TEXT NOT NULL,
                dst_ip      TEXT NOT NULL,
                src_port    INTEGER,
                dst_port    INTEGER,
                protocol    TEXT,
                app_name    TEXT,
                bytes_sent  INTEGER DEFAULT 0,
                timestamp   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                type        TEXT NOT NULL,
                severity    TEXT NOT NULL
                    CHECK(severity IN ('low','medium','high','critical')),
                message     TEXT NOT NULL,
                device_mac  TEXT,
                device_ip   TEXT,
                is_read     INTEGER DEFAULT 0,
                timestamp   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT NOT NULL,
                devices_found   INTEGER DEFAULT 0,
                new_devices     INTEGER DEFAULT 0,
                scan_type       TEXT DEFAULT 'arp'
            );

            CREATE TABLE IF NOT EXISTS bandwidth (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac  TEXT REFERENCES devices(mac),
                bytes_in    INTEGER DEFAULT 0,
                bytes_out   INTEGER DEFAULT 0,
                period      TEXT NOT NULL,
                timestamp   TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_connections_mac ON connections(device_mac);
            CREATE INDEX IF NOT EXISTS idx_connections_ts  ON connections(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_read     ON alerts(is_read);
            CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(timestamp);
        """)
        self.conn.commit()
        logger.info("Veritabanı başlatıldı: %s", self.db_path)

    # ── DEVICE METHODS ──────────────────────────────────────────────────────

    def upsert_device(self, mac: str, ip: str, hostname: str = "Bilinmiyor",
                      vendor: str = "Bilinmiyor") -> bool:
        """Cihazı ekle veya güncelle. True = yeni cihaz."""
        now = datetime.now().isoformat()
        cur = self.conn.execute("SELECT mac, status FROM devices WHERE mac=?", (mac,))
        row = cur.fetchone()
        if row:
            self.conn.execute(
                "UPDATE devices SET ip=?, hostname=?, vendor=?, last_seen=? WHERE mac=?",
                (ip, hostname, vendor, now, mac)
            )
            self.conn.commit()
            return False
        else:
            self.conn.execute(
                """INSERT INTO devices (mac,ip,hostname,vendor,first_seen,last_seen)
                   VALUES (?,?,?,?,?,?)""",
                (mac, ip, hostname, vendor, now, now)
            )
            self.conn.commit()
            return True  # yeni cihaz

    def get_all_devices(self) -> list:
        cur = self.conn.execute("SELECT * FROM devices ORDER BY last_seen DESC")
        return [dict(r) for r in cur.fetchall()]

    def get_device(self, mac: str) -> dict | None:
        cur = self.conn.execute("SELECT * FROM devices WHERE mac=?", (mac,))
        row = cur.fetchone()
        return dict(row) if row else None

    def set_device_status(self, mac: str, status: str) -> bool:
        cur = self.conn.execute(
            "UPDATE devices SET status=? WHERE mac=?", (status, mac)
        )
        self.conn.commit()
        return cur.rowcount > 0

    def whitelist_device(self, mac: str, add: bool = True) -> bool:
        cur = self.conn.execute(
            "UPDATE devices SET is_whitelisted=?, status=? WHERE mac=?",
            (1 if add else 0, "allowed" if add else "unknown", mac)
        )
        self.conn.commit()
        return cur.rowcount > 0

    def blacklist_device(self, mac: str, add: bool = True) -> bool:
        cur = self.conn.execute(
            "UPDATE devices SET is_blacklisted=?, status=? WHERE mac=?",
            (1 if add else 0, "blocked" if add else "unknown", mac)
        )
        self.conn.commit()
        return cur.rowcount > 0

    def update_device_ports(self, mac: str, ports: list, os_guess: str = None):
        import json
        self.conn.execute(
            "UPDATE devices SET open_ports=?, os_guess=? WHERE mac=?",
            (json.dumps(ports), os_guess, mac)
        )
        self.conn.commit()

    def get_device_count(self) -> dict:
        cur = self.conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status='allowed'  THEN 1 ELSE 0 END) as allowed,
                SUM(CASE WHEN status='blocked'  THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN status='unknown'  THEN 1 ELSE 0 END) as unknown
            FROM devices
        """)
        return dict(cur.fetchone())

    # ── CONNECTION METHODS ──────────────────────────────────────────────────

    def log_connection(self, device_mac: str, src_ip: str, dst_ip: str,
                       src_port: int, dst_port: int, protocol: str,
                       app_name: str, bytes_sent: int = 0):
        now = datetime.now().isoformat()
        self.conn.execute(
            """INSERT INTO connections
               (device_mac,src_ip,dst_ip,src_port,dst_port,protocol,app_name,bytes_sent,timestamp)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (device_mac, src_ip, dst_ip, src_port, dst_port, protocol, app_name, bytes_sent, now)
        )
        self.conn.commit()

    def get_connections(self, mac: str = None, limit: int = 100) -> list:
        if mac:
            cur = self.conn.execute(
                "SELECT * FROM connections WHERE device_mac=? ORDER BY timestamp DESC LIMIT ?",
                (mac, limit)
            )
        else:
            cur = self.conn.execute(
                "SELECT * FROM connections ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
        return [dict(r) for r in cur.fetchall()]

    def get_top_apps(self, mac: str = None, limit: int = 10) -> list:
        where = "WHERE device_mac=?" if mac else ""
        params = (mac, limit) if mac else (limit,)
        cur = self.conn.execute(f"""
            SELECT app_name, dst_ip, dst_port,
                   COUNT(*) as conn_count, SUM(bytes_sent) as total_bytes
            FROM connections {where}
            GROUP BY app_name, dst_port
            ORDER BY conn_count DESC LIMIT ?
        """, params)
        return [dict(r) for r in cur.fetchall()]

    # ── ALERT METHODS ───────────────────────────────────────────────────────

    def add_alert(self, alert_type: str, message: str, severity: str = "medium",
                  device_mac: str = None, device_ip: str = None):
        now = datetime.now().isoformat()
        self.conn.execute(
            """INSERT INTO alerts (type,severity,message,device_mac,device_ip,timestamp)
               VALUES (?,?,?,?,?,?)""",
            (alert_type, severity, message, device_mac, device_ip, now)
        )
        self.conn.commit()

    def get_alerts(self, unread_only: bool = False, limit: int = 50) -> list:
        where = "WHERE is_read=0" if unread_only else ""
        cur = self.conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    def mark_alerts_read(self):
        self.conn.execute("UPDATE alerts SET is_read=1")
        self.conn.commit()

    def get_unread_alert_count(self) -> int:
        cur = self.conn.execute("SELECT COUNT(*) FROM alerts WHERE is_read=0")
        return cur.fetchone()[0]

    # ── SCAN HISTORY ────────────────────────────────────────────────────────

    def log_scan(self, devices_found: int, new_devices: int, scan_type: str = "arp"):
        now = datetime.now().isoformat()
        self.conn.execute(
            "INSERT INTO scan_history (timestamp,devices_found,new_devices,scan_type) VALUES (?,?,?,?)",
            (now, devices_found, new_devices, scan_type)
        )
        self.conn.commit()

    def get_scan_history(self, limit: int = 20) -> list:
        cur = self.conn.execute(
            "SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    # ── BANDWIDTH ───────────────────────────────────────────────────────────

    def log_bandwidth(self, mac: str, bytes_in: int, bytes_out: int):
        now = datetime.now().isoformat()
        period = datetime.now().strftime("%Y-%m-%d %H:00")
        self.conn.execute(
            """INSERT INTO bandwidth (device_mac,bytes_in,bytes_out,period,timestamp)
               VALUES (?,?,?,?,?)""",
            (mac, bytes_in, bytes_out, period, now)
        )
        self.conn.commit()

    def get_bandwidth_stats(self, mac: str = None) -> list:
        where = "WHERE device_mac=?" if mac else ""
        params = (mac,) if mac else ()
        cur = self.conn.execute(f"""
            SELECT device_mac, period,
                   SUM(bytes_in) as total_in, SUM(bytes_out) as total_out
            FROM bandwidth {where}
            GROUP BY device_mac, period
            ORDER BY period DESC LIMIT 48
        """, params)
        return [dict(r) for r in cur.fetchall()]
