"""
NetGuard - FastAPI REST API Sunucusu
Tüm yönetim işlemleri bu API üzerinden yapılır.
"""
import logging
import asyncio
import json
import time
from datetime import datetime
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger("netguard.api")

# ── PYDANTIC MODELLER ────────────────────────────────────────────────────────

class DeviceNote(BaseModel):
    notes: str

class BlockRequest(BaseModel):
    reason: Optional[str] = None

class ConfigUpdate(BaseModel):
    section: str
    key: str
    value: object

class ScanRequest(BaseModel):
    subnet: Optional[str] = None
    interface: Optional[str] = None

# ── APP FACTORY ──────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    from database.db import Database
    from config import CONFIG, save_config

    app = FastAPI(
        title="NetGuard API",
        description="Askeri Düzey Ağ İzleme & Koruma Sistemi",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    db = Database()
    
    # WebSocket bağlantı havuzu
    _ws_clients: list[WebSocket] = []
    
    # ── SYSTEM ────────────────────────────────────────────────────────────────
    
    @app.get("/", tags=["System"])
    def root():
        return {
            "system": "NetGuard",
            "version": "1.0.0",
            "status": "online",
            "timestamp": datetime.now().isoformat()
        }
    
    @app.get("/api/status", tags=["System"])
    def get_status():
        counts = db.get_device_count()
        unread = db.get_unread_alert_count()
        return {
            "devices": counts,
            "unread_alerts": unread,
            "scan_history": db.get_scan_history(limit=5),
            "timestamp": datetime.now().isoformat()
        }
    
    @app.get("/api/config", tags=["System"])
    def get_config():
        from config import CONFIG as CFG
        return CFG
    
    @app.put("/api/config", tags=["System"])
    def update_config(body: ConfigUpdate):
        from config import CONFIG as CFG, save_config
        if body.section not in CFG:
            raise HTTPException(404, f"Bölüm bulunamadı: {body.section}")
        if body.key not in CFG[body.section]:
            raise HTTPException(404, f"Anahtar bulunamadı: {body.key}")
        CFG[body.section][body.key] = body.value
        save_config(CFG)
        return {"ok": True, "updated": f"{body.section}.{body.key}"}
    
    # ── DEVICES ───────────────────────────────────────────────────────────────
    
    @app.get("/api/devices", tags=["Devices"])
    def list_devices(
        status: Optional[str] = Query(None, description="allowed|blocked|unknown"),
        whitelisted: Optional[bool] = None
    ):
        devices = db.get_all_devices()
        if status:
            devices = [d for d in devices if d["status"] == status]
        if whitelisted is not None:
            devices = [d for d in devices if bool(d["is_whitelisted"]) == whitelisted]
        return {"count": len(devices), "devices": devices}
    
    @app.get("/api/devices/{mac}", tags=["Devices"])
    def get_device(mac: str):
        dev = db.get_device(mac.upper())
        if not dev:
            raise HTTPException(404, "Cihaz bulunamadı")
        dev["connections"] = db.get_connections(mac.upper(), limit=20)
        dev["top_apps"] = db.get_top_apps(mac.upper())
        dev["bandwidth"] = db.get_bandwidth_stats(mac.upper())
        return dev
    
    @app.post("/api/devices/{mac}/block", tags=["Devices"])
    def block_device(mac: str, body: BlockRequest = BlockRequest()):
        mac = mac.upper()
        dev = db.get_device(mac)
        if not dev:
            raise HTTPException(404, "Cihaz bulunamadı")
        
        from blocker.device_blocker import DeviceBlocker
        blocker = DeviceBlocker()
        ok = blocker.block(mac, dev["ip"])
        
        db.set_device_status(mac, "blocked")
        db.blacklist_device(mac, add=True)
        db.add_alert(
            alert_type="manual_block",
            severity="high",
            message=f"Manuel engelleme: {dev['ip']} ({mac}) - {body.reason or 'sebep belirtilmedi'}",
            device_mac=mac,
            device_ip=dev["ip"]
        )
        return {"ok": ok, "mac": mac, "ip": dev["ip"], "status": "blocked"}
    
    @app.post("/api/devices/{mac}/unblock", tags=["Devices"])
    def unblock_device(mac: str):
        mac = mac.upper()
        dev = db.get_device(mac)
        if not dev:
            raise HTTPException(404, "Cihaz bulunamadı")
        
        from blocker.device_blocker import DeviceBlocker
        blocker = DeviceBlocker()
        blocker.unblock(mac, dev["ip"])
        
        db.set_device_status(mac, "allowed")
        db.blacklist_device(mac, add=False)
        return {"ok": True, "mac": mac, "status": "allowed"}
    
    @app.post("/api/devices/{mac}/whitelist", tags=["Devices"])
    def whitelist_device(mac: str):
        mac = mac.upper()
        ok = db.whitelist_device(mac, add=True)
        if not ok:
            raise HTTPException(404, "Cihaz bulunamadı")
        return {"ok": True, "mac": mac, "whitelisted": True}
    
    @app.delete("/api/devices/{mac}/whitelist", tags=["Devices"])
    def remove_whitelist(mac: str):
        mac = mac.upper()
        ok = db.whitelist_device(mac, add=False)
        return {"ok": ok, "mac": mac, "whitelisted": False}
    
    @app.put("/api/devices/{mac}/notes", tags=["Devices"])
    def update_notes(mac: str, body: DeviceNote):
        mac = mac.upper()
        db.conn.execute("UPDATE devices SET notes=? WHERE mac=?", (body.notes, mac))
        db.conn.commit()
        return {"ok": True}
    
    # ── SCAN ──────────────────────────────────────────────────────────────────
    
    @app.post("/api/scan", tags=["Scanner"])
    def trigger_scan(body: ScanRequest = ScanRequest()):
        from scanner.network_scanner import scan_network
        from config import CONFIG as CFG
        
        subnet = body.subnet or CFG["network"]["subnet"]
        iface  = body.interface or CFG["network"]["interface"]
        
        devices = scan_network(subnet, iface)
        new_count = 0
        for dev in devices:
            is_new = db.upsert_device(dev["mac"], dev["ip"], dev["hostname"], dev["vendor"])
            if is_new:
                new_count += 1
        db.log_scan(len(devices), new_count)
        
        return {
            "ok": True,
            "subnet": subnet,
            "devices_found": len(devices),
            "new_devices": new_count,
            "devices": devices
        }
    
    @app.get("/api/scan/history", tags=["Scanner"])
    def scan_history(limit: int = 20):
        return {"history": db.get_scan_history(limit)}
    
    # ── MONITOR ───────────────────────────────────────────────────────────────
    
    @app.get("/api/monitor/traffic", tags=["Monitor"])
    def get_traffic(mac: Optional[str] = None, limit: int = 100):
        conns = db.get_connections(mac.upper() if mac else None, limit)
        return {"count": len(conns), "connections": conns}
    
    @app.get("/api/monitor/apps", tags=["Monitor"])
    def get_apps(mac: Optional[str] = None):
        apps = db.get_top_apps(mac.upper() if mac else None)
        return {"apps": apps}
    
    @app.get("/api/monitor/bandwidth", tags=["Monitor"])
    def get_bandwidth(mac: Optional[str] = None):
        stats = db.get_bandwidth_stats(mac.upper() if mac else None)
        return {"bandwidth": stats}
    
    @app.get("/api/monitor/live", tags=["Monitor"])
    def get_live():
        """Anlık trafik istatistikleri (Traffic Monitor çalışıyorsa)."""
        try:
            from monitor.traffic_monitor import TrafficMonitor
            # Singleton instance
            from main import _traffic_monitor
            if _traffic_monitor:
                return _traffic_monitor.get_live_stats()
        except Exception:
            pass
        return {"running": False, "message": "Trafik monitörü başlatılmamış"}
    
    # ── ALERTS ────────────────────────────────────────────────────────────────
    
    @app.get("/api/alerts", tags=["Alerts"])
    def get_alerts(unread_only: bool = False, limit: int = 50):
        alerts = db.get_alerts(unread_only, limit)
        return {"count": len(alerts), "alerts": alerts}
    
    @app.post("/api/alerts/read", tags=["Alerts"])
    def mark_read():
        db.mark_alerts_read()
        return {"ok": True}
    
    # ── WEBSOCKET (gerçek zamanlı) ─────────────────────────────────────────
    
    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        await ws.accept()
        _ws_clients.append(ws)
        logger.info("WebSocket bağlandı: %s", ws.client)
        try:
            while True:
                # Her 3 saniyede durum gönder
                stats = {
                    "type": "status",
                    "devices": db.get_device_count(),
                    "alerts": db.get_unread_alert_count(),
                    "recent_alerts": db.get_alerts(unread_only=True, limit=5),
                    "timestamp": datetime.now().isoformat()
                }
                await ws.send_text(json.dumps(stats, ensure_ascii=False))
                await asyncio.sleep(3)
        except WebSocketDisconnect:
            _ws_clients.remove(ws)
            logger.info("WebSocket ayrıldı: %s", ws.client)
        except Exception as e:
            logger.debug("WebSocket hata: %s", e)
            if ws in _ws_clients:
                _ws_clients.remove(ws)
    
    return app


# ── SUNUCU BAŞLATICI ─────────────────────────────────────────────────────────

_app_instance = None

def get_app() -> FastAPI:
    global _app_instance
    if _app_instance is None:
        _app_instance = create_app()
    return _app_instance


def start_api_server(host: str = "0.0.0.0", port: int = 8000):
    """API sunucusunu başlat (blocking)."""
    app = get_app()
    logger.info("API sunucusu başlatılıyor: http://%s:%d", host, port)
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False
    )
