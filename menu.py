"""
NetGuard - Rich Tabanlı İnteraktif Terminal Arayüzü
Askeri tema, gerçek zamanlı veriler, tam kontrol.
"""
import os
import sys
import time
import threading
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from rich.align import Align
from rich.columns import Columns

console = Console()

BANNER = """[bold red]
 ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝[/bold red]
[dim]                 Askeri Düzey Ağ İzleme & Koruma Sistemi v1.0[/dim]
[red]              ┌─────────────────────────────────────────────┐[/red]
[red]              │   ⚠ SADECE YETKİLİ PERSONEL KULLANABİLİR ⚠  │[/red]
[red]              └─────────────────────────────────────────────┘[/red]"""


def _format_bytes(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _status_color(status: str) -> str:
    return {"allowed": "green", "blocked": "red", "unknown": "yellow"}.get(status, "white")


def _severity_color(sev: str) -> str:
    return {"low": "blue", "medium": "yellow", "high": "red", "critical": "bold red"}.get(sev, "white")


class MainMenu:
    def __init__(self):
        from database.db import Database
        from config import CONFIG
        self.db = Database()
        self.cfg = CONFIG
        self._scanner = None
        self._monitor = None
        self._scanner_running = False
        self._monitor_running = False

    # ─── SCANNER ─────────────────────────────────────────────────────────────

    def _get_scanner(self):
        if self._scanner is None:
            from scanner.network_scanner import NetworkScanner
            from config import CONFIG
            self._scanner = NetworkScanner(CONFIG)
        return self._scanner

    def _get_monitor(self):
        if self._monitor is None:
            from monitor.traffic_monitor import TrafficMonitor
            from config import CONFIG
            self._monitor = TrafficMonitor(CONFIG["network"]["interface"])
        return self._monitor

    # ─── MENÜLER ─────────────────────────────────────────────────────────────

    def show_banner(self):
        console.clear()
        console.print(BANNER)
        counts = self.db.get_device_count()
        unread = self.db.get_unread_alert_count()
        console.print(
            f"\n[dim] Cihazlar: [green]{counts['allowed']} izinli[/green] | "
            f"[red]{counts['blocked']} engelli[/red] | "
            f"[yellow]{counts['unknown']} bilinmeyen[/yellow]   "
            f"Uyarılar: [{'bold red' if unread > 0 else 'dim'}]{unread} okunmamış[/]"
            f"  {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}[/dim]\n"
        )

    def main_menu(self) -> str:
        items = [
            ("1", "🔍 Ağ Tarama",          "Cihazları keşfet"),
            ("2", "📋 Cihaz Listesi",       "Tüm cihazları görüntüle"),
            ("3", "🚫 Cihaz Engelle",       "Cihaza erişimi kes"),
            ("4", "✅ Engeli Kaldır",       "Cihazı izin listesine al"),
            ("5", "⭐ Whitelist Yönetimi",  "Güvenilen cihazlar"),
            ("6", "📡 Trafik İzleme",       "Anlık bağlantılar & uygulamalar"),
            ("7", "🔴 Canlı Monitör",       "Gerçek zamanlı ağ görünümü"),
            ("8", "🔔 Uyarılar",            "Güvenlik uyarıları"),
            ("9", "⚙️  Ayarlar",             "Sistem konfigürasyonu"),
            ("0", "❌ Çıkış",               "Programı kapat"),
        ]
        
        table = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0, 2))
        table.add_column("No", style="bold cyan", width=4)
        table.add_column("İşlem", style="bold white", width=25)
        table.add_column("Açıklama", style="dim")
        
        for num, action, desc in items:
            table.add_row(f"[{num}]", action, desc)
        
        console.print(Panel(table, title="[bold red]◈ ANA MENÜ ◈[/bold red]",
                            border_style="red", padding=(1, 2)))
        return Prompt.ask("[bold cyan]Seçiminiz[/bold cyan]", default="0")

    # ─── TARAMA ──────────────────────────────────────────────────────────────

    def do_scan(self):
        self.show_banner()
        console.print(Panel("[bold]Ağ Tarama Başlatılıyor...[/bold]", border_style="cyan"))
        
        scanner = self._get_scanner()
        
        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[cyan]{task.description}"),
            console=console
        ) as prog:
            task = prog.add_task("ARP tarama yapılıyor...", total=None)
            devices = scanner.scan_once()
            prog.update(task, description=f"✓ {len(devices)} cihaz bulundu")
            time.sleep(1)
        
        if not devices:
            console.print("[yellow]Ağda cihaz bulunamadı.[/yellow]")
            self._pause()
            return
        
        table = Table(
            title=f"[bold red]📡 BULUNAN CİHAZLAR ({len(devices)})[/bold red]",
            box=box.HEAVY_HEAD,
            border_style="red",
            show_lines=True
        )
        table.add_column("#",        width=4,  style="dim")
        table.add_column("IP",       width=16, style="cyan")
        table.add_column("MAC",      width=20, style="yellow")
        table.add_column("Hostname", width=20)
        table.add_column("Üretici",  width=22)
        table.add_column("Durum",    width=12)
        
        for i, dev in enumerate(devices, 1):
            db_dev = self.db.get_device(dev["mac"])
            status = db_dev["status"] if db_dev else "unknown"
            color = _status_color(status)
            table.add_row(
                str(i),
                dev["ip"],
                dev["mac"],
                dev["hostname"],
                dev["vendor"],
                f"[{color}]{status}[/{color}]"
            )
        
        console.print(table)
        self._pause()

    # ─── CİHAZ LİSTESİ ───────────────────────────────────────────────────────

    def show_devices(self):
        self.show_banner()
        devices = self.db.get_all_devices()
        
        if not devices:
            console.print("[yellow]Henüz kayıtlı cihaz yok. Önce tarama yapın.[/yellow]")
            self._pause()
            return
        
        table = Table(
            title=f"[bold red]◈ KAYITLI CİHAZLAR ({len(devices)}) ◈[/bold red]",
            box=box.HEAVY_HEAD,
            border_style="red",
            show_lines=True
        )
        table.add_column("IP",         width=16, style="cyan")
        table.add_column("MAC",        width=20, style="yellow")
        table.add_column("Hostname",   width=18)
        table.add_column("Üretici",    width=20)
        table.add_column("Durum",      width=10)
        table.add_column("WL",         width=4)
        table.add_column("Son Görülme",width=20, style="dim")
        
        for dev in devices:
            color = _status_color(dev["status"])
            wl = "⭐" if dev["is_whitelisted"] else ""
            table.add_row(
                dev["ip"],
                dev["mac"],
                dev["hostname"],
                dev["vendor"],
                f"[{color}]{dev['status']}[/{color}]",
                wl,
                dev["last_seen"][:19]
            )
        
        console.print(table)
        
        # Cihaz detayı
        console.print("\n[dim]Cihaz detayı için MAC girin (boş = geri)[/dim]")
        mac = Prompt.ask("[cyan]MAC[/cyan]", default="").strip().upper()
        if mac:
            self._show_device_detail(mac)
        return

    def _show_device_detail(self, mac: str):
        dev = self.db.get_device(mac)
        if not dev:
            console.print(f"[red]Cihaz bulunamadı: {mac}[/red]")
            self._pause()
            return
        
        import json
        ports = json.loads(dev.get("open_ports", "[]"))
        
        info = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        info.add_column("Alan",  style="bold cyan", width=18)
        info.add_column("Değer", style="white")
        
        rows = [
            ("IP Adresi",    dev["ip"]),
            ("MAC Adresi",   dev["mac"]),
            ("Hostname",     dev["hostname"]),
            ("Üretici",      dev["vendor"]),
            ("İşletim Sistemi", dev.get("os_guess") or "Bilinmiyor"),
            ("Açık Portlar", ", ".join(map(str, ports)) or "Taranmadı"),
            ("Durum",        dev["status"]),
            ("Whitelist",    "Evet ✅" if dev["is_whitelisted"] else "Hayır"),
            ("İlk Görülme",  dev["first_seen"][:19]),
            ("Son Görülme",  dev["last_seen"][:19]),
            ("Notlar",       dev.get("notes") or "-"),
        ]
        for k, v in rows:
            info.add_row(k, str(v))
        
        console.print(Panel(info, title=f"[bold red]CİHAZ DETAYI — {mac}[/bold red]",
                            border_style="red"))
        
        # Son bağlantılar
        conns = self.db.get_connections(mac, limit=10)
        if conns:
            ct = Table(title="[cyan]Son Bağlantılar[/cyan]", box=box.SIMPLE, show_lines=False)
            ct.add_column("Hedef IP",    style="yellow")
            ct.add_column("Port",        style="cyan")
            ct.add_column("Uygulama",    style="green")
            ct.add_column("Protokol")
            ct.add_column("Zaman",       style="dim")
            for c in conns:
                ct.add_row(c["dst_ip"], str(c["dst_port"]),
                           c["app_name"], c["protocol"], c["timestamp"][:19])
            console.print(ct)
        
        self._pause()

    # ─── ENGELLEME ────────────────────────────────────────────────────────────

    def do_block(self):
        self.show_banner()
        console.print(Panel("[bold red]🚫 CİHAZ ENGELLEME[/bold red]", border_style="red"))
        
        devices = [d for d in self.db.get_all_devices() if d["status"] != "blocked"]
        if not devices:
            console.print("[yellow]Engellenecek cihaz yok.[/yellow]")
            self._pause()
            return
        
        # Seçim listesi
        for i, d in enumerate(devices, 1):
            console.print(f"  [cyan]{i:2}.[/cyan] {d['ip']:16} {d['mac']:20} {d['vendor']}")
        
        console.print()
        choice = Prompt.ask("[bold]Engellenecek cihaz No veya MAC[/bold]", default="")
        
        mac = ip = None
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(devices):
                mac, ip = devices[idx]["mac"], devices[idx]["ip"]
        elif len(choice) == 17:
            mac = choice.upper()
            dev = self.db.get_device(mac)
            if dev:
                ip = dev["ip"]
        
        if not mac:
            console.print("[red]Geçersiz seçim.[/red]")
            self._pause()
            return
        
        reason = Prompt.ask("[dim]Engelleme sebebi (opsiyonel)[/dim]", default="")
        
        if not Confirm.ask(f"[bold red]{ip} ({mac}) engellensin mi?[/bold red]"):
            return
        
        from blocker.device_blocker import DeviceBlocker
        blocker = DeviceBlocker()
        
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as p:
            t = p.add_task("Engelleniyor...", total=None)
            ok = blocker.block(mac, ip)
            self.db.set_device_status(mac, "blocked")
            self.db.blacklist_device(mac, True)
            self.db.add_alert("manual_block", f"Engellendi: {ip} ({mac}) – {reason}", "high", mac, ip)
        
        if ok:
            console.print(f"\n[bold green]✅ {ip} ({mac}) başarıyla engellendi.[/bold green]")
        else:
            console.print(f"\n[yellow]⚠ Kısmi engelleme. root yetkisi gerekli olabilir.[/yellow]")
        self._pause()

    # ─── ENGEL KALDIRMA ───────────────────────────────────────────────────────

    def do_unblock(self):
        self.show_banner()
        console.print(Panel("[bold green]✅ ENGEL KALDIRMA[/bold green]", border_style="green"))
        
        devices = [d for d in self.db.get_all_devices() if d["status"] == "blocked"]
        if not devices:
            console.print("[yellow]Engelli cihaz yok.[/yellow]")
            self._pause()
            return
        
        for i, d in enumerate(devices, 1):
            console.print(f"  [cyan]{i:2}.[/cyan] {d['ip']:16} {d['mac']}")
        
        choice = Prompt.ask("[bold]Serbest bırakılacak cihaz No[/bold]", default="")
        if not choice.isdigit() or not (1 <= int(choice) <= len(devices)):
            console.print("[red]Geçersiz seçim.[/red]")
            self._pause()
            return
        
        dev = devices[int(choice) - 1]
        if not Confirm.ask(f"[green]{dev['ip']} ({dev['mac']}) engeli kaldırılsın mı?[/green]"):
            return
        
        from blocker.device_blocker import DeviceBlocker
        blocker = DeviceBlocker()
        blocker.unblock(dev["mac"], dev["ip"])
        self.db.set_device_status(dev["mac"], "allowed")
        self.db.blacklist_device(dev["mac"], False)
        
        console.print(f"\n[bold green]✅ Engel kaldırıldı: {dev['ip']}[/bold green]")
        self._pause()

    # ─── WHİTELİST ───────────────────────────────────────────────────────────

    def whitelist_menu(self):
        self.show_banner()
        console.print(Panel("[bold yellow]⭐ WHİTELİST YÖNETİMİ[/bold yellow]", border_style="yellow"))
        
        wl = [d for d in self.db.get_all_devices() if d["is_whitelisted"]]
        
        if wl:
            t = Table(title="Güvenilen Cihazlar", box=box.SIMPLE)
            t.add_column("IP");    t.add_column("MAC");    t.add_column("Üretici")
            for d in wl:
                t.add_row(d["ip"], d["mac"], d["vendor"])
            console.print(t)
        else:
            console.print("[dim]Whitelist boş.[/dim]\n")
        
        console.print("[cyan]1[/cyan] Ekle  [cyan]2[/cyan] Çıkar  [cyan]0[/cyan] Geri")
        choice = Prompt.ask("Seçim", default="0")
        
        if choice == "1":
            devices = [d for d in self.db.get_all_devices() if not d["is_whitelisted"]]
            for i, d in enumerate(devices, 1):
                console.print(f"  {i:2}. {d['ip']:16} {d['mac']}")
            c = Prompt.ask("Eklenecek cihaz No")
            if c.isdigit() and 1 <= int(c) <= len(devices):
                dev = devices[int(c) - 1]
                self.db.whitelist_device(dev["mac"], True)
                console.print(f"[green]✅ Eklendi: {dev['mac']}[/green]")
        elif choice == "2":
            for i, d in enumerate(wl, 1):
                console.print(f"  {i:2}. {d['ip']:16} {d['mac']}")
            c = Prompt.ask("Çıkarılacak cihaz No")
            if c.isdigit() and 1 <= int(c) <= len(wl):
                dev = wl[int(c) - 1]
                self.db.whitelist_device(dev["mac"], False)
                console.print(f"[yellow]Çıkarıldı: {dev['mac']}[/yellow]")
        
        self._pause()

    # ─── TRAFİK İZLEME ───────────────────────────────────────────────────────

    def show_traffic(self):
        self.show_banner()
        conns = self.db.get_connections(limit=50)
        apps  = self.db.get_top_apps(limit=10)
        
        if conns:
            ct = Table(
                title="[bold cyan]📡 SON BAĞLANTILAR[/bold cyan]",
                box=box.HEAVY_HEAD, border_style="cyan", show_lines=True
            )
            ct.add_column("Cihaz MAC",  width=20, style="yellow")
            ct.add_column("Kaynak",     width=16)
            ct.add_column("Hedef",      width=16, style="cyan")
            ct.add_column("Port",       width=7)
            ct.add_column("Uygulama",   width=22, style="green")
            ct.add_column("Protokol",   width=8)
            ct.add_column("Zaman",      width=20, style="dim")
            
            for c in conns:
                ct.add_row(
                    c["device_mac"], c["src_ip"], c["dst_ip"],
                    str(c["dst_port"]), c["app_name"], c["protocol"],
                    c["timestamp"][:19]
                )
            console.print(ct)
        
        if apps:
            at = Table(title="[bold green]🔝 EN ÇOK KULLANILAN UYGULAMALAR[/bold green]",
                       box=box.SIMPLE)
            at.add_column("Uygulama", style="green", width=25)
            at.add_column("Port",     style="cyan",  width=8)
            at.add_column("Bağlantı", style="white", width=10)
            at.add_column("Veri",     style="yellow", width=12)
            for a in apps:
                at.add_row(
                    a["app_name"], str(a["dst_port"]),
                    str(a["conn_count"]), _format_bytes(a["total_bytes"] or 0)
                )
            console.print(at)
        
        self._pause()

    # ─── CANLI MONİTÖR ───────────────────────────────────────────────────────

    def live_monitor(self):
        """Gerçek zamanlı güncellenen ekran."""
        monitor = self._get_monitor()
        if not self._monitor_running:
            monitor.start()
            self._monitor_running = True
        
        console.print("[dim]Canlı monitör. Çıkmak için [bold]CTRL+C[/bold][/dim]\n")
        time.sleep(1)
        
        try:
            with Live(console=console, refresh_per_second=2, screen=True) as live:
                while True:
                    stats = monitor.get_live_stats()
                    devices = self.db.get_all_devices()
                    counts = self.db.get_device_count()
                    
                    # Cihaz tablosu
                    dt = Table(
                        title=f"[bold red]◈ NETGUARD CANLI MONİTÖR — {datetime.now().strftime('%H:%M:%S')} ◈[/bold red]",
                        box=box.HEAVY, border_style="red", show_lines=False
                    )
                    dt.add_column("IP",       width=16, style="cyan")
                    dt.add_column("MAC",      width=20, style="yellow")
                    dt.add_column("Üretici",  width=20)
                    dt.add_column("Durum",    width=10)
                    dt.add_column("Son Görülme", width=20, style="dim")
                    
                    for dev in devices[:15]:
                        color = _status_color(dev["status"])
                        dt.add_row(
                            dev["ip"], dev["mac"], dev["vendor"],
                            f"[{color}]{dev['status']}[/{color}]",
                            dev["last_seen"][:19]
                        )
                    
                    # Trafik istatistikleri
                    top_apps = stats.get("top_apps", [])
                    at = Table(title="[cyan]En Çok Kullanılan Uygulamalar[/cyan]",
                               box=box.SIMPLE, show_lines=False)
                    at.add_column("Uygulama", style="green", width=28)
                    at.add_column("Sayı",     style="white",  width=8)
                    for app, cnt in top_apps[:6]:
                        at.add_row(app, str(cnt))
                    
                    # Özet
                    summary = (
                        f"[green]İzinli: {counts['allowed']}[/green]  "
                        f"[red]Engelli: {counts['blocked']}[/red]  "
                        f"[yellow]Bilinmeyen: {counts['unknown']}[/yellow]  "
                        f"[cyan]Pkt/s: {stats.get('pps', 0):.1f}[/cyan]  "
                        f"[white]Toplam Pkt: {stats.get('packet_count', 0)}[/white]"
                    )
                    
                    layout = Layout()
                    layout.split_column(
                        Layout(dt, name="devices"),
                        Layout(name="bottom", size=12)
                    )
                    layout["bottom"].split_row(
                        Layout(at, name="apps"),
                        Layout(Panel(summary, title="Özet", border_style="dim"), name="summary")
                    )
                    
                    live.update(layout)
                    time.sleep(2)
        except KeyboardInterrupt:
            pass

    # ─── UYARILAR ────────────────────────────────────────────────────────────

    def show_alerts(self):
        self.show_banner()
        alerts = self.db.get_alerts(limit=30)
        
        if not alerts:
            console.print("[dim]Uyarı yok.[/dim]")
            self._pause()
            return
        
        t = Table(
            title=f"[bold red]🔔 GÜVENLİK UYARILARI ({len(alerts)})[/bold red]",
            box=box.HEAVY_HEAD, border_style="red", show_lines=True
        )
        t.add_column("Seviye",  width=10)
        t.add_column("Tür",     width=18, style="cyan")
        t.add_column("Mesaj",   width=50)
        t.add_column("Zaman",   width=20, style="dim")
        t.add_column("Okundu",  width=8)
        
        for a in alerts:
            color = _severity_color(a["severity"])
            t.add_row(
                f"[{color}]{a['severity'].upper()}[/{color}]",
                a["type"],
                a["message"][:48],
                a["timestamp"][:19],
                "✅" if a["is_read"] else "🔴"
            )
        
        console.print(t)
        
        if Confirm.ask("[dim]Tümünü okundu işaretle?[/dim]", default=False):
            self.db.mark_alerts_read()
            console.print("[green]Tümü okundu olarak işaretlendi.[/green]")
        
        self._pause()

    # ─── AYARLAR ──────────────────────────────────────────────────────────────

    def show_settings(self):
        self.show_banner()
        from config import CONFIG, save_config
        
        table = Table(title="[bold]⚙️ SİSTEM AYARLARI[/bold]", box=box.SIMPLE, show_lines=True)
        table.add_column("Bölüm",   style="cyan",   width=12)
        table.add_column("Anahtar", style="yellow",  width=25)
        table.add_column("Değer",   style="green",   width=30)
        
        for section, values in CONFIG.items():
            if isinstance(values, dict):
                for key, val in values.items():
                    if key != "secret_key":
                        table.add_row(section, key, str(val))
        
        console.print(table)
        
        console.print("\n[dim]Değiştirmek için: bölüm.anahtar=değer (ör: network.scan_interval=60)[/dim]")
        entry = Prompt.ask("[cyan]Ayar[/cyan]", default="").strip()
        
        if "=" in entry and "." in entry:
            try:
                key_path, value = entry.split("=", 1)
                section, key = key_path.split(".", 1)
                
                # Tip dönüşümü
                if value.lower() in ("true", "false"):
                    value = value.lower() == "true"
                elif value.isdigit():
                    value = int(value)
                
                CONFIG[section][key] = value
                save_config(CONFIG)
                console.print(f"[green]✅ Güncellendi: {section}.{key} = {value}[/green]")
            except Exception as e:
                console.print(f"[red]Hata: {e}[/red]")
        
        self._pause()

    # ─── YARDIMCI ─────────────────────────────────────────────────────────────

    def _pause(self):
        console.print("\n[dim]Devam etmek için Enter...[/dim]", end="")
        input()

    # ─── ANA DÖNGÜ ────────────────────────────────────────────────────────────

    def run(self):
        """Ana program döngüsü."""
        # Arka planda tarayıcıyı başlat
        scanner = self._get_scanner()
        scanner.start()
        self._scanner_running = True
        
        # Trafik monitörünü başlat
        from config import CONFIG
        if CONFIG["monitor"]["capture_packets"]:
            monitor = self._get_monitor()
            monitor.start()
            self._monitor_running = True
        
        menu_map = {
            "1": self.do_scan,
            "2": self.show_devices,
            "3": self.do_block,
            "4": self.do_unblock,
            "5": self.whitelist_menu,
            "6": self.show_traffic,
            "7": self.live_monitor,
            "8": self.show_alerts,
            "9": self.show_settings,
        }
        
        while True:
            self.show_banner()
            choice = self.main_menu()
            
            if choice == "0":
                if Confirm.ask("[bold red]Çıkmak istediğinizden emin misiniz?[/bold red]"):
                    console.print("[bold red]NetGuard kapatılıyor...[/bold red]")
                    scanner.stop()
                    if self._monitor_running:
                        self._get_monitor().stop()
                    sys.exit(0)
            elif choice in menu_map:
                menu_map[choice]()
            else:
                console.print("[red]Geçersiz seçim.[/red]")
                time.sleep(1)
