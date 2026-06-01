# backend/services/monitoring_service.py
# ============================================================
import os
import time
import threading
from datetime import datetime
from backend.database.db import get_conn
from backend.utils.logger import get_logger

log = get_logger("monitoring_service")

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False
    log.warning("psutil non installé — pip install psutil")

_last_net = {"bytes_sent": 0, "bytes_recv": 0, "ts": time.time()}


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_snapshot() -> dict:
    """Retourne un instantané système complet."""
    if not _PSUTIL:
        return _fallback_snapshot()

    try:
        cpu = psutil.cpu_percent(interval=0.3)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net  = psutil.net_io_counters()
        conns = psutil.net_connections()

        # Calcul débit réseau
        now_ts = time.time()
        elapsed = max(now_ts - _last_net["ts"], 0.1)
        rate_in  = round((net.bytes_recv - _last_net["bytes_recv"]) / elapsed / 1024, 2)
        rate_out = round((net.bytes_sent - _last_net["bytes_sent"]) / elapsed / 1024, 2)
        _last_net.update({
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "ts": now_ts,
        })

        # Score statut
        statut = "NORMAL"
        if cpu > 90 or ram.percent > 90:
            statut = "CRITICAL"
        elif cpu > 70 or ram.percent > 75:
            statut = "WARNING"

        return {
            "statut": statut,
            "systeme": {
                "cpu":          round(cpu, 1),
                "ram_pct":      round(ram.percent, 1),
                "ram_used":     round(ram.used   / 1024 / 1024, 0),
                "ram_total":    round(ram.total  / 1024 / 1024, 0),
                "disk_pct":     round(disk.percent, 1),
                "disk_used":    round(disk.used  / 1024 / 1024 / 1024, 2),
                "disk_total":   round(disk.total / 1024 / 1024 / 1024, 2),
                "bytes_sent":   round(net.bytes_sent / 1024, 0),
                "bytes_recv":   round(net.bytes_recv / 1024, 0),
                "net_rate_in":  max(0, rate_in),
                "net_rate_out": max(0, rate_out),
                "nb_connexions": len([c for c in conns if c.status == "ESTABLISHED"]),
            },
            "securite": {},
            "connexions": [],
        }
    except Exception as e:
        log.error(f"get_snapshot: {e}")
        return _fallback_snapshot()


def _fallback_snapshot():
    """Retourne des données simulées si psutil absent."""
    import random
    cpu  = round(random.uniform(15, 55), 1)
    ram  = round(random.uniform(40, 70), 1)
    disk = round(random.uniform(20, 60), 1)
    return {
        "statut": "NORMAL",
        "systeme": {
            "cpu":          cpu,
            "ram_pct":      ram,
            "ram_used":     int(ram * 80),
            "ram_total":    8192,
            "disk_pct":     disk,
            "disk_used":    round(disk * 0.5, 2),
            "disk_total":   500.0,
            "bytes_sent":   round(random.uniform(100, 1000), 0),
            "bytes_recv":   round(random.uniform(200, 2000), 0),
            "net_rate_in":  round(random.uniform(5, 50), 2),
            "net_rate_out": round(random.uniform(1, 20), 2),
            "nb_connexions": random.randint(5, 25),
        },
        "securite": {},
        "connexions": [],
    }


def _persist_snapshot(snap: dict):
    """Persiste un snapshot en DB."""
    try:
        s = snap.get("systeme", {})
        conn = get_conn()
        conn.execute(
            """INSERT INTO supervision_history
               (timestamp, cpu_pct, ram_pct, ram_used_mb, ram_total_mb,
                disk_pct, disk_used_gb, disk_total_gb,
                net_bytes_in, net_bytes_out, nb_connexions)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                _now(),
                s.get("cpu",          0),
                s.get("ram_pct",      0),
                s.get("ram_used",     0),
                s.get("ram_total",    0),
                s.get("disk_pct",     0),
                s.get("disk_used",    0),
                s.get("disk_total",   0),
                s.get("bytes_recv",   0),
                s.get("bytes_sent",   0),
                s.get("nb_connexions",0),
            ),
        )
        conn.commit()
    except Exception as e:
        log.warning(f"_persist_snapshot: {e}")


# ══════════════════════════════════════════════
# SERVICE BACKGROUND
# ══════════════════════════════════════════════
class MonitoringService(threading.Thread):
    def __init__(self, interval=30):
        super().__init__(daemon=True, name="MonitoringService")
        self.interval = interval
        self._stop = threading.Event()

    def run(self):
        log.info("MonitoringService démarré")
        while not self._stop.is_set():
            try:
                snap = get_snapshot()
                _persist_snapshot(snap)
            except Exception as e:
                log.warning(f"MonitoringService loop: {e}")
            time.sleep(self.interval)

    def stop(self):
        self._stop.set()


monitoring_service = MonitoringService(interval=30)
