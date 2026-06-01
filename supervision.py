# supervision.py — version sans psutil (lecture /proc directe)
import sqlite3
import time
import threading
from datetime import datetime
from database import DB_PATH


def init_supervision():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS supervision_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT,
            cpu_percent  REAL,
            ram_percent  REAL,
            ram_used_mb  INTEGER,
            disk_percent REAL,
            nb_appareils INTEGER DEFAULT 0,
            nb_alertes   INTEGER DEFAULT 0,
            nb_bloques   INTEGER DEFAULT 0,
            score_global INTEGER DEFAULT 0,
            statut       TEXT DEFAULT 'NORMAL'
        )
    """)
    conn.commit()
    conn.close()


def _read_cpu():
    try:
        with open('/proc/stat') as f:
            line = f.readline()
        vals = list(map(int, line.split()[1:]))
        idle  = vals[3]
        total = sum(vals)
        time.sleep(0.3)
        with open('/proc/stat') as f:
            line = f.readline()
        vals2  = list(map(int, line.split()[1:]))
        idle2  = vals2[3]
        total2 = sum(vals2)
        diff_idle  = idle2  - idle
        diff_total = total2 - total
        if diff_total == 0:
            return 0.0
        return round((1 - diff_idle / diff_total) * 100, 1)
    except:
        return 0.0


def _read_ram():
    try:
        info = {}
        with open('/proc/meminfo') as f:
            for line in f:
                k, v = line.split(':')
                info[k.strip()] = int(v.strip().split()[0])
        total     = info.get('MemTotal', 1)
        available = info.get('MemAvailable', total)
        used      = total - available
        pct       = round(used / total * 100, 1)
        return pct, used // 1024, total // 1024
    except:
        return 0.0, 0, 0


def _read_disk():
    try:
        import os
        st = os.statvfs('/')
        total = st.f_blocks * st.f_frsize
        free  = st.f_bavail * st.f_frsize
        used  = total - free
        pct   = round(used / total * 100, 1) if total else 0
        return pct, used // (1024**3), total // (1024**3)
    except:
        return 0.0, 0, 0


def _read_net():
    try:
        with open('/proc/net/dev') as f:
            lines = f.readlines()
        sent = recv = 0
        for line in lines[2:]:
            parts = line.split()
            if len(parts) >= 10:
                recv += int(parts[1])
                sent += int(parts[9])
        return sent // 1024, recv // 1024
    except:
        return 0, 0


def get_system_metrics():
    cpu             = _read_cpu()
    ram_pct, ram_mb, ram_total = _read_ram()
    disk_pct, disk_used, disk_total = _read_disk()
    bytes_sent, bytes_recv = _read_net()
    return {
        "cpu":        cpu,
        "ram_pct":    ram_pct,
        "ram_used":   ram_mb,
        "ram_total":  ram_total,
        "disk_pct":   disk_pct,
        "disk_used":  disk_used,
        "disk_total": disk_total,
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def get_security_metrics():
    conn = sqlite3.connect(DB_PATH)
    def q(sql, default=0):
        try:   return conn.execute(sql).fetchone()[0]
        except: return default

    nb_appareils        = q("SELECT COUNT(DISTINCT ip) FROM appareils")
    nb_alertes          = q("SELECT COUNT(*) FROM alertes")
    nb_alertes_critical = q("SELECT COUNT(*) FROM alertes WHERE niveau IN ('CRITICAL','HIGH')")
    nb_bloques          = q("SELECT COUNT(*) FROM blocages WHERE actif=1")
    nb_suricata         = q("SELECT COUNT(*) FROM suricata_alertes")

    scores = []
    try:
        rows = conn.execute("SELECT score FROM appareils WHERE score IS NOT NULL").fetchall()
        scores = [r[0] for r in rows]
    except: pass
    score_global = round(sum(scores) / len(scores)) if scores else 0

    derniere_alerte = None
    try:
        row = conn.execute(
            "SELECT message, niveau, date_alerte FROM alertes ORDER BY date_alerte DESC LIMIT 1"
        ).fetchone()
        if row:
            derniere_alerte = {"message": row[0], "niveau": row[1], "date": row[2]}
    except: pass

    conn.close()
    return {
        "nb_appareils":        nb_appareils,
        "nb_alertes":          nb_alertes,
        "nb_alertes_critical": nb_alertes_critical,
        "nb_bloques":          nb_bloques,
        "nb_suricata":         nb_suricata,
        "score_global":        score_global,
        "derniere_alerte":     derniere_alerte,
    }


def calculer_statut_global(sys_m, sec_m):
    problemes = []
    if sys_m["cpu"]     > 90: problemes.append("CPU critique")
    elif sys_m["cpu"]   > 70: problemes.append("CPU élevé")
    if sys_m["ram_pct"] > 90: problemes.append("RAM critique")
    elif sys_m["ram_pct"]> 75: problemes.append("RAM élevée")
    if sec_m["nb_alertes_critical"] > 5:  problemes.append("Nombreuses alertes critiques")
    elif sec_m["nb_alertes_critical"] > 0: problemes.append("Alertes critiques présentes")
    if sec_m["nb_bloques"] > 10: problemes.append("Nombreuses IPs bloquées")
    if sec_m["score_global"] < 50: problemes.append("Score sécurité critique")
    elif sec_m["score_global"] < 70: problemes.append("Score sécurité faible")

    if any("critique" in p.lower() for p in problemes): return "CRITICAL", problemes
    elif problemes: return "WARNING", problemes
    return "NORMAL", []


def get_snapshot():
    sys_m  = get_system_metrics()
    sec_m  = get_security_metrics()
    statut, problemes = calculer_statut_global(sys_m, sec_m)
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "statut":    statut,
        "problemes": problemes,
        "systeme":   sys_m,
        "securite":  sec_m,
    }


def sauvegarder_snapshot():
    snap  = get_snapshot()
    sys_m = snap["systeme"]
    sec_m = snap["securite"]
    conn  = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO supervision_history
        (timestamp, cpu_percent, ram_percent, ram_used_mb,
         disk_percent, nb_appareils, nb_alertes,
         nb_bloques, score_global, statut)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        snap["timestamp"], sys_m["cpu"], sys_m["ram_pct"],
        sys_m["ram_used"], sys_m["disk_pct"], sec_m["nb_appareils"],
        sec_m["nb_alertes"], sec_m["nb_bloques"],
        sec_m["score_global"], snap["statut"],
    ))
    conn.commit()
    conn.close()
    return snap


def get_historique_supervision(limit=20):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM supervision_history
        ORDER BY timestamp DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


_monitor_actif = False

def demarrer_monitoring(intervalle=30):
    global _monitor_actif
    if _monitor_actif:
        return
    _monitor_actif = True
    def _boucle():
        while _monitor_actif:
            try:   sauvegarder_snapshot()
            except: pass
            time.sleep(intervalle)
    threading.Thread(target=_boucle, daemon=True).start()


def arreter_monitoring():
    global _monitor_actif
    _monitor_actif = False


if __name__ == "__main__":
    init_supervision()
    snap = get_snapshot()
    print(f"CPU : {snap['systeme']['cpu']}%")
    print(f"RAM : {snap['systeme']['ram_pct']}%")
    print(f"Statut : {snap['statut']}")
