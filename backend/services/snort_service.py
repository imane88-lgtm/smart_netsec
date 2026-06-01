import os
import re
import time
import threading
import subprocess
import random
from datetime import datetime
from backend.database.db import get_conn
from backend.utils.logger import get_logger

log = get_logger("snort_service")

# Chemins Snort
SNORT_LOG_PATHS = [
    "/var/log/snort/alert.fast",
    "/var/log/snort/alert",
    "/var/log/snort/alert.log",
    os.path.expanduser("~/smart_netsec/services/snort/log/alert.fast"),
    "/tmp/snort_alert.log",
]

_DEMO_ALERTS = [
    {
        "sid": "9000001", "revision": "1", "priority": 1,
        "classification": "attempted-recon",
        "message": "ET SCAN Nmap Aggressive Scan Detected",
        "src_ip": "192.168.216.50", "src_port": "52341",
        "dst_ip":  "192.168.216.143","dst_port": "0",
        "protocole": "ICMP", "niveau": "CRITICAL",
        "action_prise": "BLOCKED",
    },
    {
        "sid": "9000002", "revision": "1", "priority": 2,
        "classification": "attempted-dos",
        "message": "ET ATTACK SSH BruteForce Attempt",
        "src_ip": "192.168.216.50", "src_port": "44321",
        "dst_ip":  "192.168.216.143","dst_port": "22",
        "protocole": "TCP", "niveau": "HIGH",
        "action_prise": "BLOCKED",
    },
    {
        "sid": "9000003", "revision": "1", "priority": 1,
        "classification": "attempted-admin",
        "message": "ET EXPLOIT EternalBlue MS17-010 SMB Exploit Pattern",
        "src_ip": "10.0.0.50", "src_port": "62100",
        "dst_ip":  "192.168.216.143","dst_port": "445",
        "protocole": "TCP", "niveau": "CRITICAL",
        "action_prise": "BLOCKED",
    },
    {
        "sid": "9000004", "revision": "1", "priority": 2,
        "classification": "trojan-activity",
        "message": "ET MALWARE CobaltStrike Beacon Detected",
        "src_ip": "185.220.101.45", "src_port": "443",
        "dst_ip":  "192.168.216.143","dst_port": "58921",
        "protocole": "TCP", "niveau": "HIGH",
        "action_prise": "BLOCKED",
    },
    {
        "sid": "9000005", "revision": "1", "priority": 3,
        "classification": "web-application-attack",
        "message": "ET WEB_SERVER SQL Injection Attempt (UNION SELECT)",
        "src_ip": "192.168.216.1", "src_port": "38920",
        "dst_ip":  "192.168.216.143","dst_port": "80",
        "protocole": "TCP", "niveau": "MEDIUM",
        "action_prise": "MONITOR",
    },
    {
        "sid": "9000006", "revision": "1", "priority": 3,
        "classification": "policy-violation",
        "message": "ET DNS Suspicious Query — Possible DGA Domain",
        "src_ip": "192.168.216.2", "src_port": "52456",
        "dst_ip":  "8.8.8.8",      "dst_port": "53",
        "protocole": "UDP", "niveau": "MEDIUM",
        "action_prise": "LOG",
    },
    {
        "sid": "9000007", "revision": "1", "priority": 2,
        "classification": "attempted-dos",
        "message": "ET DOS SYN Flood Detected — Possible DDoS",
        "src_ip": "103.35.74.55", "src_port": "0",
        "dst_ip":  "192.168.216.143","dst_port": "80",
        "protocole": "TCP", "niveau": "HIGH",
        "action_prise": "BLOCKED",
    },
    {
        "sid": "9000008", "revision": "1", "priority": 4,
        "classification": "misc-activity",
        "message": "ET INFO Reverse Shell over TCP Detected",
        "src_ip": "192.168.216.50", "src_port": "4444",
        "dst_ip":  "10.10.10.5",    "dst_port": "58432",
        "protocole": "TCP", "niveau": "LOW",
        "action_prise": "LOG",
    },
    {
        "sid": "9000009", "revision": "1", "priority": 1,
        "classification": "successful-recon-limited",
        "message": "ET SCAN Masscan Port Scan Detected",
        "src_ip": "45.142.212.18", "src_port": "61000",
        "dst_ip":  "192.168.216.0", "dst_port": "0",
        "protocole": "TCP", "niveau": "CRITICAL",
        "action_prise": "BLOCKED",
    },
    {
        "sid": "9000010", "revision": "1", "priority": 2,
        "classification": "web-application-attack",
        "message": "ET WEB_SERVER XSS Attempt in HTTP Request",
        "src_ip": "192.168.216.1", "src_port": "44200",
        "dst_ip":  "192.168.216.143","dst_port": "443",
        "protocole": "TCP", "niveau": "HIGH",
        "action_prise": "MONITOR",
    },
]


# ══════════════════════════════════════════════
# PARSING alert.fast
# ══════════════════════════════════════════════
_FAST_RE = re.compile(
    r'^(?P<ts>\d{2}/\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
    r'(?P<msg>.+?)\s+\[\*\*\]'
    r'.*?\[Priority:\s*(?P<prio>\d+)\]'
    r'.*?(?P<proto>TCP|UDP|ICMP|GRE)\s+'
    r'(?P<sip>[\d\.]+)(?::(?P<sport>\d+))?\s+->\s+'
    r'(?P<dip>[\d\.]+)(?::(?P<dport>\d+))?',
    re.IGNORECASE,
)

_CLASS_RE  = re.compile(r'\[Classification:\s*([^\]]+)\]')
_IFACE_RE  = re.compile(r'\{(\w+)\}')


def _parse_fast_line(line: str) -> dict | None:
    m = _FAST_RE.search(line)
    if not m:
        return None
    prio = int(m.group("prio") or 3)
    niveau_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
    niveau = niveau_map.get(prio, "LOW")
    cm = _CLASS_RE.search(line)
    classif = cm.group(1).strip() if cm else "misc-activity"
    ts_raw = m.group("ts")
    try:
        ts = datetime.strptime(ts_raw, "%m/%d/%y-%H:%M:%S.%f").strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "timestamp":     ts,
        "sid":           m.group("sid"),
        "revision":      m.group("rev"),
        "priority":      prio,
        "classification": classif,
        "message":       m.group("msg").strip(),
        "src_ip":        m.group("sip"),
        "src_port":      m.group("sport") or "0",
        "dst_ip":        m.group("dip"),
        "dst_port":      m.group("dport") or "0",
        "protocole":     m.group("proto").upper(),
        "niveau":        niveau,
        "action_prise":  "BLOCKED" if prio == 1 else ("MONITOR" if prio == 2 else "LOG"),
        "interface":     "eth0",
        "traite":        0,
    }


def import_snort_alerts() -> int:
    """Lit alert.fast et insère les nouvelles entrées en DB."""
    log_file = None
    for p in SNORT_LOG_PATHS:
        if os.path.exists(p):
            log_file = p
            break
    if not log_file:
        log.info("alert.fast introuvable — utiliser inject_demo_alerts()")
        return 0

    conn = get_conn()
    last_ts = conn.execute(
        "SELECT MAX(timestamp) FROM snort_alertes"
    ).fetchone()[0] or "2000-01-01 00:00:00"

    imported = 0
    try:
        with open(log_file, errors="replace") as f:
            for line in f:
                parsed = _parse_fast_line(line.strip())
                if not parsed:
                    continue
                if parsed["timestamp"] <= last_ts:
                    continue
                _insert_alert(conn, parsed)
                imported += 1
        conn.commit()
        log.info(f"Importé {imported} alertes depuis {log_file}")
    except Exception as e:
        log.error(f"import_snort_alerts: {e}")
    return imported


def _insert_alert(conn, a: dict):
    """Insère une alerte Snort en DB (ignore si déjà présente)."""
    conn.execute(
        """INSERT OR IGNORE INTO snort_alertes
           (timestamp, sid, revision, priority, classification,
            message, src_ip, src_port, dst_ip, dst_port,
            protocole, niveau, action_prise, interface, traite)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            a.get("timestamp"), a.get("sid"), a.get("revision"),
            a.get("priority"), a.get("classification"), a.get("message"),
            a.get("src_ip"), a.get("src_port"), a.get("dst_ip"), a.get("dst_port"),
            a.get("protocole"), a.get("niveau"), a.get("action_prise"),
            a.get("interface", "eth0"), 0,
        ),
    )


def inject_demo_alerts() -> int:
    """Injecte des alertes de démonstration si la DB est vide."""
    conn = get_conn()
    count = conn.execute("SELECT COUNT(*) FROM snort_alertes").fetchone()[0]
    if count > 0:
        return 0
    now = datetime.now()
    for i, a in enumerate(_DEMO_ALERTS):
        ts = now.strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            """INSERT INTO snort_alertes
               (timestamp, sid, revision, priority, classification,
                message, src_ip, src_port, dst_ip, dst_port,
                protocole, niveau, action_prise, interface, traite)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                ts, a["sid"], a["revision"], a["priority"],
                a["classification"], a["message"],
                a["src_ip"], a["src_port"], a["dst_ip"], a["dst_port"],
                a["protocole"], a["niveau"], a["action_prise"], "eth0", 0,
            ),
        )
    conn.commit()
    log.info(f"Injecté {len(_DEMO_ALERTS)} alertes démo")
    return len(_DEMO_ALERTS)


# ══════════════════════════════════════════════
# STATUT / CONTRÔLE SNORT
# ══════════════════════════════════════════════
def is_snort_running() -> bool:
    """Détection robuste du processus Snort."""
    # Méthode 1: pgrep
    try:
        r = subprocess.run(["pgrep","-f","snort"],
                          capture_output=True, timeout=3)
        if r.returncode == 0 and r.stdout.strip():
            return True
    except Exception:
        pass
    # Méthode 2: ps aux
    try:
        r = subprocess.run(["ps","aux"], capture_output=True, text=True, timeout=3)
        if "snort" in r.stdout.lower():
            for line in r.stdout.splitlines():
                if "snort" in line.lower() and "grep" not in line:
                    return True
    except Exception:
        pass
    return False


def start_snort():
    """Démarre Snort 3 avec la config locale."""
    if is_snort_running():
        return True, "✅ Snort déjà actif"

    os.makedirs("/var/log/snort", exist_ok=True)

    # Config Snort 3
    cfg   = "/etc/snort/snort_local.lua"
    rules = "/etc/snort/rules/local.rules"
    alt_cfg   = os.path.expanduser("~/smart_netsec/services/snort/snort_local.lua")
    alt_rules = os.path.expanduser("~/smart_netsec/services/snort/rules/local.rules")

    if not os.path.exists(cfg) and os.path.exists(alt_cfg):
        cfg   = alt_cfg
        rules = alt_rules

    if os.path.exists(cfg):
        cmd = ["sudo","snort","-c",cfg,"-R",rules,
               "-i","eth0","-A","alert_fast",
               "-l","/var/log/snort","-D","-q"]
    else:
        # Snort 2 fallback
        cmd = ["sudo","snort","-c","/etc/snort/snort.conf",
               "-D","-i","eth0","-l","/var/log/snort"]

    try:
        p = subprocess.Popen(cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        time.sleep(2.5)
        if is_snort_running():
            log.info("✅ Snort démarré")
            return True, "✅ Snort démarré"
        # Vérifier code de retour
        if p.poll() is not None and p.returncode != 0:
            return False, f"Snort s'est arrêté (code {p.returncode})"
        return False, "⚠️ Snort démarré mais processus non confirmé"
    except FileNotFoundError:
        return False, "❌ Snort non trouvé — sudo apt install snort"
    except Exception as e:
        return False, f"Erreur démarrage: {e}"


def stop_snort():
    try:
        subprocess.run(["pkill", "-x", "snort"], timeout=5)
        return True, "⏹ Snort arrêté"
    except Exception as e:
        return False, f"Erreur : {e}"


# ══════════════════════════════════════════════
# WATCHER BACKGROUND THREAD
# ══════════════════════════════════════════════
class SnortWatcher(threading.Thread):
    """Thread daemon qui surveille alert.fast et importe en continu."""
    def __init__(self):
        super().__init__(daemon=True, name="SnortWatcher")
        self._stop = threading.Event()

    def run(self):
        log.info("SnortWatcher démarré")
        log_file = None
        pos = 0
        while not self._stop.is_set():
            # Chercher le fichier de log
            if not log_file:
                for p in SNORT_LOG_PATHS:
                    if os.path.exists(p):
                        log_file = p
                        pos = os.path.getsize(p)
                        break
            if log_file:
                try:
                    with open(log_file, errors="replace") as f:
                        f.seek(pos)
                        lines = f.readlines()
                        pos = f.tell()
                    if lines:
                        conn = get_conn()
                        cnt = 0
                        for line in lines:
                            parsed = _parse_fast_line(line.strip())
                            if parsed:
                                _insert_alert(conn, parsed)
                                cnt += 1
                        if cnt:
                            conn.commit()
                            # Auto-block CRITICAL/HIGH
                            for line in lines:
                                parsed = _parse_fast_line(line.strip())
                                if parsed and parsed.get('priority',3) <= 2:
                                    try:
                                        from backend.services.firewall_service import auto_response
                                        from backend.database import repositories as repo
                                        ip = parsed.get('src_ip','')
                                        if ip and not repo.is_whitelisted(ip):
                                            auto_response(ip, parsed['niveau'], parsed['message'])
                                    except Exception:
                                        pass
                            log.debug(f"SnortWatcher: {cnt} nouvelles alertes")
                except Exception as e:
                    log.warning(f"SnortWatcher read: {e}")
            time.sleep(5)

    def start_watch(self):
        if not self.is_alive():
            self.start()

    def stop_watch(self):
        self._stop.set()


snort_watcher = SnortWatcher()
