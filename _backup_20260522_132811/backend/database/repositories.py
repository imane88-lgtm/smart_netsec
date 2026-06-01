# backend/database/repositories.py 
# ============================================================
from datetime import datetime
from backend.database.db import get_conn, execute


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _rows(cur):
    rows = cur.fetchall() if hasattr(cur, "fetchall") else cur
    return [dict(r) for r in rows] if rows else []


# ══════════════════════════════════════════════
# APPAREILS
# ══════════════════════════════════════════════
def get_appareils():
    try:
        return _rows(execute(
            "SELECT * FROM appareils ORDER BY score ASC, date_update DESC"
        ))
    except Exception:
        return []


def get_appareil(ip: str):
    try:
        r = execute("SELECT * FROM appareils WHERE ip=?", (ip,), fetchone=True)
        return dict(r) if r else None
    except Exception:
        return None


def save_appareil(ip, mac="", nom="", type_app="", os_="", fab="",
                   ports="", score=100, statut="SAFE"):
    n = _now()
    try:
        conn = get_conn()
        conn.execute(
            """INSERT INTO appareils
               (ip,mac,nom,type_appareil,os,fabricant,ports_ouverts,score,statut,date_scan,date_update)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(ip) DO UPDATE SET
               mac=excluded.mac, nom=excluded.nom,
               type_appareil=excluded.type_appareil, os=excluded.os,
               fabricant=excluded.fabricant, ports_ouverts=excluded.ports_ouverts,
               score=excluded.score, statut=excluded.statut, date_update=excluded.date_update""",
            (ip, mac, nom, type_app, os_, fab, ports, score, statut, n, n),
        )
        conn.commit()
    except Exception as e:
        import logging; logging.getLogger("repo").warning(f"save_appareil: {e}")


def update_appareil_score(ip: str, score: int, statut: str):
    try:
        conn = get_conn()
        conn.execute(
            "UPDATE appareils SET score=?,statut=?,date_update=? WHERE ip=?",
            (score, statut, _now(), ip),
        )
        conn.commit()
    except Exception:
        pass


# ══════════════════════════════════════════════
# ALERTES
# ══════════════════════════════════════════════
def get_alertes(limit=50):
    try:
        return _rows(execute(
            "SELECT * FROM alertes ORDER BY date_alerte DESC LIMIT ?", (limit,)
        ))
    except Exception:
        return []


def save_alerte(ip: str, message: str, niveau: str = "LOW"):
    try:
        conn = get_conn()
        conn.execute(
            "INSERT INTO alertes (ip,message,niveau,date_alerte) VALUES (?,?,?,?)",
            (ip, message, niveau, _now()),
        )
        conn.commit()
    except Exception:
        pass


# ══════════════════════════════════════════════
# SCANS
# ══════════════════════════════════════════════
def get_scans(limit=50):
    try:
        return _rows(execute(
            "SELECT * FROM scans ORDER BY date_scan DESC LIMIT ?", (limit,)
        ))
    except Exception:
        return []


def save_scan(ip, ports, os_detect="", duree=0):
    try:
        conn = get_conn()
        conn.execute(
            "INSERT INTO scans (ip,ports_ouverts,os_detect,date_scan,duree_sec) VALUES (?,?,?,?,?)",
            (ip, str(ports), os_detect, _now(), duree),
        )
        conn.commit()
    except Exception:
        pass


# ══════════════════════════════════════════════
# BLOCAGES
# ══════════════════════════════════════════════
def get_blocages(actif=None):
    try:
        if actif is not None:
            return _rows(execute(
                "SELECT * FROM blocages WHERE actif=? ORDER BY date_blocage DESC",
                (int(actif),)
            ))
        return _rows(execute(
            "SELECT * FROM blocages ORDER BY date_blocage DESC"
        ))
    except Exception:
        return []


def is_blocked(ip: str) -> bool:
    try:
        r = execute(
            "SELECT 1 FROM blocages WHERE ip=? AND actif=1", (ip,), fetchone=True
        )
        return r is not None
    except Exception:
        return False


# ══════════════════════════════════════════════
# WHITELIST
# ══════════════════════════════════════════════
def get_whitelist():
    try:
        return _rows(execute("SELECT * FROM whitelist ORDER BY date_ajout DESC"))
    except Exception:
        return []


def add_whitelist(ip: str, raison: str = "Manuel"):
    try:
        conn = get_conn()
        conn.execute(
            "INSERT OR IGNORE INTO whitelist (ip,raison,date_ajout) VALUES (?,?,?)",
            (ip, raison, _now()),
        )
        conn.commit()
    except Exception as e:
        import logging; logging.getLogger("repo").warning(f"add_whitelist: {e}")


def is_whitelisted(ip: str) -> bool:
    try:
        r = execute("SELECT 1 FROM whitelist WHERE ip=?", (ip,), fetchone=True)
        return r is not None
    except Exception:
        return False


# ══════════════════════════════════════════════
# BLACKLIST
# ══════════════════════════════════════════════
def get_blacklist():
    try:
        return _rows(execute("SELECT * FROM blacklist ORDER BY date_ajout DESC"))
    except Exception:
        return []


def add_blacklist(ip: str, raison: str = "Manuel", source: str = "manual"):
    try:
        conn = get_conn()
        conn.execute(
            "INSERT OR IGNORE INTO blacklist (ip,raison,source,date_ajout) VALUES (?,?,?,?)",
            (ip, raison, source, _now()),
        )
        conn.commit()
    except Exception as e:
        import logging; logging.getLogger("repo").warning(f"add_blacklist: {e}")


# ══════════════════════════════════════════════
# RÈGLES FIREWALL
# ══════════════════════════════════════════════
def get_fw_rules():
    try:
        return _rows(execute(
            "SELECT * FROM firewall_rules WHERE actif=1 ORDER BY priorite ASC, date_create DESC"
        ))
    except Exception:
        return []


# ══════════════════════════════════════════════
# LOGS FIREWALL
# ══════════════════════════════════════════════
def get_fw_logs(limit=50):
    try:
        return _rows(execute(
            "SELECT * FROM fw_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
        ))
    except Exception:
        return []


# ══════════════════════════════════════════════
# SNORT / IDS
# ══════════════════════════════════════════════
def get_snort_alertes(limit=100):
    try:
        return _rows(execute(
            "SELECT * FROM snort_alertes ORDER BY timestamp DESC LIMIT ?", (limit,)
        ))
    except Exception:
        return []


def get_snort_stats() -> dict:
    try:
        conn = get_conn()
        total    = conn.execute("SELECT COUNT(*) FROM snort_alertes").fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM snort_alertes WHERE niveau='CRITICAL'"
        ).fetchone()[0]
        high     = conn.execute(
            "SELECT COUNT(*) FROM snort_alertes WHERE niveau='HIGH'"
        ).fetchone()[0]
        medium   = conn.execute(
            "SELECT COUNT(*) FROM snort_alertes WHERE niveau='MEDIUM'"
        ).fetchone()[0]
        low      = conn.execute(
            "SELECT COUNT(*) FROM snort_alertes WHERE niveau='LOW'"
        ).fetchone()[0]
        top_ips  = _rows(execute(
            """SELECT src_ip, COUNT(*) as nb FROM snort_alertes
               WHERE src_ip IS NOT NULL AND src_ip != ''
               GROUP BY src_ip ORDER BY nb DESC LIMIT 10"""
        ))
        return {
            "total": total, "critical": critical,
            "high": high,   "medium": medium,
            "low": low,     "top_ips": top_ips,
        }
    except Exception:
        return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "top_ips": []}


# ══════════════════════════════════════════════
# DASHBOARD STATS
# ══════════════════════════════════════════════
def get_dashboard_stats() -> dict:
    try:
        conn = get_conn()
        nb_app   = conn.execute("SELECT COUNT(*) FROM appareils WHERE actif=1").fetchone()[0]
        score_r  = conn.execute("SELECT AVG(score) FROM appareils WHERE actif=1").fetchone()[0]
        nb_safe  = conn.execute("SELECT COUNT(*) FROM appareils WHERE statut='SAFE'").fetchone()[0]
        nb_med   = conn.execute("SELECT COUNT(*) FROM appareils WHERE statut='MEDIUM'").fetchone()[0]
        nb_dan   = conn.execute("SELECT COUNT(*) FROM appareils WHERE statut='DANGER'").fetchone()[0]
        nb_al    = conn.execute("SELECT COUNT(*) FROM alertes").fetchone()[0]
        nb_high  = conn.execute("SELECT COUNT(*) FROM alertes WHERE niveau IN ('HIGH','CRITICAL')").fetchone()[0]
        nb_sc    = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        nb_inc   = conn.execute("SELECT COUNT(*) FROM incidents WHERE statut='open'").fetchone()[0] if _table_exists(conn, "incidents") else 0
        nb_snort = conn.execute("SELECT COUNT(*) FROM snort_alertes").fetchone()[0]
        nb_crit  = conn.execute("SELECT COUNT(*) FROM snort_alertes WHERE niveau='CRITICAL'").fetchone()[0]
        return {
            "nb_appareils":   nb_app,
            "score_moyen":    round(score_r or 0, 1),
            "nb_safe":        nb_safe,
            "nb_medium":      nb_med,
            "nb_danger":      nb_dan,
            "nb_alertes":     nb_al,
            "nb_alertes_high":nb_high,
            "nb_scans":       nb_sc,
            "nb_incidents":   nb_inc,
            "nb_snort":       nb_snort,
            "nb_snort_crit":  nb_crit,
        }
    except Exception:
        return {
            "nb_appareils": 0, "score_moyen": 0, "nb_safe": 0,
            "nb_medium": 0, "nb_danger": 0, "nb_alertes": 0,
            "nb_alertes_high": 0, "nb_scans": 0, "nb_incidents": 0,
            "nb_snort": 0, "nb_snort_crit": 0,
        }


def _table_exists(conn, name: str) -> bool:
    r = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return r is not None


# ══════════════════════════════════════════════
# RAPPORTS
# ══════════════════════════════════════════════
def get_rapports(limit=20):
    try:
        return _rows(execute(
            "SELECT * FROM rapports ORDER BY date_creation DESC LIMIT ?", (limit,)
        ))
    except Exception:
        return []


def save_rapport(titre: str, nb_appareils=0, nb_alertes=0, score=0, genere_par="admin"):
    try:
        conn = get_conn()
        conn.execute(
            """INSERT INTO rapports
               (date_creation,titre,nb_appareils,nb_alertes,score_global,genere_par,fichier)
               VALUES (?,?,?,?,?,?,?)""",
            (_now(), titre, nb_appareils, nb_alertes, score, genere_par, "rapport_securite.pdf"),
        )
        conn.commit()
    except Exception as e:
        import logging; logging.getLogger("repo").warning(f"save_rapport: {e}")


# ══════════════════════════════════════════════
# CORRÉLATIONS
# ══════════════════════════════════════════════
def get_correlations(limit=50):
    try:
        return _rows(execute(
            "SELECT * FROM correlation_events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ))
    except Exception:
        return []


def save_correlation(rule_id, rule_nom, ip, severite, action, explication, impact=0):
    try:
        conn = get_conn()
        conn.execute(
            """INSERT INTO correlation_events
               (rule_id,rule_nom,ip,severite,action,explication,score_impact,timestamp)
               VALUES (?,?,?,?,?,?,?,?)""",
            (rule_id, rule_nom, ip, severite, action, explication, impact, _now()),
        )
        conn.commit()
    except Exception:
        pass


# ══════════════════════════════════════════════
# INCIDENTS
# ══════════════════════════════════════════════
def get_incidents(statut=None):
    try:
        if statut:
            return _rows(execute(
                "SELECT * FROM incidents WHERE statut=? ORDER BY date_detect DESC", (statut,)
            ))
        return _rows(execute(
            "SELECT * FROM incidents ORDER BY date_detect DESC"
        ))
    except Exception:
        return []


def save_incident(titre, desc, severity, ip, analyst="system"):
    try:
        n = _now()
        conn = get_conn()
        conn.execute(
            """INSERT INTO incidents
               (titre,description,severity,statut,analyst,ip_source,date_detect,date_update)
               VALUES (?,?,?,'open',?,?,?,?)""",
            (titre, desc, severity, analyst, ip, n, n),
        )
        conn.commit()
    except Exception:
        pass


def update_incident(id_: int, statut: str, notes: str = ""):
    try:
        conn = get_conn()
        conn.execute(
            "UPDATE incidents SET statut=?,notes=?,date_update=? WHERE id=?",
            (statut, notes, _now(), id_),
        )
        conn.commit()
    except Exception:
        pass


# ══════════════════════════════════════════════
# SUPERVISION HISTORY
# ══════════════════════════════════════════════
def get_supervision_history(limit=60):
    try:
        return _rows(execute(
            "SELECT * FROM supervision_history ORDER BY timestamp DESC LIMIT ?", (limit,)
        ))
    except Exception:
        return []
