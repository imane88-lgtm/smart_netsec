# backend/database/repositories.py — COMPLET FINAL
from datetime import datetime
from backend.database.db import get_conn, execute

def _now(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

WHITELIST_STATIC = ["127.0.0.1","192.168.216.143"]

# ══ USERS ══
def get_user_by_username(username):
    try:
        r = get_conn().execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
        return dict(r) if r else None
    except: return None

def get_all_users():
    try:
        rows = get_conn().execute(
            "SELECT id,username,role,login_attempts,locked,last_login FROM users ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]
    except: return []

def update_user_login(username, success):
    try:
        conn = get_conn()
        if success:
            conn.execute("UPDATE users SET login_attempts=0,locked=0,last_login=? WHERE username=?",
                        (_now(),username))
        else:
            conn.execute("UPDATE users SET login_attempts=login_attempts+1 WHERE username=?",
                        (username,))
            row = conn.execute("SELECT login_attempts FROM users WHERE username=?",(username,)).fetchone()
            if row and row[0] >= 5:
                conn.execute("UPDATE users SET locked=1 WHERE username=?",(username,))
        conn.commit()
    except: pass

# ══ APPAREILS ══
def get_appareils():
    try:
        # Dédupliquer par IP — garder le plus récent
        rows = get_conn().execute("""
            SELECT * FROM appareils WHERE id IN (
                SELECT MAX(id) FROM appareils GROUP BY ip
            ) ORDER BY ip
        """).fetchall()
        result = []
        for r in rows:
            a = dict(r)
            a.setdefault("nb_ports",0)
            a.setdefault("vendor", a.get("fabricant","Inconnu"))
            a.setdefault("hostname", "Inconnu")
            a.setdefault("type_appareil","Inconnu")
            a.setdefault("score",100)
            a.setdefault("mac","—")
            result.append(a)
        return result
    except: return []

def save_appareil(scan_id, info):
    try:
        conn = get_conn()
        conn.execute("""INSERT OR REPLACE INTO appareils
            (scan_id,ip,hostname,mac,vendor,fabricant,type_appareil,
             nb_ports,ports_ouverts,ports_risques,score,date_ajout)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, info.get("ip"), info.get("hostname","Inconnu"),
             info.get("mac","Inconnu"), info.get("vendor","Inconnu"),
             info.get("vendor","Inconnu"), info.get("type","Inconnu"),
             info.get("nb_ports",0),
             str(info.get("ports_ouverts",[])),
             str(info.get("ports_risques",[])),
             info.get("score",100), _now()))
        conn.commit()
    except Exception as e:
        import logging; logging.getLogger("repo").warning(f"save_appareil: {e}")

def update_score(ip, score):
    try:
        conn = get_conn()
        conn.execute("UPDATE appareils SET score=? WHERE ip=?",(score,ip))
        conn.commit()
    except: pass

# ══ SCANS ══
def get_scans(limit=20):
    try:
        rows = get_conn().execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?",(limit,)
        ).fetchall()
        result = []
        for r in rows:
            s = dict(r)
            s.setdefault("ip_debut","192.168.216.1")
            s.setdefault("ip_fin","192.168.216.254")
            s.setdefault("nb_appareils",0)
            result.append(s)
        return result
    except: return []

def create_scan(ip_debut="192.168.216.1",ip_fin="192.168.216.254",
                nb=0,duree=0,lance_par="system"):
    try:
        conn = get_conn()
        cur = conn.execute("""INSERT INTO scans
            (date_scan,ip_debut,ip_fin,nb_appareils,duree_sec,lance_par)
            VALUES (?,?,?,?,?,?)""",
            (_now(),ip_debut,ip_fin,nb,duree,lance_par))
        conn.commit()
        return cur.lastrowid
    except: return 0

def update_scan(scan_id, nb, duree):
    try:
        conn = get_conn()
        conn.execute("UPDATE scans SET nb_appareils=?,duree_sec=? WHERE id=?",(nb,duree,scan_id))
        conn.commit()
    except: pass

# ══ ALERTES ══
def get_alertes(limit=100):
    try:
        rows = get_conn().execute(
            "SELECT * FROM alertes ORDER BY date_alerte DESC LIMIT ?",(limit,)
        ).fetchall()
        result = []
        for r in rows:
            a = dict(r)
            a.setdefault("type_alerte","Sécurité")
            a.setdefault("ip","—")
            result.append(a)
        return result
    except: return []

def save_alerte(scan_id, ip, type_alerte, message, niveau="MEDIUM"):
    try:
        conn = get_conn()
        conn.execute("""INSERT INTO alertes
            (scan_id,ip,type_alerte,message,niveau,date_alerte)
            VALUES (?,?,?,?,?,?)""",
            (scan_id,ip,type_alerte,message,niveau,_now()))
        conn.commit()
    except: pass

# ══ BLOCAGES ══
def get_blocages(actif=True):
    try:
        val = 1 if actif else 0
        rows = get_conn().execute(
            "SELECT * FROM blocages WHERE actif=? ORDER BY date_blocage DESC",(val,)
        ).fetchall()
        return [dict(r) for r in rows]
    except: return []

def is_blocked(ip):
    try:
        r = get_conn().execute(
            "SELECT id FROM blocages WHERE ip=? AND actif=1",(ip,)
        ).fetchone()
        return r is not None
    except: return False

def is_whitelisted(ip):
    if ip in WHITELIST_STATIC: return True
    try:
        r = get_conn().execute("SELECT id FROM whitelist WHERE ip=?",(ip,)).fetchone()
        return r is not None
    except: return False

def save_blocage(ip, raison="Manuel", niveau="MANUAL",
                 auto_block=False, cree_par="admin"):
    try:
        conn = get_conn()
        conn.execute("""INSERT OR REPLACE INTO blocages
            (ip,raison,niveau,auto_block,cree_par,date_blocage,actif,nb_triggers)
            VALUES (?,?,?,?,?,?,1,
            COALESCE((SELECT nb_triggers+1 FROM blocages WHERE ip=? AND actif=1),1))""",
            (ip,raison,niveau,1 if auto_block else 0,cree_par,_now(),ip))
        conn.commit()
    except Exception as e:
        try:
            conn = get_conn()
            conn.execute("""INSERT INTO blocages
                (ip,raison,niveau,auto_block,cree_par,date_blocage,actif)
                VALUES (?,?,?,?,?,?,1)""",
                (ip,raison,niveau,1 if auto_block else 0,cree_par,_now()))
            conn.commit()
        except Exception as e2:
            import logging; logging.getLogger("repo").error(f"save_blocage: {e2}")

def unblock(ip):
    try:
        conn = get_conn()
        conn.execute("UPDATE blocages SET actif=0 WHERE ip=?",(ip,))
        conn.commit()
    except: pass

# ══ WHITELIST ══
def get_whitelist():
    try:
        rows = get_conn().execute(
            "SELECT * FROM whitelist ORDER BY date_ajout DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    except: return []

def add_whitelist(ip, raison="Manuel"):
    try:
        conn = get_conn()
        conn.execute("INSERT OR IGNORE INTO whitelist (ip,raison,date_ajout) VALUES (?,?,?)",
                    (ip,raison,_now()))
        conn.commit()
    except: pass

def remove_whitelist(ip):
    try:
        conn = get_conn()
        conn.execute("DELETE FROM whitelist WHERE ip=?",(ip,))
        conn.commit()
    except: pass

# ══ BLACKLIST ══
def get_blacklist():
    try:
        rows = get_conn().execute(
            "SELECT * FROM blacklist WHERE actif=1 ORDER BY date_ajout DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    except: return []

def add_blacklist(ip, raison="Manuel", source="manual"):
    try:
        conn = get_conn()
        conn.execute("""INSERT OR IGNORE INTO blacklist
            (ip,raison,source,date_ajout,actif) VALUES (?,?,?,?,1)""",
            (ip,raison,source,_now()))
        conn.commit()
    except: pass

# ══ FIREWALL RULES ══
def get_fw_rules():
    try:
        rows = get_conn().execute(
            "SELECT * FROM firewall_rules WHERE actif=1 ORDER BY priorite,date_create"
        ).fetchall()
        return [dict(r) for r in rows]
    except: return []

def save_fw_rule(rule_id, type_, ip, port, protocole,
                 direction, priorite, raison, cree_par="admin"):
    try:
        conn = get_conn()
        conn.execute("""INSERT OR REPLACE INTO firewall_rules
            (rule_id,type,ip,port,protocole,direction,priorite,
             raison,cree_par,date_create,actif)
            VALUES (?,?,?,?,?,?,?,?,?,?,1)""",
            (rule_id,type_,ip,port,protocole,direction,priorite,
             raison,cree_par,_now()))
        conn.commit()
    except Exception as e:
        import logging; logging.getLogger("repo").warning(f"save_fw_rule: {e}")

def delete_fw_rule(rule_id):
    try:
        conn = get_conn()
        conn.execute("UPDATE firewall_rules SET actif=0 WHERE rule_id=?",(rule_id,))
        conn.commit()
    except: pass

def toggle_fw_rule(rule_id, actif):
    try:
        conn = get_conn()
        conn.execute("UPDATE firewall_rules SET actif=? WHERE rule_id=?",(actif,rule_id))
        conn.commit()
    except: pass

# ══ FIREWALL LOGS ══
def get_fw_logs(limit=50):
    try:
        rows = get_conn().execute(
            "SELECT * FROM fw_logs ORDER BY timestamp DESC LIMIT ?",(limit,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            # Normaliser les noms de colonnes
            d.setdefault("ip_dst", d.get("ip_dst","*"))
            d.setdefault("port_dst", d.get("port_dst","—"))
            d.setdefault("protocole", d.get("protocole","—"))
            d.setdefault("raison", d.get("raison","—"))
            result.append(d)
        return result
    except: return []

def save_fw_log(action, ip_src, ip_dst="*",
                port_dst=None, protocole="any", raison=""):
    try:
        conn = get_conn()
        # Essayer avec toutes les colonnes connues
        try:
            conn.execute("""INSERT INTO fw_logs
                (timestamp,action,ip_src,ip_dst,port_dst,protocole,raison)
                VALUES (?,?,?,?,?,?,?)""",
                (_now(),action,ip_src,ip_dst,port_dst,protocole,raison))
        except Exception:
            # Fallback colonnes minimales
            conn.execute("""INSERT INTO fw_logs
                (timestamp,action,ip_src)
                VALUES (?,?,?)""",
                (_now(),action,ip_src))
        conn.commit()
    except Exception as e:
        import logging; logging.getLogger("repo").warning(f"save_fw_log: {e}")

# ══ SNORT ALERTES ══
def get_snort_alertes(limit=100):
    try:
        rows = get_conn().execute(
            "SELECT * FROM snort_alertes ORDER BY timestamp DESC LIMIT ?",(limit,)
        ).fetchall()
        result = []
        for r in rows:
            a = dict(r)
            a["dest_ip"] = a.get("dst_ip") or a.get("dest_ip") or "—"
            a.setdefault("signature", a.get("message",""))
            result.append(a)
        return result
    except: return []

def save_snort_alert(data):
    try:
        conn = get_conn()
        conn.execute("""INSERT OR IGNORE INTO snort_alertes
            (timestamp,sid,revision,priority,classification,
             message,src_ip,src_port,dst_ip,dest_ip,dst_port,
             protocole,niveau,action_prise,interface,traite)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (_now() if not data.get("timestamp") else data["timestamp"],
             data.get("sid","0"), data.get("revision","1"),
             data.get("priority",3), data.get("classification",""),
             data.get("message",""), data.get("src_ip",""),
             str(data.get("src_port","0")),
             data.get("dst_ip", data.get("dest_ip","")),
             data.get("dst_ip", data.get("dest_ip","")),
             str(data.get("dst_port","0")),
             data.get("protocole","TCP"),
             data.get("niveau","MEDIUM"),
             data.get("action_prise","LOG"),
             data.get("interface","eth0"), 0))
        conn.commit()
    except Exception as e:
        import logging; logging.getLogger("repo").warning(f"save_snort_alert: {e}")

def get_snort_stats():
    try:
        conn = get_conn()
        def q(sql): return conn.execute(sql).fetchone()[0] or 0
        top = conn.execute("""SELECT src_ip,COUNT(*) as nb FROM snort_alertes
            GROUP BY src_ip ORDER BY nb DESC LIMIT 5""").fetchall()
        return {
            "total":    q("SELECT COUNT(*) FROM snort_alertes"),
            "critical": q("SELECT COUNT(*) FROM snort_alertes WHERE niveau='CRITICAL'"),
            "high":     q("SELECT COUNT(*) FROM snort_alertes WHERE niveau='HIGH'"),
            "medium":   q("SELECT COUNT(*) FROM snort_alertes WHERE niveau='MEDIUM'"),
            "low":      q("SELECT COUNT(*) FROM snort_alertes WHERE niveau='LOW'"),
            "top_ips":  [dict(r) for r in top],
        }
    except:
        return {"total":0,"critical":0,"high":0,"medium":0,"low":0,"top_ips":[]}

# ══ SUPERVISION ══
def get_supervision_history(limit=30):
    try:
        rows = get_conn().execute(
            "SELECT * FROM supervision_history ORDER BY timestamp DESC LIMIT ?",(limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    except: return []

def save_supervision(data):
    try:
        conn = get_conn()
        conn.execute("""INSERT INTO supervision_history
            (timestamp,cpu_percent,ram_percent,ram_used_mb,ram_total_mb,
             disk_percent,disk_used_gb,disk_total_gb,
             net_bytes_in,net_bytes_out,nb_connexions,
             nb_alertes,nb_bloques,score_global,statut)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (_now(), data.get("cpu",0), data.get("ram_pct",0),
             data.get("ram_used",0), data.get("ram_total",0),
             data.get("disk_pct",0), data.get("disk_used",0),
             data.get("disk_total",0),
             data.get("bytes_recv",0), data.get("bytes_sent",0),
             data.get("nb_connexions",0),
             data.get("nb_alertes",0), data.get("nb_bloques",0),
             data.get("score",0), data.get("statut","NORMAL")))
        conn.commit()
    except: pass

# ══ RAPPORTS ══
def get_rapports(limit=20):
    try:
        rows = get_conn().execute(
            "SELECT * FROM rapports ORDER BY date_creation DESC LIMIT ?",(limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    except: return []

def save_rapport(titre, nb_appareils=0, nb_alertes=0,
                 score=0, genere_par="admin"):
    try:
        conn = get_conn()
        conn.execute("""INSERT INTO rapports
            (date_creation,titre,nb_appareils,nb_alertes,score_global,genere_par,fichier)
            VALUES (?,?,?,?,?,?,?)""",
            (_now(),titre,nb_appareils,nb_alertes,score,genere_par,"rapport_securite.pdf"))
        conn.commit()
    except Exception as e:
        import logging; logging.getLogger("repo").warning(f"save_rapport: {e}")

# ══ INCIDENTS ══
def get_incidents(statut=None):
    try:
        if statut:
            rows = get_conn().execute(
                "SELECT * FROM incidents WHERE statut=? ORDER BY date_detect DESC",(statut,)
            ).fetchall()
        else:
            rows = get_conn().execute(
                "SELECT * FROM incidents ORDER BY date_detect DESC"
            ).fetchall()
        return [dict(r) for r in rows]
    except: return []

def save_incident(titre, desc, severity, ip, analyst="system"):
    try:
        n = _now()
        conn = get_conn()
        conn.execute("""INSERT INTO incidents
            (titre,description,severity,statut,analyst,ip_source,date_detect,date_update)
            VALUES (?,?,?,'open',?,?,?,?)""",
            (titre,desc,severity,analyst,ip,n,n))
        conn.commit()
    except: pass

def update_incident(id_, statut, notes=""):
    try:
        conn = get_conn()
        conn.execute("UPDATE incidents SET statut=?,notes=?,date_update=? WHERE id=?",
                    (statut,notes,_now(),id_))
        conn.commit()
    except: pass

# ══ CORRÉLATIONS ══
def get_correlations(limit=50):
    try:
        rows = get_conn().execute(
            "SELECT * FROM correlation_events ORDER BY timestamp DESC LIMIT ?",(limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    except: return []

def save_correlation(rule_id, rule_nom, ip, severite,
                     action, explication, impact):
    try:
        conn = get_conn()
        conn.execute("""INSERT INTO correlation_events
            (rule_id,rule_nom,ip,severite,action,explication,score_impact,timestamp)
            VALUES (?,?,?,?,?,?,?,?)""",
            (rule_id,rule_nom,ip,severite,action,explication,impact,_now()))
        conn.commit()
    except: pass

# ══ TRAFIC ══
def get_traffic_history(limit=50):
    try:
        rows = get_conn().execute(
            "SELECT * FROM traffic_stats ORDER BY timestamp DESC LIMIT ?",(limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    except: return []

# ══ DASHBOARD STATS ══
def get_dashboard_stats():
    try:
        conn = get_conn()
        def q(sql,d=0):
            try: return conn.execute(sql).fetchone()[0] or d
            except: return d
        scores = [r[0] for r in conn.execute(
            "SELECT score FROM appareils WHERE score IS NOT NULL").fetchall()]
        score_moy = round(sum(scores)/len(scores)) if scores else 0
        return {
            "nb_appareils":    q("SELECT COUNT(DISTINCT ip) FROM appareils"),
            "score_moyen":     score_moy,
            "nb_safe":         q("SELECT COUNT(*) FROM appareils WHERE score>=80"),
            "nb_medium":       q("SELECT COUNT(*) FROM appareils WHERE score>=50 AND score<80"),
            "nb_danger":       q("SELECT COUNT(*) FROM appareils WHERE score<50"),
            "nb_alertes":      q("SELECT COUNT(*) FROM alertes"),
            "nb_alertes_high": q("SELECT COUNT(*) FROM alertes WHERE niveau IN ('HIGH','CRITICAL')"),
            "nb_scans":        q("SELECT COUNT(*) FROM scans"),
            "nb_incidents":    q("SELECT COUNT(*) FROM incidents WHERE statut='open'"),
            "nb_snort":        q("SELECT COUNT(*) FROM snort_alertes"),
            "nb_snort_crit":   q("SELECT COUNT(*) FROM snort_alertes WHERE niveau IN ('CRITICAL','HIGH')"),
        }
    except:
        return {"nb_appareils":0,"score_moyen":0,"nb_safe":0,"nb_medium":0,
                "nb_danger":0,"nb_alertes":0,"nb_alertes_high":0,"nb_scans":0,
                "nb_incidents":0,"nb_snort":0,"nb_snort_crit":0}
