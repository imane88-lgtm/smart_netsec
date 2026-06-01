# backend/api/firewall_api.py — COMPLET AUDITÉ
import uuid
from flask import Blueprint, jsonify, request, session
from functools import wraps
from backend.database import repositories as repo
from backend.database.db import get_conn
from backend.utils.logger import get_logger

log = get_logger("firewall_api")
fw_bp = Blueprint("firewall", __name__, url_prefix="/api/firewall")


def _login(f):
    @wraps(f)
    def d(*a, **kw):
        if "user" not in session:
            return jsonify({"error": "Non authentifié"}), 401
        return f(*a, **kw)
    return d

def _admin(f):
    @wraps(f)
    def d(*a, **kw):
        if "user" not in session:
            return jsonify({"error": "Non authentifié"}), 401
        if session["user"]["role"] != "admin":
            return jsonify({"error": "Admin requis"}), 403
        return f(*a, **kw)
    return d


# ── STATS ──────────────────────────────────────────────────
@fw_bp.route("/stats")
@_login
def stats():
    try:
        conn = get_conn()
        nb_bl  = conn.execute("SELECT COUNT(*) FROM blocages WHERE actif=1").fetchone()[0]
        nb_wl  = conn.execute("SELECT COUNT(*) FROM whitelist").fetchone()[0]
        nb_bll = conn.execute("SELECT COUNT(*) FROM blacklist WHERE actif=1").fetchone()[0]
        nb_ru  = conn.execute("SELECT COUNT(*) FROM firewall_rules WHERE actif=1").fetchone()[0]
        blocages = repo.get_blocages(actif=True)
        return jsonify({
            "nb_bloques":   nb_bl,
            "nb_whitelist": nb_wl,
            "nb_blacklist": nb_bll,
            "nb_rules":     nb_ru,
            "statut":       "ACTIF",
            "blocages":     blocages,
            "whitelist":    repo.get_whitelist(),
            "blacklist":    repo.get_blacklist(),
            "rules":        repo.get_fw_rules(),
            "logs":         repo.get_fw_logs(20),
        })
    except Exception as e:
        log.error(f"stats: {e}")
        return jsonify({"nb_bloques":0,"nb_whitelist":0,"nb_blacklist":0,
                        "nb_rules":0,"statut":"ERREUR","blocages":[],
                        "whitelist":[],"blacklist":[],"rules":[],"logs":[]})


# ── BLOQUER ────────────────────────────────────────────────
@fw_bp.route("/bloquer/<path:ip>", methods=["GET","POST"])
@_admin
def bloquer(ip):
    ip = ip.strip().split("?")[0]
    raison = request.args.get("raison","Blocage manuel dashboard")
    if not ip or ip in ("","*","any"):
        return jsonify({"success":False,"message":"IP invalide"}), 400
    try:
        from backend.services.firewall_service import block_ip
        ok, msg = block_ip(ip, raison, "MANUAL",
                           cree_par=session["user"]["username"])
    except Exception as e:
        log.error(f"bloquer {ip}: {e}")
        # Fallback direct DB
        try:
            repo.save_blocage(ip, raison, "MANUAL", False,
                              session["user"]["username"])
            repo.save_fw_log("BLOCK", ip, raison=raison)
            ok, msg = True, f"✅ {ip} bloquée (direct DB)"
        except Exception as e2:
            return jsonify({"success":False,"message":str(e2)}), 500
    return jsonify({"success":ok,"message":msg,"msg":msg})


# ── DÉBLOQUER ──────────────────────────────────────────────
@fw_bp.route("/debloquer/<path:ip>", methods=["GET","POST"])
@_admin
def debloquer(ip):
    ip = ip.strip().split("?")[0]
    if not ip:
        return jsonify({"success":False,"message":"IP manquante"}), 400
    try:
        from backend.services.firewall_service import unblock_ip
        ok, msg = unblock_ip(ip)
    except Exception as e:
        log.warning(f"unblock_ip service failed: {e} — fallback DB")
        try:
            conn = get_conn()
            conn.execute("UPDATE blocages SET actif=0 WHERE ip=?",(ip,))
            conn.commit()
            repo.save_fw_log("UNBLOCK", ip, raison="Déblocage manuel")
            ok, msg = True, f"✅ {ip} débloquée"
        except Exception as e2:
            return jsonify({"success":False,"message":str(e2)}), 500
    return jsonify({"success":ok,"message":msg,"msg":msg})


# ── WHITELIST LIST ──────────────────────────────────────────
@fw_bp.route("/whitelist", methods=["GET"])
@_login
def get_whitelist():
    try:
        return jsonify(repo.get_whitelist())
    except Exception as e:
        log.error(f"get_whitelist: {e}")
        return jsonify([])


# ── WHITELIST ADD ───────────────────────────────────────────
@fw_bp.route("/whitelist/add", methods=["POST"])
@_admin
def add_whitelist_post():
    data   = request.get_json(force=True) or {}
    ip     = data.get("ip","").strip()
    raison = data.get("raison","Manuel") or "Manuel"
    if not ip:
        return jsonify({"success":False,"message":"IP requise"}),400
    try:
        conn = get_conn()
        conn.execute("""INSERT OR IGNORE INTO whitelist (ip,raison,date_ajout)
                        VALUES (?,?,datetime('now'))""",(ip,raison))
        conn.commit()
        return jsonify({"success":True,"message":f"✅ {ip} whitelistée"})
    except Exception as e:
        return jsonify({"success":False,"message":str(e)}),500


# ── WHITELIST ADD (GET compat) ──────────────────────────────
@fw_bp.route("/whitelist/<path:ip>", methods=["GET","POST"])
@_admin
def add_whitelist(ip):
    ip     = ip.strip().rstrip("/remove").strip()
    raison = request.args.get("raison","Whitelist manuelle")
    if not ip:
        return jsonify({"success":False,"message":"IP manquante"}),400
    try:
        conn = get_conn()
        conn.execute("""INSERT OR IGNORE INTO whitelist (ip,raison,date_ajout)
                        VALUES (?,?,datetime('now'))""",(ip,raison))
        conn.commit()
        changes = conn.total_changes
        return jsonify({"success":True,"message":f"✅ {ip} whitelistée","msg":f"✅ {ip} whitelistée"})
    except Exception as e:
        return jsonify({"success":False,"message":str(e)}),500


# ── WHITELIST REMOVE ────────────────────────────────────────
@fw_bp.route("/whitelist/<path:ip>/remove", methods=["DELETE","POST","GET"])
@_admin
def remove_whitelist(ip):
    ip = ip.strip()
    try:
        conn = get_conn()
        conn.execute("DELETE FROM whitelist WHERE ip=?",(ip,))
        conn.commit()
        return jsonify({"success":True,"message":f"✅ {ip} retirée de la whitelist"})
    except Exception as e:
        return jsonify({"success":False,"message":str(e)}),500


# ── BLACKLIST LIST ──────────────────────────────────────────
@fw_bp.route("/blacklist", methods=["GET"])
@_login
def get_blacklist():
    try:
        return jsonify(repo.get_blacklist())
    except Exception as e:
        return jsonify([])


# ── BLACKLIST ADD ───────────────────────────────────────────
@fw_bp.route("/blacklist/add", methods=["POST"])
@_admin
def add_blacklist():
    data   = request.get_json(force=True) or {}
    ip     = data.get("ip","").strip()
    raison = data.get("raison","Blacklist manuelle") or "Blacklist manuelle"
    source = data.get("source","manual")
    if not ip:
        return jsonify({"success":False,"message":"IP requise"}),400
    try:
        conn = get_conn()
        conn.execute("""INSERT OR IGNORE INTO blacklist (ip,raison,source,date_ajout,actif)
                        VALUES (?,?,?,datetime('now'),1)""",(ip,raison,source))
        conn.commit()
        return jsonify({"success":True,"message":f"✅ {ip} ajoutée à la blacklist"})
    except Exception as e:
        return jsonify({"success":False,"message":str(e)}),500


# ── BLACKLIST REMOVE ────────────────────────────────────────
@fw_bp.route("/blacklist/<path:ip>/remove", methods=["DELETE","POST","GET"])
@_admin
def remove_blacklist(ip):
    ip = ip.strip()
    try:
        conn = get_conn()
        conn.execute("UPDATE blacklist SET actif=0 WHERE ip=?",(ip,))
        conn.commit()
        return jsonify({"success":True,"message":f"✅ {ip} retirée de la blacklist"})
    except Exception as e:
        return jsonify({"success":False,"message":str(e)}),500


# ── RULES LIST ─────────────────────────────────────────────
@fw_bp.route("/rules", methods=["GET"])
@_login
def get_rules():
    try:
        return jsonify(repo.get_fw_rules())
    except Exception:
        return jsonify([])


# ── RULES ADD ──────────────────────────────────────────────
@fw_bp.route("/rules/add", methods=["POST"])
@_admin
def add_fw_rule():
    data    = request.get_json(force=True) or {}
    ip      = data.get("ip","*").strip() or "*"
    rule_id = str(uuid.uuid4())[:18]
    try:
        conn = get_conn()
        conn.execute("""INSERT INTO firewall_rules
            (rule_id,type,ip,port,protocole,direction,priorite,raison,cree_par,date_create,actif)
            VALUES (?,?,?,?,?,?,?,?,?,datetime('now'),1)""",
            (rule_id, data.get("type","BLOCK"), ip,
             data.get("port") or None, data.get("proto","tcp"),
             data.get("direction","INPUT"), int(data.get("priorite",100)),
             data.get("raison","Règle manuelle"),
             session["user"]["username"]))
        conn.commit()
        # Appliquer nftables si possible
        try:
            from backend.services.firewall_service import _apply_nft_rule
            _apply_nft_rule(data.get("type","BLOCK"), ip,
                           data.get("port"), data.get("proto","tcp"),
                           data.get("direction","INPUT"), data.get("raison",""))
        except Exception:
            pass
        return jsonify({"success":True,"message":f"✅ Règle ajoutée ({rule_id[:8]})"})
    except Exception as e:
        return jsonify({"success":False,"message":str(e)}),500


# ── RULES DELETE ───────────────────────────────────────────
@fw_bp.route("/rules/<rule_id>/delete", methods=["DELETE","POST","GET"])
@_admin
def del_rule(rule_id):
    try:
        conn = get_conn()
        conn.execute("UPDATE firewall_rules SET actif=0 WHERE rule_id=? OR CAST(id AS TEXT)=?",
                    (rule_id, rule_id))
        conn.commit()
        return jsonify({"success":True,"message":"✅ Règle supprimée"})
    except Exception as e:
        return jsonify({"success":False,"message":str(e)}),500


# ── RULES TOGGLE ───────────────────────────────────────────
@fw_bp.route("/rules/<rule_id>/toggle", methods=["POST"])
@_admin
def toggle_rule(rule_id):
    data  = request.get_json(force=True) or {}
    actif = int(data.get("actif",1))
    try:
        conn = get_conn()
        conn.execute("UPDATE firewall_rules SET actif=? WHERE rule_id=? OR CAST(id AS TEXT)=?",
                    (actif, rule_id, rule_id))
        conn.commit()
        return jsonify({"success":True,"message":f"✅ Règle {'activée' if actif else 'désactivée'}"})
    except Exception as e:
        return jsonify({"success":False,"message":str(e)}),500


# ── LOGS ───────────────────────────────────────────────────
@fw_bp.route("/logs")
@_login
def get_logs():
    limit = int(request.args.get("limit",50))
    try:
        return jsonify(repo.get_fw_logs(limit))
    except Exception:
        return jsonify([])


# ── CONNECTIONS ────────────────────────────────────────────
@fw_bp.route("/connections")
@_login
def connections():
    try:
        from backend.services.firewall_service import get_active_connections
        return jsonify(get_active_connections())
    except Exception:
        return jsonify([])


# ── AUTO-RESPONSE ──────────────────────────────────────────
@fw_bp.route("/auto-response", methods=["POST","GET"])
@_admin
def run_auto_response():
    conn    = get_conn()
    alertes = conn.execute(
        "SELECT * FROM snort_alertes WHERE traite=0 ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    actions = []
    for a in alertes:
        a  = dict(a)
        ip = a.get("src_ip","")
        if not ip or ip in ["*","","—"]: continue
        if repo.is_whitelisted(ip): continue
        niveau = a.get("niveau","MEDIUM")
        if niveau in ("CRITICAL","HIGH"):
            try:
                repo.save_blocage(ip,
                    f"Auto-block {niveau}: {a.get('message','')[:40]}",
                    niveau, True, "auto")
                try:
                    from backend.services.firewall_service import _nft_block_ip
                    _nft_block_ip(ip)
                except Exception: pass
                repo.save_fw_log("BLOCK",ip,raison=f"Auto-block {niveau}")
                actions.append({"ip":ip,"action":"BLOCKED","niveau":niveau})
            except Exception as e:
                log.warning(f"auto-block {ip}: {e}")
        conn.execute("UPDATE snort_alertes SET traite=1 WHERE id=?",(a["id"],))
    conn.commit()
    return jsonify({"actions":actions,"total":len(actions),
                    "message":f"{len(actions)} actions effectuées"})
