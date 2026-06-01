from flask import Blueprint, jsonify, request, session
from functools import wraps
from backend.services.firewall_service import (
    block_ip, unblock_ip, add_rule, delete_rule, toggle_rule,
    get_firewall_stats, get_active_connections, auto_response,
)
from backend.database import repositories as repo
from backend.database.db import get_conn

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


# ── Stats ──────────────────────────────────────────────────
@fw_bp.route("/stats")
@_login
def stats():
    try:
        return jsonify(get_firewall_stats())
    except Exception as e:
        return jsonify({
            "nb_bloques": 0, "nb_whitelist": 0, "nb_blacklist": 0,
            "nb_rules": 0, "statut": "NORMAL", "derniere_ip": "—",
            "blocages": [], "rules": [], "logs": [],
            "connexions": [], "whitelist": [], "blacklist": [],
        })


# ── Règles nftables ────────────────────────────────────────
@fw_bp.route("/rules")
@_login
def get_rules():
    try:
        return jsonify(repo.get_fw_rules())
    except Exception:
        return jsonify([])


@fw_bp.route("/rules/add", methods=["POST"])
@_admin
def add_fw_rule():
    data = request.get_json(force=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"success": False, "message": "IP requise"}), 400
    ok, msg = add_rule(
        type_=data.get("type", "BLOCK"),
        ip=ip,
        port=data.get("port") or None,
        proto=data.get("proto", "tcp"),
        direction=data.get("direction", "INPUT"),
        priorite=int(data.get("priorite", 100)),
        raison=data.get("raison", "Règle manuelle"),
        cree_par=session["user"]["username"],
    )
    return jsonify({"success": ok, "message": msg})


@fw_bp.route("/rules/<rule_id>/delete", methods=["DELETE", "POST"])
@_admin
def del_rule(rule_id):
    ok, msg = delete_rule(rule_id)
    return jsonify({"success": ok, "message": msg})


@fw_bp.route("/rules/<rule_id>/toggle", methods=["POST"])
@_admin
def toggle(rule_id):
    data = request.get_json(force=True) or {}
    actif = int(data.get("actif", 1))
    ok, msg = toggle_rule(rule_id, actif)
    return jsonify({"success": ok, "message": msg})


# ── Blocage / Déblocage ────────────────────────────────────
@fw_bp.route("/bloquer/<path:ip>")
@_admin
def bloquer(ip):
    ip = ip.strip()
    raison = request.args.get("raison", "Blocage manuel dashboard")
    ok, msg = block_ip(
        ip, raison, "MANUAL",
        cree_par=session["user"]["username"],
    )
    return jsonify({"success": ok, "message": msg, "msg": msg})


@fw_bp.route("/debloquer/<path:ip>")
@_admin
def debloquer(ip):
    ip = ip.strip()
    ok, msg = unblock_ip(ip)
    return jsonify({"success": ok, "message": msg, "msg": msg})


# ── Whitelist ──────────────────────────────────────────────
@fw_bp.route("/whitelist", methods=["GET"])
@_login
def get_whitelist():
    try:
        return jsonify(repo.get_whitelist())
    except Exception:
        return jsonify([])


@fw_bp.route("/whitelist/<path:ip>", methods=["GET", "POST"])
@_admin
def add_whitelist(ip):
    ip = ip.strip()
    # Éviter le conflit avec /whitelist/<ip>/remove
    if ip.endswith("/remove"):
        return jsonify({"error": "Utiliser DELETE /whitelist/<ip>/remove"}), 400
    raison = request.args.get("raison", "Whitelist manuelle")
    repo.add_whitelist(ip, raison)
    return jsonify({"success": True, "message": f"✅ {ip} whitelistée", "msg": f"✅ {ip} whitelistée"})


@fw_bp.route("/whitelist/<path:ip>/remove", methods=["DELETE", "POST"])
@_admin
def remove_whitelist(ip):
    ip = ip.strip()
    try:
        conn = get_conn()
        conn.execute("DELETE FROM whitelist WHERE ip=?", (ip,))
        conn.commit()
        return jsonify({"success": True, "message": f"✅ {ip} retirée de la whitelist"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


# ── Blacklist ──────────────────────────────────────────────
@fw_bp.route("/blacklist", methods=["GET"])
@_login
def get_blacklist():
    try:
        return jsonify(repo.get_blacklist())
    except Exception:
        return jsonify([])


@fw_bp.route("/blacklist/add", methods=["POST"])
@_admin
def add_blacklist():
    data = request.get_json(force=True) or {}
    ip = data.get("ip", "").strip()
    raison = data.get("raison", "Manuel")
    if not ip:
        return jsonify({"success": False, "message": "IP requise"}), 400
    repo.add_blacklist(ip, raison, "manual")
    return jsonify({"success": True, "message": f"✅ {ip} ajoutée à la blacklist"})


# ── Logs & Connexions ──────────────────────────────────────
@fw_bp.route("/logs")
@_login
def get_logs():
    limit = int(request.args.get("limit", 50))
    try:
        return jsonify(repo.get_fw_logs(limit))
    except Exception:
        return jsonify([])


@fw_bp.route("/connections")
@_login
def connections():
    try:
        return jsonify(get_active_connections())
    except Exception:
        return jsonify([])


# ── Auto-réponse ───────────────────────────────────────────
@fw_bp.route("/auto-response", methods=["POST", "GET"])
@_admin
def run_auto_response():
    conn = get_conn()
    alertes = conn.execute(
        "SELECT * FROM snort_alertes WHERE traite=0 ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    actions = []
    for a in alertes:
        a = dict(a)
        ip = a.get("src_ip", "")
        if not ip or ip in ["*", "", "—"]:
            continue
        if repo.is_whitelisted(ip):
            continue
        action, msg = auto_response(
            ip, a.get("niveau", "MEDIUM"), a.get("message", "")
        )
        actions.append({
            "ip": ip, "niveau": a.get("niveau"), "action": action, "msg": msg,
        })
        conn.execute("UPDATE snort_alertes SET traite=1 WHERE id=?", (a["id"],))
    conn.commit()
    return jsonify({
        "actions": actions,
        "total": len(actions),
        "message": f"{len(actions)} actions effectuées",
    })
