import os
import subprocess
from flask import Blueprint, jsonify, request, session
from functools import wraps
from backend.services.snort_service import (
    import_snort_alerts, inject_demo_alerts,
    is_snort_running, start_snort, stop_snort,
)
from backend.database import repositories as repo

ids_bp = Blueprint("ids", __name__, url_prefix="/api/ids")


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


@ids_bp.route("/alerts")
@_login
def get_alerts():
    limit = int(request.args.get("limit", 100))
    try:
        return jsonify(repo.get_snort_alertes(limit))
    except Exception:
        return jsonify([])


@ids_bp.route("/stats")
@_login
def get_stats():
    try:
        return jsonify(repo.get_snort_stats())
    except Exception:
        return jsonify({
            "total": 0, "critical": 0, "high": 0,
            "medium": 0, "low": 0, "top_ips": [],
        })


@ids_bp.route("/import")
@_admin
def do_import():
    nb = import_snort_alerts()
    if nb == 0:
        nb = inject_demo_alerts()
    return jsonify({"imported": nb, "message": f"{nb} alertes importées"})


@ids_bp.route("/inject-demo")
@_admin
def demo():
    nb = inject_demo_alerts()
    return jsonify({"injected": nb, "message": f"{nb} alertes démo injectées"})


@ids_bp.route("/status")
@_login
def snort_status():
    running = is_snort_running()
    version = "Snort 3"
    try:
        r = subprocess.run(
            ["snort", "--version"],
            capture_output=True, text=True, timeout=3,
        )
        for line in (r.stdout + r.stderr).splitlines():
            if "Version" in line:
                version = line.strip()
                break
    except Exception:
        pass
    return jsonify({
        "running": running,
        "status": "ACTIF" if running else "INACTIF",
        "version": version,
    })


@ids_bp.route("/start")
@_admin
def snort_start():
    ok, msg = start_snort()
    return jsonify({"success": ok, "message": msg})


@ids_bp.route("/stop")
@_admin
def snort_stop():
    ok, msg = stop_snort()
    return jsonify({"success": ok, "message": msg})


@ids_bp.route("/rules")
@_login
def get_rules():
    """Retourne les règles Snort actives depuis le fichier local.rules."""
    rules_files = [
        "/etc/snort/rules/local.rules",
        os.path.expanduser("~/smart_netsec/services/snort/rules/local.rules"),
    ]
    rules = []
    for rules_file in rules_files:
        if os.path.exists(rules_file):
            try:
                with open(rules_file) as f:
                    for i, line in enumerate(f):
                        line = line.strip()
                        if line and not line.startswith("#"):
                            rules.append({
                                "line": i + 1,
                                "rule": line,
                                "active": True,
                                "sid": _extract_sid(line),
                                "msg": _extract_msg(line),
                            })
            except Exception:
                pass
            break  # stop at first found file
    return jsonify(rules)


def _extract_sid(rule):
    import re
    m = re.search(r'sid:(\d+)', rule)
    return m.group(1) if m else "—"


def _extract_msg(rule):
    import re
    m = re.search(r'msg:"([^"]+)"', rule)
    return m.group(1) if m else rule[:60]
