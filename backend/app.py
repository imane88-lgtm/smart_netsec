# backend/app.py — Smart NetSec SOC v3.0 FINAL
import sys, os, threading, subprocess
from datetime import datetime
from flask import (Flask, render_template, jsonify,
                   session, request, send_file,
                   redirect, url_for)
from functools import wraps

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from backend.config import config
from backend.database.db import init_db, get_conn
from backend.database import repositories as repo
from backend.utils.auth import init_users
from backend.utils.logger import get_logger
from backend.api.firewall_api  import fw_bp
from backend.api.ids_api       import ids_bp
from backend.api.monitoring_api import mon_bp
from backend.api.auth_api      import auth_bp
from backend.api.intel_api     import intel_bp

logger = get_logger("app")

TMPL   = os.path.join(ROOT_DIR, "frontend", "templates")
STATIC = os.path.join(ROOT_DIR, "frontend", "static")

app = Flask(__name__, template_folder=TMPL, static_folder=STATIC)
app.secret_key      = config.SECRET_KEY
app.config["DEBUG"] = config.DEBUG

app.register_blueprint(auth_bp)
app.register_blueprint(fw_bp)
app.register_blueprint(ids_bp)
app.register_blueprint(mon_bp)
app.register_blueprint(intel_bp)


def login_req(f):
    @wraps(f)
    def d(*a, **kw):
        if "user" not in session:
            return redirect(url_for("auth.login"))
        return f(*a, **kw)
    return d


def admin_req(f):
    @wraps(f)
    def d(*a, **kw):
        if "user" not in session:
            return redirect(url_for("auth.login"))
        if session["user"]["role"] != "admin":
            return jsonify({"error": "Admin requis"}), 403
        return f(*a, **kw)
    return d


# ── Dashboard ──────────────────────────────────────────────
@app.route("/")
@login_req
def index():
    try:
        appareils     = repo.get_appareils()
        alertes       = repo.get_alertes(limit=10)
        scans         = repo.get_scans(limit=20)
        stats         = repo.get_dashboard_stats()
        blocages      = repo.get_blocages(actif=True)
        snort_alertes = repo.get_snort_alertes(limit=10)
        snort_stats   = repo.get_snort_stats()
        rapports      = repo.get_rapports(limit=10)
    except Exception as e:
        logger.error(f"Dashboard: {e}")
        appareils = alertes = scans = blocages = snort_alertes = rapports = []
        stats = {"nb_appareils":0,"score_moyen":0,"nb_safe":0,"nb_medium":0,
                 "nb_danger":0,"nb_alertes":0,"nb_alertes_high":0,"nb_scans":0,
                 "nb_incidents":0,"nb_snort":0,"nb_snort_crit":0}
        snort_stats = {"total":0,"critical":0,"high":0,"medium":0,"low":0,"top_ips":[]}

    return render_template("index.html",
        appareils=appareils, alertes=alertes, scans=scans,
        stats=stats, blocages=blocages,
        suricata_alertes=snort_alertes, suricata_stats=snort_stats,
        rapports=rapports, user=session["user"])


# ── Scan ───────────────────────────────────────────────────
_scan = {"actif": False, "message": "Prêt"}

@app.route("/lancer-scan")
@admin_req
def lancer_scan():
    if _scan["actif"]:
        return jsonify({"status": "busy", "message": "Scan en cours"})
    def _run():
        _scan["actif"]   = True
        _scan["message"] = "Scan en cours..."
        try:
            subprocess.run(["python3", "scan_complet.py"],
                           cwd=ROOT_DIR, timeout=180)
        except Exception as e:
            logger.error(f"Scan: {e}")
        finally:
            _scan["actif"]   = False
            _scan["message"] = "Terminé"
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started"})

@app.route("/api/scan-status")
@login_req
def scan_status():
    return jsonify(_scan)


# ── Rapports ───────────────────────────────────────────────
@app.route("/generer-rapport")
@login_req
def generer_rapport_route():
    try:
        from rapport_pdf import generer_rapport
        path = generer_rapport(
            output_path=os.path.join(ROOT_DIR, "rapport_securite.pdf")
        )
        stats = repo.get_dashboard_stats()
        repo.save_rapport(
            titre=f"Rapport SOC — {datetime.now().strftime('%d/%m/%Y %H:%M')}",
            nb_appareils=stats.get("nb_appareils", 0),
            nb_alertes=stats.get("nb_alertes", 0),
            score=stats.get("score_moyen", 0),
            genere_par=session.get("user", {}).get("username", "admin"),
        )
        return send_file(path, as_attachment=True,
                         download_name="rapport_netsec.pdf")
    except Exception as e:
        logger.error(f"PDF: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/rapports")
@login_req
def api_rapports():
    try:
        return jsonify(repo.get_rapports(20))
    except Exception:
        return jsonify([])

@app.route("/api/rapports/save", methods=["POST"])
@login_req
def api_save_rapport():
    try:
        stats = repo.get_dashboard_stats()
        repo.save_rapport(
            titre=f"Rapport SOC — {datetime.now().strftime('%d/%m/%Y %H:%M')}",
            nb_appareils=stats.get("nb_appareils", 0),
            nb_alertes=stats.get("nb_alertes", 0),
            score=stats.get("score_moyen", 0),
            genere_par=session.get("user", {}).get("username", "admin"),
        )
        return jsonify({"success": True, "message": "Rapport enregistré"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# ── Supervision ────────────────────────────────────────────
@app.route("/api/supervision")
@login_req
def api_supervision():
    try:
        from backend.services.monitoring_service import get_snapshot
        return jsonify(get_snapshot())
    except Exception:
        return jsonify({
            "statut": "NORMAL",
            "systeme": {
                "cpu": 0, "ram_pct": 0, "ram_used": 0, "ram_total": 0,
                "disk_pct": 0, "disk_used": 0, "disk_total": 0,
                "bytes_sent": 0, "bytes_recv": 0,
                "net_rate_in": 0, "net_rate_out": 0, "nb_connexions": 0,
            },
            "securite": {}, "connexions": [],
        })


# ── Intelligence ───────────────────────────────────────────
@app.route("/api/intelligence/recommandations")
@login_req
def api_recommandations():
    try:
        recos = []
        for a in repo.get_appareils():
            if a.get("score", 100) < 50:
                recos.append({
                    "priorite": "CRITICAL",
                    "titre": f"Score critique : {a['ip']}",
                    "description": f"Appareil {a['ip']} — score {a.get('score',0)}/100",
                })
        for s in repo.get_snort_alertes(limit=5):
            if s.get("niveau") in ("CRITICAL","HIGH"):
                recos.append({
                    "priorite": s["niveau"],
                    "titre": f"Alerte IDS : {s.get('message','')[:50]}",
                    "description": f"IP: {s.get('src_ip','')}",
                })
        if not recos:
            recos.append({"priorite":"LOW","titre":"Système stable",
                          "description":"Aucune anomalie critique détectée"})
        return jsonify(recos)
    except Exception:
        return jsonify([{"titre":"Système actif","description":"Surveillance en cours"}])

@app.route("/api/intelligence/timeline")
@login_req
def api_timeline():
    try:
        events = []
        for a in repo.get_alertes(limit=20):
            events.append({"ts":a.get("date_alerte",""),"ip":a.get("ip",""),
                "message":a.get("message",""),"niveau":a.get("niveau",""),"type_ev":"ALERTE"})
        for s in repo.get_snort_alertes(limit=20):
            events.append({"ts":s.get("timestamp",""),"ip":s.get("src_ip",""),
                "message":s.get("message",""),"niveau":s.get("niveau",""),"type_ev":"IDS"})
        for b in repo.get_blocages():
            events.append({"ts":b.get("date_blocage",""),"ip":b.get("ip",""),
                "message":b.get("raison",""),"niveau":b.get("niveau","HIGH"),"type_ev":"FIREWALL"})
        for c in repo.get_correlations(limit=10):
            events.append({"ts":c.get("timestamp",""),"ip":c.get("ip",""),
                "message":c.get("rule_nom",""),"niveau":c.get("severite",""),"type_ev":"CORRELATION"})
        events.sort(key=lambda x: x.get("ts",""), reverse=True)
        return jsonify(events[:60])
    except Exception:
        return jsonify([])

@app.route("/api/intelligence/correlations")
@login_req
def api_correlations():
    try:
        return jsonify(repo.get_correlations())
    except Exception:
        return jsonify([])


# ── Suricata compat ────────────────────────────────────────
@app.route("/suricata/importer")
@admin_req
def suricata_importer():
    from backend.services.snort_service import import_snort_alerts, inject_demo_alerts
    nb = import_snort_alerts()
    if nb == 0:
        nb = inject_demo_alerts()
    return jsonify({"imported": nb})


# ── AI ─────────────────────────────────────────────────────
@app.route("/ai/chat", methods=["POST"])
@login_req
def ai_chat():
    try:
        from ai_assistant import AIAssistant
        data = request.get_json(force=True) or {}
        msg  = (data.get("message") or "").strip()
        if not msg:
            return jsonify({"reponse": "Message vide."})
        return jsonify({"reponse": AIAssistant().repondre(msg)})
    except Exception as e:
        return jsonify({"reponse": f"AI indisponible: {e}"})

@app.route("/ai/resume")
@login_req
def ai_resume():
    try:
        from ai_assistant import AIAssistant
        return jsonify(AIAssistant().get_resume_systeme())
    except Exception:
        s = repo.get_dashboard_stats()
        return jsonify({
            "score":        s.get("score_moyen", 0),
            "nb_appareils": s.get("nb_appareils", 0),
            "nb_critical":  s.get("nb_alertes_high", 0),
            "nb_bloques":   len(repo.get_blocages()),
        })


# ── Init ───────────────────────────────────────────────────
def create_app():
    with app.app_context():
        try:
            init_db()
            init_users()
            logger.info("✅ DB OK")
        except Exception as e:
            logger.error(f"DB: {e}")

        try:
            from backend.services.firewall_service import init_nftables
            init_nftables()
        except Exception as e:
            logger.warning(f"nftables: {e}")

        try:
            conn = get_conn()
            if conn.execute("SELECT COUNT(*) FROM snort_alertes").fetchone()[0] == 0:
                from backend.services.snort_service import inject_demo_alerts
                inject_demo_alerts()
        except Exception:
            pass

        try:
            from backend.services.monitoring_service import monitoring_service
            monitoring_service.start()
        except Exception as e:
            logger.warning(f"Monitoring: {e}")

        try:
            from backend.services.snort_service import snort_watcher
            snort_watcher.start_watch()
        except Exception as e:
            logger.warning(f"SnortWatcher: {e}")

    return app
