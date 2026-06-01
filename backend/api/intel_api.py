# backend/api/intel_api.py
from flask import Blueprint, jsonify, session, request
from functools import wraps
from backend.database import repositories as repo

intel_bp = Blueprint('intel', __name__, url_prefix='/api/intel')


def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if "user" not in session:
            return jsonify({"error": "Non authentifié"}), 401
        return f(*a, **kw)
    return d


def _build_recommandations():
    recos = []
    try:
        appareils = repo.get_appareils()
        for a in appareils:
            if a.get("score", 100) < 50:
                recos.append({
                    "priorite":    "CRITICAL",
                    "titre":       f"Score critique : {a['ip']} ({a.get('score',0)}/100)",
                    "description": "Appareil à haut risque — ports dangereux détectés",
                })
        snort = repo.get_snort_alertes(limit=5)
        for s in snort:
            if s.get("niveau") in ("CRITICAL", "HIGH"):
                recos.append({
                    "priorite":    s["niveau"],
                    "titre":       f"Alerte IDS : {str(s.get('message',''))[:50]}",
                    "description": f"Src: {s.get('src_ip','')} → Dst: {s.get('dst_ip','')}",
                })
    except Exception:
        pass

    recos.append({
        "priorite":    "LOW",
        "titre":       "Scanner régulièrement le réseau",
        "description": "Scan hebdomadaire recommandé pour détecter les nouveaux appareils",
    })
    return recos


@intel_bp.route('/risk')
@login_required
def risk_score():
    stats  = repo.get_dashboard_stats()
    score  = 100
    detail = []

    nb_crit = stats.get("nb_alertes_high", 0)
    if nb_crit:
        impact = min(nb_crit * 5, 25)
        score -= impact
        detail.append({"facteur": "Alertes critiques", "valeur": nb_crit,
                       "impact": f"-{impact}", "niveau": "danger"})

    nb_blq = len(repo.get_blocages())
    if nb_blq:
        impact = min(nb_blq * 8, 20)
        score -= impact
        detail.append({"facteur": "IPs bloquées", "valeur": nb_blq,
                       "impact": f"-{impact}", "niveau": "danger"})

    sm = stats.get("score_moyen", 100)
    if sm < 70:
        impact = 20 if sm < 50 else 10
        score -= impact
        detail.append({"facteur": "Score appareils", "valeur": f"{sm}/100",
                       "impact": f"-{impact}", "niveau": "medium"})

    nb_snort = stats.get("nb_snort_crit", 0)
    if nb_snort:
        impact = min(nb_snort * 4, 20)
        score -= impact
        detail.append({"facteur": "Alertes IDS", "valeur": nb_snort,
                       "impact": f"-{impact}", "niveau": "danger"})

    score  = max(0, min(100, score))
    statut = "SAFE" if score >= 80 else ("WARNING" if score >= 60 else "CRITICAL")
    return jsonify({"score": score, "statut": statut, "detail": detail})


@intel_bp.route('/correlations')
@login_required
def correlations():
    try:
        return jsonify(repo.get_correlations())
    except Exception:
        return jsonify([])


@intel_bp.route('/timeline')
@login_required
def timeline():
    events = []
    try:
        for a in repo.get_alertes(limit=30):
            events.append({"ts": a.get("date_alerte",""), "ip": a.get("ip",""),
                           "message": a.get("message",""), "niveau": a.get("niveau",""),
                           "type_ev": "ALERTE"})
        for s in repo.get_snort_alertes(limit=30):
            events.append({"ts": s.get("timestamp",""), "ip": s.get("src_ip",""),
                           "message": s.get("message",""), "niveau": s.get("niveau",""),
                           "type_ev": "IDS"})
        for b in repo.get_blocages():
            events.append({"ts": b.get("date_blocage",""), "ip": b.get("ip",""),
                           "message": b.get("raison",""), "niveau": b.get("niveau","HIGH"),
                           "type_ev": "FIREWALL"})
        for c in repo.get_correlations(limit=20):
            events.append({"ts": c.get("timestamp",""), "ip": c.get("ip",""),
                           "message": c.get("rule_nom",""), "niveau": c.get("severite",""),
                           "type_ev": "CORRELATION"})
    except Exception:
        pass
    events.sort(key=lambda x: x.get("ts",""), reverse=True)
    return jsonify(events[:60])


@intel_bp.route('/recommandations')
@login_required
def recommandations():
    return jsonify(_build_recommandations())


@intel_bp.route('/incidents')
@login_required
def incidents():
    try:
        return jsonify(repo.get_incidents())
    except Exception:
        return jsonify([])


@intel_bp.route('/incidents/<int:inc_id>/update', methods=['POST'])
@login_required
def update_incident(inc_id):
    data = request.get_json(force=True) or {}
    try:
        repo.update_incident(inc_id, data.get("statut","open"), data.get("notes",""))
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
