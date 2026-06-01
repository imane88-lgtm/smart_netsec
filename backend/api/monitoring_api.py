# backend/api/monitoring_api.py
from flask import Blueprint, jsonify, request, session
from functools import wraps
from backend.services.monitoring_service import get_snapshot
from backend.database import repositories as repo

mon_bp = Blueprint("monitoring", __name__, url_prefix="/api/monitoring")


def _login(f):
    @wraps(f)
    def d(*a, **kw):
        if "user" not in session:
            return jsonify({"error": "Non authentifié"}), 401
        return f(*a, **kw)
    return d


@mon_bp.route("/snapshot")
@_login
def snapshot():
    try:
        return jsonify(get_snapshot())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@mon_bp.route("/history")
@_login
def history():
    limit = int(request.args.get("limit", 60))
    try:
        return jsonify(repo.get_supervision_history(limit))
    except Exception:
        return jsonify([])


@mon_bp.route("/stats")
@_login
def stats():
    try:
        return jsonify(repo.get_dashboard_stats())
    except Exception:
        return jsonify({})
