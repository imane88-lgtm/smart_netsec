# backend/api/auth_api.py
from flask import (Blueprint, jsonify, request, session,
                   render_template, redirect, url_for)
from functools import wraps
from backend.utils.auth import verifier_login, init_users, changer_mdp, deverrouiller
from backend.database import repositories as repo

auth_bp = Blueprint("auth", __name__)

def _admin(f):
    @wraps(f)
    def d(*a,**kw):
        if "user" not in session: return redirect(url_for("auth.login"))
        if session["user"]["role"] != "admin":
            return render_template("login.html", error="Accès admin requis")
        return f(*a,**kw)
    return d

@auth_bp.route("/login", methods=["GET","POST"])
def login():
    if "user" in session: return redirect("/")
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if not username or not password:
            return render_template("login.html", error="Remplissez tous les champs")
        user, msg = verifier_login(username, password)
        if user:
            session.permanent = True
            session["user"] = {"id":user["id"],"username":user["username"],"role":user["role"]}
            return redirect("/")
        return render_template("login.html", error=msg)
    return render_template("login.html")

@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@auth_bp.route("/settings")
@_admin
def settings():
    users = repo.get_all_users()
    return render_template("settings.html",
        user=session["user"], users=users,
        msg_success=request.args.get("success"),
        msg_error=request.args.get("error"))

@auth_bp.route("/settings/changer-mdp", methods=["POST"])
@_admin
def changer_mdp_route():
    ancien  = request.form.get("ancien_pwd","")
    nouveau = request.form.get("nouveau_pwd","")
    confirm = request.form.get("confirm_pwd","")
    if nouveau != confirm: return redirect("/settings?error=Mots de passe différents")
    ok, msg = changer_mdp(session["user"]["username"], ancien, nouveau)
    return redirect(f"/settings?{'success' if ok else 'error'}={msg}")

@auth_bp.route("/settings/deverrouiller/<username>")
@_admin
def dev_compte(username):
    ok, msg = deverrouiller(username)
    return redirect(f"/settings?success={msg}")

@auth_bp.route("/api/users")
def api_users():
    if "user" not in session: return jsonify({"error":"Non auth"}),401
    if session["user"]["role"] != "admin": return jsonify({"error":"Admin"}),403
    return jsonify(repo.get_all_users())
