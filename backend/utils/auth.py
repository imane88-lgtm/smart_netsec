# backend/utils/auth.py
import bcrypt
from datetime import datetime
from backend.database import repositories as repo
from backend.database.db import get_conn

def hash_pwd(pwd):
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()

def check_pwd(pwd, hashed):
    try: return bcrypt.checkpw(pwd.encode(), hashed.encode())
    except: return False

def verifier_login(username, password):
    user = repo.get_user_by_username(username)
    if not user: return None, "Identifiants incorrects"
    if user.get("locked"): return None, "⛔ Compte verrouillé (5 tentatives)"
    if not check_pwd(password, user.get("password_hash","")):
        repo.update_user_login(username, False)
        att = (user.get("login_attempts",0) or 0) + 1
        left = 5 - att
        if left <= 0: return None, "⛔ Compte verrouillé"
        return None, f"❌ Mot de passe incorrect ({left} essais restants)"
    repo.update_user_login(username, True)
    user.pop("password_hash", None)
    return user, "OK"

def init_users():
    conn = get_conn()
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    defaults = [
        ("admin", "Admin@2025!", "admin"),
        ("user",  "User@2025!",  "user"),
    ]
    for username, pwd, role in defaults:
        existing = conn.execute(
            "SELECT id FROM users WHERE username=?",(username,)
        ).fetchone()
        if not existing:
            conn.execute("""INSERT INTO users
                (username,password_hash,role,created_at)
                VALUES (?,?,?,?)""",
                (username, hash_pwd(pwd), role, now))
    conn.commit()

def changer_mdp(username, ancien, nouveau):
    user = repo.get_user_by_username(username)
    if not user: return False,"Utilisateur introuvable"
    if not check_pwd(ancien, user.get("password_hash","")): return False,"Ancien MDP incorrect"
    conn = get_conn()
    conn.execute("UPDATE users SET password_hash=? WHERE username=?",
                (hash_pwd(nouveau),username))
    conn.commit()
    return True,"✅ Mot de passe changé"

def deverrouiller(username):
    conn = get_conn()
    conn.execute("UPDATE users SET locked=0,login_attempts=0 WHERE username=?",(username,))
    conn.commit()
    return True,f"✅ {username} déverrouillé"
