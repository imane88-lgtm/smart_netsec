# auth.py — Version sécurisée complète
# ============================================================

import sqlite3
import bcrypt
import re
from datetime import datetime
from database import DB_PATH


# ──────────────────────────────────────────────
# Validation mot de passe fort
# ──────────────────────────────────────────────
def valider_mot_de_passe(password):
    """
    Vérifie que le mot de passe est fort.
    Retourne (True, "") ou (False, "message erreur")
    """
    if len(password) < 8:
        return False, "Minimum 8 caractères requis"
    if not re.search(r"[A-Z]", password):
        return False, "Au moins une majuscule requise"
    if not re.search(r"[a-z]", password):
        return False, "Au moins une minuscule requise"
    if not re.search(r"\d", password):
        return False, "Au moins un chiffre requis"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", password):
        return False, "Au moins un caractère spécial requis"
    return True, ""


# ──────────────────────────────────────────────
# Initialiser la table users
# ──────────────────────────────────────────────
def init_users():
    """Crée la table users et comptes par défaut."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT DEFAULT 'user',
            created_at    TEXT,
            last_login    TEXT,
            login_attempts INTEGER DEFAULT 0,
            locked        INTEGER DEFAULT 0
        )
    """)

    # Comptes par défaut
    comptes = [
        ("admin", "Admin@2025!", "admin"),
        ("user",  "User@2025!",  "user"),
    ]

    for username, password, role in comptes:
        existe = cursor.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if not existe:
            hash_pwd = bcrypt.hashpw(
                password.encode("utf-8"),
                bcrypt.gensalt()
            )
            cursor.execute("""
                INSERT INTO users
                (username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
            """, (
                username,
                hash_pwd.decode("utf-8"),
                role,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))

    conn.commit()
    conn.close()


# ──────────────────────────────────────────────
# Vérifier login
# ──────────────────────────────────────────────
def verifier_login(username, password):
    """
    Vérifie les identifiants.
    Gère le verrouillage après 5 tentatives.
    Retourne le user dict ou None.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    user = cursor.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not user:
        conn.close()
        return None, "Identifiants incorrects"

    user = dict(user)

    # Vérifier si compte verrouillé
    if user["locked"]:
        conn.close()
        return None, "⛔ Compte verrouillé — contactez l'administrateur"

    # Vérifier le mot de passe
    pwd_ok = bcrypt.checkpw(
        password.encode("utf-8"),
        user["password_hash"].encode("utf-8")
    )

    if not pwd_ok:
        # Incrémenter les tentatives
        tentatives = user["login_attempts"] + 1
        locked     = 1 if tentatives >= 5 else 0

        cursor.execute("""
            UPDATE users
            SET login_attempts = ?, locked = ?
            WHERE username = ?
        """, (tentatives, locked, username))
        conn.commit()
        conn.close()

        restantes = 5 - tentatives
        if locked:
            return None, "⛔ Compte verrouillé après 5 tentatives"
        return None, f"❌ Mot de passe incorrect ({restantes} tentatives restantes)"

    # Succès — réinitialiser les tentatives
    cursor.execute("""
        UPDATE users
        SET login_attempts = 0,
            last_login = ?
        WHERE username = ?
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username))
    conn.commit()
    conn.close()

    # Ne jamais envoyer le hash au client
    user.pop("password_hash", None)
    return user, "OK"


# ──────────────────────────────────────────────
# Changer mot de passe
# ──────────────────────────────────────────────
def changer_mot_de_passe(username, ancien_pwd, nouveau_pwd):
    """Change le mot de passe après vérification."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    user = cursor.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not user:
        conn.close()
        return False, "Utilisateur introuvable"

    # Vérifier ancien mot de passe
    if not bcrypt.checkpw(
        ancien_pwd.encode("utf-8"),
        user["password_hash"].encode("utf-8")
    ):
        conn.close()
        return False, "❌ Ancien mot de passe incorrect"

    # Valider le nouveau
    valide, msg = valider_mot_de_passe(nouveau_pwd)
    if not valide:
        conn.close()
        return False, msg

    # Sauvegarder le nouveau hash
    nouveau_hash = bcrypt.hashpw(
        nouveau_pwd.encode("utf-8"),
        bcrypt.gensalt()
    )
    cursor.execute("""
        UPDATE users SET password_hash = ? WHERE username = ?
    """, (nouveau_hash.decode("utf-8"), username))
    conn.commit()
    conn.close()

    return True, "✅ Mot de passe changé avec succès"


# ──────────────────────────────────────────────
# Créer un utilisateur (admin seulement)
# ──────────────────────────────────────────────
def creer_utilisateur(username, password, role="user"):
    """Crée un nouvel utilisateur."""

    # Valider le mot de passe
    valide, msg = valider_mot_de_passe(password)
    if not valide:
        return False, msg

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Vérifier si username déjà pris
    existe = cursor.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()

    if existe:
        conn.close()
        return False, f"❌ L'utilisateur '{username}' existe déjà"

    # Créer le compte
    hash_pwd = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )
    cursor.execute("""
        INSERT INTO users (username, password_hash, role, created_at)
        VALUES (?, ?, ?, ?)
    """, (
        username,
        hash_pwd.decode("utf-8"),
        role,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()

    return True, f"✅ Utilisateur '{username}' créé ({role})"


# ──────────────────────────────────────────────
# Lister les utilisateurs
# ──────────────────────────────────────────────
def lister_utilisateurs():
    """Retourne tous les users (sans les hashs)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    users = cursor.execute("""
        SELECT id, username, role, created_at,
               last_login, login_attempts, locked
        FROM users ORDER BY id
    """).fetchall()
    conn.close()

    return [dict(u) for u in users]


# ──────────────────────────────────────────────
# Déverrouiller un compte
# ──────────────────────────────────────────────
def deverrouiller_compte(username):
    """Déverrouille un compte bloqué."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users
        SET locked = 0, login_attempts = 0
        WHERE username = ?
    """, (username,))
    conn.commit()
    conn.close()
    return True, f"✅ Compte '{username}' déverrouillé"
