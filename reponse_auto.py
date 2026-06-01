# reponse_auto.py
# ============================================================
# MODULE 8 : Réponse automatique aux menaces
# Objectif : bloquer/débloquer les IPs dangereuses
# ============================================================

import subprocess
import sqlite3
from datetime import datetime
from database import DB_PATH


# ──────────────────────────────────────────────
# Fonction : Initialiser la table des blocages
# ──────────────────────────────────────────────
def init_blocages():
    """Crée la table des IPs bloquées."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT NOT NULL,
            raison      TEXT,
            date_blocage TEXT,
            actif       INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()


# ──────────────────────────────────────────────
# Fonction : Bloquer une IP
# ──────────────────────────────────────────────
def bloquer_ip(ip, raison="Menace détectée automatiquement"):
    """
    Bloque une IP via iptables.
    Sauvegarde le blocage en base.
    """
    print(f"\n  🔴 BLOCAGE IP : {ip}")
    print(f"  📋 Raison : {raison}")

    # ── Vérifier si déjà bloquée ──
    if est_bloquee(ip):
        print(f"  ⚠️  {ip} est déjà bloquée")
        return False

    # ── Bloquer via iptables ──
    try:
        # Bloquer tout trafic entrant depuis cette IP
        subprocess.run([
            "sudo", "iptables",
            "-I", "INPUT",
            "-s", ip,
            "-j", "DROP"
        ], check=True)

        # Bloquer tout trafic sortant vers cette IP
        subprocess.run([
            "sudo", "iptables",
            "-I", "OUTPUT",
            "-d", ip,
            "-j", "DROP"
        ], check=True)

        print(f"  ✅ {ip} bloquée via iptables")

    except subprocess.CalledProcessError as e:
        print(f"  ❌ Erreur iptables : {e}")
        return False

    # ── Sauvegarder en base ──
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO blocages (ip, raison, date_blocage, actif)
        VALUES (?, ?, ?, 1)
    """, (ip, raison, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

    return True


# ──────────────────────────────────────────────
# Fonction : Débloquer une IP
# ──────────────────────────────────────────────
def debloquer_ip(ip):
    """Supprime le blocage d'une IP."""
    print(f"\n  🟢 DÉBLOCAGE IP : {ip}")

    try:
        # Supprimer la règle INPUT
        subprocess.run([
            "sudo", "iptables",
            "-D", "INPUT",
            "-s", ip,
            "-j", "DROP"
        ], check=True)

        # Supprimer la règle OUTPUT
        subprocess.run([
            "sudo", "iptables",
            "-D", "OUTPUT",
            "-d", ip,
            "-j", "DROP"
        ], check=True)

        print(f"  ✅ {ip} débloquée")

    except subprocess.CalledProcessError as e:
        print(f"  ❌ Erreur iptables : {e}")
        return False

    # ── Mettre à jour la base ──
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE blocages SET actif = 0 WHERE ip = ?", (ip,)
    )
    conn.commit()
    conn.close()

    return True


# ──────────────────────────────────────────────
# Fonction : Vérifier si une IP est bloquée
# ──────────────────────────────────────────────
def est_bloquee(ip):
    """Retourne True si l'IP est actuellement bloquée."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM blocages WHERE ip = ? AND actif = 1", (ip,)
    )
    result = cursor.fetchone()
    conn.close()
    return result is not None


# ──────────────────────────────────────────────
# Fonction : Lister les IPs bloquées
# ──────────────────────────────────────────────
def lister_blocages():
    """Affiche toutes les IPs bloquées."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM blocages ORDER BY date_blocage DESC"
    )
    blocages = [dict(row) for row in cursor.fetchall()]
    conn.close()

    print(f"\n{'='*55}")
    print(f"  🔒 IPs BLOQUÉES")
    print(f"{'='*55}")

    actives  = [b for b in blocages if b["actif"] == 1]
    inactives= [b for b in blocages if b["actif"] == 0]

    if actives:
        print(f"\n  🔴 Bloquées actuellement ({len(actives)}) :")
        for b in actives:
            print(f"     → {b['ip']:20} | {b['date_blocage']} | {b['raison'][:30]}")
    else:
        print("  ✅ Aucune IP bloquée actuellement")

    if inactives:
        print(f"\n  ✅ Débloquées ({len(inactives)}) :")
        for b in inactives:
            print(f"     → {b['ip']:20} | {b['date_blocage']}")

    print(f"{'='*55}\n")
    return blocages


# ──────────────────────────────────────────────
# Fonction : Réponse automatique basée sur score
# ──────────────────────────────────────────────
def reponse_automatique(appareils, seuil_danger=49, ip_locale=None):
    """
    Analyse les scores et bloque automatiquement
    les appareils dangereux.

    seuil_danger : score en dessous duquel on bloque
    ip_locale    : ton IP (pour ne jamais te bloquer toi-même)
    """
    print(f"\n{'='*55}")
    print(f"  ⚡ RÉPONSE AUTOMATIQUE")
    print(f"  Seuil de danger : score < {seuil_danger}")
    print(f"{'='*55}\n")

    bloques  = []
    ignores  = []

    for appareil in appareils:
        ip    = appareil.get("ip", "")
        score = appareil.get("score", 100)

        # Ne jamais bloquer son propre IP !
        if ip == ip_locale:
            print(f"  ⚪ {ip:20} → Ignoré (IP locale)")
            ignores.append(ip)
            continue

        if score <= seuil_danger:
            raison = (
                f"Score de sécurité critique : {score}/100 — "
                f"Blocage automatique"
            )
            succes = bloquer_ip(ip, raison)
            if succes:
                bloques.append(ip)
        else:
            niveau = "🟢 SAFE" if score >= 80 else "🟠 MEDIUM"
            print(f"  ✅ {ip:20} → Score {score}/100 {niveau} — OK")

    # ── Résumé ──
    print(f"\n{'='*55}")
    print(f"  📊 RÉSUMÉ RÉPONSE AUTOMATIQUE")
    print(f"{'='*55}")
    print(f"  IPs analysées  : {len(appareils)}")
    print(f"  IPs bloquées   : {len(bloques)}")
    print(f"  IPs ignorées   : {len(ignores)}")
    if bloques:
        print(f"\n  🔴 IPs bloquées :")
        for ip in bloques:
            print(f"     → {ip}")
    print(f"{'='*55}\n")

    return bloques


# ──────────────────────────────────────────────
# Fonction : Voir règles iptables actuelles
# ──────────────────────────────────────────────
def voir_regles_iptables():
    """Affiche les règles iptables actives."""
    print("\n  📋 Règles iptables actives :\n")
    try:
        result = subprocess.run(
            ["sudo", "iptables", "-L", "INPUT", "-n", "--line-numbers"],
            capture_output=True, text=True
        )
        print(result.stdout)
    except Exception as e:
        print(f"  ❌ Erreur : {e}")


# ──────────────────────────────────────────────
# Point d'entrée — Test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    init_blocages()

    # Simuler des appareils avec scores
    appareils_test = [
        {"ip": "192.168.216.1",   "score": 61},
        {"ip": "192.168.216.2",   "score": 92},
        {"ip": "192.168.216.143", "score": 85},
    ]

    # Lancer la réponse automatique
    # (ton IP = 192.168.216.143 → jamais bloquée)
    reponse_automatique(
        appareils_test,
        seuil_danger=65,              # Bloque si score < 65
        ip_locale="192.168.216.143"   # Ton IP — jamais bloquée
    )

    # Afficher les blocages
    lister_blocages()

    # Voir les règles iptables
    voir_regles_iptables()
