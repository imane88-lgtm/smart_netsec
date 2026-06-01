# firewall.py
# ============================================================
# MODULE FIREWALL INTELLIGENT
# Whitelist / Blacklist / Blocage automatique
# ============================================================

import sqlite3
import subprocess
from datetime import datetime
from database import DB_PATH


# ──────────────────────────────────────────────
# IPs jamais bloquées (whitelist statique)
# ──────────────────────────────────────────────
WHITELIST_STATIQUE = [
    "127.0.0.1",
    "192.168.216.143",   # Ton IP Kali
]


# ──────────────────────────────────────────────
# Initialiser les tables firewall
# ──────────────────────────────────────────────
def init_firewall():
    """Crée les tables whitelist, blacklist, firewall_logs."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Whitelist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT UNIQUE NOT NULL,
            raison     TEXT,
            date_ajout TEXT
        )
    """)

    # Blacklist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT UNIQUE NOT NULL,
            raison     TEXT,
            date_ajout TEXT,
            actif      INTEGER DEFAULT 1
        )
    """)

    # Logs firewall
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS firewall_logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            action    TEXT,
            ip        TEXT,
            raison    TEXT,
            niveau    TEXT,
            resultat  TEXT,
            timestamp TEXT
        )
    """)

    # Insérer whitelist statique
    for ip in WHITELIST_STATIQUE:
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO whitelist (ip, raison, date_ajout)
                VALUES (?, ?, ?)
            """, (ip, "IP système protégée",
                  datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        except:
            pass

    conn.commit()
    conn.close()
    print("  ✅ Firewall initialisé")


# ──────────────────────────────────────────────
# Vérifications whitelist / blacklist
# ──────────────────────────────────────────────
def est_whiteliste(ip):
    """Retourne True si l'IP est en whitelist."""
    if ip in WHITELIST_STATIQUE:
        return True
    conn = sqlite3.connect(DB_PATH)
    result = conn.execute(
        "SELECT id FROM whitelist WHERE ip = ?", (ip,)
    ).fetchone()
    conn.close()
    return result is not None


def est_blackliste(ip):
    """Retourne True si l'IP est en blacklist active."""
    conn = sqlite3.connect(DB_PATH)
    result = conn.execute(
        "SELECT id FROM blacklist WHERE ip = ? AND actif = 1", (ip,)
    ).fetchone()
    conn.close()
    return result is not None


def est_bloquee(ip):
    """Retourne True si l'IP est bloquée en base."""
    conn = sqlite3.connect(DB_PATH)
    try:
        result = conn.execute(
            "SELECT id FROM blocages WHERE ip = ? AND actif = 1", (ip,)
        ).fetchone()
    except:
        result = None
    conn.close()
    return result is not None


# ──────────────────────────────────────────────
# Logger une action firewall
# ──────────────────────────────────────────────
def log_action(action, ip, raison, niveau, resultat):
    """Enregistre une action firewall dans les logs."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO firewall_logs
        (action, ip, raison, niveau, resultat, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        action, ip, raison, niveau, resultat,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


# ──────────────────────────────────────────────
# Bloquer une IP
# ──────────────────────────────────────────────
def block_ip(ip, raison="Blocage manuel", niveau="HIGH"):
    """
    Bloque une IP via iptables + sauvegarde en base.
    Retourne (True, message) ou (False, erreur)
    """
    # Vérifier whitelist
    if est_whiteliste(ip):
        msg = f"⚪ {ip} est en whitelist — blocage refusé"
        log_action("BLOCK_REFUSED", ip, raison, niveau, "WHITELIST")
        return False, msg

    # Déjà bloquée ?
    if est_bloquee(ip):
        return False, f"⚠️ {ip} déjà bloquée"

    # Ajouter à la blacklist
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("""
            INSERT OR REPLACE INTO blacklist (ip, raison, date_ajout, actif)
            VALUES (?, ?, ?, 1)
        """, (ip, raison, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

        conn.execute("""
            INSERT OR REPLACE INTO blocages (ip, raison, date_blocage, actif)
            VALUES (?, ?, ?, 1)
        """, (ip, raison, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
    except Exception as e:
        conn.close()
        return False, f"Erreur base : {e}"
    conn.close()

    # Appliquer via iptables
    try:
        subprocess.run(
            ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        subprocess.run(
            ["sudo", "iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        resultat = "SUCCESS"
        msg = f"✅ {ip} bloquée via iptables"
    except Exception as e:
        resultat = "IPTABLES_ERROR"
        msg = f"⚠️ {ip} marquée bloquée (iptables: {e})"

    log_action("BLOCK", ip, raison, niveau, resultat)
    print(f"  🔴 {msg}")
    return True, msg


# ──────────────────────────────────────────────
# Débloquer une IP
# ──────────────────────────────────────────────
def unblock_ip(ip):
    """Débloque une IP."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE blocages SET actif = 0 WHERE ip = ?", (ip,)
    )
    conn.execute(
        "UPDATE blacklist SET actif = 0 WHERE ip = ?", (ip,)
    )
    conn.commit()
    conn.close()

    try:
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        subprocess.run(
            ["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
            capture_output=True
        )
    except:
        pass

    log_action("UNBLOCK", ip, "Déblocage manuel", "INFO", "SUCCESS")
    print(f"  🟢 {ip} débloquée")
    return True, f"✅ {ip} débloquée"


# ──────────────────────────────────────────────
# Ajouter à la whitelist
# ──────────────────────────────────────────────
def add_whitelist(ip, raison="Ajout manuel"):
    """Ajoute une IP à la whitelist."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("""
            INSERT OR IGNORE INTO whitelist (ip, raison, date_ajout)
            VALUES (?, ?, ?)
        """, (ip, raison, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
        log_action("WHITELIST_ADD", ip, raison, "INFO", "SUCCESS")
        return True, f"✅ {ip} ajoutée à la whitelist"
    except Exception as e:
        conn.close()
        return False, str(e)


# ──────────────────────────────────────────────
# Réponse automatique selon niveau alerte
# ──────────────────────────────────────────────
def reponse_automatique_alerte(ip, niveau, signature=""):
    """
    Décide automatiquement de l'action selon le niveau :
    CRITICAL → blocage immédiat
    HIGH     → blocage + log
    MEDIUM   → surveillance + log
    LOW      → simple log
    """
    if niveau == "CRITICAL":
        succes, msg = block_ip(
            ip,
            raison=f"Blocage automatique CRITICAL : {signature}",
            niveau="CRITICAL"
        )
        return "BLOCKED", msg

    elif niveau == "HIGH":
        succes, msg = block_ip(
            ip,
            raison=f"Blocage automatique HIGH : {signature}",
            niveau="HIGH"
        )
        return "BLOCKED", msg

    elif niveau == "MEDIUM":
        log_action("MONITOR", ip,
                   f"Surveillance MEDIUM : {signature}",
                   "MEDIUM", "MONITORING")
        return "MONITORING", f"👁️ {ip} en surveillance"

    else:
        log_action("LOG", ip,
                   f"Log LOW : {signature}",
                   "LOW", "LOGGED")
        return "LOGGED", f"📝 {ip} logué"


# ──────────────────────────────────────────────
# Récupérer données pour dashboard
# ──────────────────────────────────────────────
def get_firewall_stats():
    """Retourne les statistiques du firewall."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        nb_bloques    = conn.execute(
            "SELECT COUNT(*) FROM blocages WHERE actif=1"
        ).fetchone()[0]
        nb_whitelist  = conn.execute(
            "SELECT COUNT(*) FROM whitelist"
        ).fetchone()[0]
        nb_blacklist  = conn.execute(
            "SELECT COUNT(*) FROM blacklist WHERE actif=1"
        ).fetchone()[0]
        derniere_ip   = conn.execute(
            "SELECT ip FROM blocages WHERE actif=1 ORDER BY date_blocage DESC LIMIT 1"
        ).fetchone()
        derniere_ip   = derniere_ip[0] if derniere_ip else "—"

        logs_recents  = conn.execute("""
            SELECT * FROM firewall_logs
            ORDER BY timestamp DESC LIMIT 10
        """).fetchall()

        ips_bloquees  = conn.execute("""
            SELECT * FROM blocages WHERE actif=1
            ORDER BY date_blocage DESC
        """).fetchall()

    except Exception as e:
        print(f"Erreur firewall stats : {e}")
        nb_bloques = nb_whitelist = nb_blacklist = 0
        derniere_ip = "—"
        logs_recents = []
        ips_bloquees = []

    conn.close()

    return {
        "nb_bloques":   nb_bloques,
        "nb_whitelist": nb_whitelist,
        "nb_blacklist": nb_blacklist,
        "derniere_ip":  derniere_ip,
        "statut":       "🔴 ACTIF" if nb_bloques > 0 else "🟢 NORMAL",
        "logs":         [dict(l) for l in logs_recents],
        "ips_bloquees": [dict(i) for i in ips_bloquees],
    }


# ──────────────────────────────────────────────
# Traiter toutes les alertes Suricata
# ──────────────────────────────────────────────
def traiter_alertes_suricata():
    """
    Lit toutes les alertes Suricata non traitées
    et applique la réponse automatique.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        alertes = conn.execute("""
            SELECT * FROM suricata_alertes
            ORDER BY timestamp DESC LIMIT 50
        """).fetchall()
    except:
        alertes = []
    conn.close()

    print(f"\n  ⚡ Traitement de {len(alertes)} alertes Suricata...\n")
    actions = []

    for alerte in alertes:
        alerte = dict(alerte)
        ip     = alerte.get("src_ip", "")
        niveau = alerte.get("niveau", "LOW")
        sig    = alerte.get("signature", "")

        if not ip or ip in ["?", "127.0.0.1"]:
            continue

        action, msg = reponse_automatique_alerte(ip, niveau, sig)
        actions.append({
            "ip":     ip,
            "niveau": niveau,
            "action": action,
            "msg":    msg
        })
        print(f"  [{niveau}] {ip} → {action} : {msg}")

    return actions


# ──────────────────────────────────────────────
# Point d'entrée — Test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("\n🛡️  Test Module Firewall\n")

    init_firewall()

    # Test blocage
    block_ip("192.168.216.1",
             raison="Test blocage SMB dangereux",
             niveau="HIGH")

    # Test whitelist
    succes, msg = block_ip("192.168.216.143",
                            raison="Test whitelist")
    print(f"  Résultat whitelist : {msg}")

    # Test réponse automatique
    reponse_automatique_alerte(
        "10.0.0.5", "CRITICAL", "ET EXPLOIT EternalBlue"
    )
    reponse_automatique_alerte(
        "10.0.0.6", "MEDIUM", "ET SCAN Nmap"
    )

    # Stats
    stats = get_firewall_stats()
    print(f"""
  📊 Stats Firewall :
  IPs bloquées  : {stats['nb_bloques']}
  Whitelist     : {stats['nb_whitelist']}
  Blacklist     : {stats['nb_blacklist']}
  Dernière IP   : {stats['derniere_ip']}
  Statut        : {stats['statut']}
    """)

    # Traiter alertes Suricata
    traiter_alertes_suricata()
