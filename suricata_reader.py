# suricata_reader.py
# ============================================================
# MODULE : Lecture des alertes Suricata IDS
# Lit eve.json et stocke les alertes en base de données
# ============================================================

import json
import sqlite3
import os
from datetime import datetime
from database import DB_PATH

# Chemin du fichier de logs Suricata
EVE_JSON_PATH = "/var/log/suricata/eve.json"


# ──────────────────────────────────────────────
# Initialiser la table Suricata
# ──────────────────────────────────────────────
def init_suricata_table():
    """Crée la table pour les alertes Suricata."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS suricata_alertes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            src_ip      TEXT,
            src_port    INTEGER,
            dest_ip     TEXT,
            dest_port   INTEGER,
            protocole   TEXT,
            signature   TEXT,
            categorie   TEXT,
            severite    INTEGER DEFAULT 3,
            niveau      TEXT DEFAULT 'MEDIUM',
            raw_data    TEXT,
            date_import TEXT
        )
    """)

    conn.commit()
    conn.close()


# ──────────────────────────────────────────────
# Convertir sévérité Suricata → niveau
# ──────────────────────────────────────────────
def severite_vers_niveau(severite):
    """
    Suricata utilise 1-4 :
    1 = Critical, 2 = High, 3 = Medium, 4 = Low
    """
    mapping = {
        1: "CRITICAL",
        2: "HIGH",
        3: "MEDIUM",
        4: "LOW",
    }
    return mapping.get(severite, "MEDIUM")


# ──────────────────────────────────────────────
# Lire et parser eve.json
# ──────────────────────────────────────────────
def lire_eve_json(limit=100):
    """
    Lit le fichier eve.json de Suricata.
    Retourne uniquement les événements de type 'alert'.
    """
    if not os.path.exists(EVE_JSON_PATH):
        print(f"  ⚠️  Fichier introuvable : {EVE_JSON_PATH}")
        return []

    alertes = []

    try:
        with open(EVE_JSON_PATH, "r") as f:
            lignes = f.readlines()

        # Lire les dernières lignes (plus récentes)
        for ligne in reversed(lignes[-500:]):
            ligne = ligne.strip()
            if not ligne:
                continue

            try:
                event = json.loads(ligne)
            except json.JSONDecodeError:
                continue

            # On ne garde que les alertes
            if event.get("event_type") != "alert":
                continue

            alert = event.get("alert", {})
            severite = alert.get("severity", 3)

            alertes.append({
                "timestamp":  event.get("timestamp", ""),
                "src_ip":     event.get("src_ip", "?"),
                "src_port":   event.get("src_port", 0),
                "dest_ip":    event.get("dest_ip", "?"),
                "dest_port":  event.get("dest_port", 0),
                "protocole":  event.get("proto", "?"),
                "signature":  alert.get("signature", "Alerte inconnue"),
                "categorie":  alert.get("category", "Inconnu"),
                "severite":   severite,
                "niveau":     severite_vers_niveau(severite),
                "raw_data":   ligne,
            })

            if len(alertes) >= limit:
                break

    except Exception as e:
        print(f"  ❌ Erreur lecture eve.json : {e}")

    return alertes


# ──────────────────────────────────────────────
# Importer les alertes en base de données
# ──────────────────────────────────────────────
def importer_alertes_suricata():
    """
    Lit eve.json et importe les nouvelles alertes
    dans la base de données.
    """
    print("\n  🔍 Lecture des alertes Suricata...")

    alertes = lire_eve_json()

    if not alertes:
        print("  ℹ️  Aucune alerte Suricata trouvée")
        return 0

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    nouvelles = 0
    for alerte in alertes:
        # Vérifier si déjà importée (par timestamp + src_ip)
        existe = cursor.execute("""
            SELECT id FROM suricata_alertes
            WHERE timestamp = ? AND src_ip = ? AND signature = ?
        """, (
            alerte["timestamp"],
            alerte["src_ip"],
            alerte["signature"]
        )).fetchone()

        if not existe:
            cursor.execute("""
                INSERT INTO suricata_alertes
                (timestamp, src_ip, src_port, dest_ip, dest_port,
                 protocole, signature, categorie, severite,
                 niveau, raw_data, date_import)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alerte["timestamp"],
                alerte["src_ip"],
                alerte["src_port"],
                alerte["dest_ip"],
                alerte["dest_port"],
                alerte["protocole"],
                alerte["signature"],
                alerte["categorie"],
                alerte["severite"],
                alerte["niveau"],
                alerte["raw_data"],
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ))
            nouvelles += 1

    conn.commit()
    conn.close()

    print(f"  ✅ {nouvelles} nouvelles alertes importées")
    return nouvelles


# ──────────────────────────────────────────────
# Récupérer les alertes depuis la base
# ──────────────────────────────────────────────
def get_suricata_alertes(limit=50):
    """Retourne les alertes Suricata depuis la base."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    alertes = cursor.execute("""
        SELECT * FROM suricata_alertes
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,)).fetchall()

    conn.close()
    return [dict(a) for a in alertes]


# ──────────────────────────────────────────────
# Statistiques Suricata
# ──────────────────────────────────────────────
def get_suricata_stats():
    """Retourne les statistiques des alertes Suricata."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        total    = cursor.execute(
            "SELECT COUNT(*) FROM suricata_alertes"
        ).fetchone()[0]

        critical = cursor.execute(
            "SELECT COUNT(*) FROM suricata_alertes WHERE niveau='CRITICAL'"
        ).fetchone()[0]

        high     = cursor.execute(
            "SELECT COUNT(*) FROM suricata_alertes WHERE niveau='HIGH'"
        ).fetchone()[0]

        medium   = cursor.execute(
            "SELECT COUNT(*) FROM suricata_alertes WHERE niveau='MEDIUM'"
        ).fetchone()[0]

        low      = cursor.execute(
            "SELECT COUNT(*) FROM suricata_alertes WHERE niveau='LOW'"
        ).fetchone()[0]

        # Top IPs suspectes
        top_ips  = cursor.execute("""
            SELECT src_ip, COUNT(*) as nb
            FROM suricata_alertes
            GROUP BY src_ip
            ORDER BY nb DESC
            LIMIT 5
        """).fetchall()

    except:
        total = critical = high = medium = low = 0
        top_ips = []

    conn.close()

    return {
        "total":    total,
        "critical": critical,
        "high":     high,
        "medium":   medium,
        "low":      low,
        "top_ips":  [{"ip": r[0], "nb": r[1]} for r in top_ips],
    }


# ──────────────────────────────────────────────
# Simuler des alertes (si Suricata pas actif)
# ──────────────────────────────────────────────
def simuler_alertes_test():
    """
    Insère des alertes de test dans la base.
    Utile si Suricata n'est pas encore actif.
    """
    alertes_test = [
        {
            "timestamp":  "2026-04-13T14:00:00",
            "src_ip":     "192.168.216.1",
            "src_port":   4444,
            "dest_ip":    "192.168.216.143",
            "dest_port":  80,
            "protocole":  "TCP",
            "signature":  "ET SCAN Nmap SYN Scan",
            "categorie":  "Network Scan",
            "severite":   2,
            "niveau":     "HIGH",
            "raw_data":   "{}",
        },
        {
            "timestamp":  "2026-04-13T14:01:00",
            "src_ip":     "192.168.216.1",
            "src_port":   445,
            "dest_ip":    "192.168.216.143",
            "dest_port":  445,
            "protocole":  "TCP",
            "signature":  "ET EXPLOIT EternalBlue MS17-010",
            "categorie":  "Exploit",
            "severite":   1,
            "niveau":     "CRITICAL",
            "raw_data":   "{}",
        },
        {
            "timestamp":  "2026-04-13T14:02:00",
            "src_ip":     "192.168.216.2",
            "src_port":   22,
            "dest_ip":    "192.168.216.143",
            "dest_port":  22,
            "protocole":  "TCP",
            "signature":  "ET BRUTE SSH Brute Force",
            "categorie":  "Brute Force",
            "severite":   2,
            "niveau":     "HIGH",
            "raw_data":   "{}",
        },
        {
            "timestamp":  "2026-04-13T14:03:00",
            "src_ip":     "192.168.216.1",
            "src_port":   80,
            "dest_ip":    "192.168.216.143",
            "dest_port":  8080,
            "protocole":  "TCP",
            "signature":  "ET WEB SQL Injection Attempt",
            "categorie":  "Web Attack",
            "severite":   2,
            "niveau":     "HIGH",
            "raw_data":   "{}",
        },
        {
            "timestamp":  "2026-04-13T14:04:00",
            "src_ip":     "192.168.216.2",
            "src_port":   53,
            "dest_ip":    "8.8.8.8",
            "dest_port":  53,
            "protocole":  "UDP",
            "signature":  "ET DNS Suspicious Query",
            "categorie":  "DNS",
            "severite":   3,
            "niveau":     "MEDIUM",
            "raw_data":   "{}",
        },
    ]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    importees = 0

    for a in alertes_test:
        existe = cursor.execute("""
            SELECT id FROM suricata_alertes
            WHERE timestamp = ? AND signature = ?
        """, (a["timestamp"], a["signature"])).fetchone()

        if not existe:
            cursor.execute("""
                INSERT INTO suricata_alertes
                (timestamp, src_ip, src_port, dest_ip, dest_port,
                 protocole, signature, categorie, severite,
                 niveau, raw_data, date_import)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                a["timestamp"], a["src_ip"], a["src_port"],
                a["dest_ip"],   a["dest_port"], a["protocole"],
                a["signature"], a["categorie"], a["severite"],
                a["niveau"],    a["raw_data"],
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ))
            importees += 1

    conn.commit()
    conn.close()

    print(f"  ✅ {importees} alertes de test insérées")
    return importees


# ──────────────────────────────────────────────
# Point d'entrée — Test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("\n🛡️  Test module Suricata\n")

    init_suricata_table()

    # Essayer de lire le vrai eve.json
    alertes_reelles = lire_eve_json()

    if alertes_reelles:
        print(f"  📡 {len(alertes_reelles)} alertes Suricata réelles trouvées")
        importer_alertes_suricata()
    else:
        print("  ℹ️  Suricata inactif — insertion alertes de test...")
        simuler_alertes_test()

    # Afficher les stats
    stats = get_suricata_stats()
    print(f"""
  📊 Statistiques Suricata :
  Total     : {stats['total']}
  Critical  : {stats['critical']}
  High      : {stats['high']}
  Medium    : {stats['medium']}
  Low       : {stats['low']}
    """)

    # Afficher les alertes
    alertes = get_suricata_alertes(limit=5)
    print("  📋 Dernières alertes :")
    for a in alertes:
        print(f"     [{a['niveau']}] {a['src_ip']} → {a['signature']}")
