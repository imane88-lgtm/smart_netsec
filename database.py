# database.py
# ============================================================
# MODULE 3 : Base de données SQLite
# Objectif : stocker et récupérer les résultats des scans
# ============================================================

import sqlite3
import json
from datetime import datetime

# Chemin de la base de données
DB_PATH = "smart_netsec.db"


# ──────────────────────────────────────────────
# Fonction 1 : Initialiser la base de données
# Crée les tables si elles n'existent pas
# ──────────────────────────────────────────────
def init_db():
    """Crée la base de données et les tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ── Table 1 : Historique des scans ──
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            date_scan   TEXT NOT NULL,
            ip_debut    TEXT,
            ip_fin      TEXT,
            nb_appareils INTEGER DEFAULT 0
        )
    """)

    # ── Table 2 : Appareils détectés ──
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS appareils (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      INTEGER,
            ip           TEXT NOT NULL,
            hostname     TEXT DEFAULT 'Inconnu',
            mac          TEXT DEFAULT 'Inconnu',
            vendor       TEXT DEFAULT 'Inconnu',
            type_appareil TEXT DEFAULT 'Inconnu',
            nb_ports     INTEGER DEFAULT 0,
            ports_ouverts TEXT,
            ports_risques TEXT,
            score        INTEGER DEFAULT 100,
            date_ajout   TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    # ── Table 3 : Alertes de sécurité ──
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alertes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER,
            ip          TEXT,
            type_alerte TEXT,
            message     TEXT,
            niveau      TEXT DEFAULT 'MEDIUM',
            date_alerte TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    conn.commit()
    conn.close()
    print("  ✅ Base de données initialisée avec succès")


# ──────────────────────────────────────────────
# Fonction 2 : Créer un nouveau scan
# ──────────────────────────────────────────────
def creer_scan(ip_debut, ip_fin, nb_appareils):
    """
    Enregistre un nouveau scan dans la base.
    Retourne l'ID du scan créé.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans (date_scan, ip_debut, ip_fin, nb_appareils)
        VALUES (?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ip_debut,
        ip_fin,
        nb_appareils
    ))

    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()

    print(f"  📝 Scan #{scan_id} enregistré")
    return scan_id


# ──────────────────────────────────────────────
# Fonction 3 : Sauvegarder un appareil
# ──────────────────────────────────────────────
def sauvegarder_appareil(scan_id, info_appareil):
    """
    Sauvegarde les infos d'un appareil dans la base.
    info_appareil = dictionnaire retourné par nmap_scan.py
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Convertir les listes en JSON pour stockage
    ports_ouverts_json = json.dumps(info_appareil.get("ports_ouverts", []))
    ports_risques_json = json.dumps(info_appareil.get("ports_risques", []))

    cursor.execute("""
        INSERT INTO appareils 
        (scan_id, ip, hostname, mac, vendor, type_appareil,
         nb_ports, ports_ouverts, ports_risques, date_ajout)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        info_appareil.get("ip", "?"),
        info_appareil.get("hostname", "Inconnu"),
        info_appareil.get("mac", "Inconnu"),
        info_appareil.get("vendor", "Inconnu"),
        info_appareil.get("type", "Inconnu"),
        info_appareil.get("nb_ports", 0),
        ports_ouverts_json,
        ports_risques_json,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ))

    conn.commit()
    conn.close()


# ──────────────────────────────────────────────
# Fonction 4 : Sauvegarder une alerte
# ──────────────────────────────────────────────
def sauvegarder_alerte(scan_id, ip, type_alerte, message, niveau="MEDIUM"):
    """
    Enregistre une alerte de sécurité.
    niveau : LOW / MEDIUM / HIGH / CRITICAL
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alertes (scan_id, ip, type_alerte, message, niveau, date_alerte)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        ip,
        type_alerte,
        message,
        niveau,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ))

    conn.commit()
    conn.close()


# ──────────────────────────────────────────────
# Fonction 5 : Récupérer tous les appareils
# ──────────────────────────────────────────────
def get_appareils(scan_id=None):
    """
    Récupère les appareils depuis la base.
    Si scan_id fourni → appareils de ce scan uniquement.
    Sinon → tous les appareils.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Pour accès par nom de colonne
    cursor = conn.cursor()

    if scan_id:
        cursor.execute(
            "SELECT * FROM appareils WHERE scan_id = ? ORDER BY ip",
            (scan_id,)
        )
    else:
        cursor.execute("SELECT * FROM appareils ORDER BY date_ajout DESC")

    appareils = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return appareils


# ──────────────────────────────────────────────
# Fonction 6 : Récupérer toutes les alertes
# ──────────────────────────────────────────────
def get_alertes(scan_id=None):
    """Récupère les alertes depuis la base."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if scan_id:
        cursor.execute(
            "SELECT * FROM alertes WHERE scan_id = ? ORDER BY niveau DESC",
            (scan_id,)
        )
    else:
        cursor.execute("SELECT * FROM alertes ORDER BY date_alerte DESC")

    alertes = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return alertes


# ──────────────────────────────────────────────
# Fonction 7 : Récupérer l'historique des scans
# ──────────────────────────────────────────────
def get_historique_scans():
    """Récupère tous les scans effectués."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans ORDER BY date_scan DESC")
    scans = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return scans


# ──────────────────────────────────────────────
# Fonction 8 : Afficher un résumé de la base
# ──────────────────────────────────────────────
def afficher_stats():
    """Affiche les statistiques de la base de données."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    nb_scans     = cursor.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    nb_appareils = cursor.execute("SELECT COUNT(*) FROM appareils").fetchone()[0]
    nb_alertes   = cursor.execute("SELECT COUNT(*) FROM alertes").fetchone()[0]

    conn.close()

    print(f"\n{'='*45}")
    print(f"  📊 STATISTIQUES BASE DE DONNÉES")
    print(f"{'='*45}")
    print(f"  Scans effectués   : {nb_scans}")
    print(f"  Appareils stockés : {nb_appareils}")
    print(f"  Alertes générées  : {nb_alertes}")
    print(f"{'='*45}\n")


# ──────────────────────────────────────────────
# TEST : Si on lance ce fichier directement
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("\n🗄️  Test de la base de données...\n")

    # 1. Initialiser
    init_db()

    # 2. Créer un scan test
    scan_id = creer_scan("192.168.216.1", "192.168.216.254", 3)

    # 3. Sauvegarder les appareils détectés à l'étape 2
    appareils_test = [
        {
            "ip": "192.168.216.1",
            "hostname": "Inconnu",
            "mac": "00:50:56:C0:00:08",
            "vendor": "VMware",
            "type": "💻 Machine Virtuelle",
            "nb_ports": 3,
            "ports_ouverts": [
                {"port": 135, "service": "msrpc",        "version": ""},
                {"port": 139, "service": "netbios-ssn",  "version": ""},
                {"port": 445, "service": "microsoft-ds", "version": ""},
            ],
            "ports_risques": [
                {"port": 445, "risque": "SMB — partage Windows"}
            ],
        },
        {
            "ip": "192.168.216.2",
            "hostname": "Inconnu",
            "mac": "00:50:56:FF:3D:68",
            "vendor": "VMware",
            "type": "💻 Machine Virtuelle",
            "nb_ports": 1,
            "ports_ouverts": [
                {"port": 53, "service": "domain", "version": ""},
            ],
            "ports_risques": [],
        },
        {
            "ip": "192.168.216.143",
            "hostname": "MRINO",
            "mac": "Inconnu",
            "vendor": "Inconnu",
            "type": "💻 PC/Autre",
            "nb_ports": 0,
            "ports_ouverts": [],
            "ports_risques": [],
        },
    ]

    for appareil in appareils_test:
        sauvegarder_appareil(scan_id, appareil)
        print(f"  💾 {appareil['ip']} sauvegardé")

    # 4. Sauvegarder une alerte
    sauvegarder_alerte(
        scan_id,
        ip="192.168.216.1",
        type_alerte="PORT_DANGEREUX",
        message="Port 445 (SMB) ouvert — risque WannaCry",
        niveau="HIGH"
    )
    print("  🔴 Alerte sauvegardée")

    # 5. Afficher les stats
    afficher_stats()

    # 6. Vérifier les données
    print("  📋 Appareils en base :")
    for a in get_appareils(scan_id):
        print(f"     → {a['ip']} | {a['type_appareil']} | {a['nb_ports']} ports")

    print("\n  ⚠️  Alertes en base :")
    for alerte in get_alertes(scan_id):
        print(f"     → {alerte['ip']} | {alerte['niveau']} | {alerte['message']}")
