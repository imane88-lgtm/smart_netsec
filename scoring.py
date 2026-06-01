# scoring.py
# ============================================================
# MODULE 4 : Système de scoring de sécurité
# Objectif : calculer un score de risque pour chaque appareil
# ============================================================

import sqlite3
import json
from database import DB_PATH, get_appareils, sauvegarder_alerte

# ──────────────────────────────────────────────
# Définition des poids de risque
# ──────────────────────────────────────────────

# Ports CRITIQUES — grosse pénalité
PORTS_CRITIQUES = {
    23:   (-25, "CRITICAL", "Telnet actif — protocole NON chiffré"),
    21:   (-20, "HIGH",     "FTP ouvert — transfert non sécurisé"),
    3389: (-20, "HIGH",     "RDP ouvert — accès bureau distant exposé"),
    5900: (-20, "HIGH",     "VNC ouvert — bureau distant non sécurisé"),
    4444: (-30, "CRITICAL", "Port Metasploit détecté — backdoor possible"),
    1337: (-30, "CRITICAL", "Port suspect — possible backdoor"),
}

# Ports RISQUÉS — pénalité moyenne
PORTS_RISQUES = {
    445:  (-15, "HIGH",   "SMB ouvert — risque ransomware (WannaCry)"),
    139:  (-10, "MEDIUM", "NetBIOS ouvert — partage réseau exposé"),
    80:   (-5,  "LOW",    "HTTP ouvert — trafic non chiffré"),
    8080: (-5,  "LOW",    "HTTP alternatif ouvert"),
    3306: (-15, "HIGH",   "MySQL exposé — base de données accessible"),
    27017:(-15, "HIGH",   "MongoDB exposé — base de données accessible"),
    6379: (-15, "HIGH",   "Redis exposé — base de données accessible"),
}

# Pénalités générales
PENALITE_PAR_PORT_OUVERT  = -3   # Chaque port ouvert supplémentaire
PENALITE_VENDOR_INCONNU   = -15  # Appareil non identifié
PENALITE_HOSTNAME_INCONNU = -5   # Hostname non résolu
PENALITE_MAC_INCONNU      = -10  # MAC non lisible (peut masquer identité)
BONUS_AUCUN_PORT          = +10  # Aucun port ouvert = bien fermé


# ──────────────────────────────────────────────
# Fonction principale : Calculer le score
# ──────────────────────────────────────────────
def calculer_score(appareil, scan_id=None):
    """
    Calcule le score de sécurité d'un appareil.
    Retourne un dict avec score, niveau, détails.
    """
    score = 100
    details = []
    alertes_a_sauvegarder = []

    # Récupérer les ports (depuis JSON si string)
    ports_ouverts = appareil.get("ports_ouverts", [])
    if isinstance(ports_ouverts, str):
        ports_ouverts = json.loads(ports_ouverts)

    ports_risques = appareil.get("ports_risques", [])
    if isinstance(ports_risques, str):
        ports_risques = json.loads(ports_risques)

    ip = appareil.get("ip", "?")

    # ── 1. Analyse des ports critiques ──
    for port_info in ports_ouverts:
        port = port_info.get("port") or port_info.get("port_num")

        if port in PORTS_CRITIQUES:
            penalite, niveau, message = PORTS_CRITIQUES[port]
            score += penalite
            details.append(f"🔴 Port {port} : {message} ({penalite} pts)")
            alertes_a_sauvegarder.append((ip, "PORT_CRITIQUE", message, niveau))

        elif port in PORTS_RISQUES:
            penalite, niveau, message = PORTS_RISQUES[port]
            score += penalite
            details.append(f"🟠 Port {port} : {message} ({penalite} pts)")
            alertes_a_sauvegarder.append((ip, "PORT_RISQUE", message, niveau))

    # ── 2. Pénalité par nombre de ports ──
    nb_ports = appareil.get("nb_ports", len(ports_ouverts))
    if nb_ports > 0:
        penalite_ports = nb_ports * PENALITE_PAR_PORT_OUVERT
        score += penalite_ports
        details.append(f"🟡 {nb_ports} ports ouverts ({penalite_ports} pts)")
    else:
        # Bonus si aucun port ouvert
        score += BONUS_AUCUN_PORT
        details.append(f"✅ Aucun port ouvert (+{BONUS_AUCUN_PORT} pts)")

    # ── 3. Vendor inconnu ──
    vendor = appareil.get("vendor", "Inconnu")
    if vendor in ["Inconnu", "", None]:
        score += PENALITE_VENDOR_INCONNU
        details.append(f"⚠️  Vendor inconnu ({PENALITE_VENDOR_INCONNU} pts)")
        alertes_a_sauvegarder.append((
            ip, "VENDOR_INCONNU",
            "Appareil non identifié — vendor inconnu",
            "MEDIUM"
        ))

    # ── 4. Hostname inconnu ──
    hostname = appareil.get("hostname", "Inconnu")
    if hostname in ["Inconnu", "", None]:
        score += PENALITE_HOSTNAME_INCONNU
        details.append(f"⚠️  Hostname inconnu ({PENALITE_HOSTNAME_INCONNU} pts)")

    # ── 5. MAC inconnu ──
    mac = appareil.get("mac", "Inconnu")
    if mac in ["Inconnu", "", None]:
        score += PENALITE_MAC_INCONNU
        details.append(f"⚠️  MAC inconnu ({PENALITE_MAC_INCONNU} pts)")
        alertes_a_sauvegarder.append((
            ip, "MAC_INCONNU",
            "Adresse MAC non lisible — identité masquée possible",
            "MEDIUM"
        ))

    # ── 6. Limiter le score entre 0 et 100 ──
    score = max(0, min(100, score))

    # ── 7. Déterminer le niveau ──
    if score >= 80:
        niveau = "SAFE"
        emoji  = "🟢"
    elif score >= 50:
        niveau = "MEDIUM"
        emoji  = "🟠"
    else:
        niveau = "DANGER"
        emoji  = "🔴"

    # ── 8. Sauvegarder les alertes en base ──
    if scan_id:
        for (ip_a, type_a, msg_a, niv_a) in alertes_a_sauvegarder:
            sauvegarder_alerte(scan_id, ip_a, type_a, msg_a, niv_a)

    return {
        "ip":      ip,
        "score":   score,
        "niveau":  niveau,
        "emoji":   emoji,
        "details": details,
    }


# ──────────────────────────────────────────────
# Fonction : Mettre à jour le score en base
# ──────────────────────────────────────────────
def mettre_a_jour_score(ip, score):
    """Met à jour le score d'un appareil dans la base."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE appareils SET score = ? WHERE ip = ?",
        (score, ip)
    )
    conn.commit()
    conn.close()


# ──────────────────────────────────────────────
# Fonction : Afficher le score d'un appareil
# ──────────────────────────────────────────────
def afficher_score(resultat):
    """Affiche le score de façon visuelle."""
    score  = resultat["score"]
    niveau = resultat["niveau"]
    emoji  = resultat["emoji"]
    ip     = resultat["ip"]

    # Barre de progression visuelle
    nb_blocs  = score // 10
    barre     = "█" * nb_blocs + "░" * (10 - nb_blocs)

    print(f"\n  {'─'*45}")
    print(f"  📍 {ip}")
    print(f"  {emoji} Score : {score}/100  [{barre}]  {niveau}")
    print(f"\n  📋 Détails :")
    for detail in resultat["details"]:
        print(f"     {detail}")


# ──────────────────────────────────────────────
# Fonction : Scorer tous les appareils d'un scan
# ──────────────────────────────────────────────
def scorer_tous(scan_id):
    """
    Calcule et sauvegarde le score de tous
    les appareils d'un scan.
    """
    appareils = get_appareils(scan_id)

    print(f"\n{'='*50}")
    print(f"  🧠 CALCUL DES SCORES DE SÉCURITÉ")
    print(f"  Scan #{scan_id} — {len(appareils)} appareils")
    print(f"{'='*50}")

    resultats = []

    for appareil in appareils:
        resultat = calculer_score(appareil, scan_id)
        afficher_score(resultat)
        mettre_a_jour_score(appareil["ip"], resultat["score"])
        resultats.append(resultat)

    # ── Résumé global ──
    scores      = [r["score"] for r in resultats]
    score_moyen = sum(scores) // len(scores) if scores else 0
    nb_danger   = sum(1 for r in resultats if r["niveau"] == "DANGER")
    nb_medium   = sum(1 for r in resultats if r["niveau"] == "MEDIUM")
    nb_safe     = sum(1 for r in resultats if r["niveau"] == "SAFE")

    print(f"\n{'='*50}")
    print(f"  📊 RÉSUMÉ SCORING")
    print(f"{'='*50}")
    print(f"  Score moyen réseau : {score_moyen}/100")
    print(f"  🟢 SAFE            : {nb_safe} appareils")
    print(f"  🟠 MEDIUM          : {nb_medium} appareils")
    print(f"  🔴 DANGER          : {nb_danger} appareils")
    print(f"{'='*50}\n")

    return resultats


# ──────────────────────────────────────────────
# Point d'entrée — Test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    # On score les appareils du scan #1 (créé à l'étape 3)
    resultats = scorer_tous(scan_id=1)
