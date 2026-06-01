# scan_complet.py
# ============================================================
# MODULE 6 : Scan complet intégré
# Connecte tous les modules : ping → nmap → scoring → DB
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.ping_scan  import scan_reseau
from scanner.nmap_scan  import scanner_liste
from scoring            import scorer_tous
from database           import init_db, creer_scan, sauvegarder_appareil, afficher_stats
from datetime           import datetime


def scan_complet(ip_debut, ip_fin):
    """
    Lance un scan complet du réseau :
    Ping → Nmap → Scoring → Sauvegarde DB
    """
    print(f"""
╔══════════════════════════════════════════════╗
║       🛡️  SMART NETSEC SOC PLATFORM          ║
║       Scan Complet Intégré                   ║
╚══════════════════════════════════════════════╝
    Début   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    Plage   : {ip_debut} → {ip_fin}
""")

    # ── ÉTAPE 1 : Ping Scan ──────────────────────
    print("━"*50)
    print("  📡 ÉTAPE 1/4 — Ping Scan")
    print("━"*50)
    appareils_actifs = scan_reseau(ip_debut, ip_fin)

    if not appareils_actifs:
        print("  ⚠️  Aucun appareil détecté. Fin du scan.")
        return

    # ── ÉTAPE 2 : Scan Nmap ──────────────────────
    print("\n" + "━"*50)
    print("  🔍 ÉTAPE 2/4 — Scan Nmap Avancé")
    print("━"*50)
    infos_appareils = scanner_liste(appareils_actifs)

    # ── ÉTAPE 3 : Sauvegarde en base ─────────────
    print("\n" + "━"*50)
    print("  💾 ÉTAPE 3/4 — Sauvegarde en base")
    print("━"*50)
    init_db()
    scan_id = creer_scan(ip_debut, ip_fin, len(infos_appareils))

    for appareil in infos_appareils:
        sauvegarder_appareil(scan_id, appareil)
        print(f"  💾 {appareil['ip']} sauvegardé")

    # ── ÉTAPE 4 : Scoring ────────────────────────
    print("\n" + "━"*50)
    print("  🧠 ÉTAPE 4/4 — Calcul des scores")
    print("━"*50)
    scorer_tous(scan_id)

    # ── Résumé final ─────────────────────────────
    print(f"""
╔══════════════════════════════════════════════╗
║       ✅ SCAN TERMINÉ                        ║
╚══════════════════════════════════════════════╝
    Fin     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    Scan ID : #{scan_id}
    Appareils analysés : {len(infos_appareils)}

  🌐 Ouvre le dashboard pour voir les résultats :
     http://127.0.0.1:5000
""")
    afficher_stats()


# ── Point d'entrée ───────────────────────────
if __name__ == "__main__":
    IP_DEBUT = "192.168.216.1"
    IP_FIN   = "192.168.216.254"
    scan_complet(IP_DEBUT, IP_FIN)

