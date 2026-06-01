# security_test.py
# ============================================================
# FONCTION DE TEST SÉCURITÉ COMPLÈTE
# Simule : attaque → alerte → blocage → dashboard update
# ============================================================

import sqlite3
import time
from datetime import datetime
from database  import DB_PATH
from firewall  import block_ip, init_firewall
from intelligence import CorrelationEngine, RiskEngine


def run_security_test(verbose=True):
    """
    Simule un scénario d'attaque complet :
    Scan → Brute Force → Exploit → Corrélation → Blocage
    Retourne un dict avec les résultats.
    """
    results  = []
    ip_test  = "10.99.99.99"
    start    = datetime.now()

    def log(etape, action, niveau, ok=True):
        r = {
            "etape":     etape,
            "action":    action,
            "niveau":    niveau,
            "ok":        ok,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }
        results.append(r)
        if verbose:
            status = "OK" if ok else "FAIL"
            print(f"  [{status}] [{niveau}] {etape} — {action}")
        return r

    if verbose:
        print("\n" + "="*55)
        print("  SMART NETSEC — TEST DE SECURITE COMPLET")
        print("="*55 + "\n")

    # ── Étape 1 : Initialisation ──────────────────
    try:
        init_firewall()
        log("INIT", "Firewall initialisé", "INFO")
    except Exception as e:
        log("INIT", f"Erreur : {e}", "ERROR", ok=False)

    conn = sqlite3.connect(DB_PATH)

    # ── Étape 2 : Injecter scan réseau ───────────
    try:
        scan_id = conn.execute("""
            INSERT INTO scans
            (date_scan, ip_debut, ip_fin, nb_appareils)
            VALUES (?,?,?,?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "10.99.99.0", "10.99.99.255", 1
        )).lastrowid
        conn.commit()
        log("SCAN", f"Scan depuis {ip_test}", "MEDIUM")
    except Exception as e:
        log("SCAN", f"Erreur : {e}", "ERROR", ok=False)
        scan_id = 1

    # ── Étape 3 : Alerte Scan ────────────────────
    try:
        conn.execute("""
            INSERT INTO alertes
            (scan_id, ip, type_alerte, message, niveau, date_alerte)
            VALUES (?,?,?,?,?,?)
        """, (
            scan_id, ip_test, "SCAN",
            f"Nmap SYN scan depuis {ip_test} — 1024 ports",
            "MEDIUM",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        log("ALERTE", "Alerte scan générée", "MEDIUM")
    except Exception as e:
        log("ALERTE", f"Erreur : {e}", "ERROR", ok=False)

    time.sleep(0.3)

    # ── Étape 4 : Alerte Brute Force ─────────────
    try:
        conn.execute("""
            INSERT INTO alertes
            (scan_id, ip, type_alerte, message, niveau, date_alerte)
            VALUES (?,?,?,?,?,?)
        """, (
            scan_id, ip_test, "BRUTE",
            f"Brute Force SSH depuis {ip_test} — 47 tentatives",
            "HIGH",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        log("BRUTE FORCE", "Alerte brute force générée", "HIGH")
    except Exception as e:
        log("BRUTE FORCE", f"Erreur : {e}", "ERROR", ok=False)

    # ── Étape 5 : Alerte Suricata ─────────────────
    try:
        conn.execute("""
            INSERT INTO suricata_alertes
            (timestamp, src_ip, src_port, dest_ip, dest_port,
             protocole, signature, categorie, severite,
             niveau, raw_data, date_import)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip_test, 4444, "192.168.216.143", 445,
            "TCP",
            "ET EXPLOIT MS17-010 EternalBlue — TEST",
            "Exploit", 1, "CRITICAL",
            '{"test": true}',
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        log("IDS SURICATA", "Alerte EternalBlue injectée", "CRITICAL")
    except Exception as e:
        log("IDS SURICATA", f"Erreur : {e}", "ERROR", ok=False)

    conn.close()
    time.sleep(0.3)

    # ── Étape 6 : Corrélation ─────────────────────
    try:
        engine = CorrelationEngine()
        engine._init_table()
        events = engine.analyser_ip(ip_test)
        nb = len(events)
        log(
            "CORRELATION",
            f"{nb} règle(s) déclenchée(s)",
            "CRITICAL" if nb > 0 else "INFO"
        )
    except Exception as e:
        log("CORRELATION", f"Erreur : {e}", "ERROR", ok=False)
        nb = 0

    # ── Étape 7 : Calcul Risk Score ───────────────
    try:
        risk   = RiskEngine()
        score  = risk.calculer_score_global()
        log(
            "RISK SCORE",
            f"Score global : {score['score']}/100 — {score['statut']}",
            score['statut']
        )
    except Exception as e:
        log("RISK SCORE", f"Erreur : {e}", "ERROR", ok=False)

    # ── Étape 8 : Blocage automatique ────────────
    try:
        succes, msg = block_ip(
            ip_test,
            raison="Blocage automatique test sécurité",
            niveau="CRITICAL"
        )
        log(
            "FIREWALL",
            msg[:60],
            "BLOCKED" if succes else "SKIP"
        )
    except Exception as e:
        log("FIREWALL", f"Erreur : {e}", "ERROR", ok=False)

    # ── Résumé ─────────────────────────────────────
    duree  = (datetime.now() - start).total_seconds()
    nb_ok  = sum(1 for r in results if r["ok"])
    nb_err = sum(1 for r in results if not r["ok"])

    if verbose:
        print(f"\n{'='*55}")
        print(f"  RESULTATS DU TEST")
        print(f"{'='*55}")
        print(f"  Etapes OK    : {nb_ok}/{len(results)}")
        print(f"  Erreurs      : {nb_err}")
        print(f"  Duree        : {duree:.2f}s")
        print(f"  IP testee    : {ip_test}")
        print(f"{'='*55}\n")
        if nb_err == 0:
            print("  PIPELINE COMPLET : SUCCES\n")
        else:
            print(f"  ATTENTION : {nb_err} erreur(s) detectee(s)\n")

    return {
        "success":    nb_err == 0,
        "nb_ok":      nb_ok,
        "nb_errors":  nb_err,
        "duree":      round(duree, 2),
        "ip_test":    ip_test,
        "steps":      results,
    }


if __name__ == "__main__":
    run_security_test(verbose=True)
