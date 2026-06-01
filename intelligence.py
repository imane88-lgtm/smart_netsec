# intelligence.py
# ============================================================
# MOTEUR D'INTELLIGENCE : Corrélation + Risk Score + Comportement
# ============================================================

import sqlite3
from datetime import datetime, timedelta
from database import DB_PATH


# ══════════════════════════════════════════════
# RÈGLES DE CORRÉLATION
# ══════════════════════════════════════════════
REGLES_CORRELATION = [
    {
        "id":          "RULE_001",
        "nom":         "Scan + Brute Force",
        "description": "Scan réseau suivi d'une tentative brute force",
        "conditions":  ["SCAN", "BRUTE"],
        "severite":    "CRITICAL",
        "score_impact": -30,
        "action":      "BLOCK",
        "explication": (
            "Un attaquant a d'abord scanné le réseau pour "
            "identifier les services, puis tenté de forcer "
            "l'accès. Cela indique une attaque ciblée."
        ),
    },
    {
        "id":          "RULE_002",
        "nom":         "IP Inconnue + Port Dangereux",
        "description": "Appareil inconnu avec ports critiques ouverts",
        "conditions":  ["VENDOR_INCONNU", "PORT_CRITIQUE"],
        "severite":    "HIGH",
        "score_impact": -20,
        "action":      "MONITOR",
        "explication": (
            "Un appareil non identifié expose des ports "
            "sensibles. Risque élevé de point d'entrée "
            "pour un attaquant."
        ),
    },
    {
        "id":          "RULE_003",
        "nom":         "Exploit + Propagation",
        "description": "Tentative d'exploit suivie d'activité SMB",
        "conditions":  ["EXPLOIT", "SMB"],
        "severite":    "CRITICAL",
        "score_impact": -40,
        "action":      "BLOCK",
        "explication": (
            "Pattern similaire au ransomware WannaCry : "
            "exploitation d'une faille puis propagation "
            "via SMB. Blocage immédiat recommandé."
        ),
    },
    {
        "id":          "RULE_004",
        "nom":         "Multiples Alertes Même IP",
        "description": "Plus de 3 alertes depuis la même IP",
        "conditions":  ["MULTI_ALERT"],
        "severite":    "HIGH",
        "score_impact": -15,
        "action":      "BLOCK",
        "explication": (
            "Une IP générant plusieurs alertes en peu de "
            "temps indique une activité malveillante persistante."
        ),
    },
    {
        "id":          "RULE_005",
        "nom":         "Activité Hors Horaire",
        "description": "Activité suspecte détectée la nuit (00h-06h)",
        "conditions":  ["HORS_HORAIRE"],
        "severite":    "MEDIUM",
        "score_impact": -10,
        "action":      "LOG",
        "explication": (
            "Une activité réseau intense pendant les heures "
            "creuses peut indiquer un accès non autorisé "
            "ou une exfiltration de données."
        ),
    },
]


# ══════════════════════════════════════════════
# MOTEUR DE CORRÉLATION
# ══════════════════════════════════════════════
class CorrelationEngine:

    def __init__(self):
        self.conn = None

    def _get_conn(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_table(self):
        """Crée la table des événements corrélés."""
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS correlation_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id     TEXT,
                rule_nom    TEXT,
                ip          TEXT,
                severite    TEXT,
                action      TEXT,
                explication TEXT,
                score_impact INTEGER,
                timestamp   TEXT,
                traite      INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()

    # ──────────────────────────────────────────
    # Analyser les alertes d'une IP
    # ──────────────────────────────────────────
    def _get_alertes_ip(self, ip, minutes=60):
        """Récupère les alertes récentes d'une IP."""
        conn = self._get_conn()
        depuis = (datetime.now() - timedelta(minutes=minutes)
                  ).strftime("%Y-%m-%d %H:%M:%S")

        # Alertes normales
        alertes = conn.execute("""
            SELECT type_alerte, niveau, message
            FROM alertes
            WHERE ip = ? AND date_alerte >= ?
        """, (ip, depuis)).fetchall()

        # Alertes Suricata
        try:
            suricata = conn.execute("""
                SELECT signature, niveau, categorie
                FROM suricata_alertes
                WHERE src_ip = ? AND timestamp >= ?
            """, (ip, depuis)).fetchall()
        except:
            suricata = []

        conn.close()
        return [dict(a) for a in alertes], [dict(s) for s in suricata]

    # ──────────────────────────────────────────
    # Détecter les patterns
    # ──────────────────────────────────────────
    def _detecter_patterns(self, ip, alertes, suricata):
        """Détecte les patterns de comportement pour une IP."""
        patterns = set()
        heure    = datetime.now().hour

        # Textes combinés pour analyse
        tous_textes = (
            " ".join([
                a.get("type_alerte","") + " " +
                a.get("message","")
                for a in alertes
            ]) + " " +
            " ".join([
                s.get("signature","") + " " +
                s.get("categorie","")
                for s in suricata
            ])
        ).upper()

        # Détecter patterns
        if any(k in tous_textes for k in ["SCAN","NMAP","SWEEP"]):
            patterns.add("SCAN")
        if any(k in tous_textes for k in ["BRUTE","FORCE","SSH","LOGIN"]):
            patterns.add("BRUTE")
        if any(k in tous_textes for k in ["EXPLOIT","ETERNAL","CVE"]):
            patterns.add("EXPLOIT")
        if any(k in tous_textes for k in ["SMB","445","NETBIOS"]):
            patterns.add("SMB")
        if any(k in tous_textes for k in ["VENDOR_INCONNU","UNKNOWN"]):
            patterns.add("VENDOR_INCONNU")
        if any(k in tous_textes for k in
               ["PORT_CRITIQUE","TELNET","FTP","RDP"]):
            patterns.add("PORT_CRITIQUE")

        # Multiples alertes
        if len(alertes) + len(suricata) >= 3:
            patterns.add("MULTI_ALERT")

        # Hors horaire (minuit - 6h)
        if 0 <= heure < 6:
            patterns.add("HORS_HORAIRE")

        return patterns

    # ──────────────────────────────────────────
    # Appliquer les règles
    # ──────────────────────────────────────────
    def analyser_ip(self, ip):
        """Analyse une IP et retourne les événements corrélés."""
        alertes, suricata = self._get_alertes_ip(ip)
        patterns = self._detecter_patterns(ip, alertes, suricata)

        if not patterns:
            return []

        events = []
        conn   = self._get_conn()

        for regle in REGLES_CORRELATION:
            conditions = set(regle["conditions"])

            # Vérifier si toutes les conditions sont remplies
            if conditions.issubset(patterns):

                # Vérifier si pas déjà enregistré (dernière heure)
                depuis = (datetime.now() - timedelta(hours=1)
                          ).strftime("%Y-%m-%d %H:%M:%S")
                existe = conn.execute("""
                    SELECT id FROM correlation_events
                    WHERE rule_id=? AND ip=? AND timestamp>=?
                """, (regle["id"], ip, depuis)).fetchone()

                if not existe:
                    timestamp = datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    conn.execute("""
                        INSERT INTO correlation_events
                        (rule_id, rule_nom, ip, severite, action,
                         explication, score_impact, timestamp)
                        VALUES (?,?,?,?,?,?,?,?)
                    """, (
                        regle["id"],
                        regle["nom"],
                        ip,
                        regle["severite"],
                        regle["action"],
                        regle["explication"],
                        regle["score_impact"],
                        timestamp,
                    ))
                    events.append({
                        "regle":       regle["nom"],
                        "ip":          ip,
                        "severite":    regle["severite"],
                        "action":      regle["action"],
                        "explication": regle["explication"],
                        "timestamp":   timestamp,
                    })

        conn.commit()
        conn.close()
        return events

    # ──────────────────────────────────────────
    # Analyser toutes les IPs actives
    # ──────────────────────────────────────────
    def analyser_tout(self):
        """Analyse toutes les IPs et retourne les corrélations."""
        conn = self._get_conn()

        # Récupérer toutes les IPs avec alertes
        try:
            ips_alertes = conn.execute(
                "SELECT DISTINCT ip FROM alertes"
            ).fetchall()
        except:
            ips_alertes = []

        try:
            ips_suricata = conn.execute(
                "SELECT DISTINCT src_ip FROM suricata_alertes"
            ).fetchall()
        except:
            ips_suricata = []

        conn.close()

        toutes_ips = set(
            [r["ip"] for r in ips_alertes] +
            [r["src_ip"] for r in ips_suricata]
        )

        tous_events = []
        for ip in toutes_ips:
            if ip and ip != "?":
                events = self.analyser_ip(ip)
                tous_events.extend(events)

        return tous_events

    # ──────────────────────────────────────────
    # Récupérer les événements corrélés
    # ──────────────────────────────────────────
    def get_correlation_events(self, limit=20):
        """Retourne les derniers événements corrélés."""
        conn = self._get_conn()
        try:
            rows = conn.execute("""
                SELECT * FROM correlation_events
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,)).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except:
            conn.close()
            return []


# ══════════════════════════════════════════════
# RISK ENGINE — Score Global
# ══════════════════════════════════════════════
class RiskEngine:

    def calculer_score_global(self):
        """
        Calcule le score de risque global (0-100).
        100 = parfaitement sécurisé
        0   = extrêmement dangereux
        """
        score  = 100
        detail = []
        conn   = sqlite3.connect(DB_PATH)

        # ── Facteur 1 : Alertes critiques ──
        try:
            nb_critical = conn.execute("""
                SELECT COUNT(*) FROM alertes
                WHERE niveau IN ('CRITICAL','HIGH')
            """).fetchone()[0]
            if nb_critical > 0:
                penalite = min(nb_critical * 5, 25)
                score   -= penalite
                detail.append({
                    "facteur":  "Alertes critiques",
                    "valeur":   nb_critical,
                    "impact":   f"-{penalite}",
                    "niveau":   "danger",
                })
        except:
            pass

        # ── Facteur 2 : IPs bloquées ──
        try:
            nb_bloques = conn.execute(
                "SELECT COUNT(*) FROM blocages WHERE actif=1"
            ).fetchone()[0]
            if nb_bloques > 0:
                penalite = min(nb_bloques * 8, 20)
                score   -= penalite
                detail.append({
                    "facteur": "IPs bloquées actives",
                    "valeur":  nb_bloques,
                    "impact":  f"-{penalite}",
                    "niveau":  "danger",
                })
        except:
            pass

        # ── Facteur 3 : Score moyen appareils ──
        try:
            scores = conn.execute(
                "SELECT score FROM appareils WHERE score IS NOT NULL"
            ).fetchall()
            if scores:
                avg = sum(s[0] for s in scores) / len(scores)
                if avg < 50:
                    penalite = 20
                elif avg < 70:
                    penalite = 10
                else:
                    penalite = 0
                score -= penalite
                if penalite > 0:
                    detail.append({
                        "facteur": "Score moyen appareils",
                        "valeur":  f"{round(avg)}/100",
                        "impact":  f"-{penalite}",
                        "niveau":  "medium" if penalite < 15 else "danger",
                    })
        except:
            pass

        # ── Facteur 4 : Alertes Suricata ──
        try:
            nb_suricata_critical = conn.execute("""
                SELECT COUNT(*) FROM suricata_alertes
                WHERE niveau IN ('CRITICAL','HIGH')
            """).fetchone()[0]
            if nb_suricata_critical > 0:
                penalite = min(nb_suricata_critical * 4, 20)
                score   -= penalite
                detail.append({
                    "facteur": "Alertes IDS critiques",
                    "valeur":  nb_suricata_critical,
                    "impact":  f"-{penalite}",
                    "niveau":  "danger",
                })
        except:
            pass

        # ── Facteur 5 : Corrélations ──
        try:
            nb_correlations = conn.execute("""
                SELECT COUNT(*) FROM correlation_events
                WHERE severite IN ('CRITICAL','HIGH')
            """).fetchone()[0]
            if nb_correlations > 0:
                penalite = min(nb_correlations * 10, 15)
                score   -= penalite
                detail.append({
                    "facteur": "Événements corrélés",
                    "valeur":  nb_correlations,
                    "impact":  f"-{penalite}",
                    "niveau":  "danger",
                })
        except:
            pass

        conn.close()

        score = max(0, min(100, score))

        # Statut global
        if score >= 80:
            statut = "SAFE"
            couleur = "green"
        elif score >= 60:
            statut = "WARNING"
            couleur = "orange"
        elif score >= 40:
            statut = "DANGER"
            couleur = "red"
        else:
            statut = "CRITICAL"
            couleur = "red"

        return {
            "score":   score,
            "statut":  statut,
            "couleur": couleur,
            "detail":  detail,
        }


# ══════════════════════════════════════════════
# DÉTECTION COMPORTEMENTALE
# ══════════════════════════════════════════════
class BehaviorDetector:

    def detecter_anomalies(self):
        """Détecte les comportements anormaux."""
        anomalies = []
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        heure = datetime.now().hour

        # ── Anomalie 1 : Activité nocturne ──
        if 0 <= heure < 6:
            try:
                nb_recent = conn.execute("""
                    SELECT COUNT(*) FROM alertes
                    WHERE date_alerte >= datetime('now','-1 hour')
                """).fetchone()[0]
                if nb_recent > 2:
                    anomalies.append({
                        "type":        "ACTIVITE_NOCTURNE",
                        "description": f"Activité intense la nuit "
                                       f"({nb_recent} alertes)",
                        "severite":    "HIGH",
                        "timestamp":   datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                    })
            except:
                pass

        # ── Anomalie 2 : Explosion d'alertes ──
        try:
            nb_30min = conn.execute("""
                SELECT COUNT(*) FROM alertes
                WHERE date_alerte >= datetime('now','-30 minutes')
            """).fetchone()[0]
            if nb_30min > 10:
                anomalies.append({
                    "type":        "EXPLOSION_ALERTES",
                    "description": f"{nb_30min} alertes en 30 minutes — "
                                   f"possible attaque en cours",
                    "severite":    "CRITICAL",
                    "timestamp":   datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                })
        except:
            pass

        # ── Anomalie 3 : Nouveau appareil ──
        try:
            nouveaux = conn.execute("""
                SELECT ip, vendor FROM appareils
                WHERE date_ajout >= datetime('now','-1 hour')
                AND vendor = 'Inconnu'
            """).fetchall()
            for a in nouveaux:
                anomalies.append({
                    "type":        "NOUVEL_APPAREIL_INCONNU",
                    "description": f"Nouvel appareil non identifié : "
                                   f"{a['ip']}",
                    "severite":    "MEDIUM",
                    "timestamp":   datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                })
        except:
            pass

        # ── Anomalie 4 : IP multi-attaques ──
        try:
            multi = conn.execute("""
                SELECT src_ip, COUNT(*) as nb
                FROM suricata_alertes
                WHERE timestamp >= datetime('now','-1 hour')
                GROUP BY src_ip
                HAVING nb >= 5
            """).fetchall()
            for m in multi:
                anomalies.append({
                    "type":        "IP_MULTI_ATTAQUE",
                    "description": f"IP {m['src_ip']} a généré "
                                   f"{m['nb']} alertes en 1h",
                    "severite":    "HIGH",
                    "timestamp":   datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                })
        except:
            pass

        conn.close()
        return anomalies


# ══════════════════════════════════════════════
# RECOMMANDATIONS AUTOMATIQUES
# ══════════════════════════════════════════════
def generer_recommandations():
    """Génère des recommandations automatiques."""
    recommandations = []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Vérifier ports dangereux
    try:
        ports_dangereux = conn.execute("""
            SELECT DISTINCT ip, ports_risques FROM appareils
            WHERE ports_risques != '[]' AND ports_risques IS NOT NULL
        """).fetchall()
        for a in ports_dangereux:
            recommandations.append({
                "priorite":    "HIGH",
                "icon":        "fa-plug",
                "titre":       f"Ports dangereux sur {a['ip']}",
                "description": "Fermer les ports non nécessaires",
                "action":      f"bloquer/{a['ip']}",
                "action_label":"Bloquer IP",
            })
    except:
        pass

    # IPs avec score bas
    try:
        scores_bas = conn.execute("""
            SELECT ip, score FROM appareils
            WHERE score < 50
        """).fetchall()
        for a in scores_bas:
            recommandations.append({
                "priorite":    "CRITICAL",
                "icon":        "fa-exclamation-triangle",
                "titre":       f"Score critique : {a['ip']} ({a['score']}/100)",
                "description": "Appareil à haut risque détecté",
                "action":      f"api/firewall/bloquer/{a['ip']}",
                "action_label":"Bloquer maintenant",
            })
    except:
        pass

    # Alertes non traitées
    try:
        nb_alertes = conn.execute("""
            SELECT COUNT(*) FROM alertes
            WHERE niveau = 'CRITICAL'
        """).fetchone()[0]
        if nb_alertes > 0:
            recommandations.append({
                "priorite":    "CRITICAL",
                "icon":        "fa-bell",
                "titre":       f"{nb_alertes} alertes critiques non traitées",
                "description": "Analyser et traiter les alertes critiques",
                "action":      None,
                "action_label":None,
            })
    except:
        pass

    # Recommandation générale
    recommandations.append({
        "priorite":    "LOW",
        "icon":        "fa-sync",
        "titre":       "Scanner régulièrement le réseau",
        "description": "Effectuer un scan hebdomadaire minimum",
        "action":      "lancer-scan",
        "action_label":"Lancer scan",
    })

    conn.close()
    return recommandations


# ══════════════════════════════════════════════
# TIMELINE DES ATTAQUES
# ══════════════════════════════════════════════
def get_timeline(limit=30):
    """Construit la timeline des événements de sécurité."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    timeline = []

    # Alertes normales
    try:
        alertes = conn.execute("""
            SELECT date_alerte as ts, ip, message, niveau,
                   'ALERTE' as type_ev
            FROM alertes
            ORDER BY date_alerte DESC LIMIT ?
        """, (limit,)).fetchall()
        for a in alertes:
            timeline.append(dict(a))
    except:
        pass

    # Alertes Suricata
    try:
        suricata = conn.execute("""
            SELECT timestamp as ts, src_ip as ip,
                   signature as message, niveau,
                   'IDS' as type_ev
            FROM suricata_alertes
            ORDER BY timestamp DESC LIMIT ?
        """, (limit,)).fetchall()
        for s in suricata:
            timeline.append(dict(s))
    except:
        pass

    # Blocages firewall
    try:
        blocages = conn.execute("""
            SELECT date_blocage as ts, ip,
                   raison as message,
                   'HIGH' as niveau,
                   'FIREWALL' as type_ev
            FROM blocages
            ORDER BY date_blocage DESC LIMIT ?
        """, (limit,)).fetchall()
        for b in blocages:
            timeline.append(dict(b))
    except:
        pass

    # Corrélations
    try:
        correlations = conn.execute("""
            SELECT timestamp as ts, ip,
                   rule_nom as message, severite as niveau,
                   'CORRELATION' as type_ev
            FROM correlation_events
            ORDER BY timestamp DESC LIMIT ?
        """, (limit,)).fetchall()
        for c in correlations:
            timeline.append(dict(c))
    except:
        pass

    conn.close()

    # Trier par timestamp décroissant
    timeline.sort(
        key=lambda x: x.get("ts", "") or "",
        reverse=True
    )

    return timeline[:limit]


# ══════════════════════════════════════════════
# EXPLICATION INTELLIGENTE DES ALERTES
# ══════════════════════════════════════════════
EXPLICATIONS_ALERTES = {
    "PORT_DANGEREUX": {
        "description": "Un port potentiellement dangereux est ouvert",
        "danger":      "Peut permettre un accès non autorisé au système",
        "impact":      "Compromission possible du système ou vol de données",
        "recommandation": "Fermer le port ou restreindre l'accès via firewall",
    },
    "PORT_CRITIQUE": {
        "description": "Port critique exposé (Telnet/FTP/RDP)",
        "danger":      "Ces protocoles transmettent les données en clair",
        "impact":      "Interception de mots de passe et données sensibles",
        "recommandation": "Remplacer par SSH/SFTP/VPN immédiatement",
    },
    "VENDOR_INCONNU": {
        "description": "Appareil non identifié sur le réseau",
        "danger":      "Peut être un appareil non autorisé ou malveillant",
        "impact":      "Point d'entrée potentiel pour un attaquant",
        "recommandation": "Identifier et isoler l'appareil",
    },
    "MAC_INCONNU": {
        "description": "Adresse MAC non lisible",
        "danger":      "Possible usurpation d'identité (MAC spoofing)",
        "impact":      "Contournement du contrôle d'accès réseau",
        "recommandation": "Vérifier l'appareil physiquement",
    },
    "PORT_RISQUE": {
        "description": "Port à risque modéré détecté",
        "danger":      "Service exposé pouvant être exploité",
        "impact":      "Accès non autorisé aux ressources réseau",
        "recommandation": "Restreindre l'accès via liste blanche IP",
    },
}

def expliquer_alerte(type_alerte):
    """Retourne une explication détaillée d'une alerte."""
    explication = EXPLICATIONS_ALERTES.get(
        type_alerte,
        {
            "description":    "Activité suspecte détectée",
            "danger":         "Comportement anormal sur le réseau",
            "impact":         "Impact potentiel sur la sécurité",
            "recommandation": "Analyser et surveiller cette activité",
        }
    )
    return explication


# ══════════════════════════════════════════════
# SIMULATION D'ATTAQUE
# ══════════════════════════════════════════════
def simuler_attaque():
    """
    Simule une attaque complète pour démonstration.
    Génère des alertes réalistes et déclenche le pipeline.
    """
    from database import sauvegarder_alerte, creer_scan
    from suricata_reader import simuler_alertes_test

    print("\n  🎯 SIMULATION D'ATTAQUE EN COURS...\n")
    resultats = []
    ip_attaquant = "10.10.10.99"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Étape 1 : Scan réseau
    conn = sqlite3.connect(DB_PATH)
    scan_id = conn.execute("""
        INSERT INTO scans (date_scan, ip_debut, ip_fin, nb_appareils)
        VALUES (?,?,?,?)
    """, (timestamp, "10.10.10.0", "10.10.10.255", 1)).lastrowid
    conn.commit()

    conn.execute("""
        INSERT INTO alertes
        (scan_id, ip, type_alerte, message, niveau, date_alerte)
        VALUES (?,?,?,?,?,?)
    """, (
        scan_id, ip_attaquant, "SCAN",
        f"Scan réseau depuis {ip_attaquant} — "
        f"192 ports analysés",
        "MEDIUM", timestamp
    ))

    resultats.append({
        "etape": "1 — Scan réseau",
        "action": "Détection scan Nmap",
        "niveau": "MEDIUM",
    })

    # Étape 2 : Brute force
    conn.execute("""
        INSERT INTO alertes
        (scan_id, ip, type_alerte, message, niveau, date_alerte)
        VALUES (?,?,?,?,?,?)
    """, (
        scan_id, ip_attaquant, "BRUTE",
        f"Tentative brute force SSH depuis {ip_attaquant}",
        "HIGH",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    resultats.append({
        "etape": "2 — Brute Force SSH",
        "action": "Alerte HIGH générée",
        "niveau": "HIGH",
    })

    # Étape 3 : Exploit
    conn.execute("""
        INSERT INTO suricata_alertes
        (timestamp, src_ip, src_port, dest_ip, dest_port,
         protocole, signature, categorie, severite, niveau,
         raw_data, date_import)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ip_attaquant, 4444,
        "192.168.216.143", 445,
        "TCP",
        "ET EXPLOIT EternalBlue MS17-010 — SIMULATION",
        "Exploit", 1, "CRITICAL", "{}",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    resultats.append({
        "etape": "3 — Exploit EternalBlue",
        "action": "Alerte Suricata CRITICAL",
        "niveau": "CRITICAL",
    })

    conn.commit()
    conn.close()

    # Étape 4 : Corrélation
    engine = CorrelationEngine()
    engine._init_table()
    events = engine.analyser_ip(ip_attaquant)
    resultats.append({
        "etape": "4 — Corrélation",
        "action": f"{len(events)} règles déclenchées",
        "niveau": "CRITICAL",
    })

    # Étape 5 : Blocage automatique
    from firewall import block_ip
    succes, msg = block_ip(
        ip_attaquant,
        "Blocage automatique simulation attaque",
        "CRITICAL"
    )
    resultats.append({
        "etape": "5 — Firewall",
        "action": msg,
        "niveau": "BLOCKED",
    })

    print("  ✅ Simulation terminée !")
    for r in resultats:
        print(f"  [{r['niveau']}] {r['etape']} → {r['action']}")

    return resultats


# ══════════════════════════════════════════════
# POINT D'ENTRÉE
# ══════════════════════════════════════════════
if __name__ == "__main__":
    print("\n🧠 Test Intelligence Engine\n")

    # Init
    engine   = CorrelationEngine()
    risk     = RiskEngine()
    behavior = BehaviorDetector()

    engine._init_table()

    # Risk score
    score = risk.calculer_score_global()
    print(f"  📊 Risk Score : {score['score']}/100 — {score['statut']}")
    for d in score["detail"]:
        print(f"     {d['facteur']} : {d['impact']}")

    # Corrélation
    events = engine.analyser_tout()
    print(f"\n  🔗 Corrélations : {len(events)} événements")
    for e in events:
        print(f"     [{e['severite']}] {e['ip']} → {e['regle']}")

    # Anomalies
    anomalies = behavior.detecter_anomalies()
    print(f"\n  🧬 Anomalies : {len(anomalies)}")
    for a in anomalies:
        print(f"     [{a['severite']}] {a['description']}")

    # Recommandations
    recos = generer_recommandations()
    print(f"\n  💡 Recommandations : {len(recos)}")
    for r in recos:
        print(f"     [{r['priorite']}] {r['titre']}")

    # Timeline
    timeline = get_timeline(limit=5)
    print(f"\n  🕐 Timeline : {len(timeline)} événements")
    for t in timeline:
        print(f"     {t.get('ts','')} | {t.get('type_ev','')} | {t.get('ip','')}")
