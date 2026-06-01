# ai_assistant.py
# ============================================================
# AI ASSISTANT — Analyse intelligente et recommandations
# ============================================================

import sqlite3
from datetime import datetime
from database import DB_PATH
from intelligence import (
    RiskEngine, generer_recommandations,
    get_timeline, CorrelationEngine
)


# ══════════════════════════════════════════════
# RÉPONSES SIMULÉES (Base de connaissances)
# ══════════════════════════════════════════════
KNOWLEDGE_BASE = {
    "scan": {
        "keywords": ["scan","nmap","scanner","réseau"],
        "reponse":  (
            "Un scan réseau détecte les appareils actifs et "
            "leurs ports ouverts. Un scan Nmap SYN (-sS) est "
            "le plus utilisé. Si vous détectez un scan depuis "
            "une IP inconnue, c'est souvent la première étape "
            "d'une attaque (reconnaissance)."
        ),
    },
    "smb": {
        "keywords": ["smb","445","wannacry","ransomware"],
        "reponse":  (
            "Le port 445 (SMB) est extrêmement dangereux s'il "
            "est exposé. WannaCry et NotPetya ont exploité une "
            "faille SMB (EternalBlue/MS17-010). "
            "Recommandation : bloquer le port 445 sur le "
            "firewall et appliquer les patches Microsoft."
        ),
    },
    "brute": {
        "keywords": ["brute","force","password","mot de passe"],
        "reponse":  (
            "Une attaque brute force tente toutes les "
            "combinaisons de mots de passe. Pour s'en "
            "protéger : activer fail2ban, utiliser des mots "
            "de passe forts (12+ caractères), activer la "
            "double authentification (2FA) et limiter les "
            "tentatives de connexion."
        ),
    },
    "score": {
        "keywords": ["score","risque","sécurité","niveau"],
        "reponse":  None,  # Dynamique
    },
    "alerte": {
        "keywords": ["alerte","alert","critique","danger"],
        "reponse":  None,  # Dynamique
    },
    "ip": {
        "keywords": ["bloquer","débloquer","ip","firewall"],
        "reponse":  (
            "Pour bloquer une IP suspecte, utilisez le bouton "
            "Bloquer dans le tableau des appareils ou la "
            "section Firewall. Le blocage est appliqué via "
            "iptables automatiquement. Vous pouvez débloquer "
            "à tout moment depuis la même interface."
        ),
    },
    "telnet": {
        "keywords": ["telnet","23","ftp","21"],
        "reponse":  (
            "Telnet (port 23) et FTP (port 21) transmettent "
            "les données en clair, sans chiffrement. "
            "Alternatives sécurisées : SSH (port 22) pour "
            "remplacer Telnet, et SFTP/SCP pour remplacer "
            "FTP. Désactivez ces services immédiatement."
        ),
    },
    "bonjour": {
        "keywords": ["bonjour","salut","hello","aide","help"],
        "reponse":  (
            "Bonjour ! Je suis l'assistant IA de Smart NetSec "
            "SOC. Je peux vous aider à : analyser les alertes "
            "de sécurité, comprendre les risques détectés, "
            "obtenir des recommandations, et expliquer les "
            "menaces réseau. Posez-moi une question !"
        ),
    },
}


# ══════════════════════════════════════════════
# GÉNÉRATEUR DE RÉPONSES
# ══════════════════════════════════════════════
class AIAssistant:

    def __init__(self):
        self.risk_engine        = RiskEngine()
        self.correlation_engine = CorrelationEngine()

    def _get_contexte(self):
        """Récupère le contexte actuel du système."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        try:
            nb_appareils = conn.execute(
                "SELECT COUNT(*) FROM appareils"
            ).fetchone()[0]
            nb_alertes = conn.execute(
                "SELECT COUNT(*) FROM alertes"
            ).fetchone()[0]
            nb_bloques = conn.execute(
                "SELECT COUNT(*) FROM blocages WHERE actif=1"
            ).fetchone()[0]
            nb_critical = conn.execute(
                """SELECT COUNT(*) FROM alertes
                   WHERE niveau IN ('CRITICAL','HIGH')"""
            ).fetchone()[0]
        except:
            nb_appareils = nb_alertes = nb_bloques = nb_critical = 0

        conn.close()

        risk = self.risk_engine.calculer_score_global()

        return {
            "nb_appareils": nb_appareils,
            "nb_alertes":   nb_alertes,
            "nb_bloques":   nb_bloques,
            "nb_critical":  nb_critical,
            "risk_score":   risk["score"],
            "risk_statut":  risk["statut"],
        }

    def _reponse_score(self, ctx):
        """Réponse dynamique sur le score."""
        score  = ctx["risk_score"]
        statut = ctx["risk_statut"]
        if score >= 80:
            return (
                f"Votre score de sécurité est {score}/100 — "
                f"état {statut}. Le réseau est bien sécurisé. "
                f"Continuez à surveiller les nouveaux appareils "
                f"et effectuez des scans réguliers."
            )
        elif score >= 60:
            return (
                f"Votre score est {score}/100 — état {statut}. "
                f"Des risques modérés ont été détectés. "
                f"Vous avez {ctx['nb_alertes']} alertes et "
                f"{ctx['nb_bloques']} IP bloquées. "
                f"Traitez les alertes critiques en priorité."
            )
        else:
            return (
                f"⚠️ Score critique : {score}/100 — {statut}. "
                f"{ctx['nb_critical']} alertes critiques "
                f"nécessitent une attention immédiate. "
                f"Vérifiez la section Firewall et bloquez "
                f"les IPs suspectes."
            )

    def _reponse_alertes(self, ctx):
        """Réponse dynamique sur les alertes."""
        return (
            f"Vous avez actuellement {ctx['nb_alertes']} alertes "
            f"dont {ctx['nb_critical']} critiques. "
            f"{'Attention : des menaces actives nécessitent une action immédiate !' if ctx['nb_critical'] > 0 else 'La situation est sous contrôle.'} "
            f"Consultez l'onglet Alertes pour les détails."
        )

    def _reponse_reseau(self, ctx):
        """Résumé de l'état du réseau."""
        return (
            f"État du réseau — Score : {ctx['risk_score']}/100 "
            f"({ctx['risk_statut']}). "
            f"{ctx['nb_appareils']} appareils détectés, "
            f"{ctx['nb_alertes']} alertes générées, "
            f"{ctx['nb_bloques']} IPs bloquées. "
            f"{'Menaces actives détectées !' if ctx['nb_critical'] > 0 else 'Aucune menace critique active.'}"
        )

    def get_resume_systeme(self):
        """Génère un résumé complet du système."""
        ctx  = self._get_contexte()
        risk = self.risk_engine.calculer_score_global()
        recos = generer_recommandations()

        resume = {
            "score":          ctx["risk_score"],
            "statut":         ctx["risk_statut"],
            "nb_appareils":   ctx["nb_appareils"],
            "nb_alertes":     ctx["nb_alertes"],
            "nb_bloques":     ctx["nb_bloques"],
            "nb_critical":    ctx["nb_critical"],
            "recommandations": recos[:3],
            "risk_detail":    risk["detail"],
            "timestamp":      datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        }
        return resume

    def repondre(self, message):
        """
        Génère une réponse à un message utilisateur.
        Analyse le message et retourne une réponse contextuelle.
        """
        msg_lower = message.lower().strip()
        ctx = self._get_contexte()

        # ── Réponses spéciales dynamiques ──
        if any(k in msg_lower for k in
               ["réseau","résumé","état","status","summary"]):
            return self._reponse_reseau(ctx)

        if any(k in msg_lower for k in ["score","risque","risk"]):
            return self._reponse_score(ctx)

        if any(k in msg_lower for k in
               ["alerte","alert","critique","menace"]):
            return self._reponse_alertes(ctx)

        if any(k in msg_lower for k in
               ["recommand","conseil","faire","améliorer"]):
            recos = generer_recommandations()
            if recos:
                texte = "Recommandations prioritaires :\n"
                for r in recos[:3]:
                    texte += f"• [{r['priorite']}] {r['titre']}\n"
                return texte
            return "Aucune recommandation urgente pour le moment."

        # ── Base de connaissances ──
        for key, data in KNOWLEDGE_BASE.items():
            if any(kw in msg_lower for kw in data["keywords"]):
                if data["reponse"]:
                    return data["reponse"]

        # ── Réponse par défaut ──
        return (
            "Je n'ai pas compris votre question. "
            "Essayez : 'état du réseau', 'score de sécurité', "
            "'alertes critiques', 'recommandations', "
            "ou posez une question sur SMB, Telnet, brute force..."
        )
