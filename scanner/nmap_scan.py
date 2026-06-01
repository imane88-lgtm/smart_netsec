# scanner/nmap_scan.py
# ============================================================
# MODULE 2 : Scanner avancé avec Nmap
# Objectif : identifier chaque appareil en détail
# ============================================================

import nmap
from datetime import datetime

# ──────────────────────────────────────────────
# Dictionnaire : détecter le type d'appareil
# selon le vendor (fabricant)
# ──────────────────────────────────────────────
VENDORS_TYPES = {
    "apple":     "📱 Mobile/Mac",
    "samsung":   "📱 Mobile",
    "xiaomi":    "📱 Mobile",
    "huawei":    "📱 Mobile/Routeur",
    "cisco":     "🌐 Routeur/Switch",
    "tp-link":   "🌐 Routeur",
    "vmware":    "💻 Machine Virtuelle",
    "virtualbox":"💻 Machine Virtuelle",
    "intel":     "💻 PC",
    "dell":      "💻 PC",
    "hp":        "💻 PC",
    "raspberry": "🔧 IoT/Raspberry Pi",
    "espressif": "🔧 IoT",
}

# Ports considérés comme dangereux
PORTS_DANGEREUX = {
    21:   "FTP — transfert fichiers non chiffré",
    22:   "SSH — accès distant",
    23:   "Telnet — NON CHIFFRÉ ⚠️",
    80:   "HTTP — non chiffré",
    443:  "HTTPS",
    445:  "SMB — partage Windows",
    3389: "RDP — bureau à distance",
    8080: "HTTP alternatif",
    3306: "MySQL — base de données",
    5900: "VNC — bureau distant",
}


# ──────────────────────────────────────────────
# Fonction 1 : Détecter le type d'appareil
# ──────────────────────────────────────────────
def detecter_type(vendor):
    """Identifie le type d'appareil selon le fabricant."""
    if not vendor:
        return "❓ Inconnu"
    
    vendor_lower = vendor.lower()
    for mot_cle, type_appareil in VENDORS_TYPES.items():
        if mot_cle in vendor_lower:
            return type_appareil
    
    return "💻 PC/Autre"


# ──────────────────────────────────────────────
# Fonction 2 : Scanner un appareil avec Nmap
# ──────────────────────────────────────────────
def scanner_appareil(ip):
    """
    Scan complet d'un appareil :
    - Ports ouverts
    - Services
    - MAC + Vendor
    - Hostname
    """
    nm = nmap.PortScanner()
    
    print(f"\n  🔎 Scan de {ip}...")
    
    # Arguments Nmap expliqués :
    # -sS  : Scan SYN (rapide et discret)
    # -O   : Détection OS
    # -sV  : Détection version des services
    # -T4  : Vitesse rapide
    # --top-ports 100 : Les 100 ports les plus communs
    try:
        nm.scan(
            hosts=ip,
            arguments="-sS -sV -T4 --top-ports 100",
            sudo=True
        )
    except Exception as e:
        print(f"  ❌ Erreur scan {ip} : {e}")
        return None
    
    # Vérifier si l'hôte a répondu
    if ip not in nm.all_hosts():
        return None
    
    hote = nm[ip]
    
    # ── Récupérer les infos de base ──
    hostname = "Inconnu"
    if hote.hostname():
        hostname = hote.hostname()
    
    mac = "Inconnu"
    vendor = "Inconnu"
    if "mac" in hote.get("addresses", {}):
        mac = hote["addresses"]["mac"]
    if "vendor" in hote and mac in hote["vendor"]:
        vendor = hote["vendor"][mac]
    
    # ── Récupérer les ports ouverts ──
    ports_ouverts = []
    ports_risques = []
    
    for protocole in hote.all_protocols():
        ports = hote[protocole].keys()
        for port in ports:
            info_port = hote[protocole][port]
            if info_port["state"] == "open":
                service = info_port.get("name", "?")
                version = info_port.get("version", "")
                
                ports_ouverts.append({
                    "port":    port,
                    "service": service,
                    "version": version,
                })
                
                # Vérifier si port dangereux
                if port in PORTS_DANGEREUX:
                    ports_risques.append({
                        "port":   port,
                        "risque": PORTS_DANGEREUX[port]
                    })
    
    # ── Construire le résultat ──
    resultat = {
        "ip":            ip,
        "hostname":      hostname,
        "mac":           mac,
        "vendor":        vendor,
        "type":          detecter_type(vendor),
        "ports_ouverts": ports_ouverts,
        "ports_risques": ports_risques,
        "nb_ports":      len(ports_ouverts),
        "timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    
    return resultat


# ──────────────────────────────────────────────
# Fonction 3 : Afficher le résultat proprement
# ──────────────────────────────────────────────
def afficher_appareil(info):
    """Affiche les infos d'un appareil de façon lisible."""
    if not info:
        return
    
    print(f"\n  {'─'*45}")
    print(f"  📍 IP       : {info['ip']}")
    print(f"  🖥️  Type     : {info['type']}")
    print(f"  🏷️  Hostname : {info['hostname']}")
    print(f"  🔑 MAC      : {info['mac']}")
    print(f"  🏭 Vendor   : {info['vendor']}")
    print(f"  🔌 Ports    : {info['nb_ports']} ouverts")
    
    # Afficher les ports ouverts
    if info["ports_ouverts"]:
        print(f"\n     Ports ouverts :")
        for p in info["ports_ouverts"]:
            print(f"     → {p['port']:5} | {p['service']:10} | {p['version']}")
    
    # Afficher les alertes de sécurité
    if info["ports_risques"]:
        print(f"\n     ⚠️  ALERTES SÉCURITÉ :")
        for r in info["ports_risques"]:
            print(f"     🔴 Port {r['port']} : {r['risque']}")
    else:
        print(f"\n     ✅ Aucun port dangereux détecté")


# ──────────────────────────────────────────────
# Fonction principale : Scanner toute une liste
# ──────────────────────────────────────────────
def scanner_liste(liste_ips):
    """Scanner plusieurs appareils et retourner les résultats."""
    print(f"\n{'='*50}")
    print(f"  🔍 SCAN AVANCÉ NMAP")
    print(f"  {len(liste_ips)} appareils à analyser")
    print(f"{'='*50}")
    
    resultats = []
    
    for ip in liste_ips:
        info = scanner_appareil(ip)
        if info:
            afficher_appareil(info)
            resultats.append(info)
    
    # Résumé final
    print(f"\n{'='*50}")
    print(f"  📊 RÉSUMÉ SCAN AVANCÉ")
    print(f"{'='*50}")
    print(f"  Appareils analysés : {len(resultats)}")
    
    total_risques = sum(len(r["ports_risques"]) for r in resultats)
    print(f"  Alertes sécurité   : {total_risques}")
    print(f"{'='*50}\n")
    
    return resultats


# ──────────────────────────────────────────────
# Point d'entrée
# ──────────────────────────────────────────────
if __name__ == "__main__":
    # ✅ Les IPs détectées à l'étape 1
    appareils_actifs = [
        "192.168.216.1",
        "192.168.216.2",
        "192.168.216.143",
    ]
    
    resultats = scanner_liste(appareils_actifs)
