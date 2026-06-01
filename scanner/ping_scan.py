# scanner/ping_scan.py
# ============================================================
# MODULE 1 : Scan réseau par ping (ICMP)
# Objectif : détecter les appareils actifs sur le réseau
# ============================================================

import subprocess
import platform
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

def ping_host(ip):
    systeme = platform.system()
    if systeme == "Windows":
        commande = ["ping", "-n", "1", "-w", "500", str(ip)]
    else:
        commande = ["ping", "-c", "1", "-W", "1", str(ip)]
    
    resultat = subprocess.run(
        commande,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return resultat.returncode == 0


def scan_reseau(ip_debut, ip_fin):
    print(f"\n{'='*50}")
    print(f"  🔍 SMART NETSEC — Scan Réseau")
    print(f"  Plage : {ip_debut} → {ip_fin}")
    print(f"  Heure : {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*50}\n")
    
    debut = ipaddress.IPv4Address(ip_debut)
    fin   = ipaddress.IPv4Address(ip_fin)
    
    liste_ips = []
    ip_courante = debut
    while ip_courante <= fin:
        liste_ips.append(str(ip_courante))
        ip_courante += 1
    
    print(f"  📡 Scan de {len(liste_ips)} adresses IP...\n")
    
    appareils_actifs = []
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        resultats = {executor.submit(ping_host, ip): ip for ip in liste_ips}
        
        for futur in resultats:
            ip = resultats[futur]
            est_actif = futur.result()
            
            if est_actif:
                appareils_actifs.append(ip)
                print(f"  ✅ {ip:20} → ACTIF")
    
    print(f"\n{'='*50}")
    print(f"  📊 RÉSULTATS DU SCAN")
    print(f"{'='*50}")
    print(f"  Total IPs scannées  : {len(liste_ips)}")
    print(f"  Appareils détectés  : {len(appareils_actifs)}")
    print(f"  Appareils inactifs  : {len(liste_ips) - len(appareils_actifs)}")
    print(f"{'='*50}\n")
    
    return appareils_actifs


if __name__ == "__main__":
    # ✅ MODIFIÉ — Plage correcte pour ton réseau
    IP_DEBUT = "192.168.216.1"
    IP_FIN   = "192.168.216.254"
    
    appareils = scan_reseau(IP_DEBUT, IP_FIN)
    
    if appareils:
        print("  🖥️  Appareils actifs trouvés :")
        for ip in sorted(appareils):
            print(f"     → {ip}")
    else:
        print("  ⚠️  Aucun appareil détecté.")
