import re
import uuid
import subprocess
import platform
from datetime import datetime
from backend.database.db import get_conn
from backend.utils.logger import get_logger

log = get_logger("firewall_service")

NFT_TABLE  = "netsec_filter"
NFT_CHAIN  = "input_block"
_SIM       = False   # True = mode simulation (nft absent)


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _nft(*args, check=False):
    """Exécute une commande nft et retourne (ok, stdout, stderr)."""
    global _SIM
    if _SIM:
        return True, "", ""
    try:
        r = subprocess.run(
            ["nft"] + list(args),
            capture_output=True, text=True, timeout=8,
        )
        if r.returncode != 0 and check:
            return False, r.stdout, r.stderr
        return r.returncode == 0, r.stdout, r.stderr
    except FileNotFoundError:
        _SIM = True
        log.warning("nft non trouvé — mode simulation activé")
        return True, "", ""
    except Exception as e:
        log.error(f"nft error: {e}")
        return False, "", str(e)


# ══════════════════════════════════════════════
# INIT nftables
# ══════════════════════════════════════════════
def init_nftables():
    """Crée la table et les chaînes netsec_filter si absentes."""
    cmds = [
        f"add table ip {NFT_TABLE}",
        f"add chain ip {NFT_TABLE} {NFT_CHAIN} {{ type filter hook input priority 0; policy accept; }}",
        f"add chain ip {NFT_TABLE} output_block {{ type filter hook output priority 0; policy accept; }}",
        f"add chain ip {NFT_TABLE} forward_block {{ type filter hook forward priority 0; policy accept; }}",
    ]
    for c in cmds:
        _nft(*c.split())
    log.info(f"nftables table '{NFT_TABLE}' initialisée")
    # Charger les règles persistées depuis la DB
    _reload_persisted_rules()


def _reload_persisted_rules():
    """Recharge toutes les règles actives depuis la DB vers nftables."""
    try:
        conn = get_conn()
        rules = conn.execute(
            "SELECT * FROM firewall_rules WHERE actif=1"
        ).fetchall()
        for r in rules:
            r = dict(r)
            _apply_nft_rule(
                r["type"], r["ip"], r.get("port"), r.get("protocole", "tcp"),
                r.get("direction", "INPUT"), comment=r.get("raison", "")
            )
        # Recharger les blocages actifs
        blocages = conn.execute(
            "SELECT * FROM blocages WHERE actif=1"
        ).fetchall()
        for b in blocages:
            _nft_block_ip(dict(b)["ip"])
        log.info(f"Rechargé {len(rules)} règles + {len(blocages)} blocages")
    except Exception as e:
        log.warning(f"_reload_persisted_rules: {e}")


# ══════════════════════════════════════════════
# BLOCAGE IP
# ══════════════════════════════════════════════
def _nft_block_ip(ip: str):
    ok, _, err = _nft(
        "add", "rule", "ip", NFT_TABLE, NFT_CHAIN,
        "ip", "saddr", ip, "drop",
        "comment", f'"blocked-{ip}"',
    )
    if not ok and not _SIM:
        log.warning(f"nft block {ip}: {err}")
    return ok


def _nft_unblock_ip(ip: str):
    """Supprime toutes les règles de blocage pour cette IP."""
    ok, out, _ = _nft("list", "ruleset")
    if not ok:
        return True  # simulation
    handles = []
    in_chain = False
    for line in out.splitlines():
        if NFT_CHAIN in line:
            in_chain = True
        if in_chain and ip in line and "drop" in line:
            m = re.search(r"handle (\d+)", line)
            if m:
                handles.append(m.group(1))
    for h in handles:
        _nft("delete", "rule", "ip", NFT_TABLE, NFT_CHAIN, "handle", h)
    return True


def block_ip(ip: str, raison: str = "Blocage manuel",
             niveau: str = "MANUAL", cree_par: str = "admin",
             auto_block: int = 0):
    """Bloque une IP via nftables + persist en DB."""
    ip = ip.strip()
    if not _validate_ip(ip):
        return False, f"IP invalide : {ip}"

    # Vérifier si déjà bloquée
    conn = get_conn()
    existing = conn.execute(
        "SELECT id FROM blocages WHERE ip=? AND actif=1", (ip,)
    ).fetchone()
    if existing:
        return True, f"ℹ️ {ip} déjà bloquée"

    # Appliquer nftables
    _nft_block_ip(ip)

    # Ajouter log FW
    _fw_log("BLOCK", ip, "*", None, "any", raison)

    # Persister en DB
    conn.execute(
        """INSERT OR REPLACE INTO blocages
           (ip, raison, niveau, auto_block, cree_par, date_blocage, actif)
           VALUES (?,?,?,?,?,?,1)""",
        (ip, raison, niveau, auto_block, cree_par, _now()),
    )
    conn.commit()
    log.info(f"BLOCK {ip} — {raison}")
    return True, f"✅ {ip} bloquée"


def unblock_ip(ip: str):
    """Débloque une IP via nftables + MAJ DB."""
    ip = ip.strip()
    _nft_unblock_ip(ip)
    conn = get_conn()
    conn.execute("UPDATE blocages SET actif=0 WHERE ip=?", (ip,))
    conn.commit()
    _fw_log("UNBLOCK", ip, "*", None, "any", "Déblocage manuel")
    log.info(f"UNBLOCK {ip}")
    return True, f"✅ {ip} débloquée"


# ══════════════════════════════════════════════
# RÈGLES FIREWALL
# ══════════════════════════════════════════════
def _apply_nft_rule(type_: str, ip: str, port, proto: str,
                    direction: str, comment: str = ""):
    """Traduit une règle DB en commande nftables."""
    chain = {
        "INPUT":   NFT_CHAIN,
        "OUTPUT":  "output_block",
        "FORWARD": "forward_block",
    }.get(direction.upper(), NFT_CHAIN)

    parts = ["add", "rule", "ip", NFT_TABLE, chain]

    if ip and ip not in ("*", "any", ""):
        addr_kw = "saddr" if direction.upper() in ("INPUT", "FORWARD") else "daddr"
        parts += ["ip", addr_kw, ip]

    if proto and proto.lower() not in ("all", "any", "*", ""):
        parts += [proto.lower()]
        if port and str(port) not in ("*", "0", ""):
            parts += ["dport", str(port)]

    verdict = "drop" if type_.upper() == "BLOCK" else "accept"
    parts += [verdict]

    if comment:
        parts += ["comment", f'"{comment[:60]}"']

    return _nft(*parts)


def add_rule(type_: str = "BLOCK", ip: str = "*",
             port=None, proto: str = "tcp",
             direction: str = "INPUT", priorite: int = 100,
             raison: str = "Règle manuelle", cree_par: str = "admin"):
    """Ajoute une règle nftables et la persiste en DB."""
    rule_id = str(uuid.uuid4())[:18]
    ok, _, err = _apply_nft_rule(type_, ip, port, proto, direction, raison)
    if not ok and not _SIM:
        log.warning(f"nft rule add failed: {err}")

    conn = get_conn()
    conn.execute(
        """INSERT INTO firewall_rules
           (rule_id, type, ip, port, protocole, direction, priorite, raison,
            cree_par, date_create, actif)
           VALUES (?,?,?,?,?,?,?,?,?,?,1)""",
        (rule_id, type_.upper(), ip, port, proto, direction.upper(),
         priorite, raison, cree_par, _now()),
    )
    conn.commit()
    _fw_log("RULE_ADD", ip, "*", port, proto, raison)
    log.info(f"ADD_RULE {type_} {ip}:{port}/{proto} [{direction}]")
    return True, f"✅ Règle ajoutée ({rule_id[:8]})"


def delete_rule(rule_id: str):
    """Supprime une règle de la DB (la règle nftables survivra jusqu'au prochain flush)."""
    conn = get_conn()
    r = conn.execute(
        "SELECT * FROM firewall_rules WHERE rule_id=?", (rule_id,)
    ).fetchone()
    if not r:
        # Essayer id entier
        r = conn.execute(
            "SELECT * FROM firewall_rules WHERE id=?", (rule_id,)
        ).fetchone()
    if not r:
        return False, "Règle introuvable"
    r = dict(r)
    conn.execute(
        "UPDATE firewall_rules SET actif=0 WHERE rule_id=?", (r["rule_id"],)
    )
    conn.commit()
    log.info(f"DELETE_RULE {rule_id}")
    return True, f"✅ Règle {rule_id[:8]} supprimée"


def toggle_rule(rule_id: str, actif: int):
    """Active ou désactive une règle."""
    conn = get_conn()
    conn.execute(
        "UPDATE firewall_rules SET actif=? WHERE rule_id=?", (actif, rule_id)
    )
    conn.commit()
    log.info(f"TOGGLE_RULE {rule_id} → actif={actif}")
    return True, f"✅ Règle {'activée' if actif else 'désactivée'}"


# ══════════════════════════════════════════════
# STATISTIQUES
# ══════════════════════════════════════════════
def get_firewall_stats():
    """Retourne les statistiques firewall complètes."""
    from backend.database import repositories as repo
    conn = get_conn()

    nb_bl = conn.execute(
        "SELECT COUNT(*) FROM blocages WHERE actif=1"
    ).fetchone()[0]
    nb_wl = conn.execute("SELECT COUNT(*) FROM whitelist").fetchone()[0]
    nb_bll = conn.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]
    nb_ru  = conn.execute(
        "SELECT COUNT(*) FROM firewall_rules WHERE actif=1"
    ).fetchone()[0]
    last_row = conn.execute(
        "SELECT ip FROM blocages WHERE actif=1 ORDER BY date_blocage DESC LIMIT 1"
    ).fetchone()
    last_ip = last_row[0] if last_row else "—"

    # Statut nftables
    ok, out, _ = _nft("list", "table", "ip", NFT_TABLE)
    statut = "ACTIF" if (ok or _SIM) else "INACTIF"

    return {
        "nb_bloques":  nb_bl,
        "nb_whitelist": nb_wl,
        "nb_blacklist": nb_bll,
        "nb_rules":    nb_ru,
        "derniere_ip": last_ip,
        "statut":      statut,
        "simulation":  _SIM,
        "blocages":    repo.get_blocages(actif=True),
        "rules":       repo.get_fw_rules(),
        "whitelist":   repo.get_whitelist(),
        "blacklist":   repo.get_blacklist(),
        "logs":        repo.get_fw_logs(20),
        "connexions":  get_active_connections(),
    }


# ══════════════════════════════════════════════
# CONNEXIONS ACTIVES
# ══════════════════════════════════════════════
def get_active_connections():
    """Parse /proc/net/tcp et /proc/net/udp pour les connexions actives."""
    connections = []
    _states = {
        "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
        "04": "FIN_WAIT1",   "05": "FIN_WAIT2","06": "TIME_WAIT",
        "07": "CLOSE",       "08": "CLOSE_WAIT","09": "LAST_ACK",
        "0A": "LISTEN",      "0B": "CLOSING",
    }
    blocked_ips = set()
    try:
        conn = get_conn()
        rows = conn.execute(
            "SELECT ip FROM blocages WHERE actif=1"
        ).fetchall()
        blocked_ips = {r[0] for r in rows}
    except Exception:
        pass

    for proto, path in [("tcp", "/proc/net/tcp"), ("udp", "/proc/net/udp")]:
        try:
            with open(path) as f:
                lines = f.readlines()[1:]
            for line in lines[:80]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local_h, rem_h, state_h = parts[1], parts[2], parts[3]
                lip, lport = _hex_to_addr(local_h)
                rip, rport = _hex_to_addr(rem_h)
                if lip in ("0.0.0.0", "127.0.0.1") and rip in ("0.0.0.0", "127.0.0.1"):
                    continue
                state = _states.get(state_h.upper(), state_h)
                suspicious = rip in blocked_ips
                connections.append({
                    "proto": proto.upper(), "state": state,
                    "local_ip": lip,  "local_port":  lport,
                    "remote_ip": rip, "remote_port": rport,
                    "suspicious": suspicious, "process": "—",
                })
        except Exception:
            pass

    # Si /proc non disponible (macOS/Windows), retourner via netstat
    if not connections:
        try:
            r = subprocess.run(
                ["netstat", "-tn"], capture_output=True, text=True, timeout=4
            )
            for line in r.stdout.splitlines()[2:]:
                p = line.split()
                if len(p) < 5:
                    continue
                lip, lport = _parse_addr(p[3])
                rip, rport = _parse_addr(p[4])
                connections.append({
                    "proto": p[0], "state": p[5] if len(p) > 5 else "—",
                    "local_ip": lip, "local_port": lport,
                    "remote_ip": rip, "remote_port": rport,
                    "suspicious": rip in blocked_ips, "process": "—",
                })
        except Exception:
            pass
    return connections[:60]


def _hex_to_addr(hex_str: str):
    try:
        addr, port = hex_str.split(":")
        ip_int = int(addr, 16)
        ip = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
        port_int = int(port, 16)
        return ip, port_int
    except Exception:
        return "—", 0


def _parse_addr(s: str):
    try:
        parts = s.rsplit(":", 1)
        return parts[0].strip("[]"), parts[1] if len(parts) > 1 else "0"
    except Exception:
        return "—", 0


# ══════════════════════════════════════════════
# AUTO-RÉPONSE
# ══════════════════════════════════════════════
def auto_response(ip: str, niveau: str = "MEDIUM", message: str = ""):
    """Détermine et applique une action automatique selon la sévérité."""
    from backend.database import repositories as repo
    if repo.is_whitelisted(ip):
        return "SKIP_WHITELIST", f"{ip} ignorée (whitelist)"

    if niveau in ("CRITICAL",):
        ok, msg = block_ip(ip, f"Auto-block CRITICAL: {message[:40]}", niveau, "auto", auto_block=1)
        return "BLOCKED", msg

    if niveau in ("HIGH",):
        ok, msg = block_ip(ip, f"Auto-block HIGH: {message[:40]}", niveau, "auto", auto_block=1)
        return "BLOCKED", msg

    if niveau == "MEDIUM":
        # Log uniquement
        _fw_log("MONITOR", ip, "*", None, "any", f"Medium alert: {message[:40]}")
        return "MONITOR", f"Surveillance de {ip}"

    return "LOG", f"Alerte LOW enregistrée pour {ip}"


# ══════════════════════════════════════════════
# LOGS FIREWALL
# ══════════════════════════════════════════════
def _fw_log(action: str, ip_src: str, ip_dst: str = "*",
            port_dst=None, protocole: str = "any", raison: str = ""):
    try:
        conn = get_conn()
        conn.execute(
            """INSERT INTO fw_logs
               (timestamp, action, ip_src, ip_dst, port_dst, protocole, raison)
               VALUES (?,?,?,?,?,?,?)""",
            (_now(), action, ip_src, ip_dst, port_dst, protocole, raison),
        )
        conn.commit()
    except Exception as e:
        log.warning(f"_fw_log: {e}")


# ══════════════════════════════════════════════
# VALIDATION
# ══════════════════════════════════════════════
def _validate_ip(ip: str) -> bool:
    if ip in ("*", "any", ""):
        return False
    # CIDR accepté
    if "/" in ip:
        ip = ip.split("/")[0]
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
