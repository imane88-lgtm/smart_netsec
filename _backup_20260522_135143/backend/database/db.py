import sqlite3
import threading
import os
from backend.utils.logger import get_logger

log = get_logger("db")

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH  = os.path.join(ROOT_DIR, "netsec.db")

_local = threading.local()


def get_conn() -> sqlite3.Connection:
    """Retourne la connexion SQLite locale au thread courant."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
        _local.conn.execute("PRAGMA synchronous=NORMAL")
    return _local.conn


def execute(sql: str, params=(), fetchall=False, fetchone=False, commit=False):
    """Helper pratique pour exécuter du SQL depuis n'importe où."""
    conn = get_conn()
    cur  = conn.execute(sql, params)
    if commit:
        conn.commit()
    if fetchall:
        return cur.fetchall()
    if fetchone:
        return cur.fetchone()
    return cur


# ══════════════════════════════════════════════
# SCHÉMA COMPLET
# ══════════════════════════════════════════════
SCHEMA = """
-- Appareils réseau
CREATE TABLE IF NOT EXISTS appareils (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT UNIQUE,
    mac          TEXT,
    nom          TEXT,
    type_appareil TEXT,
    os           TEXT,
    fabricant    TEXT,
    ports_ouverts TEXT,
    score        INTEGER DEFAULT 100,
    statut       TEXT DEFAULT 'SAFE',
    actif        INTEGER DEFAULT 1,
    date_scan    TEXT,
    date_update  TEXT
);

-- Alertes globales
CREATE TABLE IF NOT EXISTS alertes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT,
    message      TEXT,
    niveau       TEXT DEFAULT 'LOW',
    date_alerte  TEXT,
    traite       INTEGER DEFAULT 0
);

-- Scans réseau
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT,
    ports_ouverts TEXT,
    os_detect    TEXT,
    date_scan    TEXT,
    duree_sec    REAL DEFAULT 0
);

-- Blocages IP
CREATE TABLE IF NOT EXISTS blocages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT,
    raison       TEXT,
    niveau       TEXT DEFAULT 'MANUAL',
    auto_block   INTEGER DEFAULT 0,
    cree_par     TEXT DEFAULT 'admin',
    date_blocage TEXT,
    date_expir   TEXT,
    actif        INTEGER DEFAULT 1
);

-- Whitelist
CREATE TABLE IF NOT EXISTS whitelist (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT UNIQUE,
    raison       TEXT,
    date_ajout   TEXT
);

-- Blacklist
CREATE TABLE IF NOT EXISTS blacklist (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT UNIQUE,
    raison       TEXT,
    source       TEXT DEFAULT 'manual',
    date_ajout   TEXT
);

-- Règles Firewall nftables
CREATE TABLE IF NOT EXISTS firewall_rules (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id      TEXT UNIQUE,
    type         TEXT DEFAULT 'BLOCK',
    ip           TEXT DEFAULT '*',
    port         TEXT,
    protocole    TEXT DEFAULT 'tcp',
    direction    TEXT DEFAULT 'INPUT',
    priorite     INTEGER DEFAULT 100,
    raison       TEXT,
    cree_par     TEXT DEFAULT 'admin',
    date_create  TEXT,
    actif        INTEGER DEFAULT 1
);

-- Logs Firewall
CREATE TABLE IF NOT EXISTS fw_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT,
    action       TEXT,
    ip_src       TEXT,
    ip_dst       TEXT DEFAULT '*',
    port_dst     TEXT,
    protocole    TEXT DEFAULT 'any',
    raison       TEXT
);

-- Alertes Snort IDS
CREATE TABLE IF NOT EXISTS snort_alertes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT,
    sid            TEXT,
    revision       TEXT,
    priority       INTEGER DEFAULT 3,
    classification TEXT,
    message        TEXT,
    src_ip         TEXT,
    src_port       TEXT,
    dst_ip         TEXT,
    dst_port       TEXT,
    protocole      TEXT,
    niveau         TEXT DEFAULT 'LOW',
    action_prise   TEXT DEFAULT 'LOG',
    interface      TEXT DEFAULT 'eth0',
    traite         INTEGER DEFAULT 0,
    UNIQUE(timestamp, sid, src_ip, dst_ip)
);

-- Supervision système
CREATE TABLE IF NOT EXISTS supervision_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT,
    cpu_pct         REAL DEFAULT 0,
    ram_pct         REAL DEFAULT 0,
    ram_used_mb     REAL DEFAULT 0,
    ram_total_mb    REAL DEFAULT 0,
    disk_pct        REAL DEFAULT 0,
    disk_used_gb    REAL DEFAULT 0,
    disk_total_gb   REAL DEFAULT 0,
    net_bytes_in    INTEGER DEFAULT 0,
    net_bytes_out   INTEGER DEFAULT 0,
    net_packets_in  INTEGER DEFAULT 0,
    net_packets_out INTEGER DEFAULT 0,
    nb_connexions   INTEGER DEFAULT 0
);

-- Rapports générés
CREATE TABLE IF NOT EXISTS rapports (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    date_creation  TEXT,
    titre          TEXT,
    nb_appareils   INTEGER DEFAULT 0,
    nb_alertes     INTEGER DEFAULT 0,
    score_global   INTEGER DEFAULT 0,
    genere_par     TEXT DEFAULT 'admin',
    fichier        TEXT DEFAULT 'rapport_securite.pdf'
);

-- Incidents SOC
CREATE TABLE IF NOT EXISTS incidents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    titre        TEXT,
    description  TEXT,
    severity     TEXT DEFAULT 'medium',
    statut       TEXT DEFAULT 'open',
    analyst      TEXT DEFAULT '—',
    ip_source    TEXT,
    date_detect  TEXT,
    date_update  TEXT,
    notes        TEXT DEFAULT ''
);

-- Corrélation
CREATE TABLE IF NOT EXISTS correlation_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id      TEXT,
    rule_nom     TEXT,
    ip           TEXT,
    severite     TEXT,
    action       TEXT,
    explication  TEXT,
    score_impact INTEGER DEFAULT 0,
    timestamp    TEXT,
    traite       INTEGER DEFAULT 0
);

-- Trafic réseau
CREATE TABLE IF NOT EXISTS traffic_stats (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT,
    interface       TEXT DEFAULT 'eth0',
    bytes_in        INTEGER DEFAULT 0,
    bytes_out       INTEGER DEFAULT 0,
    pkts_in         INTEGER DEFAULT 0,
    pkts_out        INTEGER DEFAULT 0,
    rate_in_kbps    REAL DEFAULT 0,
    rate_out_kbps   REAL DEFAULT 0
);

-- Utilisateurs
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT UNIQUE,
    password     TEXT,
    role         TEXT DEFAULT 'viewer',
    actif        INTEGER DEFAULT 1,
    date_create  TEXT
);
"""


def init_db():
    """Crée toutes les tables si elles n'existent pas."""
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    log.info(f"✅ DB initialisée: {DB_PATH}")
    _run_migrations(conn)


def _run_migrations(conn):
    """Migrations incrémentales — ajoute colonnes manquantes."""
    alters = [
        ("supervision_history", "net_bytes_in",    "INTEGER DEFAULT 0"),
        ("supervision_history", "net_bytes_out",   "INTEGER DEFAULT 0"),
        ("supervision_history", "net_packets_in",  "INTEGER DEFAULT 0"),
        ("supervision_history", "net_packets_out", "INTEGER DEFAULT 0"),
        ("supervision_history", "nb_connexions",   "INTEGER DEFAULT 0"),
        ("firewall_rules",      "rule_id",         "TEXT"),
        ("blocages",            "cree_par",        "TEXT DEFAULT 'admin'"),
        ("blocages",            "date_expir",      "TEXT"),
    ]
    for table, col, typedef in alters:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}")
        except Exception:
            pass  # colonne déjà existante
    conn.commit()
