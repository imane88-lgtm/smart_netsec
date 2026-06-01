# backend/database/db.py
import sqlite3, threading, os
from backend.utils.logger import get_logger
log = get_logger("db")

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH  = os.path.join(ROOT_DIR, "smart_netsec.db")

_local = threading.local()

def get_conn():
    if not hasattr(_local,"conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn

def execute(sql, params=(), fetchall=False, fetchone=False, commit=False):
    conn = get_conn()
    cur  = conn.execute(sql, params)
    if commit:
        conn.commit()
        return cur.lastrowid
    if fetchall: return cur.fetchall()
    if fetchone: return cur.fetchone()
    return cur

def init_db():
    conn = get_conn()
    conn.executescript("""
-- Users
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    login_attempts INTEGER DEFAULT 0,
    locked INTEGER DEFAULT 0,
    last_login TEXT,
    created_at TEXT
);

-- Appareils
CREATE TABLE IF NOT EXISTS appareils (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    ip TEXT NOT NULL,
    hostname TEXT DEFAULT 'Inconnu',
    mac TEXT DEFAULT 'Inconnu',
    vendor TEXT DEFAULT 'Inconnu',
    type_appareil TEXT DEFAULT 'Inconnu',
    fabricant TEXT DEFAULT 'Inconnu',
    nb_ports INTEGER DEFAULT 0,
    ports_ouverts TEXT DEFAULT '[]',
    ports_risques TEXT DEFAULT '[]',
    score INTEGER DEFAULT 100,
    date_ajout TEXT,
    date_scan TEXT
);

-- Scans
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date_scan TEXT,
    ip_debut TEXT DEFAULT '192.168.216.1',
    ip_fin TEXT DEFAULT '192.168.216.254',
    nb_appareils INTEGER DEFAULT 0,
    duree_sec REAL DEFAULT 0,
    lance_par TEXT DEFAULT 'system'
);

-- Alertes
CREATE TABLE IF NOT EXISTS alertes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    ip TEXT,
    type_alerte TEXT,
    message TEXT,
    niveau TEXT DEFAULT 'MEDIUM',
    date_alerte TEXT,
    traite INTEGER DEFAULT 0
);

-- Blocages
CREATE TABLE IF NOT EXISTS blocages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    raison TEXT,
    niveau TEXT DEFAULT 'MANUAL',
    auto_block INTEGER DEFAULT 0,
    cree_par TEXT DEFAULT 'admin',
    date_blocage TEXT,
    date_expire TEXT,
    actif INTEGER DEFAULT 1,
    nb_triggers INTEGER DEFAULT 1
);

-- Whitelist
CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    raison TEXT,
    date_ajout TEXT
);

-- Blacklist
CREATE TABLE IF NOT EXISTS blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    raison TEXT,
    source TEXT DEFAULT 'manual',
    date_ajout TEXT,
    actif INTEGER DEFAULT 1
);

-- Règles firewall
CREATE TABLE IF NOT EXISTS firewall_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT UNIQUE,
    type TEXT DEFAULT 'BLOCK',
    ip TEXT DEFAULT '*',
    port TEXT,
    protocole TEXT DEFAULT 'tcp',
    direction TEXT DEFAULT 'INPUT',
    priorite INTEGER DEFAULT 100,
    raison TEXT,
    cree_par TEXT DEFAULT 'admin',
    date_create TEXT,
    actif INTEGER DEFAULT 1,
    nb_hits INTEGER DEFAULT 0
);

-- Logs firewall
CREATE TABLE IF NOT EXISTS fw_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    action TEXT,
    ip_src TEXT,
    ip_dst TEXT DEFAULT '*',
    port_dst TEXT,
    protocole TEXT DEFAULT 'any',
    raison TEXT
);

-- Alertes Snort
CREATE TABLE IF NOT EXISTS snort_alertes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    sid TEXT,
    revision TEXT DEFAULT '1',
    priority INTEGER DEFAULT 3,
    classification TEXT,
    message TEXT,
    src_ip TEXT,
    src_port TEXT DEFAULT '0',
    dst_ip TEXT,
    dst_port TEXT DEFAULT '0',
    dest_ip TEXT DEFAULT '',
    protocole TEXT,
    niveau TEXT DEFAULT 'MEDIUM',
    action_prise TEXT DEFAULT 'LOG',
    interface TEXT DEFAULT 'eth0',
    traite INTEGER DEFAULT 0,
    UNIQUE(timestamp, src_ip, dst_ip, message)
);

-- Supervision
CREATE TABLE IF NOT EXISTS supervision_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    cpu_percent REAL DEFAULT 0,
    ram_percent REAL DEFAULT 0,
    ram_used_mb REAL DEFAULT 0,
    ram_total_mb REAL DEFAULT 0,
    disk_percent REAL DEFAULT 0,
    disk_used_gb REAL DEFAULT 0,
    disk_total_gb REAL DEFAULT 0,
    net_bytes_in INTEGER DEFAULT 0,
    net_bytes_out INTEGER DEFAULT 0,
    net_packets_in INTEGER DEFAULT 0,
    net_packets_out INTEGER DEFAULT 0,
    nb_connexions INTEGER DEFAULT 0,
    nb_alertes INTEGER DEFAULT 0,
    nb_bloques INTEGER DEFAULT 0,
    score_global INTEGER DEFAULT 0,
    statut TEXT DEFAULT 'NORMAL'
);

-- Rapports
CREATE TABLE IF NOT EXISTS rapports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date_creation TEXT,
    titre TEXT,
    nb_appareils INTEGER DEFAULT 0,
    nb_alertes INTEGER DEFAULT 0,
    score_global INTEGER DEFAULT 0,
    genere_par TEXT DEFAULT 'admin',
    fichier TEXT DEFAULT 'rapport_securite.pdf'
);

-- Incidents
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    titre TEXT,
    description TEXT,
    severity TEXT DEFAULT 'medium',
    statut TEXT DEFAULT 'open',
    analyst TEXT DEFAULT '—',
    ip_source TEXT,
    date_detect TEXT,
    date_update TEXT,
    notes TEXT DEFAULT ''
);

-- Corrélations
CREATE TABLE IF NOT EXISTS correlation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT, rule_nom TEXT, ip TEXT,
    severite TEXT, action TEXT, explication TEXT,
    score_impact INTEGER DEFAULT 0,
    timestamp TEXT, traite INTEGER DEFAULT 0
);

-- Trafic
CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT, interface TEXT DEFAULT 'eth0',
    bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0,
    pkts_in INTEGER DEFAULT 0, pkts_out INTEGER DEFAULT 0,
    rate_in_kbps REAL DEFAULT 0, rate_out_kbps REAL DEFAULT 0
);
""")
    conn.commit()
    _migrate(conn)
    log.info(f"DB initialisée: {DB_PATH}")

def _migrate(conn):
    alters = [
        ("blocages","niveau","TEXT DEFAULT 'MANUAL'"),
        ("blocages","auto_block","INTEGER DEFAULT 0"),
        ("blocages","cree_par","TEXT DEFAULT 'admin'"),
        ("blocages","nb_triggers","INTEGER DEFAULT 1"),
        ("snort_alertes","dest_ip","TEXT DEFAULT ''"),
        ("snort_alertes","interface","TEXT DEFAULT 'eth0'"),
        ("supervision_history","net_bytes_in","INTEGER DEFAULT 0"),
        ("supervision_history","net_bytes_out","INTEGER DEFAULT 0"),
        ("supervision_history","nb_connexions","INTEGER DEFAULT 0"),
    ]
    for table,col,typedef in alters:
        try: conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}")
        except: pass
    conn.commit()
