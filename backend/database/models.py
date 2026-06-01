# backend/database/models.py
# ============================================================
# Schémas des tables SQLite
# ============================================================

CREATE_TABLES = [

    # ── Utilisateurs ──
    """CREATE TABLE IF NOT EXISTS users (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        username       TEXT UNIQUE NOT NULL,
        password_hash  TEXT NOT NULL,
        role           TEXT DEFAULT 'user',
        created_at     TEXT,
        last_login     TEXT,
        login_attempts INTEGER DEFAULT 0,
        locked         INTEGER DEFAULT 0
    )""",

    # ── Scans réseau ──
    """CREATE TABLE IF NOT EXISTS scans (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        date_scan    TEXT NOT NULL,
        ip_debut     TEXT,
        ip_fin       TEXT,
        nb_appareils INTEGER DEFAULT 0,
        duree_sec    REAL DEFAULT 0,
        lance_par    TEXT DEFAULT 'system'
    )""",

    # ── Appareils détectés ──
    """CREATE TABLE IF NOT EXISTS appareils (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id       INTEGER,
        ip            TEXT NOT NULL,
        hostname      TEXT DEFAULT 'Inconnu',
        mac           TEXT DEFAULT 'Inconnu',
        vendor        TEXT DEFAULT 'Inconnu',
        type_appareil TEXT DEFAULT 'Inconnu',
        nb_ports      INTEGER DEFAULT 0,
        ports_ouverts TEXT DEFAULT '[]',
        ports_risques TEXT DEFAULT '[]',
        score         INTEGER DEFAULT 100,
        date_ajout    TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    )""",

    # ── Alertes sécurité ──
    """CREATE TABLE IF NOT EXISTS alertes (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id     INTEGER,
        ip          TEXT,
        type_alerte TEXT,
        message     TEXT,
        niveau      TEXT DEFAULT 'MEDIUM',
        date_alerte TEXT,
        traite      INTEGER DEFAULT 0,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    )""",

    # ── Firewall rules (nftables) ──
    """CREATE TABLE IF NOT EXISTS fw_rules (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id     TEXT UNIQUE,
        type        TEXT,        -- BLOCK / ALLOW / RATE_LIMIT
        ip          TEXT,
        port        INTEGER,
        protocole   TEXT DEFAULT 'all',
        direction   TEXT DEFAULT 'INPUT',
        priorite    INTEGER DEFAULT 100,
        actif       INTEGER DEFAULT 1,
        raison      TEXT,
        cree_par    TEXT DEFAULT 'system',
        date_create TEXT,
        date_expire TEXT,
        nb_hits     INTEGER DEFAULT 0,
        derniere_hit TEXT
    )""",

    # ── Firewall logs ──
    """CREATE TABLE IF NOT EXISTS fw_logs (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        action    TEXT,
        ip_src    TEXT,
        ip_dst    TEXT,
        port_src  INTEGER,
        port_dst  INTEGER,
        protocole TEXT,
        interface TEXT,
        bytes     INTEGER DEFAULT 0,
        rule_id   TEXT,
        raw_log   TEXT
    )""",

    # ── Blocages actifs ──
    """CREATE TABLE IF NOT EXISTS blocages (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        ip           TEXT NOT NULL,
        raison       TEXT,
        niveau       TEXT DEFAULT 'MANUAL',
        date_blocage TEXT,
        date_expire  TEXT,
        actif        INTEGER DEFAULT 1,
        auto_block   INTEGER DEFAULT 0,
        nb_triggers  INTEGER DEFAULT 1
    )""",

    # ── Whitelist ──
    """CREATE TABLE IF NOT EXISTS whitelist (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ip         TEXT UNIQUE NOT NULL,
        raison     TEXT,
        date_ajout TEXT
    )""",

    # ── Blacklist persistante ──
    """CREATE TABLE IF NOT EXISTS blacklist (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ip         TEXT UNIQUE NOT NULL,
        raison     TEXT,
        source     TEXT DEFAULT 'manual',
        date_ajout TEXT,
        actif      INTEGER DEFAULT 1
    )""",

    # ── Alertes Snort IDS ──
    """CREATE TABLE IF NOT EXISTS snort_alertes (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp    TEXT,
        priority     INTEGER DEFAULT 3,
        message      TEXT,
        protocole    TEXT,
        src_ip       TEXT,
        src_port     INTEGER,
        dst_ip       TEXT,
        dst_port     INTEGER,
        sid          TEXT,
        revision     TEXT,
        classification TEXT,
        niveau       TEXT DEFAULT 'MEDIUM',
        action_prise TEXT DEFAULT 'LOG',
        raw_alert    TEXT,
        date_import  TEXT,
        traite       INTEGER DEFAULT 0
    )""",

    # ── Connexions actives ──
    """CREATE TABLE IF NOT EXISTS connexions_actives (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT,
        proto      TEXT,
        local_ip   TEXT,
        local_port INTEGER,
        remote_ip  TEXT,
        remote_port INTEGER,
        etat       TEXT,
        pid        INTEGER,
        process    TEXT
    )""",

    # ── Monitoring système ──
    """CREATE TABLE IF NOT EXISTS supervision_history (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp    TEXT,
        cpu_percent  REAL,
        ram_percent  REAL,
        ram_used_mb  INTEGER,
        disk_percent REAL,
        net_bytes_in  INTEGER DEFAULT 0,
        net_bytes_out INTEGER DEFAULT 0,
        net_packets_in  INTEGER DEFAULT 0,
        net_packets_out INTEGER DEFAULT 0,
        nb_connexions INTEGER DEFAULT 0,
        nb_alertes    INTEGER DEFAULT 0,
        nb_bloques    INTEGER DEFAULT 0,
        score_global  INTEGER DEFAULT 0,
        statut        TEXT DEFAULT 'NORMAL'
    )""",

    # ── Corrélations ──
    """CREATE TABLE IF NOT EXISTS correlation_events (
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
    )""",

    # ── Incidents SOC ──
    """CREATE TABLE IF NOT EXISTS incidents (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        titre       TEXT,
        description TEXT,
        severity    TEXT DEFAULT 'medium',
        statut      TEXT DEFAULT 'open',
        analyst     TEXT DEFAULT '—',
        ip_source   TEXT,
        date_detect TEXT,
        date_update TEXT,
        date_close  TEXT,
        notes       TEXT
    )""",

    # ── Statistiques trafic réseau ──
    """CREATE TABLE IF NOT EXISTS traffic_stats (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT,
        interface   TEXT,
        bytes_in    INTEGER DEFAULT 0,
        bytes_out   INTEGER DEFAULT 0,
        pkts_in     INTEGER DEFAULT 0,
        pkts_out    INTEGER DEFAULT 0,
        rate_in_kbps  REAL DEFAULT 0,
        rate_out_kbps REAL DEFAULT 0
    )""",
]
