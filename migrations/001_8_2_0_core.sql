-- migrations/001_8_2_0_core.sql — additive only. No DROP, no rebuild.
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_context_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    fingerprint TEXT,
    fingerprint_class TEXT,
    fingerprint_weight REAL,
    subnet TEXT,
    gateway TEXT,
    gateway_class TEXT,
    gateway_mac TEXT,
    gateway_mac_class TEXT,
    dns TEXT,
    dns_class TEXT,
    dhcp TEXT,
    dhcp_class TEXT,
    ssid TEXT,
    bssid TEXT,
    source_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_nco_time ON network_context_observations(timestamp);

CREATE TABLE IF NOT EXISTS identity_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_a TEXT NOT NULL,
    device_b TEXT NOT NULL,
    outcome TEXT NOT NULL,
    score REAL NOT NULL,
    explain_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    created_at TEXT NOT NULL,
    reviewed_at TEXT,
    reviewer TEXT,
    UNIQUE(device_a, device_b, outcome)
);
CREATE INDEX IF NOT EXISTS idx_ic_status ON identity_candidates(status, created_at);

CREATE TABLE IF NOT EXISTS device_presence_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    device_id TEXT,
    ip TEXT,
    state TEXT NOT NULL,
    prior_state TEXT,
    confidence REAL,
    evidence_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_dpe_dev ON device_presence_events(device_id, timestamp);

CREATE TABLE IF NOT EXISTS engine_diagnostics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    engine TEXT NOT NULL,
    state TEXT NOT NULL,
    reason TEXT,
    detail_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_ed_engine ON engine_diagnostics(engine, timestamp);