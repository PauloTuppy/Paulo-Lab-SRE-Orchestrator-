CREATE TABLE IF NOT EXISTS incident_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    action_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    proof_contract_json TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    decision_reason TEXT,
    applied_at DATETIME,
    classified_at DATETIME,
    historian_model TEXT,
    trace_id TEXT,
    run_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_history_fingerprint ON incident_history (fingerprint);
CREATE INDEX IF NOT EXISTS idx_history_fingerprint_action ON incident_history (fingerprint, action_type);
CREATE INDEX IF NOT EXISTS idx_history_created ON incident_history (created_at);
