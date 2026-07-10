CREATE TABLE IF NOT EXISTS pending_incidents (
    incident_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    namespace TEXT NOT NULL,
    pod_name TEXT NOT NULL,
    proposed_action TEXT NOT NULL,
    manifest_path TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    retry_count INTEGER DEFAULT 0,
    ts_applied DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_incidents (status);
CREATE INDEX IF NOT EXISTS idx_pending_created ON pending_incidents (created_at);
