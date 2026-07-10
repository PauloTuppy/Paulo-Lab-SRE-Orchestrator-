CREATE TABLE IF NOT EXISTS pending_incidents (
    incident_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    namespace TEXT NOT NULL,
    pod_name TEXT NOT NULL,
    proposed_action TEXT NOT NULL,
    playbook_id TEXT NOT NULL,
    playbook_parameters TEXT,
    manifest_path TEXT,
    status TEXT DEFAULT 'pending',
    retry_count INTEGER DEFAULT 0,
    ts_applied DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    error_message TEXT,
    fingerprint TEXT NOT NULL,
    incident_version INTEGER NOT NULL DEFAULT 1,
    idempotency_key TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at DATETIME,
    attempt_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_incidents (status);
CREATE INDEX IF NOT EXISTS idx_pending_created ON pending_incidents (created_at);

-- Partial unique index to enforce active fingerprint idempotency
CREATE UNIQUE INDEX IF NOT EXISTS idx_active_fingerprint 
ON pending_incidents (fingerprint) 
WHERE status IN ('pending', 'applying', 'validated', 'dry_run_passed', 'applied');
