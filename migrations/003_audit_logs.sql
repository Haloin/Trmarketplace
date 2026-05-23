-- Audit logging table for security events
-- Never stores IP addresses or other identifying metadata
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    pubkey_hash TEXT,
    resource_id TEXT,
    resource_type TEXT,
    details TEXT,
    timestamp INTEGER NOT NULL,
    severity TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_pubkey_hash ON audit_logs(pubkey_hash);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_severity ON audit_logs(severity);
