-- glc_v1 audit log. Append-only; the application layer never issues
-- UPDATE or DELETE against this table.

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    session_id      TEXT,
    channel         TEXT    NOT NULL,
    channel_user_id TEXT    NOT NULL,
    trust_level     TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    tool            TEXT,
    policy_verdict  TEXT,
    params_json     TEXT,
    result_json     TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_channel ON audit_log(channel, ts DESC);

-- Invariant 7: components must not be able to edit or delete their own
-- audit logs. Section 7 leak 2 previously demonstrated a plain
-- sqlite3.connect(...).execute("DELETE FROM audit_log") emptying the
-- table — the append-only contract lived only in glc/audit/store.py's
-- Python API (no update()/delete() method exposed), which any other
-- code opening the same file with the stdlib sqlite3 module bypassed
-- trivially. These triggers move the guarantee into the database
-- itself: SQLite enforces them for *any* connection to this file,
-- regardless of which Python code — or which language — issued the
-- statement.
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is not permitted');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is not permitted');
END;

-- Schema version table: any change to the columns above requires a
-- documented version bump. Migrations are not automatic.
CREATE TABLE IF NOT EXISTS audit_schema (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);
INSERT OR IGNORE INTO audit_schema (version, applied_at) VALUES (1, strftime('%s','now'));
