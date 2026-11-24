-- Small key/value settings (notification switches "notify.<event>", the
-- last notified "Needs attention" state).
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
