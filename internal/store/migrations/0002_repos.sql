-- Repositories found by discovery (internal/repos). A repository that
-- disappears is kept and marked missing, so its history stays.
CREATE TABLE repos (
    path        TEXT    PRIMARY KEY,
    missing     INTEGER NOT NULL DEFAULT 0,
    first_seen  INTEGER NOT NULL,           -- Unix ms
    last_seen   INTEGER NOT NULL,           -- Unix ms
    usage_bytes INTEGER,                    -- NULL until measured
    usage_files INTEGER,
    usage_time  INTEGER                     -- Unix ms of the measurement
);
